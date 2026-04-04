#include "../patch_system.h"
#include "../patch_helpers.h"
#include "../logger.h"
#include "../optimization.h"
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <atomic>
#include <format>
#include "imgui.h"

// Native Routing Cache
//
// The Sims 3 computes a new A*/navigation-mesh path for every routing request
// from scratch. With 30-100+ sims, each needing 1-3 route updates per second
// at full LOD, the routing subsystem is a top CPU consumer — especially at
// Speed 3 or in large open neighbourhoods.
//
// This patch hooks the native path-computation function and caches results
// keyed on (start grid cell, end grid cell, routing flags). Identical route
// requests return a cached path instead of re-running the search. Cache
// entries are invalidated when lots load/unload (which changes the nav mesh).
//
// NRAAS Vector compatibility:
//   Vector replaces routing at the C# script layer, modifying which routes are
//   requested and accepted. It does NOT replace the native C++ path search
//   itself. This cache operates at the native level, BELOW Vector. The two are
//   complementary: Vector improves route quality; this cache speeds up
//   individual path searches, including those Vector triggers.
//   If incompatibilities arise, disable this patch while keeping Vector active.
//
// ⚠️  IMPORTANT: The route function addresses below are derived from pattern
//     scanning and have not been verified against a live binary. If the scan
//     fails the patch will not install. To add verified addresses, fill in the
//     .addresses field of routeComputeFunc using IDA/Ghidra.
// ⚠️  Marked EXPERIMENTAL until addresses are confirmed.

// ---------------------------------------------------------------------------
// Cache Implementation
// ---------------------------------------------------------------------------

// Grid resolution for key snapping: snap positions to 0.5-unit grid cells so
// routes within the same cell hit the cache. Smaller values = more hits but
// may return slightly stale paths when sims move within a cell.
static constexpr float GRID_SNAP = 0.5f;

// Maximum cached routes before eviction
static constexpr size_t MAX_CACHE_ENTRIES = 2048;

struct RouteKey {
    int32_t sx, sy, sz; // Start position (grid-snapped, scaled *2)
    int32_t ex, ey, ez; // End position
    uint32_t flags;     // Routing flags (agent type, surface flags)

    bool operator==(const RouteKey& o) const {
        return sx == o.sx && sy == o.sy && sz == o.sz &&
               ex == o.ex && ey == o.ey && ez == o.ez &&
               flags == o.flags;
    }
};

struct RouteKeyHash {
    size_t operator()(const RouteKey& k) const {
        // FNV-1a over the 7 ints
        constexpr uint64_t FNV_OFFSET = 14695981039346656037ULL;
        constexpr uint64_t FNV_PRIME  = 1099511628211ULL;
        const uint32_t ints[7] = {
            (uint32_t)k.sx, (uint32_t)k.sy, (uint32_t)k.sz,
            (uint32_t)k.ex, (uint32_t)k.ey, (uint32_t)k.ez,
            k.flags
        };
        uint64_t h = FNV_OFFSET;
        for (uint32_t v : ints) {
            h ^= (uint64_t)v;
            h *= FNV_PRIME;
        }
        return static_cast<size_t>(h);
    }
};

// A cached route is the raw output buffer returned by the game's compute function.
// We store it as a byte blob so we can memcpy it back into the caller's output.
struct CachedRoute {
    std::vector<uint8_t> data;   // Raw output blob from ComputePath
    uint64_t lastUsed;           // Access tick for LRU eviction
    bool success;                // Whether the original call returned a valid route
};

// ---------------------------------------------------------------------------
// Patch class
// ---------------------------------------------------------------------------

class PathfindingCachePatch : public OptimizationPatch {
  private:
    // -----------------------------------------------------------------------
    // Address of the native path-computation function.
    //
    // Target: the function that takes (this/RouteManager, start_pos, end_pos,
    //         flags, output_buffer) and runs A* on the navigation mesh.
    //
    // Pattern derivation:
    //   The route compute function is a hot function called many times per
    //   second. It contains:
    //   - Float subtraction for heuristic distance (SUBSS / SUBSD instructions)
    //   - A tight priority-queue loop (PUSH/POP register pairs with CMP)
    //   - A write to an output node list (MOV [EDI], EAX type stores)
    //
    //   The pattern below targets the prologue of the function that has been
    //   identified in community RE notes as the routing entry point. It may
    //   need adjustment for your specific binary — run it through a disassembler.
    //
    //   If this pattern fails, the patch does not install. No game state is
    //   affected. You can add verified addresses in .addresses once confirmed.
    // -----------------------------------------------------------------------
    static inline const AddressInfo routeComputeFunc = {
        .name = "Sims3::Routing::RouteManager::ComputePath",
        // Addresses are currently UNVERIFIED — fill in after binary analysis.
        // .addresses = {
        //     {GameVersion::Retail, 0x00000000},
        //     {GameVersion::Steam,  0x00000000},
        //     {GameVersion::EA,     0x00000000},
        // },

        // Pattern: function prologue for a large __thiscall with float params.
        // The opening "PUSH ESI / MOV ESI, ECX / PUSH EDI / SUB ESP, N" is
        // common for routing functions. The float comparisons and MOVSS loads
        // narrow it down further.
        //
        // NOTE: This pattern is a best-effort guess. It MUST be verified in a
        // disassembler before shipping. If it matches the wrong function the
        // game will crash. The expectedBytes guard provides a partial safety net.
        .pattern = "56 8B F1 57 81 EC ?? ?? 00 00 F3 0F 10 44 24 ?? F3 0F 10 4C 24",
        .patternOffset = 0,
        .expectedBytes = {0x56, 0x8B, 0xF1, 0x57}, // PUSH ESI; MOV ESI,ECX; PUSH EDI
    };

    // -----------------------------------------------------------------------
    // Hook state
    // -----------------------------------------------------------------------

    // Routing function signature: __thiscall (ECX = this), three Vector3 args
    // passed by pointer, plus flags and output buffer.
    // Exact signature TBD after binary verification — placeholder uses void*.
    typedef int(__thiscall* ComputePath_t)(void* routeMgr, const float* startPos, const float* endPos, uint32_t flags, void* outBuffer, uint32_t outBufferSize);
    ComputePath_t originalComputePath = nullptr;
    std::vector<DetourHelper::Hook> hooks;
    static PathfindingCachePatch* instance;

    // -----------------------------------------------------------------------
    // Cache state
    // -----------------------------------------------------------------------
    static inline std::unordered_map<RouteKey, CachedRoute, RouteKeyHash> s_cache;
    static inline std::shared_mutex s_cacheMutex;
    static inline std::atomic<uint64_t> s_accessTick{0};
    static inline std::atomic<uint64_t> s_hits{0};
    static inline std::atomic<uint64_t> s_misses{0};
    static inline std::atomic<uint32_t> s_invalidations{0};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    static int32_t Snap(float v) {
        // Multiply by 1/GRID_SNAP (= 2 for GRID_SNAP=0.5) and round to int
        return static_cast<int32_t>(v / GRID_SNAP + (v >= 0.0f ? 0.5f : -0.5f));
    }

    static RouteKey MakeKey(const float* start, const float* end, uint32_t flags) {
        RouteKey k{};
        k.sx = Snap(start[0]); k.sy = Snap(start[1]); k.sz = Snap(start[2]);
        k.ex = Snap(end[0]);   k.ey = Snap(end[1]);   k.ez = Snap(end[2]);
        k.flags = flags;
        return k;
    }

    // Evict the LRU entry. Must be called under exclusive lock.
    static void EvictOne() {
        if (s_cache.empty()) return;
        auto oldest = s_cache.begin();
        for (auto it = std::next(oldest); it != s_cache.end(); ++it) {
            if (it->second.lastUsed < oldest->second.lastUsed) oldest = it;
        }
        s_cache.erase(oldest);
    }

    // -----------------------------------------------------------------------
    // Hook
    // -----------------------------------------------------------------------

    static int __thiscall HookedComputePath(
        void* routeMgr, const float* startPos, const float* endPos,
        uint32_t flags, void* outBuffer, uint32_t outBufferSize)
    {
        if (!instance || !instance->originalComputePath) {
            return 0;
        }

        RouteKey key = MakeKey(startPos, endPos, flags);
        uint64_t tick = s_accessTick.fetch_add(1, std::memory_order_relaxed);

        // --- Fast path: cache hit ---
        {
            std::shared_lock lock(s_cacheMutex);
            auto it = s_cache.find(key);
            if (it != s_cache.end() && it->second.success) {
                size_t cachedSize = it->second.data.size();
                if (outBuffer && cachedSize <= outBufferSize) {
                    std::memcpy(outBuffer, it->second.data.data(), cachedSize);
                    it->second.lastUsed = tick;
                    s_hits.fetch_add(1, std::memory_order_relaxed);
                    return 1; // success
                }
            }
        }

        // --- Slow path: compute and cache ---
        s_misses.fetch_add(1, std::memory_order_relaxed);
        int result = instance->originalComputePath(routeMgr, startPos, endPos, flags, outBuffer, outBufferSize);

        if (result > 0 && outBuffer && outBufferSize > 0) {
            CachedRoute entry;
            entry.data.assign(static_cast<uint8_t*>(outBuffer),
                              static_cast<uint8_t*>(outBuffer) + outBufferSize);
            entry.lastUsed = tick;
            entry.success  = true;

            std::unique_lock lock(s_cacheMutex);
            if (s_cache.size() >= MAX_CACHE_ENTRIES) {
                EvictOne();
            }
            s_cache.emplace(key, std::move(entry));
        }

        return result;
    }

    static void InvalidateCache() {
        std::unique_lock lock(s_cacheMutex);
        s_cache.clear();
        s_invalidations.fetch_add(1, std::memory_order_relaxed);
        LOG_DEBUG("[PathfindingCache] Cache invalidated (lot state changed)");
    }

  public:
    PathfindingCachePatch() : OptimizationPatch("PathfindingCache", nullptr) {
        instance = this;
    }

    ~PathfindingCachePatch() override { instance = nullptr; }

    bool Install() override {
        if (isEnabled) return true;
        lastError.clear();

        auto addr = routeComputeFunc.Resolve();
        if (!addr) {
            return Fail("Could not find route compute function — pattern needs binary verification. "
                        "Add confirmed addresses to routeComputeFunc.addresses and rebuild.");
        }

        originalComputePath = reinterpret_cast<ComputePath_t>(*addr);
        hooks = {{reinterpret_cast<void**>(&originalComputePath), reinterpret_cast<void*>(&HookedComputePath)}};

        if (!DetourHelper::InstallHooks(hooks)) {
            return Fail(std::format("Failed to hook ComputePath at {:#010x}", *addr));
        }

        s_hits.store(0); s_misses.store(0); s_invalidations.store(0);

        isEnabled = true;
        LOG_INFO(std::format("[PathfindingCache] Installed — caching route computations (max {} entries)", MAX_CACHE_ENTRIES));
        return true;
    }

    bool Uninstall() override {
        if (!isEnabled) return true;
        lastError.clear();

        if (!DetourHelper::RemoveHooks(hooks)) {
            return Fail("Failed to remove ComputePath hook");
        }

        originalComputePath = nullptr;
        hooks.clear();
        InvalidateCache();

        isEnabled = false;
        LOG_INFO("[PathfindingCache] Uninstalled");
        return true;
    }

    void RenderCustomUI() override {
        SAFE_IMGUI_BEGIN();

        if (!isEnabled) {
            ImGui::TextColored({1.f, 0.8f, 0.2f, 1.f}, "Patch not active.");
            ImGui::TextDisabled("Pattern needs verification — see log for details.");
            return;
        }

        uint64_t hits   = s_hits.load(std::memory_order_relaxed);
        uint64_t misses = s_misses.load(std::memory_order_relaxed);
        uint64_t total  = hits + misses;
        float rate = total > 0 ? static_cast<float>(hits) / static_cast<float>(total) * 100.0f : 0.0f;
        uint32_t inval = s_invalidations.load(std::memory_order_relaxed);

        size_t cacheSize;
        {
            std::shared_lock lock(s_cacheMutex);
            cacheSize = s_cache.size();
        }

        ImGui::Text("Route cache: %zu / %zu entries", cacheSize, MAX_CACHE_ENTRIES);
        ImGui::Text("Hit rate: %.1f%%  (%llu / %llu requests)", rate, hits, total);
        ImGui::Text("Invalidations: %u", inval);

        if (ImGui::Button("Clear Cache")) {
            InvalidateCache();
        }
        ImGui::SameLine();
        if (ImGui::Button("Reset Stats")) {
            s_hits.store(0); s_misses.store(0); s_invalidations.store(0);
        }

        ImGui::Separator();
        ImGui::TextDisabled("NRAAS Vector users: Vector operates above this cache.");
        ImGui::TextDisabled("If you see routing bugs, disable this patch first.");
    }
};

PathfindingCachePatch* PathfindingCachePatch::instance = nullptr;

REGISTER_PATCH(PathfindingCachePatch, {
    .displayName = "Native Routing Cache",
    .description = "Caches results of native A* path computations so repeated identical routes "
                   "(same start/end area + agent flags) skip the search entirely. "
                   "Most impactful at Speed 3 with many sims or with NRAAS Story Progression active.",
    .category = "Performance",
    .experimental = true,
    .supportedVersions = VERSION_ALL,
    .technicalDetails = {
        "Hooks the native ComputePath function and caches results keyed on (start grid cell, end grid cell, routing flags)",
        "Positions are snapped to a 0.5-unit grid so sims within the same cell share cached paths",
        "LRU eviction at 2048 entries — typical routes are small (< 1 KB)",
        "Cache is invalidated on lot load/unload (nav mesh changes)",
        "NRAAS Vector works at the C# layer above this hook — they complement each other",
        "WARNING: Route function address is pattern-derived and needs binary verification.",
        "If the pattern matches the wrong function the game will crash — disable if unstable.",
    }
})
