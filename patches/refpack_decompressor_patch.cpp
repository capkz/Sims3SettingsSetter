#include "../patch_system.h"
#include "../patch_helpers.h"
#include "../logger.h"
#include "../optimization.h"
#include <windows.h>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <atomic>
#include <immintrin.h>
#include "imgui.h"
// my magnum opus I fear

// There are probably other optimisations (PGO??? idk what that is but sure) but for now I am never touching this again ever
class RefPackDecompressorPatch : public OptimizationPatch {
  private:
    static inline const AddressInfo refPackDecompressor = {
        .name = "RefPackDecompressor::hookAddr",
        .addresses =
            {
                {GameVersion::Retail, 0x004eb900},
                {GameVersion::Steam, 0x004eb3b0},
                {GameVersion::EA, 0x004eb4f0},
            },
        .pattern = "83 EC 10 8B 4C 24 1C 85 C9 53 55 56 8B 74 24 20 57 C7 44 24 1C 00 00 00 00 0F 84",
        .expectedBytes = {0x83, 0xEC, 0x10, 0x8B, 0x4C, 0x24, 0x1C},
    };

    std::vector<PatchHelper::PatchLocation> patchedLocations;
    static RefPackDecompressorPatch* instance;
    static bool cpuHasAVX2;

    // Strategy structs, compiler inlines these directly into template instantiations instead of causing indirect jump if we did function pointer h-haha... Totally worth it...
    // We use these because some people can't use AVX2 :( BOOOOOOOOOOOOOOOOO
    struct StrategySSE2 {
        static __forceinline void Copy(uint8_t* dst, const uint8_t* src, uint32_t len) {
            uint8_t* d = dst;
            const uint8_t* s = src;
            while (len >= 16) {
                _mm_storeu_si128((__m128i*)d, _mm_loadu_si128((const __m128i*)s));
                d += 16;
                s += 16;
                len -= 16;
            }
            while (len--) *d++ = *s++;
        }
    };

    struct StrategyAVX2 {
        static __forceinline void Copy(uint8_t* dst, const uint8_t* src, uint32_t len) {
            uint8_t* d = dst;
            const uint8_t* s = src;
            // 32-byte chunks (AVX2)
            while (len >= 32) {
                _mm256_storeu_si256((__m256i*)d, _mm256_loadu_si256((const __m256i*)s));
                d += 32;
                s += 32;
                len -= 32;
            }
            // 16-byte chunks (SSE2)
            while (len >= 16) {
                _mm_storeu_si128((__m128i*)d, _mm_loadu_si128((const __m128i*)s));
                d += 16;
                s += 16;
                len -= 16;
            }
            // Tail
            while (len--) *d++ = *s++;
        }
    };

    template <typename Strategy> static __forceinline void CopyOverlapping(uint8_t* dst, const uint8_t* src, uint32_t len) {
        ptrdiff_t offset = dst - src;

        // For RLE (offset < len), src is 'history' relative to dst
        // As long as offset >= 32, the 32-byte load reads data that was written at least 32 bytes ago
        // Since we write 32 bytes at a time, we never overwrite data we are about to read in the SAME iteration... we pray
        if (offset >= 32) {
            Strategy::Copy(dst, src, len);
        } else if (offset >= 16) {
            while (len >= 16) {
                _mm_storeu_si128((__m128i*)dst, _mm_loadu_si128((const __m128i*)src));
                dst += 16;
                src += 16;
                len -= 16;
            }
            while (len--) *dst++ = *src++;
        } else {
            // Tight byte-copy loop for small overlaps
            while (len--) *dst++ = *src++;
        }
    }

    template <typename Strategy> static int DecompressImpl(uint8_t* __restrict dst, uint32_t dstSize, uint8_t* __restrict src, uint32_t srcSize) {
        // Basic sanity checks
        if (!dst || !src || srcSize < 2) return 0;

        uint8_t* dstStart = dst;
        uint8_t* dstEnd = dst + dstSize;
        uint8_t* srcEnd = src + srcSize;

        // Header parsing + validation
        // We MUST validate the header to ensure we don't overrun input or output
        uint16_t header = (src[0] << 8) | src[1];
        src += 2;
        // srcSize tracked implicitly by pointer comparison now, but we need to check initial header read
        // (Checked by srcSize < 2 above)

        uint32_t skipBytes = 0;
        uint32_t sizeBytes = 3;

        if (header & 0x8000) {
            skipBytes = (header & 0x100) ? 4 : 0;
            sizeBytes = 4;
        } else {
            skipBytes = (header & 0x100) ? 3 : 0;
            sizeBytes = 3;
        }

        // Validate header read bounds
        if (src + skipBytes + sizeBytes > srcEnd) return 0;

        src += skipBytes;

        // Read expected size to validate against buffer size
        uint32_t expectedSize = 0;
        if (sizeBytes == 4) {
            expectedSize = (src[0] << 24) | (src[1] << 16) | (src[2] << 8) | src[3];
            src += 4;
        } else {
            expectedSize = (src[0] << 16) | (src[1] << 8) | src[2];
            src += 3;
        }

        // Validate output buffer size
        // If the caller provided a buffer smaller than the decompressed size, fail asap
        if (expectedSize > dstSize) {
            // Log error? For now just return 0 to match original behavior on error, really doubt this ever gets hit anyway
            return 0;
        }

        // main loop
        while (src < srcEnd) {
            // Ensure we can read at least the command byte
            if (src >= srcEnd) break;

            uint8_t cmd = *src++;

            // Type 1: Short Backref (0x00-0x7F)
            if (cmd < 0x80) {
                if (src >= srcEnd) goto error_truncated;
                uint8_t offset_low = *src++;

                uint32_t literal_len = cmd & 0x3;
                uint32_t match_len = ((cmd >> 2) & 0x7) + 3;
                uint32_t offset = (((cmd & 0x60) << 3) | offset_low) + 1;

                // Literal Copy
                if (literal_len) {
                    // Bounds check: input and output
                    if (src + literal_len > srcEnd || dst + literal_len > dstEnd) goto error_overflow;

                    dst[0] = src[0];
                    if (literal_len > 1) dst[1] = src[1];
                    if (literal_len > 2) dst[2] = src[2];

                    dst += literal_len;
                    src += literal_len;
                }

                // Backref Copy
                if (offset > (uint32_t)(dst - dstStart) || dst + match_len > dstEnd) goto error_overflow;

                CopyOverlapping<Strategy>(dst, dst - offset, match_len);
                dst += match_len;
            }
            // Type 2: Medium Backref (0x80-0xBF)
            else if (!(cmd & 0x40)) {
                if (src + 2 > srcEnd) goto error_truncated;
                uint8_t offset_high = *src++;
                uint8_t offset_low = *src++;

                uint32_t literal_len = offset_high >> 6;
                uint32_t match_len = (cmd & 0x3F) + 4;
                uint32_t offset = (((offset_high & 0x3F) << 8) | offset_low) + 1;

                if (literal_len) {
                    if (src + literal_len > srcEnd || dst + literal_len > dstEnd) goto error_overflow;
                    dst[0] = src[0];
                    if (literal_len > 1) dst[1] = src[1];
                    if (literal_len > 2) dst[2] = src[2];
                    dst += literal_len;
                    src += literal_len;
                }

                if (offset > (uint32_t)(dst - dstStart) || dst + match_len > dstEnd) goto error_overflow;
                CopyOverlapping<Strategy>(dst, dst - offset, match_len);
                dst += match_len;
            }
            // Type 3: Long Backref (0xC0-0xDF)
            else if (!(cmd & 0x20)) {
                if (src + 3 > srcEnd) goto error_truncated;
                uint8_t b2 = *src++;
                uint8_t b3 = *src++;
                uint8_t b4 = *src++;

                uint32_t literal_len = cmd & 0x3;
                uint32_t match_len = (((cmd & 0xC) << 6) + b4) + 5;
                uint32_t offset = (((cmd & 0x10) << 12) | (b2 << 8) | b3) + 1;

                if (literal_len) {
                    if (src + literal_len > srcEnd || dst + literal_len > dstEnd) goto error_overflow;
                    dst[0] = src[0];
                    if (literal_len > 1) dst[1] = src[1];
                    if (literal_len > 2) dst[2] = src[2];
                    dst += literal_len;
                    src += literal_len;
                }

                if (offset > (uint32_t)(dst - dstStart) || dst + match_len > dstEnd) goto error_overflow;
                CopyOverlapping<Strategy>(dst, dst - offset, match_len);
                dst += match_len;
            }
            // Type 4: Literal Run / Stop (0xE0-0xFF)
            else {
                uint32_t len = ((cmd & 0x1F) << 2) + 4;

                if (len > 112) {
                    len = cmd & 0x3; // Stop code
                    // Handle tail bytes
                    if (len) {
                        if (src + len > srcEnd || dst + len > dstEnd) goto error_overflow;
                        dst[0] = src[0];
                        if (len > 1) dst[1] = src[1];
                        if (len > 2) dst[2] = src[2];
                    }
                    return (int)expectedSize;
                }

                if (src + len > srcEnd || dst + len > dstEnd) goto error_overflow;
                Strategy::Copy(dst, src, len);
                dst += len;
                src += len;
            }
        }
        return 0; // Source exhausted without stop code = malformed data

    error_truncated:
    error_overflow:
        return 0;
    }

    static int __cdecl Dispatch(uint8_t* dst, uint32_t dstSize, uint8_t* src, uint32_t srcSize) {
        if (cpuHasAVX2) {
            return DecompressImpl<StrategyAVX2>(dst, dstSize, src, srcSize);
        } else {
            return DecompressImpl<StrategySSE2>(dst, dstSize, src, srcSize);
        }
    }

    // -------------------------------------------------------------------------
    // Decompression Result Cache — Slab + O(1) LRU
    //
    // Caches decompressed data keyed by FNV-1a of ALL compressed bytes.
    //
    // Memory design (critical for 32-bit address space):
    //   - ONE contiguous VirtualAlloc slab holds all cached data back-to-back.
    //     This means a single VA region, not N scattered heap allocations.
    //   - Each slot in the slab is a fixed-size record:
    //       [uint32 size | uint64 key | data bytes (up to SLOT_SIZE)]
    //   - A separate std::unordered_map<key → slot_index> provides O(1) lookup.
    //   - A doubly-linked list of slot indices maintains LRU order. Eviction
    //     is O(1): remove the tail node.
    //   - s_slabUsedBytes tracks only the data portion — but reported overhead
    //     in the UI accounts for the map + list metadata.
    //
    // Tradeoffs:
    //   - Fixed slot size means assets larger than SLOT_SIZE are never cached.
    //     This is intentional — large assets (>256KB decompressed) are rare and
    //     decompressed quickly with AVX2. Caching them would waste VA space.
    //   - Map overhead is bounded: at most MAX_SLOTS entries, each ~80 bytes
    //     node overhead → at 4096 slots that's ~320 KB total overhead.
    //
    // Net result: the cache occupies exactly ONE contiguous VA region
    // (the slab) + one small hash map. No fragmentation, no scattered
    // allocations eating into the 32-bit address space.
    // -------------------------------------------------------------------------

    static constexpr uint32_t SLOT_SIZE  = 256 * 1024; // 256 KB max per entry
    static constexpr uint32_t MAX_SLOTS  = 512;         // slab has at most 512 slots
    // Slab record layout: [uint32_t dataSize | uint64_t key | uint8_t data[SLOT_SIZE]]
    static constexpr uint32_t SLOT_BYTES = sizeof(uint32_t) + sizeof(uint64_t) + SLOT_SIZE;

    struct SlotHeader {
        uint32_t dataSize;
        uint64_t key;
    };

    // LRU doubly-linked list node (stored separately, tiny)
    struct LRUNode {
        int prev = -1; // slot index (-1 = none)
        int next = -1;
    };

    // Slab state — all protected by s_cacheMutex
    static inline uint8_t*   s_slab      = nullptr;   // VirtualAlloc'd
    static inline uint32_t   s_slabSlots = 0;         // actual number of slots allocated
    static inline std::vector<bool>    s_slotUsed;    // which slots are occupied
    static inline std::vector<LRUNode> s_lru;          // LRU doubly-linked list nodes
    static inline int s_lruHead = -1;                  // most recently used slot
    static inline int s_lruTail = -1;                  // least recently used slot (eviction target)
    static inline std::unordered_map<uint64_t, int> s_index; // key → slot index

    static inline std::shared_mutex s_cacheMutex;
    static inline std::atomic<size_t>   s_cacheDataBytes{0}; // sum of all dataSize fields
    static inline std::atomic<uint64_t> s_cacheHits{0};
    static inline std::atomic<uint64_t> s_cacheMisses{0};

    // Settings
    bool s_cacheEnabled = false;
    int  s_cacheMaxMB   = 32; // lower default — slab is pre-reserved, keep it modest

    // FNV-1a over ALL compressed bytes.
    static uint64_t HashKey(const uint8_t* src, uint32_t srcSize) {
        constexpr uint64_t FNV_OFFSET = 14695981039346656037ULL;
        constexpr uint64_t FNV_PRIME  = 1099511628211ULL;
        uint64_t hash = FNV_OFFSET;
        for (uint32_t i = 0; i < srcSize; i++) {
            hash ^= src[i];
            hash *= FNV_PRIME;
        }
        return hash;
    }

    // Slot data pointer (within slab)
    static inline uint8_t* SlotDataPtr(int idx) {
        return s_slab + (size_t)idx * SLOT_BYTES + sizeof(SlotHeader);
    }
    static inline SlotHeader* SlotHeaderPtr(int idx) {
        return reinterpret_cast<SlotHeader*>(s_slab + (size_t)idx * SLOT_BYTES);
    }

    // LRU: move slot to head (most recently used)
    static void LRUPromote(int idx) {
        if (s_lruHead == idx) return;
        LRUNode& n = s_lru[idx];
        // Detach
        if (n.prev != -1) s_lru[n.prev].next = n.next;
        if (n.next != -1) s_lru[n.next].prev = n.prev;
        if (s_lruTail == idx) s_lruTail = n.prev;
        // Insert at head
        n.prev = -1;
        n.next = s_lruHead;
        if (s_lruHead != -1) s_lru[s_lruHead].prev = idx;
        s_lruHead = idx;
        if (s_lruTail == -1) s_lruTail = idx;
    }

    // LRU: evict tail (least recently used) — O(1)
    static void LRUEvictTail() {
        if (s_lruTail == -1) return;
        int idx = s_lruTail;
        SlotHeader* hdr = SlotHeaderPtr(idx);
        s_cacheDataBytes.fetch_sub(hdr->dataSize, std::memory_order_relaxed);
        s_index.erase(hdr->key);
        s_slotUsed[idx] = false;
        // Detach from list
        LRUNode& n = s_lru[idx];
        s_lruTail = n.prev;
        if (s_lruTail != -1) s_lru[s_lruTail].next = -1;
        else s_lruHead = -1;
        n.prev = n.next = -1;
    }

    // Find a free slot, evicting LRU if necessary
    static int AcquireSlot() {
        // Prefer a free slot
        for (int i = 0; i < (int)s_slabSlots; ++i) {
            if (!s_slotUsed[i]) return i;
        }
        // No free slot — evict LRU tail
        int idx = s_lruTail;
        if (idx == -1) return -1;
        LRUEvictTail();
        return idx;
    }

    static int __cdecl CachedDispatch(uint8_t* dst, uint32_t dstSize, uint8_t* src, uint32_t srcSize) {
        // Never cache assets that exceed the slot size — just decompress normally
        // (We only know decompressed size after decompressing, so check dstSize as proxy)
        if (!s_slab || dstSize > SLOT_SIZE) {
            s_cacheMisses.fetch_add(1, std::memory_order_relaxed);
            return Dispatch(dst, dstSize, src, srcSize);
        }

        uint64_t key = HashKey(src, srcSize);

        // --- Fast path: cache hit (shared lock) ---
        {
            std::shared_lock lock(s_cacheMutex);
            auto it = s_index.find(key);
            if (it != s_index.end()) {
                int idx = it->second;
                SlotHeader* hdr = SlotHeaderPtr(idx);
                uint32_t cachedSize = hdr->dataSize;
                if (cachedSize <= dstSize) {
                    std::memcpy(dst, SlotDataPtr(idx), cachedSize);
                    s_cacheHits.fetch_add(1, std::memory_order_relaxed);
                    // Promote needs exclusive lock — upgrade only if easy
                    lock.unlock();
                    std::unique_lock wlock(s_cacheMutex);
                    // Re-check it's still there after upgrade
                    if (s_index.count(key)) LRUPromote(idx);
                    return static_cast<int>(cachedSize);
                }
            }
        }

        // --- Slow path: decompress then store ---
        s_cacheMisses.fetch_add(1, std::memory_order_relaxed);
        int result = Dispatch(dst, dstSize, src, srcSize);

        if (result > 0 && result <= (int)SLOT_SIZE && instance) {
            size_t budget = static_cast<size_t>(instance->s_cacheMaxMB) * 1024 * 1024;

            std::unique_lock lock(s_cacheMutex);
            // Don't store if key already inserted by another thread
            if (s_index.count(key)) return result;

            // Evict until we're under budget (each eviction is O(1))
            while (s_cacheDataBytes.load(std::memory_order_relaxed) + (size_t)result > budget
                   && s_lruTail != -1) {
                LRUEvictTail();
            }

            if (s_cacheDataBytes.load(std::memory_order_relaxed) + (size_t)result <= budget) {
                int slot = AcquireSlot();
                if (slot >= 0) {
                    SlotHeader* hdr  = SlotHeaderPtr(slot);
                    hdr->dataSize    = static_cast<uint32_t>(result);
                    hdr->key         = key;
                    std::memcpy(SlotDataPtr(slot), dst, result);
                    s_slotUsed[slot] = true;
                    s_index[key]     = slot;
                    // Insert at LRU head
                    s_lru[slot].prev = -1;
                    s_lru[slot].next = s_lruHead;
                    if (s_lruHead != -1) s_lru[s_lruHead].prev = slot;
                    s_lruHead = slot;
                    if (s_lruTail == -1) s_lruTail = slot;
                    s_cacheDataBytes.fetch_add(result, std::memory_order_relaxed);
                }
            }
        }

        return result;
    }

    bool AllocateSlab() {
        if (s_slab) return true;
        uint32_t slots    = static_cast<uint32_t>(s_cacheMaxMB) * 1024 * 1024 / SLOT_BYTES;
        if (slots < 1)   slots = 1;
        if (slots > MAX_SLOTS) slots = MAX_SLOTS;
        size_t slabBytes  = (size_t)slots * SLOT_BYTES;
        s_slab = static_cast<uint8_t*>(VirtualAlloc(nullptr, slabBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!s_slab) {
            LOG_ERROR(std::format("[RefPackDecompressor] Failed to allocate cache slab ({} MB)",
                slabBytes / (1024*1024)));
            return false;
        }
        s_slabSlots = slots;
        s_slotUsed.assign(slots, false);
        s_lru.resize(slots);
        s_index.reserve(slots);
        s_lruHead = s_lruTail = -1;
        LOG_INFO(std::format("[RefPackDecompressor] Cache slab: {} slots × {} KB = {} MB  (1 VA region)",
            slots, SLOT_BYTES / 1024, slabBytes / (1024*1024)));
        return true;
    }

    static void FreeSlab() {
        std::unique_lock lock(s_cacheMutex);
        if (s_slab) {
            VirtualFree(s_slab, 0, MEM_RELEASE);
            s_slab = nullptr;
        }
        s_slabSlots = 0;
        s_slotUsed.clear();
        s_lru.clear();
        s_index.clear();
        s_lruHead = s_lruTail = -1;
        s_cacheDataBytes.store(0, std::memory_order_relaxed);
        s_cacheHits.store(0, std::memory_order_relaxed);
        s_cacheMisses.store(0, std::memory_order_relaxed);
    }

    static void ClearCache() {
        std::unique_lock lock(s_cacheMutex);
        s_index.clear();
        for (auto& n : s_lru) n.prev = n.next = -1;
        for (auto& b : s_slotUsed) b = false;
        s_lruHead = s_lruTail = -1;
        s_cacheDataBytes.store(0, std::memory_order_relaxed);
        s_cacheHits.store(0, std::memory_order_relaxed);
        s_cacheMisses.store(0, std::memory_order_relaxed);
        LOG_INFO("[RefPackDecompressor] Cache cleared");
    }

  public:
    RefPackDecompressorPatch() : OptimizationPatch("RefPackDecompressor", nullptr) {
        instance = this;

        RegisterBoolSetting(&s_cacheEnabled, "cacheEnabled", false,
            "Cache decompressed results so revisited lots and repeated asset loads skip decompression entirely. "
            "Most impactful for open-world play with heavy CC. Increases memory usage.");

        RegisterIntSetting(&s_cacheMaxMB, "cacheMaxMB", 32, 8, 128,
            "Maximum memory the decompression cache may use (MB). Allocated as a single contiguous VA region. "
            "Larger = more hits but more of the 32-bit address space consumed.",
            {{"8 MB (~32 slots)", 8}, {"16 MB (~64 slots)", 16}, {"32 MB (~128 slots)", 32}, {"64 MB (~256 slots)", 64}, {"128 MB (~512 slots)", 128}});
    }

    bool Install() override {
        if (isEnabled) return true;

        lastError.clear();

        auto addr = refPackDecompressor.Resolve();
        if (!addr) { return Fail("Could not resolve RefPack decompressor address"); }

        const auto& cpuFeatures = CPUFeatures::Get();
        cpuHasAVX2 = cpuFeatures.hasAVX2;

        if (s_cacheEnabled && !AllocateSlab()) {
            LOG_WARNING("[RefPackDecompressor] Cache slab allocation failed — running without cache");
        }

        uintptr_t targetAddr = (s_cacheEnabled && s_slab)
            ? reinterpret_cast<uintptr_t>(&CachedDispatch)
            : reinterpret_cast<uintptr_t>(&Dispatch);

        const char* variant = (s_cacheEnabled && s_slab)
            ? (cpuHasAVX2 ? "AVX2 + Cache" : "SSE2 + Cache")
            : (cpuHasAVX2 ? "AVX2"         : "SSE2");
        LOG_INFO(std::string("[RefPackDecompressor] Installing optimized decompressor (") + variant + " + Safety Checks)...");

        if (!PatchHelper::WriteRelativeJump(*addr, targetAddr, &patchedLocations)) { return Fail(std::format("Failed to install decompressor hook at {:#010x}", *addr)); }

        isEnabled = true;
        LOG_INFO("[RefPackDecompressor] Successfully installed");
        return true;
    }

    bool Uninstall() override {
        if (!isEnabled) return true;

        lastError.clear();
        LOG_INFO("[RefPackDecompressor] Uninstalling...");

        if (!PatchHelper::RestoreAll(patchedLocations)) { return Fail("Failed to restore original decompressor"); }

        FreeSlab();
        isEnabled = false;
        LOG_INFO("[RefPackDecompressor] Successfully uninstalled");
        return true;
    }

    void RenderCustomUI() override {
        SAFE_IMGUI_BEGIN();

        // Render the registered settings (cache enabled toggle + max MB slider)
        OptimizationPatch::RenderCustomUI();

        // Cache stats (only useful when cache is active)
        if (s_cacheEnabled && isEnabled && s_slab) {
            uint64_t hits    = s_cacheHits.load(std::memory_order_relaxed);
            uint64_t misses  = s_cacheMisses.load(std::memory_order_relaxed);
            uint64_t total   = hits + misses;
            float    rate    = total > 0 ? static_cast<float>(hits) / static_cast<float>(total) * 100.0f : 0.0f;
            size_t   dataMB  = s_cacheDataBytes.load(std::memory_order_relaxed) / (1024 * 1024);
            // Slab total VA = slots × SLOT_BYTES
            size_t   slabMB  = (size_t)s_slabSlots * SLOT_BYTES / (1024 * 1024);

            ImGui::Separator();
            ImGui::Text("Cache data : %zu MB / %zu MB slab  (%u slots, %u KB each)",
                dataMB, slabMB, s_slabSlots, SLOT_BYTES / 1024);
            ImGui::Text("Hit rate   : %.1f%%  (%llu hits / %llu calls)", rate, hits, total);
            ImGui::TextDisabled("Slab = 1 contiguous VA region — no fragmentation");

            if (ImGui::Button("Clear Cache")) {
                ClearCache();
            }
        } else if (s_cacheEnabled && isEnabled && !s_slab) {
            ImGui::Separator();
            ImGui::TextColored(ImVec4(1.f, 0.5f, 0.3f, 1.f), "Cache slab not allocated (VirtualAlloc failed)");
        }
    }
};

// Static member init
RefPackDecompressorPatch* RefPackDecompressorPatch::instance = nullptr;
bool RefPackDecompressorPatch::cpuHasAVX2 = false;

REGISTER_PATCH(RefPackDecompressorPatch, {.displayName = "RefPack Decompressor Optimization",
                                             .description = "Highly optimized RefPack decompression using AVX2/SSE2 intrinsics with safety checks. Optional result cache for repeated lot loads. Auto-detects CPU capabilities.",
                                             .category = "Performance",
                                             .experimental = false,
                                             .supportedVersions = VERSION_ALL,
                                             .technicalDetails = {"Replaces original RefPack decompressor entirely", "AVX2 path for modern CPUs, SSE2 fallback for older ones",
                                                 "Optional LRU decompression cache: serves repeated asset loads (lot streaming, revisited lots) from memory instead of re-decompressing",
                                                 "Cache key: FNV-1a of full compressed data. LRU eviction when over memory budget",
                                                 "Optimizes quite a significant amount, probably one of the most impactful patches", "Essentially decompression/reading .package files big faster now yes :D yipeee"}})
