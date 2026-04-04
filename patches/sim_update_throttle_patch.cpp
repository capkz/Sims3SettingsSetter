#include "../patch_system.h"
#include "../patch_helpers.h"
#include "../logger.h"
#include "../optimization.h"
#include <windows.h>
#include <atomic>
#include <format>
#include "imgui.h"

// Lot Streaming Update Throttle
//
// WorldManager::Update runs every game tick. Among other things it evaluates
// which lots need to stream in or out, updates lot LOD transitions, and
// processes world streaming logic. On large open-world neighbourhoods this
// can be expensive, especially when many lots are in various stages of
// loading/unloading simultaneously (high CC, many sims in the world).
//
// This patch throttles lot streaming updates by temporarily asserting the
// game's own "skip lot processing" flag (at WorldManager + 0x258) on a
// configurable fraction of frames. The flag is the same mechanism used by
// the Map View Lot Blocker — it causes WorldManager::Update to skip the lot
// streaming inner loop for that call while still completing all other world
// management tasks.
//
// Effect: lot streaming decisions are made every N frames instead of every
// frame. The player's active household simulation is UNAFFECTED because Mono
// script simulation runs separately from WorldManager::Update.
//
// Co-existence with Map View Lot Blocker: both patches hook the same function
// and both use the same flag. Detours correctly chains the hooks. When map
// view is active, lot streaming is already blocked, so this patch's throttle
// is a no-op during that period.
//
// NRAAS compatibility: NRAAS operates in Mono script space, which is
// independent of WorldManager::Update. Throttling lot streaming does NOT
// affect NRAAS story progression, sim AI, or MC scheduling.

class SimUpdateThrottlePatch : public OptimizationPatch {
  private:
    // Same addresses as MapViewLotBlockerPatch for WorldManager::Update
    static inline const AddressInfo worldManagerUpdate = {
        .name = "Sims3::World::WorldManager::Update",
        .addresses =
            {
                {GameVersion::Retail, 0x00c6d3b0},
                {GameVersion::Steam,  0x00c6d570},
                {GameVersion::EA,     0x00c6c8f0},
            },
        .pattern = "55 8B EC 83 E4 F0 83 EC 64 53 56 8B F1 83 BE B4 01 00 00 00 57 75",
        .expectedBytes = {0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF0},
    };

    // Offset within WorldManager where the "skip lot processing" flag lives
    // Confirmed by MapViewLotBlockerPatch: worldMgr + 0x258
    static constexpr uintptr_t LOT_SKIP_FLAG_OFFSET = 0x258;

    // Settings
    int s_throttleN = 2; // Skip N-1 out of every N frames (2 = every other frame)

    // Frame counter
    static inline std::atomic<uint32_t> s_frameCounter{0};

    // Stats
    static inline std::atomic<uint64_t> s_framesThrottled{0};
    static inline std::atomic<uint64_t> s_framesTotal{0};

    // Hook state
    typedef int(__fastcall* WorldManager_Update_t)(void* worldMgr, void* unused, float param2, float param3);
    WorldManager_Update_t originalWorldManagerUpdate = nullptr;
    std::vector<DetourHelper::Hook> hooks;

    static SimUpdateThrottlePatch* instance;

    static int __fastcall HookedWorldManagerUpdate(void* worldMgr, void* unused, float param2, float param3) {
        if (!instance || !instance->originalWorldManagerUpdate) {
            return 0;
        }

        uint32_t frame = s_frameCounter.fetch_add(1, std::memory_order_relaxed);
        s_framesTotal.fetch_add(1, std::memory_order_relaxed);

        int throttleN = instance->s_throttleN;

        // On skip frames (all but the last in each cycle), assert the lot-skip flag
        // for this WorldManager::Update call so the lot streaming inner loop is bypassed.
        // Never skip on frame 0 (the update frame in each cycle).
        bool doSkip = (throttleN > 1) && ((frame % throttleN) != 0);

        if (doSkip) {
            s_framesThrottled.fetch_add(1, std::memory_order_relaxed);

            char* skipFlag = reinterpret_cast<char*>(worldMgr) + LOT_SKIP_FLAG_OFFSET;
            char originalFlagValue = *skipFlag;

            // Only assert skip if it's not already set (map view blocker may have set it)
            if (originalFlagValue == 0) {
                *skipFlag = 1;
            }

            int result = instance->originalWorldManagerUpdate(worldMgr, unused, param2, param3);

            // Restore only if WE set it (avoid fighting with map view blocker)
            if (originalFlagValue == 0) {
                *skipFlag = 0;
            }

            return result;
        }

        return instance->originalWorldManagerUpdate(worldMgr, unused, param2, param3);
    }

  public:
    SimUpdateThrottlePatch() : OptimizationPatch("SimUpdateThrottle", nullptr) {
        instance = this;

        RegisterIntSetting(&s_throttleN, "throttleN", 2, 1, 8,
            "Process lot streaming every N frames. 1 = every frame (disabled). "
            "2 = every other frame (recommended). Higher values reduce CPU cost further "
            "but lot transitions become less responsive.",
            {{"Off (1)", 1}, {"Every 2nd (recommended)", 2}, {"Every 3rd", 3}, {"Every 4th", 4}},
            SettingUIType::Slider);
    }

    ~SimUpdateThrottlePatch() override { instance = nullptr; }

    bool Install() override {
        if (isEnabled) return true;
        lastError.clear();

        auto addr = worldManagerUpdate.Resolve();
        if (!addr) { return Fail("Could not resolve WorldManager::Update address"); }

        originalWorldManagerUpdate = reinterpret_cast<WorldManager_Update_t>(*addr);
        hooks = {{reinterpret_cast<void**>(&originalWorldManagerUpdate), reinterpret_cast<void*>(&HookedWorldManagerUpdate)}};

        if (!DetourHelper::InstallHooks(hooks)) { return Fail(std::format("Failed to hook WorldManager::Update at {:#010x}", *addr)); }

        s_frameCounter.store(0, std::memory_order_relaxed);
        s_framesThrottled.store(0, std::memory_order_relaxed);
        s_framesTotal.store(0, std::memory_order_relaxed);

        isEnabled = true;
        LOG_INFO(std::format("[SimUpdateThrottle] Installed — throttling lot streaming (every {} frames)", s_throttleN));
        return true;
    }

    bool Uninstall() override {
        if (!isEnabled) return true;
        lastError.clear();

        if (!DetourHelper::RemoveHooks(hooks)) { return Fail("Failed to remove WorldManager::Update hook"); }

        originalWorldManagerUpdate = nullptr;
        hooks.clear();
        isEnabled = false;
        LOG_INFO("[SimUpdateThrottle] Uninstalled");
        return true;
    }

    void RenderCustomUI() override {
        SAFE_IMGUI_BEGIN();

        OptimizationPatch::RenderCustomUI();

        if (isEnabled) {
            uint64_t throttled = s_framesThrottled.load(std::memory_order_relaxed);
            uint64_t total     = s_framesTotal.load(std::memory_order_relaxed);
            float rate = total > 0 ? static_cast<float>(throttled) / static_cast<float>(total) * 100.0f : 0.0f;

            ImGui::Separator();
            ImGui::Text("Lot streaming throttled: %llu / %llu frames  (%.1f%%)", throttled, total, rate);
            ImGui::TextDisabled("Sim/household AI runs independently and is unaffected.");

            if (ImGui::Button("Reset Stats")) {
                s_framesThrottled.store(0, std::memory_order_relaxed);
                s_framesTotal.store(0, std::memory_order_relaxed);
            }
        }
    }
};

SimUpdateThrottlePatch* SimUpdateThrottlePatch::instance = nullptr;

REGISTER_PATCH(SimUpdateThrottlePatch, {
    .displayName = "Lot Streaming Update Throttle",
    .description = "Reduces lot streaming update frequency to every N frames, decreasing CPU overhead "
                   "from lot load/unload decisions on large neighbourhoods. Sim and household AI are unaffected.",
    .category = "Performance",
    .experimental = true,
    .supportedVersions = VERSION_ALL,
    .technicalDetails = {
        "Hooks WorldManager::Update and asserts the lot-skip flag on throttled frames",
        "Lot streaming runs every N frames (configurable, default: every 2nd frame)",
        "Mono script simulation (sims, households, NRAAS) runs independently — not throttled",
        "Co-exists correctly with Map View Lot Blocker via Detours hook chaining",
        "NRAAS compatible: NRAAS mods operate in Mono space, above WorldManager",
        "Lot transitions may appear slightly less responsive at higher throttle ratios",
    }
})
