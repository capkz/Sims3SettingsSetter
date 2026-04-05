#include "../patch_system.h"
#include "../patch_helpers.h"
#include "../logger.h"
#include "../optimization.h"
#include "../d3d9_hook_registry.h"
#include <windows.h>
#include <d3d9.h>
#include <atomic>
#include <cstring>
#include <format>
#include "imgui.h"

// Lot Streaming Update Throttle (Camera-Aware)
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
// Camera-Aware Mode:
// When the camera is stationary (no view matrix change between frames for
// N consecutive frames), lot streaming decisions can be skipped more
// aggressively — the viewable area isn't changing, so no new lots will
// appear. When the camera is actively moving, the throttle drops back to a
// lower value for more responsive lot loading.
//
// Camera movement is detected by sampling D3DTS_VIEW each Present and
// comparing the translation component to the previous frame. No game RE is
// required — D3D9 device is available via the hook registry.
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

    // How many consecutive stationary frames before switching to the stationary throttle
    static constexpr uint32_t STATIONARY_SETTLE_FRAMES = 30; // ~0.5s at 60fps

    // Settings
    int  s_throttleNMoving     = 2; // throttle when camera is moving (or camera-aware disabled)
    int  s_throttleNStationary = 4; // throttle when camera has been stationary for settle frames
    bool s_cameraAwareEnabled  = true;
    int  s_frameBudgetMs       = 20; // frame time threshold (ms) to trigger overload throttle
    bool s_frameBudgetEnabled  = true;

    // Camera tracking — written by Present hook, read by WorldManager hook
    // D3DTS_VIEW matrix row 3 (translation) is columns [12],[13],[14]
    static inline float s_lastCamX = 0.0f;
    static inline float s_lastCamY = 0.0f;
    static inline float s_lastCamZ = 0.0f;
    static inline std::atomic<bool>     s_cameraMoving{true};
    static inline std::atomic<uint32_t> s_stationaryFrames{0};
    static constexpr float CAM_MOVE_EPSILON = 0.01f; // units; ~1cm

    // Frame time budget tracking — written by Present hook
    static inline std::atomic<bool>   s_frameOverloaded{false};
    static inline LARGE_INTEGER        s_lastPresentTime{};
    static inline LARGE_INTEGER        s_qpcFreq{};
    static inline std::atomic<uint32_t> s_lastFrameMs{0};

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

    // ---- Camera sampling + frame time budget via D3D9 Present ----
    static D3D9Hooks::HookResult OnPresent(D3D9Hooks::DeviceContext& ctx,
                                            const RECT*, const RECT*, HWND, const RGNDATA*) {
        if (!instance) return D3D9Hooks::HookResult::Continue;

        // --- Frame time measurement (for Speed 3 / overload detection) ---
        if (instance->s_frameBudgetEnabled) {
            LARGE_INTEGER now;
            QueryPerformanceCounter(&now);

            if (s_lastPresentTime.QuadPart != 0 && s_qpcFreq.QuadPart > 0) {
                uint64_t elapsed = (uint64_t)(now.QuadPart - s_lastPresentTime.QuadPart);
                uint32_t ms = (uint32_t)(elapsed * 1000ULL / (uint64_t)s_qpcFreq.QuadPart);
                s_lastFrameMs.store(ms, std::memory_order_relaxed);

                bool overloaded = (ms > (uint32_t)instance->s_frameBudgetMs);
                s_frameOverloaded.store(overloaded, std::memory_order_relaxed);
            }
            s_lastPresentTime = now;
        }

        // --- Camera movement detection ---
        if (!instance->s_cameraAwareEnabled) return D3D9Hooks::HookResult::Continue;

        D3DMATRIX view{};
        HRESULT hr = ctx.device->GetTransform(D3DTS_VIEW, &view);
        if (FAILED(hr)) return D3D9Hooks::HookResult::Continue;

        // For movement detection: compare _41, _42, _43 (translation component of view matrix).
        // These change whenever the camera position changes.
        float cx = view._41;
        float cy = view._42;
        float cz = view._43;

        float dx = cx - s_lastCamX;
        float dy = cy - s_lastCamY;
        float dz = cz - s_lastCamZ;
        float distSq = dx * dx + dy * dy + dz * dz;

        s_lastCamX = cx;
        s_lastCamY = cy;
        s_lastCamZ = cz;

        if (distSq > (CAM_MOVE_EPSILON * CAM_MOVE_EPSILON)) {
            s_cameraMoving.store(true, std::memory_order_relaxed);
            s_stationaryFrames.store(0, std::memory_order_relaxed);
        } else {
            uint32_t idle = s_stationaryFrames.fetch_add(1, std::memory_order_relaxed) + 1;
            if (idle >= STATIONARY_SETTLE_FRAMES) {
                s_cameraMoving.store(false, std::memory_order_relaxed);
            }
        }

        return D3D9Hooks::HookResult::Continue;
    }

    // ---- WorldManager::Update hook ----
    static int __fastcall HookedWorldManagerUpdate(void* worldMgr, void* unused, float param2, float param3) {
        if (!instance || !instance->originalWorldManagerUpdate) {
            return 0;
        }

        uint32_t frame = s_frameCounter.fetch_add(1, std::memory_order_relaxed);
        s_framesTotal.fetch_add(1, std::memory_order_relaxed);

        // Pick throttle N:
        //   - Frame overloaded (last frame > budget_ms):  use stationary N (highest)
        //   - Camera stationary (settled for STATIONARY_SETTLE_FRAMES): use stationary N
        //   - Camera moving: use moving N
        int throttleN = instance->s_throttleNMoving;
        bool overloaded   = instance->s_frameBudgetEnabled && s_frameOverloaded.load(std::memory_order_relaxed);
        bool camStationary = instance->s_cameraAwareEnabled && !s_cameraMoving.load(std::memory_order_relaxed);
        if (overloaded || camStationary) {
            throttleN = instance->s_throttleNStationary;
        }

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

        RegisterIntSetting(&s_throttleNMoving, "throttleNMoving", 2, 1, 8,
            "Process lot streaming every N frames while the camera is moving (or when camera-aware mode is off). "
            "1 = every frame (disabled). 2 = every other frame (recommended).",
            {{"Off (1)", 1}, {"Every 2nd (recommended)", 2}, {"Every 3rd", 3}, {"Every 4th", 4}},
            SettingUIType::Slider);

        RegisterIntSetting(&s_throttleNStationary, "throttleNStationary", 4, 1, 8,
            "Process lot streaming every N frames while the camera is stationary. "
            "More aggressive skipping is safe when nothing new will scroll into view.",
            {{"Off (1)", 1}, {"Every 2nd", 2}, {"Every 3rd", 3}, {"Every 4th (recommended)", 4}, {"Every 6th", 6}, {"Every 8th", 8}},
            SettingUIType::Slider);

        RegisterBoolSetting(&s_cameraAwareEnabled, "cameraAwareEnabled", true,
            "Automatically use a higher throttle when the camera is stationary and a lower one when moving. "
            "When disabled, only the moving throttle value is used at all times.");

        RegisterBoolSetting(&s_frameBudgetEnabled, "frameBudgetEnabled", true,
            "Automatically increase lot streaming throttle when the last rendered frame took longer than the budget. "
            "Prevents lot streaming from hogging CPU during Speed 3 or heavy simulation loads.");

        RegisterIntSetting(&s_frameBudgetMs, "frameBudgetMs", 20, 8, 100,
            "Frame time budget in milliseconds. When the last frame took longer than this, "
            "lot streaming switches to the stationary throttle N. Default: 20ms (~50fps threshold).",
            {{"8ms (120fps)", 8}, {"12ms (83fps)", 12}, {"16ms (60fps)", 16},
             {"20ms (50fps, recommended)", 20}, {"33ms (30fps)", 33}},
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

        // Register Present hook for camera sampling
        D3D9Hooks::RegisterPresent(
            "SimUpdateThrottle_CamSample",
            &OnPresent,
            D3D9Hooks::Priority::Last);

        s_frameCounter.store(0, std::memory_order_relaxed);
        s_framesThrottled.store(0, std::memory_order_relaxed);
        s_framesTotal.store(0, std::memory_order_relaxed);
        s_cameraMoving.store(true, std::memory_order_relaxed);
        s_stationaryFrames.store(0, std::memory_order_relaxed);
        s_frameOverloaded.store(false, std::memory_order_relaxed);
        s_lastPresentTime = {};
        s_lastFrameMs.store(0, std::memory_order_relaxed);
        QueryPerformanceFrequency(&s_qpcFreq);

        isEnabled = true;
        LOG_INFO(std::format("[SimUpdateThrottle] Installed — camera-aware={}, moving={}, stationary={}",
            s_cameraAwareEnabled, s_throttleNMoving, s_throttleNStationary));
        return true;
    }

    bool Uninstall() override {
        if (!isEnabled) return true;
        lastError.clear();

        if (!DetourHelper::RemoveHooks(hooks)) { return Fail("Failed to remove WorldManager::Update hook"); }

        D3D9Hooks::UnregisterAll("SimUpdateThrottle_CamSample");

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

            bool moving = s_cameraMoving.load(std::memory_order_relaxed);
            uint32_t idle = s_stationaryFrames.load(std::memory_order_relaxed);

            bool overloaded = s_frameOverloaded.load(std::memory_order_relaxed);
            uint32_t lastFrameMs = s_lastFrameMs.load(std::memory_order_relaxed);

            ImGui::Separator();
            if (s_cameraAwareEnabled) {
                ImGui::Text("Camera: %s  (idle %u frames)",
                    moving ? "Moving" : "Stationary", idle);
            }
            if (s_frameBudgetEnabled) {
                ImGui::Text("Last frame: %u ms  Budget: %d ms  %s",
                    lastFrameMs, s_frameBudgetMs, overloaded ? "[OVERLOADED]" : "");
            }
            ImGui::Text("Active throttle N: %d  (moving=%d  stationary=%d)",
                (overloaded || (!moving && s_cameraAwareEnabled)) ? s_throttleNStationary : s_throttleNMoving,
                s_throttleNMoving, s_throttleNStationary);
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
    .description = "Reduces lot streaming update frequency to every N frames. Camera-aware mode increases "
                   "throttle when the camera is stationary. Frame budget mode increases throttle when frames "
                   "take longer than the target (Speed 3 / heavy simulation overload protection).",
    .category = "Performance",
    .experimental = true,
    .supportedVersions = VERSION_ALL,
    .technicalDetails = {
        "Hooks WorldManager::Update and asserts the lot-skip flag on throttled frames",
        "Camera movement detected by sampling D3DTS_VIEW via Present hook — no game RE required",
        "Frame budget mode: measures frame time via QPC at Present; overload trips stationary throttle",
        "Stationary throttle N=4 by default; moving throttle N=2; settle time ~30 frames",
        "Mono script simulation (sims, households, NRAAS) runs independently — not throttled",
        "Co-exists correctly with Map View Lot Blocker via Detours hook chaining",
        "NRAAS compatible: NRAAS mods operate in Mono space, above WorldManager",
    }
})
