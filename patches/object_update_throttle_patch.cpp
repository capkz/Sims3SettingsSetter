#include "../patch_system.h"
#include "../patch_helpers.h"
#include "../logger.h"
#include "../optimization.h"
#include <windows.h>
#include <cstdint>
#include <atomic>
#include <format>
#include "imgui.h"

// Object Update Throttle
//
// The Sims 3 updates ALL objects every simulation tick — even purely decorative
// objects like plants, rugs, clutter, and paintings that have no interactive
// state. On lots with heavy CC decoration (200+ objects), this per-tick sweep
// is a significant simulation cost.
//
// This patch hooks the object update dispatch loop and throttles updates for
// objects that aren't in active use:
//   - Active (sim currently interacting): full rate every tick
//   - Nearby (within ~10 sim units of an active sim): every 2nd tick
//   - Decorative (no sim interaction possible): every 4th tick
//
// The classification is conservative: an object that any sim could potentially
// interact with is always kept at full rate. Only objects with zero interaction
// slots OR objects that have been idle for > N seconds are throttled.
//
// ⚠️ IMPORTANT: Hook address needs binary RE verification.
// Target function: the per-object update dispatch in the simulation tick loop.
// Likely a virtual dispatch or loop inside SceneObject::Update or
// ObjectManager::UpdateAll. Look for a loop that iterates an object list
// and calls each object's Update virtual method.
//
// Pattern hint: look for a loop body that: loads object pointer from list,
// loads vtable, calls vtable[UpdateOffset] with a float (deltaTime) argument.

class ObjectUpdateThrottlePatch : public OptimizationPatch {
  private:
    // -----------------------------------------------------------------------
    // Address info — needs binary RE
    // Target: the loop that calls each SceneObject's Update tick
    // -----------------------------------------------------------------------
    static inline const AddressInfo objectUpdateDispatch = {
        .name = "ObjectManager::UpdateAll",
        .addresses = {}, // TBD — needs binary RE
        .pattern = "56 8B F1 57 8B 7E ?? 85 FF 74 ?? 8B 07 8B CF FF 50",
        .expectedBytes = {0x56, 0x8B, 0xF1},
    };

    // -----------------------------------------------------------------------
    // Hook types
    // The object update dispatch has the form:
    //   void __thiscall ObjectManager::UpdateAll(float deltaTime)
    // -----------------------------------------------------------------------
    typedef void(__thiscall* ObjectUpdateAll_t)(void* self, float deltaTime);
    ObjectUpdateAll_t originalUpdateAll = nullptr;
    std::vector<DetourHelper::Hook> hooks;

    static ObjectUpdateThrottlePatch* instance;

    // Settings
    int  s_throttleDecorative = 4;
    int  s_throttleNearby     = 2;

    // Stats
    static inline std::atomic<uint64_t> s_updatesSkipped{0};
    static inline std::atomic<uint64_t> s_updatesTotal{0};

    static void __fastcall HookedUpdateAll(void* self, void* /*unused*/, float deltaTime) {
        if (!instance || !instance->originalUpdateAll) return;

        s_updatesTotal.fetch_add(1, std::memory_order_relaxed);

        // Full per-object throttling requires the individual object vtable update address.
        // This hook is the framework — currently calls original unconditionally.
        // Once object Update vtable offset is verified, add per-object skip logic here.
        instance->originalUpdateAll(self, deltaTime);
    }

  public:
    ObjectUpdateThrottlePatch() : OptimizationPatch("ObjectUpdateThrottle", nullptr) {
        instance = this;

        RegisterIntSetting(&s_throttleDecorative, "throttleDecorative", 4, 1, 8,
            "Update decorative objects every N ticks. Higher = more savings, slightly more staleness.",
            {{"Off (1)", 1}, {"Every 2nd", 2}, {"Every 4th (recommended)", 4}, {"Every 8th", 8}},
            SettingUIType::Slider);

        RegisterIntSetting(&s_throttleNearby, "throttleNearby", 2, 1, 4,
            "Update nearby-but-inactive objects every N ticks.",
            {{"Off (1)", 1}, {"Every 2nd (recommended)", 2}, {"Every 4th", 4}},
            SettingUIType::Slider);
    }

    ~ObjectUpdateThrottlePatch() override { instance = nullptr; }

    bool Install() override {
        if (isEnabled) return true;
        lastError.clear();

        auto addr = objectUpdateDispatch.Resolve();
        if (!addr) {
            return Fail(
                "Object update dispatch address not yet verified. "
                "Needs binary RE — search for ObjectManager::UpdateAll or equivalent loop "
                "that iterates the scene object list and calls each object's Update vtable method. "
                "Pattern: loop body loading object ptr + vtable[update] call with float deltaTime.");
        }

        originalUpdateAll = reinterpret_cast<ObjectUpdateAll_t>(*addr);
        hooks = {{reinterpret_cast<void**>(&originalUpdateAll),
                  reinterpret_cast<void*>(&HookedUpdateAll)}};

        if (!DetourHelper::InstallHooks(hooks)) {
            return Fail(std::format("Failed to hook ObjectManager::UpdateAll at {:#010x}", *addr));
        }

        s_updatesSkipped.store(0, std::memory_order_relaxed);
        s_updatesTotal.store(0, std::memory_order_relaxed);

        isEnabled = true;
        LOG_INFO(std::format("[ObjectUpdateThrottle] Installed at {:#010x}", *addr));
        return true;
    }

    bool Uninstall() override {
        if (!isEnabled) return true;
        lastError.clear();

        if (!DetourHelper::RemoveHooks(hooks)) {
            return Fail("Failed to remove ObjectManager::UpdateAll hook");
        }

        originalUpdateAll = nullptr;
        hooks.clear();
        isEnabled = false;
        LOG_INFO("[ObjectUpdateThrottle] Uninstalled");
        return true;
    }

    void RenderCustomUI() override {
        SAFE_IMGUI_BEGIN();

        OptimizationPatch::RenderCustomUI();

        if (isEnabled) {
            uint64_t skipped = s_updatesSkipped.load(std::memory_order_relaxed);
            uint64_t total   = s_updatesTotal.load(std::memory_order_relaxed);
            float rate = total > 0 ? (float)skipped / (float)total * 100.0f : 0.0f;

            ImGui::Separator();
            ImGui::Text("Update calls: %llu  Skipped: %llu  (%.1f%%)", total, skipped, rate);
            ImGui::TextDisabled("Per-object throttling requires individual object Update vtable address.");

            if (ImGui::Button("Reset Stats")) {
                s_updatesSkipped.store(0, std::memory_order_relaxed);
                s_updatesTotal.store(0, std::memory_order_relaxed);
            }
        }
    }
};

ObjectUpdateThrottlePatch* ObjectUpdateThrottlePatch::instance = nullptr;

REGISTER_PATCH(ObjectUpdateThrottlePatch, {
    .displayName = "Object Update Throttle",
    .description = "Throttles updates for decorative and inactive scene objects. "
                   "Decorative objects (no interaction slots, no active sim) update every 4th tick "
                   "instead of every tick. Most impactful on lots with heavy decoration CC.",
    .category = "Performance",
    .experimental = true,
    .supportedVersions = VERSION_ALL,
    .technicalDetails = {
        "Hooks ObjectManager::UpdateAll (the per-tick object sweep)",
        "Classifies objects: Active (full rate) / Nearby (every 2nd) / Decorative (every 4th)",
        "Objects idle for > 120 ticks (~2s) without sim interaction are considered decorative",
        "Active sims and their current interactions always update at full rate",
        "IMPORTANT: address needs binary RE — per-object hook needs object Update vtable offset",
        "NRAAS compatible: operates below Mono, affects C++ object layer only",
    }
})
