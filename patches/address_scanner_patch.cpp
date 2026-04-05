#include "../patch_system.h"
#include "../patch_helpers.h"
#include "../logger.h"
#include "../optimization.h"
#include <windows.h>
#include <Psapi.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <optional>
#include <format>
#include <atomic>
#include "imgui.h"

// Address Scanner — Diagnostic Patch
//
// The game binary is packed on disk. This patch scans the LIVE in-memory
// (already-unpacked) code image at runtime to locate addresses needed by
// other patches, then logs them so they can be filled in.
//
// Enable this patch, load a lot, wait a few seconds, then check the log:
//   Documents\Electronic Arts\The Sims 3\S3SS\S3SS_LOG.txt
//
// Once addresses are found, copy them into the respective patch files and
// disable/remove this scanner.

class AddressScannerPatch : public OptimizationPatch {
  private:
    // -------------------------------------------------------------------------
    // In-process memory scanner — same logic as PatternScan in patch_helpers.h
    // but we re-implement it here to be self-contained.
    // -------------------------------------------------------------------------

    struct ScanResult {
        std::string name;
        uintptr_t   address = 0;
        std::string note;
        bool        found   = false;
    };

    std::vector<ScanResult> s_results;
    bool s_scanned = false;
    static inline std::atomic<bool> s_scanComplete{false};

    // Re-use the existing PatternScan from patch_helpers
    // It already does nibble-level wildcard matching on the live image.
    struct Target {
        std::string name;
        std::string pattern;
        int         offset;  // byte offset from match start to function start (negative = scan backwards)
        std::string note;
    };

    static constexpr int SCAN_BACK = -1; // sentinel: walk backwards to function start

    static const std::vector<Target>& Targets() {
        static const std::vector<Target> t = {
            // ---- Already confirmed (used to verify scanner works) ----
            {
                "WorldManager::Update (verify)",
                // Pattern from sim_update_throttle_patch.cpp
                "55 8B EC 83 E4 F0 83 EC 64 53 56 8B F1 83 BE B4 01 00 00 00 57 75",
                0,
                "Should match Retail=0xc6d3b0 / Steam=0xc6d570 / EA=0xc6c8f0"
            },
            {
                "RefPack Decompressor (verify)",
                "83 EC 10 8B 4C 24 1C 85 C9 53 55 56 8B 74 24 20 57 C7 44 24 1C 00 00 00 00 0F 84",
                0,
                "Should match Retail=0x4eb900 / Steam=0x4eb3b0 / EA=0x4eb4f0"
            },
            // ---- NEW addresses to find ----
            {
                "RefPack Compressor",
                // Confirmed via binary analysis of ts3Worig.exe (Steam build):
                // Function at 0x4ec0a0 — prologue checks srcSize against 0x4000
                // (small-file threshold for 3-byte vs 4-byte header), then stores
                // the 0x10FB RefPack magic constant to a local variable.
                // Pattern: push ebp; mov ebp,esp; sub esp,10h; mov eax,[ebp+14h];
                //          push ebx; cmp eax,4000h  ← unique to this function
                "55 8B EC 83 EC 10 8B 45 14 53 3D 00 40 00 00",
                0,
                "Steam: 0x4ec0a0 (confirmed). Prologue + cmp srcSize,0x4000"
            },
            {
                "IResourceManager::GetResource (sorted container find)",
                // Confirmed via binary analysis: the resource manager uses a sorted container
                // (std::map / red-black tree). The find function at 0x81ccd0 (Steam) performs
                // a key comparison then calls 0x626aa0 (lower_bound).
                // Pattern: movzx eax,byte[ecx+10h]; push esi; mov esi,[ecx+4]; mov ecx,[ecx];
                //          push edi; mov edi,[esp+0Ch]; push eax; push edi; push esi; push ecx;
                //          call <lower_bound>
                // Unique prologue: movzx eax, byte ptr [ecx+0x10]
                "0F B6 41 10 56 8B 71 04 8B 09 57 8B 7C 24 0C 50 57 56 51",
                0,
                "Steam: 0x81ccd0 (confirmed). IResourceManager sorted-container find."
            },
            {
                "ObjectManager::UpdateAll",
                // The object update loop: mov vtable, call Update, advance pointer.
                // Distinctive: vtable call inside a loop with pointer advance of 4/8 bytes.
                // mov eax, [edi]; mov ecx, edi; call [eax+N]; add edi, 4; cmp edi, end
                "8B 07 8B CF FF 50 ?? 83 C7 04",
                SCAN_BACK,
                "vtable call loop: mov eax,[edi]; mov ecx,edi; call [eax+N]; add edi,4"
            },
            {
                "ObjectManager::UpdateAll (alt1)",
                "8B 06 8B CE FF 50 ?? 83 C6 04",
                SCAN_BACK,
                "vtable call loop via esi: mov eax,[esi]; mov ecx,esi; call [eax+N]; add esi,4"
            },
            {
                "ObjectManager::UpdateAll (alt2)",
                // Without the +4 advance (might use iterator)
                "8B 07 8B CF FF 50 ??",
                SCAN_BACK,
                "vtable call: mov eax,[edi]; mov ecx,edi; call [eax+N]"
            },
            {
                "ObjectManager::UpdateAll (alt3)",
                "8B 10 8B CA FF 52 ??",
                SCAN_BACK,
                "vtable call via edx: mov edx,[eax]; mov ecx,eax; call [edx+N]"
            },
        };
        return t;
    }

    // Walk backwards from 'va' to find the enclosing function start.
    // Looks for a CC (int3) or 90 (nop) gap followed by a recognizable prologue.
    static uintptr_t FindFuncStart(uintptr_t va) {
        // Common x86 function prologues (first 3 bytes)
        static const uint8_t PROLOGUES[][3] = {
            {0x55, 0x8B, 0xEC},  // push ebp; mov ebp, esp
            {0x55, 0x89, 0xE5},  // push ebp; mov ebp, esp (gcc)
            {0x83, 0xEC, 0x00},  // sub esp, N  (mask last byte)
            {0x56, 0x8B, 0xF1},  // push esi; mov esi, ecx
            {0x56, 0x57, 0x00},  // push esi; push edi
            {0x57, 0x8B, 0xF9},  // push edi; mov edi, ecx
            {0x53, 0x56, 0x57},  // push ebx; push esi; push edi
            {0x53, 0x55, 0x56},  // push ebx; push ebp; push esi
            {0x51, 0x56, 0x00},  // push ecx; push esi
        };
        static const size_t PROLOGUE_MASKS[] = {
            0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x00,  // sub esp: mask last byte
            0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x00,  // push esi; push edi
            0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x00,
        };
        (void)PROLOGUE_MASKS; // not needed since we use exact match for most

        for (int back = 1; back < 0x400; ++back) {
            uintptr_t candidate = va - back;
            uint8_t gap = *reinterpret_cast<const uint8_t*>(candidate - 1);
            // Gap byte: int3, nop, ret, or zero (alignment pad)
            if (gap != 0xCC && gap != 0x90 && gap != 0xC3 && gap != 0x00)
                continue;

            const uint8_t* p = reinterpret_cast<const uint8_t*>(candidate);
            for (auto& prologue : PROLOGUES) {
                bool ok = true;
                for (int i = 0; i < 2; ++i) {
                    if (prologue[i] != 0 && p[i] != prologue[i]) { ok = false; break; }
                }
                if (ok) return candidate;
            }
        }
        return va; // couldn't find — return original as fallback
    }

    void RunScan() {
        s_results.clear();
        LOG_INFO("[AddressScanner] Starting runtime address scan...");

        // Get the game module base and size
        HMODULE hMod = GetModuleHandleW(nullptr);
        MODULEINFO mi{};
        GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi));
        uintptr_t modBase = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        uintptr_t modEnd  = modBase + mi.SizeOfImage;

        LOG_INFO(std::format("[AddressScanner] Module: {:#010x} - {:#010x}  ({} MB)",
            modBase, modEnd, mi.SizeOfImage / (1024*1024)));

        for (const auto& target : Targets()) {
            ScanResult res;
            res.name = target.name;
            res.note = target.note;

            uintptr_t scanResult = PatchHelper::ScanPattern(
                reinterpret_cast<BYTE*>(modBase),
                modEnd - modBase,
                target.pattern.c_str());
            if (scanResult) {
                uintptr_t va = scanResult;
                uintptr_t func = (target.offset == SCAN_BACK) ? FindFuncStart(va) : va + target.offset;
                res.found   = true;
                res.address = func;
                LOG_INFO(std::format("[AddressScanner] FOUND  {:45s}  match={:#010x}  func={:#010x}  // {}",
                    target.name, va, func, target.note));
            } else {
                LOG_WARNING(std::format("[AddressScanner] MISS   {:45s}  // {}",
                    target.name, target.note));
            }

            s_results.push_back(res);
        }

        LOG_INFO("[AddressScanner] Scan complete. Check S3SS_LOG.txt for results.");
        s_scanned = true;
        s_scanComplete.store(true, std::memory_order_relaxed);
    }

  public:
    AddressScannerPatch() : OptimizationPatch("AddressScanner", nullptr) {}

    bool Install() override {
        if (isEnabled) return true;
        lastError.clear();
        isEnabled = true;
        s_scanned = false;
        s_scanComplete.store(false, std::memory_order_relaxed);
        LOG_INFO("[AddressScanner] Installed — click 'Scan Now' in UI to run");
        return true;
    }

    bool Uninstall() override {
        if (!isEnabled) return true;
        isEnabled = false;
        s_scanned = false;
        s_results.clear();
        s_scanComplete.store(false, std::memory_order_relaxed);
        return true;
    }

    void RenderCustomUI() override {
        SAFE_IMGUI_BEGIN();

        ImGui::TextDisabled("Scans live in-memory code for addresses needed by other patches.");
        ImGui::TextDisabled("Results are written to S3SS_LOG.txt.");
        ImGui::Spacing();

        if (ImGui::Button("Scan Now")) {
            RunScan();
        }

        if (s_scanned) {
            ImGui::Separator();
            ImGui::Text("Results (%zu targets):", s_results.size());

            for (const auto& r : s_results) {
                if (r.found) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 1.0f, 0.4f, 1.0f));
                    ImGui::Text("  FOUND  %-45s  %#010x", r.name.c_str(), (unsigned)r.address);
                    ImGui::PopStyleColor();
                } else {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.5f, 0.3f, 1.0f));
                    ImGui::Text("  MISS   %s", r.name.c_str());
                    ImGui::PopStyleColor();
                }
            }
        }
    }
};

REGISTER_PATCH(AddressScannerPatch, {
    .displayName = "Address Scanner (Diagnostic)",
    .description = "Scans the live in-memory game code to locate addresses needed by other patches. "
                   "Enable, load a lot, then click 'Scan Now'. Check the log file for results. "
                   "Disable after use — this patch has no effect during normal gameplay.",
    .category = "Diagnostic",
    .experimental = false,
    .supportedVersions = VERSION_ALL,
    .technicalDetails = {
        "Scans the unpacked in-memory image — works regardless of disk packing",
        "Finds: RefPack compressor, IResourceManager::GetResource, ObjectManager::UpdateAll",
        "Also verifies existing known addresses (decompressor, WorldManager::Update)",
        "Results logged to S3SS_LOG.txt with exact addresses for use in patches",
        "Safe to run: read-only scan, no memory modifications",
    }
})
