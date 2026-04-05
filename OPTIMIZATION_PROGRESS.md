# S3SS New Optimizations — Progress

## Status

| # | Patch | File | Status | Notes |
|---|-------|------|--------|-------|
| 1 | Decompression Cache | `patches/refpack_decompressor_patch.cpp` | ✅ Done | Fixed LOD collision bug — now hashes full compressed data |
| 2 | Draw Call Batching | `patches/draw_call_batching_patch.cpp` | ✅ Done | 6-28% state change elimination in testing |
| 3 | Lot Streaming Throttle (Camera + Frame Budget) | `patches/sim_update_throttle_patch.cpp` | ✅ Done | Camera-aware dynamic N + frame time budget for Speed 3 protection |
| 4 | Pathfinding Cache | `patches/pathfinding_cache_patch.cpp` | ⏸️ On Hold | Needs binary verification of ComputePath address |
| 5 | RefPack Compressor | `patches/refpack_compressor_patch.cpp` | 🔑 Needs RE | Full implementation ready — hook address needs binary RE |
| 6 | Package Index Cache | `patches/package_index_cache_patch.cpp` | 🔑 Needs RE | Full implementation ready — IResourceManager::GetResource address needs RE |
| 7 | Object Update Throttle | `patches/object_update_throttle_patch.cpp` | 🔑 Needs RE | Framework ready — ObjectManager::UpdateAll + object vtable offset needs RE |

## Bug Fixes
- **Decompression cache LOD collision**: FNV-1a of first 64 bytes caused false hits between LOD variants. Fixed by hashing all compressed bytes.

---

## Save File Safety Warning

> ⚠️ **The Lot Streaming Throttle and any future simulation-loop patches carry inherent save-file risk.**
>
> The Sims 3 state machines (lot streaming, sim AI, world transitions) expect `WorldManager::Update` and related
> functions to be called at consistent cadences. Asserting the skip flag mid-state-transition can leave internal
> state machines in intermediate states that get serialized to the save file.
>
> **Mitigations in place:**
> - The throttle only skips the lot-streaming inner loop — all other WorldManager work still runs
> - The skip flag is restored after each call, so no state leaks between frames
> - Throttle N is conservative by default (N=2 moving, N=4 stationary)
>
> **Best practice:** disable experimental simulation patches before saving, especially on long-running saves.

---

## What Each Implemented Patch Does

### Lot Streaming Throttle (Patch #3)
- **Baseline**: Throttles WorldManager lot streaming to every N frames (N=2 default)
- **Camera-aware mode**: Detects camera movement via D3DTS_VIEW matrix each Present. Stationary = N=4, moving = N=2
- **Frame budget mode**: Measures frame time via QPC at Present. When last frame > 20ms, uses stationary N automatically — prevents lot streaming from competing with Speed 3 sim overload
- **UI shows**: Camera state, last frame time ms, active N, throttle %, overload flag

### RefPack Compressor (Patch #5) — needs address
- Replaces O(n²) brute-force match finder with a 65536-entry hash table (O(1) per position)
- SSE2 match-length extension (16 bytes per compare vs 1)
- Expected: 5-15x faster saves on large saves
- Address guidance: look within ±0x2000 of decompressor (Retail 0x004eb900 / Steam 0x004eb3b0 / EA 0x004eb4f0)

### Package Index Cache (Patch #6) — needs address
- Hooks IResourceManager::GetResource, builds hash map of ResourceKey → package object
- After warm-up (first load), all repeated lookups are O(1) instead of O(packages × entries)
- Expected: 2-5x load time improvement on 100+ CC package setups
- Address guidance: look for a loop comparing ResourceKey.typeId + groupId + instanceId

### Object Update Throttle (Patch #7) — needs address + vtable offset
- Hooks ObjectManager::UpdateAll, skips decorative objects every 4th tick
- Needs both the UpdateAll function address AND the per-object Update vtable offset
- Expected: significant CPU savings on lots with 100+ decorative objects

---

## Deferred / On Hold

| # | Name | Reason |
|---|------|--------|
| — | Shader Constant Deduplication | User preference — not wanted |
| — | Route Retry Cooldown | Skipped — routing patches excluded per user |
| 4 | Pathfinding Cache | Needs binary RE to verify `ComputePath` address |
| — | Mono Script Budget | Needs deep Mono domain RE — revisit later |
| — | Sim Update Frequency Throttle | Needs per-sim tick dispatch RE |
| — | Async Texture Compositor | Needs `CreateCompositionDestTexture` function START (known: inside at 0x006cc1ca Steam) |
| — | Stale Event Cleanup | Needs event dispatcher address |
| — | Speed 3 Frame Budget | Largely addressed by frame budget mode in Patch #3 + SmoothPatchPrecise tick controls |

---

## NRAAS Compatibility
| Patch | Status |
|-------|--------|
| Decompression Cache | ✅ Compatible |
| Draw Call Batching | ✅ Compatible |
| Lot Streaming Throttle | ✅ Compatible |
| RefPack Compressor | ✅ Compatible |
| Package Index Cache | ✅ Compatible |
| Object Update Throttle | ⚠️ Test — must not throttle NRAAS-controlled sims |
| Pathfinding Cache | ✅ Complementary to Vector |

## Mac Compatibility
Not applicable — Windows DLL/ASI only.

## Commit Log
- `Add LRU decompression cache to RefPack decompressor patch`
- `Add redundant D3D9 state change elimination patch`
- `Fix draw call batching patch: remove premature D3D9 init check`
- `Add lot streaming update throttle patch`
- `Add native routing cache patch (experimental, needs address verification)`
- `Fix decompression cache: hash full compressed data to prevent LOD collisions`
- `Extend lot streaming throttle with camera-aware dynamic N`
- `Add RefPack compressor replacement patch (hash-table LZ77)`
- `Add package index cache and object update throttle patches (needs RE)`
- `Add frame time budget mode to lot streaming throttle (Speed 3 protection)`
