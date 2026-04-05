# S3SS New Optimizations — Progress

## Status

| # | Patch | File | Status | Notes |
|---|-------|------|--------|-------|
| 1 | Decompression Cache | `patches/refpack_decompressor_patch.cpp` | ✅ Done | Fixed LOD collision bug — now hashes full compressed data |
| 2 | Draw Call Batching | `patches/draw_call_batching_patch.cpp` | ✅ Done | 6-28% state change elimination in testing |
| 3 | Lot Streaming Throttle | `patches/sim_update_throttle_patch.cpp` | ✅ Done | Throttles WorldManager lot updates every N frames |
| 4 | Pathfinding Cache | `patches/pathfinding_cache_patch.cpp` | ⏸️ On Hold | Needs binary verification of ComputePath address |
| 5 | Camera-Aware Lot Throttle | `patches/sim_update_throttle_patch.cpp` | 🔄 Planned | Extend #3: dynamic N based on camera movement |
| 6 | RefPack Compressor | `patches/refpack_compressor_patch.cpp` | 🔄 Planned | SIMD save-path compression (mirrors decompressor) |
| 7 | Package Index Cache | `patches/package_index_cache_patch.cpp` | 🔄 Planned | Hash-map DBPF resource lookup, disk cache |
| 8 | Object Update Throttle | `patches/object_update_throttle_patch.cpp` | 🔄 Planned | Throttle decorative/non-interactive objects |
| 9 | Async Texture Compositor | `patches/async_texture_compositor_patch.cpp` | 🔄 Planned | Move texture composition off main thread |
| 10 | Stale Event Cleanup | `patches/event_cleanup_patch.cpp` | 🔄 Planned | Purge orphaned event listeners during long sessions |
| 11 | Speed 3 Frame Budget | `patches/speed3_frame_budget_patch.cpp` | 🔄 Planned | Cap ticks-per-frame to prevent frame pacing churn |

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
> - Throttle N is conservative by default (N=2)
>
> **Best practice:** disable experimental simulation patches before saving, especially on long-running saves.

---

## Deferred / On Hold

| # | Name | Reason |
|---|------|--------|
| — | Shader Constant Deduplication | User preference — not wanted |
| — | Route Retry Cooldown | Skipped — routing patches excluded |
| 4 | Pathfinding Cache | Needs binary RE to verify `ComputePath` address |
| — | Mono Script Budget | Needs deep Mono domain RE — revisit later |
| — | Sim Update Frequency Throttle | Needs per-sim tick dispatch RE |

---

## NRAAS Compatibility
| Patch | Status |
|-------|--------|
| Decompression Cache | ✅ Compatible |
| Draw Call Batching | ✅ Compatible |
| Lot Streaming Throttle | ✅ Compatible |
| Camera-Aware Throttle | ✅ Compatible |
| RefPack Compressor | ✅ Compatible |
| Package Index Cache | ✅ Compatible |
| Object Update Throttle | ⚠️ Test — must not throttle NRAAS-controlled sims |
| Async Texture Compositor | ✅ Compatible |
| Stale Event Cleanup | ⚠️ Test with heavy NRAAS setups |
| Speed 3 Frame Budget | ⚠️ Must respect NRAAS sim priority flags |
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
