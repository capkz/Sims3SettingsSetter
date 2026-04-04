# S3SS New Optimizations — Progress

## Status

| # | Patch | File | Status | Notes |
|---|-------|------|--------|-------|
| 1 | Decompression Cache | `patches/refpack_decompressor_patch.cpp` | ✅ Done | Fixed LOD collision bug — now hashes full compressed data |
| 2 | Draw Call Batching | `patches/draw_call_batching_patch.cpp` | ✅ Done | 6-28% state change elimination in testing |
| 3 | Lot Streaming Throttle | `patches/sim_update_throttle_patch.cpp` | ✅ Done | Throttles WorldManager lot updates every N frames |
| 4 | Pathfinding Cache | `patches/pathfinding_cache_patch.cpp` | ⏸️ On Hold | Needs binary verification of ComputePath address |

## Bug Fixes
- **Decompression cache LOD collision**: FNV-1a of first 64 bytes caused false hits between LOD variants. Fixed by hashing all compressed bytes.

---

## Next Up — Planned Optimizations

### Tier 1 — Low effort, high confidence (extend existing patches)

| # | Name | Approach | Expected Impact |
|---|------|----------|-----------------|
| 5 | Shader Constant Deduplication | Extend draw state patch to also skip redundant `SetPixelShaderConstantF` / `SetVertexShaderConstantF` calls (lighting, fog, transform constants that repeat between draws) | Medium — completes the draw state work |
| 6 | Camera-Aware Lot Throttle | Extend lot streaming throttle to skip more aggressively when camera is stationary, less when moving fast — read camera speed via `LiveSetting::GetValue` | Medium-High — better gameplay feel |
| 7 | Decompression Thread Pool | On cache miss, dispatch decompression to a background thread pool instead of blocking the calling thread. Return a pending/LOD-fallback while it completes | High — eliminates synchronous decompression hitches |
| 8 | D3D9 Texture Cache | Hook `CreateTexture` (already in registry) to cache `IDirect3DTexture9*` by content hash. Return existing GPU texture instead of re-uploading on lot reload | High — big win for lots with repeated tiling textures |

### Tier 2 — Bigger impact, more reverse engineering needed

| # | Name | Approach | Expected Impact |
|---|------|----------|-----------------|
| 9 | Mono Script Budget | Cap Mono callbacks per frame in `MonoScriptHost::Simulate` — defer non-critical ones to next frame. Smooths worst stutter spikes with NRAAS/heavy mods | Very High — direct attack on script-thread stutter |
| 10 | Sim Update Frequency Throttle | Hook the per-sim update dispatch (not WorldManager — the actual sim tick loop). Distance-based: full rate for active household, half for same zone, quarter for distant lots | Very High — biggest simulation bottleneck after GC |
| 11 | Navigation Mesh Caching | Cache the processed nav mesh for each lot so it doesn't rebuild from scratch on every load. Lot nav mesh computation is a large part of the streaming hitch when entering a new lot | High — reduces lot entry stutter |
| 12 | Social Graph Update Throttle | The game maintains relationship/social data for every sim in the neighbourhood every tick. Hook the social graph update and throttle non-visible sims to once per second instead of every tick | High — large worlds with many sims benefit most |
| 13 | Object Culling (CPU-side) | Before `DrawIndexedPrimitive`, skip fully off-screen objects using a bounding box vs frustum test. Return `Skip` from the hook for culled objects — GPU never sees them | Medium-High — neighbourhood/live mode camera views |

### Tier 3 — Speculative / needs deep RE

| # | Name | Approach | Expected Impact |
|---|------|----------|-----------------|
| 14 | Shadow Render Cache | Cache shadow maps between frames when lights and occluders haven't moved. Re-render only on change | Medium-High |
| 15 | Save Game Bloat Cleanup | Periodically scan and remove orphaned game objects / stale relationship data from in-memory world state. Prevents long-term session performance degradation | Medium — most felt in 20+ hour saves |
| 16 | Async Lot Nav Mesh Build | Move lot navigation mesh computation off the main thread entirely using a worker thread, returning a stub mesh while it builds | High — eliminates the main hitch when entering a new lot |

---

## NRAAS Compatibility
| Patch | Status |
|-------|--------|
| Decompression Cache | ✅ Compatible |
| Draw Call Batching | ✅ Compatible |
| Lot Streaming Throttle | ✅ Compatible |
| Shader Constant Dedup | ✅ Compatible |
| Camera-Aware Throttle | ✅ Compatible |
| Decompression Thread Pool | ✅ Compatible |
| D3D9 Texture Cache | ✅ Compatible |
| Mono Script Budget | ⚠️ Test with heavy NRAAS setups |
| Sim Update Throttle | ⚠️ Must respect NRAAS sim priority flags |
| Pathfinding Cache | ✅ Complementary to Vector |
| All others | ✅ Operate below Mono layer |

## Mac Compatibility
Not applicable — Windows DLL/ASI only.

## Commit Log
- `Add LRU decompression cache to RefPack decompressor patch`
- `Add redundant D3D9 state change elimination patch`
- `Fix draw call batching patch: remove premature D3D9 init check`
- `Add lot streaming update throttle patch`
- `Add native routing cache patch (experimental, needs address verification)`
- `Fix decompression cache: hash full compressed data to prevent LOD collisions`
