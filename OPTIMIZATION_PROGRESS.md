# S3SS New Optimizations — Progress

## Status

| # | Patch | File | Status | Notes |
|---|-------|------|--------|-------|
| 1 | Decompression Cache | `patches/refpack_decompressor_patch.cpp` | 🔄 In Progress | Adds LRU cache to existing RefPack patch |
| 2 | Draw Call Batching | `patches/draw_call_batching_patch.cpp` | ⏳ Pending | D3D9 hook registry state-sort |
| 3 | Sim Update Throttle | `patches/sim_update_throttle_patch.cpp` | ⏳ Pending | Needs RE of sim dispatch loop |
| 4 | Pathfinding Cache | `patches/pathfinding_cache_patch.cpp` | ⏳ Pending | Needs RE of routing system |

## NRAAS Compatibility Notes
- **Decompression Cache**: ✅ Fully compatible, more impactful with NRAAS installed
- **Draw Call Batching**: ✅ Fully compatible (below Mono layer)
- **Sim Update Throttle**: ⚠️ Must respect NRAAS sim priority flags; throttle only inactive/distant sims
- **Pathfinding Cache**: ⚠️ Detect NRAAS Vector and disable if present (Vector replaces the pathing algorithm)

## Commit Log
<!-- Updated as each patch lands -->
