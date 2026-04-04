# S3SS New Optimizations — Progress

## Status

| # | Patch | File | Status | Notes |
|---|-------|------|--------|-------|
| 1 | Decompression Cache | `patches/refpack_decompressor_patch.cpp` | ✅ Done | Fixed: was hashing only first 64 bytes causing LOD mesh collisions. Now hashes full compressed data. |
| 2 | Draw Call Batching | `patches/draw_call_batching_patch.cpp` | ✅ Done | Redundant PS/VS/Texture/RT elimination. 6-28% elimination rate in testing. |
| 3 | Lot Streaming Throttle | `patches/sim_update_throttle_patch.cpp` | ✅ Done | Throttles WorldManager lot updates to every N frames. Default N=2. |
| 4 | Pathfinding Cache | `patches/pathfinding_cache_patch.cpp` | ⏸️ On Hold | Infrastructure complete. ComputePath address needs binary verification. |

## Bug Fixes
- **Decompression cache LOD collision** (fixed in same commit): FNV-1a of first 64 bytes caused false cache hits between LOD variants of the same mesh — same header bytes, same size. Served low-LOD meshes in place of high-LOD, breaking sim body/hair/clothing visuals. Fixed by hashing all compressed bytes.

## NRAAS Compatibility
| Patch | Status |
|-------|--------|
| Decompression Cache | ✅ Compatible |
| Draw Call Batching | ✅ Compatible |
| Lot Streaming Throttle | ✅ Compatible |
| Pathfinding Cache | ✅ Complementary to Vector (on hold) |

## Mac Compatibility
Not applicable — Windows DLL/ASI only.

## Commit Log
- `Add LRU decompression cache to RefPack decompressor patch`
- `Add redundant D3D9 state change elimination patch`
- `Fix draw call batching patch: remove premature D3D9 init check`
- `Add lot streaming update throttle patch`
- `Add native routing cache patch (experimental, needs address verification)`
- `Fix decompression cache: hash full compressed data to prevent LOD collisions`
