# S3SS New Optimizations — Progress

## Status

| # | Patch | File | Status | Notes |
|---|-------|------|--------|-------|
| 1 | Decompression Cache | `patches/refpack_decompressor_patch.cpp` | ✅ Done | LRU cache added to existing RefPack patch. Opt-in, 8-256 MB budget. |
| 2 | Draw Call Batching | `patches/draw_call_batching_patch.cpp` | ✅ Done | Redundant PS/VS/Texture/RT state change elimination via D3D9 hooks. Enabled by default. |
| 3 | Lot Streaming Throttle | `patches/sim_update_throttle_patch.cpp` | ✅ Done | Throttles WorldManager lot updates to every N frames. Default N=2. |
| 4 | Pathfinding Cache | `patches/pathfinding_cache_patch.cpp` | ⚠️ Needs RE | Infrastructure complete. ComputePath address needs binary verification. |

## NRAAS Compatibility

| Patch | NRAAS Compatibility |
|-------|-------------------|
| Decompression Cache | ✅ Fully compatible. More impactful with NRAAS (more .package files loaded) |
| Draw Call Batching | ✅ Fully compatible. Operates below Mono layer |
| Lot Streaming Throttle | ✅ Compatible. NRAAS operates in Mono space, above WorldManager |
| Pathfinding Cache | ✅ Complementary to NRAAS Vector. Vector works at C# layer; cache works at native level |

## Mac Compatibility
Not applicable. The mod is a Windows DLL (ASI). The Mac version of Sims 3 uses OpenGL (not D3D9), Mach-O binaries, and different APIs throughout. A Mac port would require ground-up rewriting.

## What Still Needs Work

### Pathfinding Cache Address (`patches/pathfinding_cache_patch.cpp`)
The routing cache infrastructure is complete but the hook can't install until the ComputePath function address is found. To complete this:
1. Open Retail/Steam/EA binary in IDA Pro or Ghidra (x86 32-bit)
2. Search for the routing function: look for large __thiscall functions that contain MOVSS/SUBSS float ops + a tight priority-queue loop + output buffer writes
3. Fill in addresses in `routeComputeFunc.addresses`
4. Verify the pattern `"56 8B F1 57 81 EC ?? ?? 00 00 F3 0F 10..."` or update it

## Commit Log
- `Add LRU decompression cache to RefPack decompressor patch`
- `Add redundant D3D9 state change elimination patch`
- `Fix draw call batching patch: remove premature D3D9 init check`
- `Add lot streaming update throttle patch`
- `Add native routing cache patch (experimental, needs address verification)`
