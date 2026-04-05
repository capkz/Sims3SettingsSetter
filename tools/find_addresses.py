#!/usr/bin/env python3
"""
Sims 3 Binary Address Finder
Locates function addresses needed for S3SS patches via pattern scanning.
Usage: python find_addresses.py [path_to_TS3.exe]
"""

import sys
import struct
import pefile
import capstone
from typing import Optional

EXE_PATH = sys.argv[1] if len(sys.argv) > 1 else r"D:/games/the sims 3/Game/Bin/TS3.exe"

print(f"Loading {EXE_PATH} ...")
pe = pefile.PE(EXE_PATH)
IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase

# Rebuild the virtual address space from all sections
# (some PE loaders adjust RVAs; we manually reconstruct to be safe)
VA_MAP: dict[int, bytearray] = {}
for section in pe.sections:
    vaddr = IMAGE_BASE + section.VirtualAddress
    raw   = section.get_data()
    # Extend to virtual size if needed
    vsz = section.Misc_VirtualSize
    data = bytearray(raw)
    if len(data) < vsz:
        data += bytearray(vsz - len(data))
    VA_MAP[vaddr] = data

text_section = next(s for s in pe.sections if b".text" in s.Name)
TEXT_VA = IMAGE_BASE + text_section.VirtualAddress
TEXT_DATA = VA_MAP[TEXT_VA]
TEXT_END  = TEXT_VA + len(TEXT_DATA)

print(f"  ImageBase:   {hex(IMAGE_BASE)}")
print(f"  .text:       {hex(TEXT_VA)} - {hex(TEXT_END)}  ({len(TEXT_DATA)//1024} KB)")
print()

def read_at(va: int, n: int) -> bytes:
    off = va - TEXT_VA
    if off < 0 or off + n > len(TEXT_DATA):
        return b""
    return bytes(TEXT_DATA[off:off+n])

def u32_at(va: int) -> int:
    b = read_at(va, 4)
    return struct.unpack_from("<I", b)[0] if len(b) == 4 else 0

# ---------------------------------------------------------------------------
# Pattern scanner — supports ?? (full wildcard) only
# ---------------------------------------------------------------------------
def parse_pattern(pat: str) -> list:
    tokens = pat.strip().split()
    out = []
    for t in tokens:
        if t == "??":
            out.append(None)
        else:
            out.append(int(t, 16))
    return out

def scan(pattern: str, start_va: int = TEXT_VA, end_va: int = TEXT_END,
         limit: int = 20) -> list[int]:
    pat = parse_pattern(pattern)
    plen = len(pat)
    s = max(0, start_va - TEXT_VA)
    e = min(len(TEXT_DATA) - plen, end_va - TEXT_VA)
    results = []
    i = s
    data = TEXT_DATA
    while i < e and len(results) < limit:
        ok = True
        for j, b in enumerate(pat):
            if b is not None and data[i+j] != b:
                ok = False
                break
        if ok:
            results.append(TEXT_VA + i)
        i += 1
    return results

# ---------------------------------------------------------------------------
# Disassembler
# ---------------------------------------------------------------------------
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def disasm_at(va: int, max_insns: int = 20, max_bytes: int = 120) -> list:
    off = va - TEXT_VA
    code = bytes(TEXT_DATA[off:off+max_bytes])
    insns = []
    for ins in md.disasm(code, va):
        insns.append(ins)
        if len(insns) >= max_insns:
            break
    return insns

def show(va: int, n: int = 20, n_bytes: int = 120, label: str = ""):
    if label:
        print(f"  [{label}  @{hex(va)}]")
    for ins in disasm_at(va, n, n_bytes):
        print(f"    {hex(ins.address)}:  {ins.mnemonic:8s} {ins.op_str}")

# ---------------------------------------------------------------------------
# Walk backwards to likely function start (INT3/NOP gap + prologue)
# ---------------------------------------------------------------------------
PROLOGUES = [
    b"\x55\x8b\xec",       # push ebp; mov ebp,esp
    b"\x55\x89\xe5",       # push ebp; mov ebp,esp (GCC)
    b"\x53\x55\x56",       # push ebx; push ebp; push esi
    b"\x56\x57",           # push esi; push edi
    b"\x56\x8b\xf1",       # push esi; mov esi,ecx
    b"\x57\x8b\xf9",       # push edi; mov edi,ecx
    b"\x83\xec",           # sub esp,N
    b"\x51\x56",           # push ecx; push esi
]

def find_func_start(va: int, max_back: int = 0x300) -> Optional[int]:
    off = va - TEXT_VA
    for back in range(1, max_back):
        co = off - back
        if co < 0:
            break
        # Check for gap byte (CC=int3, 90=nop, C3=ret) immediately before
        gap = TEXT_DATA[co - 1] if co > 0 else 0
        if gap not in (0xCC, 0x90, 0xC3, 0x00):
            continue
        chunk = bytes(TEXT_DATA[co:co+4])
        for p in PROLOGUES:
            if chunk[:len(p)] == p:
                return TEXT_VA + co
    return None

# ===========================================================================
# 1. REFPACK DECOMPRESSOR — scan for the known pattern, confirm EA version
# ===========================================================================
print("=" * 72)
print("1. REFPACK DECOMPRESSOR")
print("=" * 72)

# Primary pattern from the patch
DECOMP_PAT = "83 EC 10 8B 4C 24 1C 85 C9 53 55 56 8B 74 24 20 57 C7 44 24 1C 00 00 00 00 0F 84"
hits = scan(DECOMP_PAT)
print(f"  Primary pattern scan: {[hex(h) for h in hits]}")

# Sanity check: read raw bytes at all three known addresses
print("  Raw bytes at known decompressor addresses:")
for name, addr in [("Retail", 0x004eb900), ("Steam", 0x004eb3b0), ("EA", 0x004eb4f0)]:
    b = read_at(addr, 12)
    print(f"    {name:6s} {hex(addr)}: {b.hex(' ')}")

# Direct byte scan for 83 EC 10 8B 4C 24 1C (no wildcards, very specific)
hits_direct = scan("83 EC 10 8B 4C 24 1C 85 C9")
print(f"  Direct 9-byte scan: {[hex(h) for h in hits_direct]}")

# Also try the shorter prefix in case the function was inlined differently
hits2 = scan("83 EC 10 8B 4C 24 1C 85 C9 53 55 56 8B 74 24 20 57")
print(f"  Short prefix scan:    {[hex(h) for h in hits2]}")

# The decompressor uses RefPack header 0x10 0xFB; look for that constant check
hits3 = scan("81 ?? FB 10 00 00")  # cmp reg, 0x000010FB
print(f"  Header magic check:   {[hex(h) for h in hits3[:5]]}")

# Also scan for the decompressor output size read pattern (common)
# Expected size read: mov eax,[src] with 3-byte shift arithmetic
hits4 = scan("C1 E0 10 0F B6")  # shl eax,16 + movzx (size byte reads)
print(f"  Size shift pattern:   {[hex(h) for h in hits4[:5]]}")

# Check EA 1.69 stored address
EA_DECOMP = 0x004eb4f0
stored_bytes = read_at(EA_DECOMP, 8)
print(f"  EA stored addr {hex(EA_DECOMP)}: {stored_bytes.hex(' ')}")

# Try all three version addresses
for name, addr in [("Retail", 0x004eb900), ("Steam", 0x004eb3b0), ("EA", 0x004eb4f0)]:
    b = read_at(addr, 6)
    print(f"  {name:6s} {hex(addr)}: {b.hex(' ')}")

print()
if hits or hits2:
    best = (hits or hits2)[0]
    print(f"  Found decompressor at {hex(best)}")
    show(best, n=8, label="decompressor start")

# ===========================================================================
# 2. REFPACK COMPRESSOR — adjacent to decompressor, writes 0x10 0xFB header
# ===========================================================================
print()
print("=" * 72)
print("2. REFPACK COMPRESSOR")
print("=" * 72)

# The compressor writes big-endian header: first byte 0x10 then 0xFB
# Scan for the literal sequence stored as immediate (or as two separate byte stores)

# Pattern A: MOV byte [reg], 0x10  followed within 4 bytes by 0xFB
#   C6 07 10 = MOV [edi], 0x10
#   C6 06 10 = MOV [esi], 0x10
#   C6 00 10 = MOV [eax], 0x10
# Pattern B: the output size write: store 3 bytes of uncompressed size big-endian
#   Typical: C1 EB 10 (shr ebx, 16) then 88 07 (mov [edi], bl)

# Scan for MOV [reg], 0x10 near MOV [reg+1], 0xFB
comp_funcs = {}
for pat, name in [
    ("C6 07 10", "MOV [edi],0x10"),
    ("C6 06 10", "MOV [esi],0x10"),
    ("C6 00 10", "MOV [eax],0x10"),
    ("C6 01 10", "MOV [ecx],0x10"),
    ("C6 04 24 10", "MOV [esp],0x10"),
]:
    for h in scan(pat, limit=20):
        # Check if 0xFB appears within the next 8 bytes
        nearby = read_at(h, 12)
        if 0xFB in nearby:
            func = find_func_start(h, 0x800)
            if func and func not in comp_funcs:
                comp_funcs[func] = h
                print(f"  {name} at {hex(h)}, 0xFB nearby, func ~ {hex(func)}")

# Also: scan for the size-encode pattern unique to compressor
# Compressor writes 3-byte uncompressed size big-endian after the 2-byte header
# Typical sequence: shift and mask to extract bytes
for pat, name in [
    ("C1 EB 10 88 5C ?? ??", "shr ebx,16; mov [reg+N],bl"),
    ("C1 E8 10 88 44 ?? ??", "shr eax,16; mov [reg+N],al"),
    ("C1 EB 10 88 1C ?? ??", "shr ebx,16; mov [reg+N],bl (alt)"),
]:
    for h in scan(pat, limit=10):
        func = find_func_start(h, 0x800)
        if func and func not in comp_funcs:
            comp_funcs[func] = h
            print(f"  {name} at {hex(h)}, func ~ {hex(func)}")

# Scan for the actual 0x10FB word constant
for h in scan("66 C7 ?? FB 10", limit=10):   # MOV WORD PTR [reg], 0x10FB (LE stored as FB 10)
    func = find_func_start(h, 0x800)
    if func and func not in comp_funcs:
        comp_funcs[func] = h
        print(f"  MOV WORD [reg],0x10FB at {hex(h)}, func ~ {hex(func)}")

print(f"\n  Compressor candidate functions: {[hex(f) for f in comp_funcs]}")
for func in list(comp_funcs)[:3]:
    show(func, n=20, label=f"candidate {hex(func)}")

# Deep dive: look at functions near the decompressor (within ±0x2000)
# The compressor is almost always compiled adjacent to the decompressor.
print("\n  Deep scan: functions near decompressor (±0x4000):")
decomp_va = (scan(DECOMP_PAT) or [None])[0]
if decomp_va:
    # Scan for all function prologues in range
    for off in range(max(0, decomp_va - TEXT_VA - 0x4000),
                     min(len(TEXT_DATA)-4, decomp_va - TEXT_VA + 0x4000)):
        va = TEXT_VA + off
        if va == decomp_va:
            continue
        chunk = bytes(TEXT_DATA[off:off+4])
        # Check for function start preceded by gap byte
        gap = TEXT_DATA[off-1] if off > 0 else 0
        if gap not in (0xCC, 0x90, 0xC3, 0x00):
            continue
        # Must look like a function prologue
        is_prologue = (
            (chunk[0] == 0x55 and chunk[1] == 0x8B and chunk[2] == 0xEC) or  # push ebp; mov ebp,esp
            (chunk[0] == 0x83 and chunk[1] == 0xEC) or                         # sub esp,N
            (chunk[0] == 0x56 and chunk[1] == 0x8B and chunk[2] == 0xF1) or  # push esi; mov esi,ecx
            (chunk[0] == 0x53 and chunk[1] == 0x55 and chunk[2] == 0x56)      # push ebx/ebp/esi
        )
        if not is_prologue:
            continue
        # Look for 0x10 0xFB writes in this function (up to 512 bytes)
        func_bytes = bytes(TEXT_DATA[off:off+512])
        # Check for the byte 0xFB appearing in this function
        if 0xFB in func_bytes and 0x10 in func_bytes:
            # Also check for a loop (JMP backward or LOOP instruction)
            has_loop = any(func_bytes[i] in (0xEB, 0xE9, 0xE2) and
                          func_bytes[i+1] < 0x80  # relative jump backward: would be > 0x80
                          or func_bytes[i] in (0xEB,) and func_bytes[i+1] > 0x80
                          for i in range(min(400, len(func_bytes)-2)))
            print(f"    Near-decompressor func at {hex(va)} — has 0x10 and 0xFB bytes, loop={has_loop}")
            show(va, n=12, label=f"near-decomp func {hex(va)}")

# ===========================================================================
# 3. WORLDMANAGER::UPDATE — verify EA address
# ===========================================================================
print()
print("=" * 72)
print("3. WORLDMANAGER::UPDATE")
print("=" * 72)

WM_PAT = "55 8B EC 83 E4 F0 83 EC 64 53 56 8B F1 83 BE B4 01 00 00 00 57 75"
hits = scan(WM_PAT)
print(f"  Pattern scan: {[hex(h) for h in hits]}")

# Check stored EA address
EA_WM = 0x00c6c8f0
b = read_at(EA_WM, 8)
print(f"  EA stored {hex(EA_WM)}: {b.hex(' ')}")
if hits:
    show(hits[0], n=10, label="WorldManager::Update")

# ===========================================================================
# 4. RESOURCE MANAGER LOOKUP
# ===========================================================================
print()
print("=" * 72)
print("4. RESOURCE LOOKUP (DBPF / IResourceManager::GetResource)")
print("=" * 72)

# ResourceKey = {uint32 typeId, uint32 groupId, uint64 instanceId} = 16 bytes
# The lookup function iterates package entries comparing all 3 fields.
# Look for a quadruple CMP sequence — each field compared then JNE to next entry.
# Pattern: 4 comparisons in a short span, each followed by JNE/JNZ

# 3B 46 ?? = CMP EAX, [ESI+N]   (common form)
# 75 ?? = JNZ
rk_patterns = [
    "3B 46 ?? 75 ?? 3B 4E ?? 75",   # cmp eax,[esi+N]; jnz; cmp ecx,[esi+N]; jnz
    "3B 47 ?? 75 ?? 3B 4F ?? 75",   # cmp eax,[edi+N]; jnz; cmp ecx,[edi+N]; jnz
    "39 46 ?? 75 ?? 39 4E ?? 75",   # cmp [esi+N],eax; jnz; cmp [esi+N],ecx; jnz
    "39 47 ?? 75 ?? 39 4F ?? 75",   # cmp [edi+N],eax; jnz; cmp [edi+N],ecx; jnz
    # Might also be: cmp [reg+typeId_offset], eax form
    "3B 03 75 ?? 3B 43 ?? 75",      # cmp eax,[ebx]; jnz; cmp eax,[ebx+N]; jnz
    "3B 01 75 ?? 3B 41 ?? 75",      # cmp eax,[ecx]; jnz; cmp eax,[ecx+N]; jnz
    # OR a tighter form: compare all 4 DWORDs of key
    "3B ?? 75 ?? 3B ?? 75 ?? 3B ?? 75 ?? 3B ?? 75",
    # struct comparison via REPE CMPSD (REP prefix)
    "F3 A7",                         # REP CMPSD (compare 4-byte blocks repeatedly)
]

print("  Scanning for ResourceKey comparison patterns:")
res_funcs = {}
for pat in rk_patterns:
    for h in scan(pat, limit=5):
        func = find_func_start(h, 0x500)
        if func and func not in res_funcs:
            res_funcs[func] = h
            print(f"    Hit at {hex(h)}, func ~ {hex(func)}")
            show(h, n=14, label=f"compare site")
            print()

print(f"  Resource lookup candidates: {[hex(f) for f in res_funcs]}")

# ===========================================================================
# 5. OBJECT UPDATE DISPATCH
# ===========================================================================
print()
print("=" * 72)
print("5. OBJECT UPDATE DISPATCH (ObjectManager::UpdateAll)")
print("=" * 72)

# A vtable-call loop: mov eax,[edi/esi]; call [eax+offset]
# with surrounding loop structure (compare + add/inc pointer)
obj_patterns = [
    "8B 07 8B CF FF 50 ?? 83 C7 04",   # mov eax,[edi]; mov ecx,edi; call [eax+N]; add edi,4
    "8B 06 8B CE FF 50 ?? 83 C6 04",   # mov eax,[esi]; mov ecx,esi; call [eax+N]; add esi,4
    "8B 07 8B CF FF 50 ??",            # mov eax,[edi]; mov ecx,edi; call [eax+N]
    "8B 06 8B CE FF 50 ??",            # mov eax,[esi]; mov ecx,esi; call [eax+N]
    "8B 10 8B CA FF 52 ??",            # mov edx,[eax]; mov ecx,eax; call [edx+N]
    "8B 0B FF 51 ??",                  # mov ecx,[ebx]; call [ecx+N]
    "8B 08 FF 51 ??",                  # mov ecx,[eax]; call [ecx+N]
    "FF 50 ?? 83 C7 04",               # call [eax+N]; add edi,4
    "FF 50 ?? 83 C6 04",               # call [eax+N]; add esi,4
    "FF 51 ?? 83 C7 04",               # call [ecx+N]; add edi,4
    "FF 51 ?? 83 C6 04",               # call [ecx+N]; add esi,4
]

print("  Scanning for vtable call loop patterns:")
obj_funcs = {}
for pat in obj_patterns:
    for h in scan(pat, limit=8):
        func = find_func_start(h, 0x300)
        if func and func not in obj_funcs:
            obj_funcs[func] = h
            # Filter: function should be reasonably sized (>30 bytes before the site)
            if h - func >= 10:
                print(f"    Call site at {hex(h)}, func ~ {hex(func)}")

# Show top candidates
for func in list(obj_funcs)[:4]:
    show(func, n=18, label=f"candidate {hex(func)}")
    print()

# ===========================================================================
# 6. SUMMARY
# ===========================================================================
print()
print("=" * 72)
print("SUMMARY")
print("=" * 72)
all_hits = {
    "Refpack Decompressor": (hits or hits2 or [None])[0],
    "WorldManager::Update": (scan(WM_PAT) or [None])[0],
}
for name, va in all_hits.items():
    print(f"  {name:30s}: {hex(va) if va else 'NOT FOUND'}")
print(f"  Compressor candidates:        {[hex(f) for f in list(comp_funcs)[:3]]}")
print(f"  Resource lookup candidates:   {[hex(f) for f in list(res_funcs)[:3]]}")
print(f"  Object update candidates:     {[hex(f) for f in list(obj_funcs)[:4]]}")
