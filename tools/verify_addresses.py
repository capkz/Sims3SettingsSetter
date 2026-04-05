#!/usr/bin/env python3
"""
Targeted verification of candidate addresses found by find_addresses.py
"""

import sys
import struct
import pefile
import capstone

EXE_PATH = sys.argv[1] if len(sys.argv) > 1 else r"D:/GitHub/Sims3SettingsSetter/tools/ts3Worig.exe"
pe = pefile.PE(EXE_PATH)
IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase
text_section = next(s for s in pe.sections if b".text" in s.Name)
TEXT_VA = IMAGE_BASE + text_section.VirtualAddress
TEXT_DATA = bytearray(text_section.get_data())
TEXT_END = TEXT_VA + len(TEXT_DATA)

def read_at(va, n=4):
    off = va - TEXT_VA
    return bytes(TEXT_DATA[off:off+n]) if 0 <= off < len(TEXT_DATA)-n else b""

def u32(va):
    b = read_at(va, 4)
    return struct.unpack_from("<I", b)[0] if len(b)==4 else 0

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def disasm(va, n=30, nb=160):
    off = va - TEXT_VA
    code = bytes(TEXT_DATA[off:off+nb])
    insns = []
    for ins in md.disasm(code, va):
        insns.append(ins)
        if len(insns) >= n: break
    return insns

def show(va, n=30, nb=160, label=""):
    if label: print(f"\n  [{label}  @{hex(va)}]")
    for ins in disasm(va, n, nb):
        print(f"    {hex(ins.address)}:  {ins.mnemonic:8s} {ins.op_str}")

def parse_pattern(pat):
    out = []
    for t in pat.strip().split():
        if t == "??": out.append(None)
        else:
            hi = t[0]; lo = t[1]
            hi_val = None if hi == "?" else int(hi, 16) << 4
            lo_val = None if lo == "?" else int(lo, 16)
            if hi_val is None and lo_val is None: out.append(None)
            elif hi_val is None: out.append(("lo", lo_val))
            elif lo_val is None: out.append(("hi", hi_val))
            else: out.append(hi_val | lo_val)
    return out

def scan(pattern, start=TEXT_VA, end=TEXT_END, limit=20):
    pat = parse_pattern(pattern)
    plen = len(pat)
    s = max(0, start - TEXT_VA); e = min(len(TEXT_DATA)-plen, end - TEXT_VA)
    results = []
    data = TEXT_DATA
    i = s
    while i < e and len(results) < limit:
        ok = True
        for j, b in enumerate(pat):
            byte = data[i+j]
            if b is None: pass
            elif isinstance(b, tuple):
                mask, val = (0x0F, b[1]) if b[0]=="lo" else (0xF0, b[1])
                if byte & mask != val: ok = False; break
            else:
                if byte != b: ok = False; break
        if ok: results.append(TEXT_VA + i)
        i += 1
    return results

# Find cross-references (CALL instructions pointing to a target)
def find_callers(target_va, search_start=TEXT_VA, search_end=TEXT_END, limit=20):
    """Find all CALL rel32 instructions that call target_va"""
    callers = []
    s = max(0, search_start - TEXT_VA)
    e = min(len(TEXT_DATA)-5, search_end - TEXT_VA)
    data = TEXT_DATA
    for i in range(s, e):
        if data[i] == 0xE8:  # CALL rel32
            rel32 = struct.unpack_from("<i", data, i+1)[0]
            call_target = TEXT_VA + i + 5 + rel32
            if call_target == target_va:
                callers.append(TEXT_VA + i)
                if len(callers) >= limit: break
    return callers

print("=" * 72)
print("VERIFIED ADDRESSES")
print("=" * 72)

DECOMP = 0x4eb3b0
WM_UPDATE = 0xc6d570

print(f"\n  Decompressor  : {hex(DECOMP)}")
print(f"  WM::Update    : {hex(WM_UPDATE)}")
show(DECOMP, n=6, label="Decompressor")
show(WM_UPDATE, n=6, label="WorldManager::Update")

# ============================================================
# 1. FIND COMPRESSOR via cross-reference to decompressor
# ============================================================
print("\n" + "=" * 72)
print("1. COMPRESSOR — callers of decompressor (cross-ref)")
print("=" * 72)

callers = find_callers(DECOMP)
print(f"  Functions that CALL decompressor at {hex(DECOMP)}: {[hex(c) for c in callers]}")
for caller in callers[:5]:
    show(caller, n=4, label=f"caller at {hex(caller)}")

# Also look for CALL+5 pattern (indirect call through register to decompressor)
# and JMP-based calls
print("\n  Scanning 0x4e7000-0x4ef000 for the compressor function:")
# The compressor takes (dst, dstCapacity, src, srcSize) — 4 args on stack
# It writes output[0]=0x10, output[1]=0xFB, then 3 size bytes
# Specific pattern: write the 3-byte big-endian size after the 2-byte magic
# shr eax/ebx/ecx/edx, 16 followed by byte store is the top byte of the 24-bit size
for pat, desc in [
    ("C6 40 01 FB", "MOV [eax+1], 0xFB"),
    ("C6 41 01 FB", "MOV [ecx+1], 0xFB"),
    ("C6 42 01 FB", "MOV [edx+1], 0xFB"),
    ("C6 43 01 FB", "MOV [ebx+1], 0xFB"),
    ("C6 45 01 FB", "MOV [ebp+1], 0xFB"),
    ("C6 46 01 FB", "MOV [esi+1], 0xFB"),
    ("C6 47 01 FB", "MOV [edi+1], 0xFB"),
    # Or: byte stored at [dst+1] via indexed addressing
    ("C6 44 ?? 01 FB", "MOV [reg+reg+1], 0xFB"),
    # Or the 2-byte header stored as a word (stored as LE: FB 10)
    ("66 C7 00 FB 10", "MOV WORD [eax], 0x10FB (LE=FB10)"),
    ("66 C7 01 FB 10", "MOV WORD [ecx], 0x10FB"),
    ("66 C7 06 FB 10", "MOV WORD [esi], 0x10FB"),
    ("66 C7 07 FB 10", "MOV WORD [edi], 0x10FB"),
]:
    hits = scan(pat)
    for h in hits:
        nearby = bytes(TEXT_DATA[h-TEXT_VA:h-TEXT_VA+16])
        print(f"    {desc:35s} at {hex(h)}, bytes={nearby.hex(' ')}")
        show(h, n=8, nb=50, label=f"write site {hex(h)}")

# ============================================================
# 2. VERIFY RESOURCE LOOKUP CANDIDATE 0x81ccb0
# ============================================================
print("\n" + "=" * 72)
print("2. RESOURCE LOOKUP — verify 0x81ccb0")
print("=" * 72)

RES_CANDIDATE = 0x81ccb0
show(RES_CANDIDATE, n=50, nb=280, label="IResourceManager::GetResource candidate")

# Check what calls it
callers2 = find_callers(RES_CANDIDATE, limit=10)
print(f"\n  Callers of {hex(RES_CANDIDATE)}: {[hex(c) for c in callers2]}")
for c in callers2[:3]:
    show(c, n=5, label=f"caller {hex(c)}")

# ============================================================
# 3. OBJECT UPDATE — float argument patterns (deltaTime)
# ============================================================
print("\n" + "=" * 72)
print("3. OBJECT UPDATE — float deltaTime dispatch")
print("=" * 72)

# Object update passes deltaTime as a float. In __fastcall/__thiscall
# the float is passed on stack: PUSH float_reg then CALL vtable
# Look for: movss xmm0 then push/call, or fld + push + vtable call
# Also: many objects updated = loop over vector/list calling the same vtable slot
for pat, desc in [
    # updateAll-style: load vtable, push float (xmm or fpu), call
    ("F3 0F 11 04 24 8B ?? FF 5? ??", "movss [esp],xmm0; mov reg; call [reg+N]"),
    ("D9 1C 24 8B ?? FF 5? ??",        "fstp [esp]; mov reg; call [reg+N]"),
    # Loop: dec count + vtable call pattern
    ("4? 85 ?? 75 ?? 8B 0? FF 5? ??",  "dec; test; jnz; mov ecx; call vtable"),
    # Common: call vtable offset 0x40-0x80 range (Update is typically mid-vtable)
    ("8B 08 FF 51 40", "mov ecx,[eax]; call [ecx+0x40]"),
    ("8B 08 FF 51 44", "mov ecx,[eax]; call [ecx+0x44]"),
    ("8B 08 FF 51 48", "mov ecx,[eax]; call [ecx+0x48]"),
    ("8B 08 FF 51 4C", "mov ecx,[eax]; call [ecx+0x4c]"),
    ("8B 08 FF 51 50", "mov ecx,[eax]; call [ecx+0x50]"),
    ("8B 08 FF 51 54", "mov ecx,[eax]; call [ecx+0x54]"),
    ("8B 08 FF 51 58", "mov ecx,[eax]; call [ecx+0x58]"),
    ("8B 08 FF 51 5C", "mov ecx,[eax]; call [ecx+0x5c]"),
    # Also the add-and-loop variant
    ("FF 51 ?? 83 C0 04 3B C? 7? ??",  "call [ecx+N]; add eax,4; cmp eax,reg; jxx"),
    ("FF 51 ?? 83 C1 04 3B C? 7? ??",  "call [ecx+N]; add ecx,4; cmp ecx,reg; jxx"),
    ("FF 50 ?? 83 C6 04 3B F? 7? ??",  "call [eax+N]; add esi,4; cmp esi,reg; jxx"),
    ("FF 50 ?? 83 C7 04 3B F? 7? ??",  "call [eax+N]; add edi,4; cmp edi,reg; jxx"),
]:
    hits = scan(pat, limit=5)
    if hits:
        print(f"\n  {desc}: {[hex(h) for h in hits]}")
        show(hits[0], n=10, nb=60, label=hits[0])

# ============================================================
# 4. SUMMARY
# ============================================================
print("\n" + "=" * 72)
print("FINAL SUMMARY")
print("=" * 72)
print(f"  Decompressor:              {hex(DECOMP)}  (Steam — confirmed)")
print(f"  WorldManager::Update:      {hex(WM_UPDATE)}  (Steam — confirmed)")
print(f"  Compressor:                TBD (see section 1 above)")
print(f"  IResourceManager::GetResource: {hex(RES_CANDIDATE)}  (verify above)")
print(f"  ObjectManager::UpdateAll:  TBD (see section 3 above)")
