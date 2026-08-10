#!/usr/bin/env python3
"""
find_chain.py — find pointer chain from MesenCore.so to any target address

Usage:
    python3 find_chain.py <pid> <target_addr_hex> [subtract_offset_hex]

  target_addr_hex     : absolute address found in memory (e.g. from scanmem)
  subtract_offset_hex : optional byte offset to subtract from target_addr_hex
                        to arrive at the value stored in the chain.
                        Default: 0  (target_addr IS the stored value/pointer).

Examples:
    # NES RAM via level_num field:
    python3 find_chain.py 159127 7fb67cf289dc 75c

    # Frame counter — pass the address exactly as found; no subtract offset:
    python3 find_chain.py 159127 7fb67cf00000
"""
import sys, struct, re

PTR_MIN = 0x10000
PTR_MAX = 0x7fffffffffff

# ── Known NES RAM chain (already working in lib.rs) ──────────────────────────
KNOWN_MODULE = 'MesenCore.so'
KNOWN_RVA    = 0xc541b0
KNOWN_HOPS   = [0x00, 0x40, 0x28]
# ─────────────────────────────────────────────────────────────────────────────

def valid_ptr(v):
    return isinstance(v, int) and PTR_MIN <= v <= PTR_MAX

def read_maps(pid):
    regions = []
    with open(f'/proc/{pid}/maps') as f:
        for line in f:
            m = re.match(
                r'([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s*(.*)', line)
            if m:
                regions.append((
                    int(m.group(1), 16),
                    int(m.group(2), 16),
                    m.group(3),
                    m.group(4).strip()
                ))
    return regions

def r64(f, addr):
    if not valid_ptr(addr):
        return None
    try:
        f.seek(addr)
        d = f.read(8)
        return struct.unpack('<Q', d)[0] if len(d) == 8 else None
    except OSError:
        return None

def read_slots(f, start, end):
    slots = {}
    try:
        f.seek(start)
        data = f.read(end - start)
        for i in range(0, len(data) - 7, 8):
            v = struct.unpack_from('<Q', data, i)[0]
            if valid_ptr(v):
                slots[start + i] = v
    except OSError:
        pass
    return slots

# ─────────────────────────────────────────────────────────────────────────────

if len(sys.argv) < 3:
    print(__doc__)
    sys.exit(1)

pid      = int(sys.argv[1])
raw_addr = int(sys.argv[2], 16)
subtract = int(sys.argv[3], 16) if len(sys.argv) >= 4 else 0
target   = raw_addr - subtract

print(f"PID          : {pid}")
print(f"Raw address  : {raw_addr:#x}")
if subtract:
    print(f"Subtract     : {subtract:#x}")
print(f"Target       : {target:#x}")

maps = read_maps(pid)

mc_segs = [r for r in maps if KNOWN_MODULE in r[3]]
if not mc_segs:
    print(f"ERROR: {KNOWN_MODULE} not found in /proc/maps")
    sys.exit(1)

mc_base = min(r[0] for r in mc_segs)
mc_rw   = [(r[0], r[1]) for r in mc_segs if 'w' in r[2]]

print(f"\n{KNOWN_MODULE} base : {mc_base:#x}")
for s, e in mc_rw:
    print(f"  writable: {s:#x}–{e:#x}  RVA {s-mc_base:#x}–{e-mc_base:#x}")

mesen_segs = [r for r in maps
              if r[3].endswith('/Mesen') and 'w' in r[2] and 'x' not in r[2]]
mesen_base = min((r[0] for r in maps if r[3].endswith('/Mesen')), default=0)
mesen_rw   = [(r[0], r[1]) for r in mesen_segs]

print(f"Mesen exe base    : {mesen_base:#x}")
for s, e in mesen_rw:
    print(f"  writable: {s:#x}–{e:#x}  RVA {s-mesen_base:#x}–{e-mesen_base:#x}")

def label(addr):
    if mc_base <= addr < mc_base + 0x10000000:
        return f"MesenCore.so+{addr - mc_base:#x}"
    return f"Mesen+{addr - mesen_base:#x}"

with open(f'/proc/{pid}/mem', 'rb') as mem:

    mc_slots  = {}
    for s, e in mc_rw:
        mc_slots.update(read_slots(mem, s, e))

    exe_slots = {}
    for s, e in mesen_rw:
        exe_slots.update(read_slots(mem, s, e))

    all_slots = {**mc_slots, **exe_slots}
    print(f"\nSlots: {len(mc_slots)} (MesenCore.so)"
          f" + {len(exe_slots)} (Mesen) = {len(all_slots)} total\n")

    # ═════════════════════════════════════════════════════════════════════════
    # Step 0: Walk the KNOWN NES RAM chain to harvest shared intermediates.
    #
    # For the frame counter, the Windows chain is reported as:
    #   MesenCore + 0x541b0  →  +0x00  → [3 more offsets]
    # The first two steps (RVA=0xc541b0, hop +0x00) are identical to NES RAM,
    # so p2 (the value produced after those two steps) is already known.
    # ═════════════════════════════════════════════════════════════════════════
    print("=== Walking known NES RAM chain ===")
    known_ivals  = []
    known_labels = []
    cur = r64(mem, mc_base + KNOWN_RVA)
    if cur and valid_ptr(cur):
        known_ivals.append(cur)
        known_labels.append(f"*(MesenCore.so+{KNOWN_RVA:#x})")
        for hi, hop in enumerate(KNOWN_HOPS):
            nxt = r64(mem, cur + hop)
            if not nxt or not valid_ptr(nxt):
                print(f"  WARNING: chain broke at hop {hi} (+{hop:#x})")
                break
            known_ivals.append(nxt)
            known_labels.append(f"*(prev +{hop:#x})")
            cur = nxt
    else:
        print("  WARNING: could not read first pointer in known chain")

    for val, lbl in zip(known_ivals, known_labels):
        marker = " ← p2 (shared root for frame counter)" if lbl == "*(prev +0x0)" else ""
        print(f"  {lbl} = {val:#x}{marker}")

    # p2 = intermediate value after RVA-deref + hop 0x00
    p2 = known_ivals[1] if len(known_ivals) > 1 else None
    print()

    # ═════════════════════════════════════════════════════════════════════════
    # Fast path A: original Windows NES RAM pattern (sanity check)
    # ═════════════════════════════════════════════════════════════════════════
    print("=== Fast path A: NES RAM pattern (+0, +0x40, +0x28) ===")
    found_a = False
    for addr, v1 in all_slots.items():
        v2 = r64(mem, v1)
        if not v2: continue
        v3 = r64(mem, v2 + 0x40)
        if not v3: continue
        v4 = r64(mem, v3 + 0x28)
        if v4 == target:
            print(f"  MATCH [{label(addr)}] -> {v1:#x} +0 -> {v2:#x}"
                  f" +0x40 -> {v3:#x} +0x28 -> target ✓")
            found_a = True
    if not found_a:
        print("  (no match)")

    # ═════════════════════════════════════════════════════════════════════════
    # Fast path B: 3-hop extension from p2
    #
    # The frame counter chain shares p2 with NES RAM, then diverges over
    # 3 more steps.  Two sub-cases are reported:
    #
    #  B1 — STRUCT FIELD (most likely for an integer field in a C++ object)
    #       *(*(p2+o1)+o2) gives struct_base,
    #       and struct_base + field_off = target  (target is inside the struct)
    #       → FC_HOPS = [0x00, o1, o2]   FC_FIELD_OFFSET = field_off
    #
    #  B2 — FULL POINTER CHAIN (if the value is a separately heap-allocated int)
    #       *(*(*(p2+o1)+o2)+o3) == target
    #       → FC_HOPS = [0x00, o1, o2, o3]   FC_FIELD_OFFSET = 0x00
    #
    # B1 is almost certainly correct for Mesen2's frameCount (uint64_t field
    # inside the PPU/console struct).
    # ═════════════════════════════════════════════════════════════════════════
    print("\n=== Fast path B: 3-hop extension from p2 ===")
    if p2 is None:
        print("  SKIPPED — could not walk known NES RAM chain far enough")
    else:
        print(f"  Starting from p2 = {p2:#x}")
        print(f"  Scanning o1 in [0x00..0x200), o2 in [0x00..0x100)…")
        found_b = False

        for o1 in range(0, 0x200, 8):
            p3_b = r64(mem, p2 + o1)
            if not p3_b or not valid_ptr(p3_b):
                continue
            for o2 in range(0, 0x100, 8):
                p4_b = r64(mem, p3_b + o2)
                if not p4_b or not valid_ptr(p4_b):
                    continue

                # ── B1: struct-field match ─────────────────────────────────
                # target lies within the first 0x400 bytes of p4_b
                if p4_b <= target <= p4_b + 0x400:
                    field_off = target - p4_b
                    if field_off % 4 == 0:   # must be at least u32-aligned
                        print(
                            f"\n  *** [B1 — STRUCT FIELD MATCH] ***\n"
                            f"    p2={p2:#x}\n"
                            f"      +{o1:#06x} → {p3_b:#x}\n"
                            f"      +{o2:#06x} → struct_base={p4_b:#x}\n"
                            f"    frame counter at struct_base + {field_off:#x} = {target:#x}\n"
                            f"\n"
                            f"    Copy into lib.rs:\n"
                            f"      const FC_RVA:          u64     = {KNOWN_RVA:#x};\n"
                            f"      const FC_HOPS:         [u64;3] = [0x00, {o1:#x}, {o2:#x}];\n"
                            f"      const FC_FIELD_OFFSET: u64     = {field_off:#x};\n"
                            f"      const FC_CHAIN_READY:  bool    = true;"
                        )
                        found_b = True

                # ── B2: full pointer-chain match ───────────────────────────
                for o3 in range(0, 0x80, 8):
                    v = r64(mem, p4_b + o3)
                    if v == target:
                        print(
                            f"\n  *** [B2 — PTR CHAIN MATCH] ***\n"
                            f"    p2={p2:#x}\n"
                            f"      +{o1:#06x} → {p3_b:#x}\n"
                            f"      +{o2:#06x} → {p4_b:#x}\n"
                            f"      +{o3:#06x} → target={target:#x} ✓\n"
                            f"\n"
                            f"    Copy into lib.rs:\n"
                            f"      const FC_RVA:          u64     = {KNOWN_RVA:#x};\n"
                            f"      const FC_HOPS:         [u64;4] = [0x00, {o1:#x}, {o2:#x}, {o3:#x}];\n"
                            f"      const FC_FIELD_OFFSET: u64     = 0x00;\n"
                            f"      const FC_CHAIN_READY:  bool    = true;"
                        )
                        found_b = True

        if not found_b:
            print("  (no match — falling through to general scans)")

    # ═════════════════════════════════════════════════════════════════════════
    # General 2-hop scan (exhaustive fallback)
    # ═════════════════════════════════════════════════════════════════════════
    print("\n=== General 2-hop scan ===")
    found_2 = False
    for addr, v1 in all_slots.items():
        for o1 in range(0, 0x200, 8):
            v2 = r64(mem, v1 + o1)
            if v2 == target:
                print(f"  [{label(addr)}] -> {v1:#x} +{o1:#x} -> target ✓")
                found_2 = True
    if not found_2:
        print("  (no match)")

    # ═════════════════════════════════════════════════════════════════════════
    # General 3-hop scan
    # ═════════════════════════════════════════════════════════════════════════
    print("\n=== General 3-hop scan ===")
    found_3 = False
    for addr, v1 in all_slots.items():
        for o1 in range(0, 0x100, 8):
            v2 = r64(mem, v1 + o1)
            if not v2: continue
            for o2 in range(0, 0x100, 8):
                v3 = r64(mem, v2 + o2)
                if v3 == target:
                    print(f"  [{label(addr)}] -> {v1:#x} +{o1:#x}"
                          f" -> {v2:#x} +{o2:#x} -> target ✓")
                    found_3 = True
    if not found_3:
        print("  (no match)")

    # ═════════════════════════════════════════════════════════════════════════
    # General 4-hop scan (slow — also covers struct-field in outer 3-hop chains)
    # ═════════════════════════════════════════════════════════════════════════
    print("\n=== General 4-hop scan (slow) ===")
    found_4 = False
    total = len(all_slots)
    for i, (addr, v1) in enumerate(all_slots.items()):
        if i % 500 == 0:
            print(f"  … {i}/{total} root slots checked …", flush=True)
        for o1 in range(0, 0x80, 8):
            v2 = r64(mem, v1 + o1)
            if not v2: continue
            for o2 in range(0, 0x80, 8):
                v3 = r64(mem, v2 + o2)
                if not v3: continue
                for o3 in range(0, 0x80, 8):
                    v4 = r64(mem, v3 + o3)
                    if v4 == target:
                        print(f"  [{label(addr)}] -> {v1:#x} +{o1:#x}"
                              f" -> {v2:#x} +{o2:#x} -> {v3:#x} +{o3:#x}"
                              f" -> target ✓")
                        found_4 = True
    if not found_4:
        print("  (no match)")

    # ═════════════════════════════════════════════════════════════════════════
    # General struct-field scan (3-hop chain ending near target)
    #
    # Same as 3-hop scan but accepts "target within first 0x400 bytes of
    # chain endpoint" instead of requiring an exact match.  Covers the case
    # where no pointer in the tree points *directly* to fc_addr, but a
    # pointer points to the struct that *contains* it.
    # ═════════════════════════════════════════════════════════════════════════
    print("\n=== General struct-field scan (3-hop chain, endpoint near target) ===")
    found_sf = False
    for addr, v1 in all_slots.items():
        for o1 in range(0, 0x100, 8):
            v2 = r64(mem, v1 + o1)
            if not v2 or not valid_ptr(v2): continue
            for o2 in range(0, 0x100, 8):
                v3 = r64(mem, v2 + o2)
                if not v3 or not valid_ptr(v3): continue
                if v3 <= target <= v3 + 0x400:
                    field_off = target - v3
                    if field_off % 4 == 0:
                        print(f"  [{label(addr)}] -> {v1:#x} +{o1:#x}"
                              f" -> {v2:#x} +{o2:#x}"
                              f" -> struct_base={v3:#x}  field_off={field_off:#x}")
                        found_sf = True
    if not found_sf:
        print("  (no match)")

    any_found = any([found_a, found_b, found_2, found_3, found_4, found_sf])
    if not any_found:
        print("\n*** Nothing found. ***")
        print("Possible reasons and fixes:")
        print("  1. Address went stale: re-scan for the frame counter immediately")
        print("     before running this script (the heap layout doesn't change")
        print("     as long as Mesen is open, but scanmem results can be wrong")
        print("     if you let time pass).")
        print("  2. The chain diverges before p2: on this Mesen build, the root")
        print("     RVA or first hop may differ.  Try running with the NES RAM")
        print("     address (subtract 0x75c from level_num addr) to confirm the")
        print("     known chain still resolves, then re-derive from scratch.")
        print("  3. Chain longer than 5 hops: uncomment and widen the 4-hop scan")
        print("     ranges, or add a 5-hop scan.")

print("\nDone.")
