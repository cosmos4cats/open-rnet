#!/usr/bin/env python3
"""
POP transfer reassembly post-processor.

The Wireshark dissector is per-frame and can't easily track cross-frame state.
This script walks a pcap (or candump log) and groups POP frames into complete
transfer episodes:

  * Setup frame   : POP std with bit-4 (CRCFlag) set, OR a Programmer-side
                    SET_ADDR (byte 0 = 0x83)
  * Data segments : POP-ext frames flowing toward one party (`(id >> 18) & 0xF`
                    = destination node)
  * Completion    : POP std with byte 0 = 0x8F (COMPLETE), carrying the
                    embedded CRC-16/CCITT-FALSE at bytes 4-5 LE

For each complete episode we report:
  - Direction (which slot is writing to which)
  - Setup register (PAGE0 / POINTER / TEXT / DATA / other)
  - Payload (concatenated POP-ext segment bytes)
  - CRC: computed locally and compared to the embedded value (✓/✗/—)
  - ASCII rendering when the register is TEXT

Usage:
  python3 reassemble_transfers.py <capture.pcapng-or-.log>          # default: all transfers
  python3 reassemble_transfers.py <capture> --crc-only              # show only CRC-protected
  python3 reassemble_transfers.py <capture> --reg TEXT              # filter by register
"""

import argparse, subprocess, re, sys
from collections import defaultdict
from pathlib import Path


def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


SLOT_NAMES = {0: "PM", 1: "JSM", 2: "IOM/ISM", 3: "BTM",
              4: "ILM", 5: "Slot5", 15: "Programmer"}
REG_NAMES = {0x80: "PAGE0", 0x81: "POINTER", 0x8C: "TEXT", 0x8F: "DATA"}


def slot(n): return SLOT_NAMES.get(n, f"Slot{n}")


# Load Permobil PWC param_id → name map from registry (the same data the
# dissector uses). Wire mapping: param_id = (sub << 8) | idx.
_PARAM_CACHE = None
def load_pwc_params():
    global _PARAM_CACHE
    if _PARAM_CACHE is not None: return _PARAM_CACHE
    import json
    _PARAM_CACHE = {}
    # Vendored snapshot lives next to this script. Keys are decimal strings.
    snap_path = Path(__file__).resolve().parent / "pwc_params.json"
    if not snap_path.exists():
        return _PARAM_CACHE
    with open(snap_path) as f:
        raw = json.load(f)
    for k, v in raw.items():
        try: _PARAM_CACHE[int(k)] = v
        except ValueError: pass
    return _PARAM_CACHE


def pull_frames(cap: str) -> list:
    """Return list of (frame_no, time, cid, is_extended, dlc, data_bytes)."""
    out = subprocess.run(
        ["tshark", "-r", cap, "-T", "fields",
         "-e", "frame.number", "-e", "frame.time_relative",
         "-e", "can.id", "-e", "can.flags.xtd", "-e", "can.len"],
        capture_output=True, text=True, check=True,
    )
    frames = []
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 5: continue
        try:
            fn = int(parts[0])
            t = float(parts[1]) if parts[1] else 0
            cid = int(parts[2])
            is_xtd = parts[3].lower() in ("1", "true")
            dlc = int(parts[4])
        except (ValueError, IndexError):
            continue
        frames.append([fn, t, cid, is_xtd, dlc, None])

    # Pull payloads in batch via -x. tshark emits the hex dump only (no
    # "Frame N:" header), separated by blank lines, in the same order as
    # the filter result — so we zip the blocks with the filtered fns.
    fns_needing_data = [f[0] for f in frames if f[4] > 0]
    if not fns_needing_data: return frames
    # Filter must return frames in numeric order (tshark default)
    filt = " or ".join(f"frame.number=={fn}" for fn in fns_needing_data)
    out2 = subprocess.run(["tshark", "-r", cap, "-Y", filt, "-x"],
                          capture_output=True, text=True, check=True)
    # Split into blocks separated by blank lines
    blocks = [b for b in out2.stdout.split("\n\n") if b.strip()]
    payloads = {}
    for fn, block in zip(fns_needing_data, blocks):
        # Concatenate all hex bytes from "0000  XX XX ..." rows
        all_bytes = []
        for line in block.splitlines():
            m = re.match(r"^[0-9a-f]{4}\s+(.+?)\s{2,}", line)
            if m:
                for tok in m.group(1).split():
                    if re.fullmatch(r"[0-9a-f]{2}", tok):
                        all_bytes.append(int(tok, 16))
        # SocketCAN: bytes 0-3 = ID, 4 = DLC, 5-7 = pad, 8+ = data
        if len(all_bytes) >= 9:
            dlc = all_bytes[4]
            payloads[fn] = bytes(all_bytes[8:8 + dlc])
    for f in frames:
        f[5] = payloads.get(f[0], b"")
    return frames


def classify(cid, is_xtd, data):
    """Return ("pop_std", b0, reg) | ("pop_ext", node, tc, seg) | ("other", ...)"""
    if not is_xtd and cid < 0x800 and (cid & 0x7E0) == 0x780:
        b0 = data[0] if data else 0
        reg = data[1] if len(data) > 1 else 0
        return ("pop_std", b0, reg)
    if is_xtd and ((cid >> 18) & 0x7E0) == 0x780:
        node = (cid >> 18) & 0xF
        tc = (cid >> 16) & 0x3
        seg = cid & 0xFFFF
        return ("pop_ext", node, tc, seg)
    return ("other", cid)


def reassemble(frames):
    """Walk frames and emit transfer episodes.

    A transfer = setup frame(s) + ext segments + COMPLETE. We track this
    loosely: every COMPLETE response defines a transfer that ends there,
    and we collect ext segments and last-seen setup state from the
    preceding window.
    """
    transfers = []
    open_setups = {}  # (this_node, other_node) → last setup frame
    ext_buffer = defaultdict(list)  # destination_node → [(seg, data, fn, t)]
    last_pointer = {}  # (this_node, other_node) → (param_id, name) of most-recent POINTER
    params = load_pwc_params()

    for fn, t, cid, is_xtd, dlc, data in frames:
        c = classify(cid, is_xtd, data)
        if c[0] == "pop_std" and data:
            _, b0, reg = c
            this_node = cid & 0xF
            other = b0 & 0xF
            # POINTER (reg=0x81) — track the most-recent NON-ZERO param being
            # addressed. param_id=0 is the "no param" sentinel emitted by
            # idle POINTER frames; recording it would shadow real values.
            if reg == 0x81 and len(data) >= 7:
                p_idx = data[4]
                p_sub = data[6]
                pid = (p_sub << 8) | p_idx
                if pid > 3:  # exclude WriteLive/WriteDraft/Wide/TRY_HARDER meta-IDs
                    pname = params.get(pid)
                    last_pointer[(this_node, other)] = (pid, pname, fn)
                    last_pointer[(other, this_node)] = (pid, pname, fn)
            # COMPLETE — close out a transfer
            if b0 == 0x8F:
                segs = sorted(ext_buffer.get(this_node, []), key=lambda x: x[0])
                payload = b"".join(s[1] for s in segs)
                embedded_crc = (data[4] | (data[5] << 8)) if len(data) >= 6 else None
                computed = crc16_ccitt_false(payload) if payload else None
                # Use POINTER only if it was set within 30 frames of this COMPLETE
                # (otherwise it's stale state from an earlier transfer).
                ptr = None
                for key in [(this_node, other), (other, this_node)]:
                    v = last_pointer.get(key)
                    if v and fn - v[2] <= 30:
                        ptr = v
                        break
                transfers.append({
                    "completes_at_fn": fn,
                    "time": t,
                    "from": this_node,
                    "to": other,
                    "register": REG_NAMES.get(reg, f"0x{reg:02X}"),
                    "register_byte": reg,
                    "payload_bytes": payload,
                    "n_segments": len(segs),
                    "first_seg_fn": segs[0][2] if segs else None,
                    "embedded_crc": embedded_crc,
                    "computed_crc": computed,
                    "crc_match": (embedded_crc == computed) if (computed is not None and embedded_crc is not None) else None,
                    "setup_fn": (open_setups.get((other, this_node)) or [None])[0] if (other, this_node) in open_setups else None,
                    "param_id": ptr[0] if ptr else None,
                    "param_name": ptr[1] if ptr else None,
                })
                # Clear the buffer for this destination
                ext_buffer[this_node] = []
                # Clear pointer state — the next transfer should set its own
                last_pointer.pop((this_node, other), None)
                last_pointer.pop((other, this_node), None)
            else:
                # Setup-side: record the latest "I'm starting an exchange" state
                open_setups[(this_node, other)] = (fn, t, b0, reg)
        elif c[0] == "pop_ext":
            _, node, tc, seg = c
            if data:  # only non-empty data segments contribute payload
                ext_buffer[node].append((seg, data, fn, t))
    return transfers


def fmt_transfer(tx, show_ascii=True):
    """Format one transfer episode as a multi-line block."""
    lines = []
    direction = f"{slot(tx['from'])} → {slot(tx['to'])}"
    n_bytes = len(tx['payload_bytes'])
    pname = tx.get('param_name')
    pinfo = ""
    if pname:
        pinfo = f"  [param={pname} ({tx['param_id']})]"
    elif tx.get('param_id'):
        pinfo = f"  [param_id={tx['param_id']} (not in registry)]"
    lines.append(
        f"[fn {tx['completes_at_fn']:5d}  t={tx['time']:7.3f}s]  "
        f"{direction}  reg={tx['register']}  "
        f"{n_bytes} bytes in {tx['n_segments']} segs{pinfo}"
    )
    if tx['embedded_crc'] is not None:
        mark = "✓" if tx['crc_match'] else ("✗" if tx['crc_match'] is False else "—")
        lines.append(
            f"    CRC: embedded=0x{tx['embedded_crc']:04X}  "
            f"computed={'0x%04X' % tx['computed_crc'] if tx['computed_crc'] is not None else 'n/a'}  {mark}"
        )
    if tx['payload_bytes']:
        hex_str = " ".join(f"{b:02X}" for b in tx['payload_bytes'][:32])
        if n_bytes > 32: hex_str += " …"
        lines.append(f"    bytes: {hex_str}")
        if show_ascii and tx['register'] == 'TEXT':
            ascii_str = "".join(chr(b) if 0x20 <= b < 0x7F else "·" for b in tx['payload_bytes'])
            lines.append(f"    ascii: \"{ascii_str}\"")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("--crc-only", action="store_true",
                    help="Show only transfers with embedded CRC")
    ap.add_argument("--reg", help="Filter to a specific register (TEXT/PAGE0/POINTER/DATA)")
    ap.add_argument("--min-bytes", type=int, default=0,
                    help="Skip transfers with payload smaller than N bytes")
    args = ap.parse_args()

    frames = pull_frames(args.capture)
    transfers = reassemble(frames)

    # Filters
    if args.crc_only:
        transfers = [t for t in transfers if t['embedded_crc'] is not None]
    if args.reg:
        transfers = [t for t in transfers if t['register'] == args.reg]
    if args.min_bytes:
        transfers = [t for t in transfers if len(t['payload_bytes']) >= args.min_bytes]

    print(f"# {Path(args.capture).name}: {len(transfers)} transfers")
    print()
    for tx in transfers:
        print(fmt_transfer(tx))
        print()

    # Summary
    n_crc = sum(1 for t in transfers if t['embedded_crc'] is not None)
    n_match = sum(1 for t in transfers if t.get('crc_match'))
    by_reg = defaultdict(int)
    for t in transfers:
        by_reg[t['register']] += 1
    print(f"# Summary: {len(transfers)} transfers, {n_crc} with embedded CRC, {n_match} CRC-verified")
    print(f"# By register: {dict(by_reg)}")


if __name__ == "__main__":
    main()
