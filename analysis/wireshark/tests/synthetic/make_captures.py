"""Tiny pcap writer for hand-crafted SocketCAN frames.

Generates a single pcap file per call with the requested set of CAN
frames. Used by test_edge_cases.py to exercise the dissector against
edge cases the real-capture corpus doesn't reach.

No dependencies — bundles a small writer for the LINKTYPE_CAN_SOCKETCAN
(linktype 227) pcap format. Compatible with Wireshark/tshark.

Format references:
- pcap classic: https://www.tcpdump.org/manpages/pcap-savefile.5.txt
- LINKTYPE_CAN_SOCKETCAN: tcpdump.org/linktypes/LINKTYPE_CAN_SOCKETCAN.html
"""

import struct
from pathlib import Path

PCAP_MAGIC      = 0xA1B2C3D4
PCAP_VERS_MAJOR = 2
PCAP_VERS_MINOR = 4
LINKTYPE_CAN_SOCKETCAN = 227

# Per-frame SocketCAN flags packed into the top bits of the 32-bit CAN ID
CAN_EFF_FLAG = 0x80000000  # extended ID
CAN_RTR_FLAG = 0x40000000  # remote transmission request
CAN_ERR_FLAG = 0x20000000


def _pcap_global_header():
    return struct.pack(
        "<IHHiIII",
        PCAP_MAGIC, PCAP_VERS_MAJOR, PCAP_VERS_MINOR,
        0,        # thiszone
        0,        # sigfigs
        65535,    # snaplen
        LINKTYPE_CAN_SOCKETCAN,
    )


def _socketcan_frame(can_id: int, data: bytes, *, extended=False, rtr=False):
    if extended:
        can_id |= CAN_EFF_FLAG
    if rtr:
        can_id |= CAN_RTR_FLAG
    # SocketCAN pseudo-header is the CAN ID (BE 32-bit), DLC, 3 padding bytes
    # NOTE: Wireshark expects CAN ID in NETWORK byte order (big-endian).
    hdr = struct.pack(">I", can_id) + struct.pack(">B3x", len(data))
    payload = hdr + data
    # SocketCAN frame is always 16 bytes wire; pad if needed
    if len(payload) < 16:
        payload += b"\x00" * (16 - len(payload))
    return payload


def _pcap_record(ts_sec: int, ts_usec: int, frame_bytes: bytes):
    return struct.pack(
        "<IIII",
        ts_sec, ts_usec, len(frame_bytes), len(frame_bytes),
    ) + frame_bytes


def write_pcap(path, frames):
    """Write a pcap file at `path` containing the given frames.

    frames: list of dicts:
      {"id": int, "data": bytes, "extended": bool=False, "rtr": bool=False,
       "ts_sec": int=0, "ts_usec": int=N}
    """
    out = _pcap_global_header()
    for i, f in enumerate(frames):
        sc = _socketcan_frame(
            f["id"], f.get("data", b""),
            extended=f.get("extended", False),
            rtr=f.get("rtr", False),
        )
        out += _pcap_record(
            f.get("ts_sec", 0),
            f.get("ts_usec", i * 1000),  # 1 ms apart by default
            sc,
        )
    Path(path).write_bytes(out)


# --- Edge-case frame catalog ----------------------------------------------
# Each entry: {label: list-of-frames}. Test code asserts the dissector
# handles each without crashing AND produces a sensible class label.

# --- HIGH-VALUE-FRAME CLARITY FIXTURES ---------------------------------
# These are NOT edge cases — they're CANONICAL examples of frames where
# the per-frame decoded output really matters for a researcher reading
# a capture. Each one has a paired clarity test (test_clarity_*) that
# asserts on the EXACT output text, so any future change that degrades
# the user-facing semantics gets caught immediately.
#
# Scope criterion: a frame is "high-value" if a researcher seeing it
# in their capture needs to immediately understand (a) what it is at
# the protocol level, (b) what it implies operationally, (c) where
# the evidence comes from. Includes security-relevant frames (Unlock,
# auth), session-state transitions (handshake, transfer complete),
# and cross-frame protocols (POINTER→DATA binding).

HIGH_VALUE_FRAMES = {
    # 1. R-Net Unlock — service-mode credential. THE single highest-
    #    value frame to decode clearly: the CAN ID itself IS the
    #    credential; chair gates destructive operations on receipt.
    "hv_rnet_unlock": [
        {"id": 0x08280F02, "data": b"", "extended": True},
    ],
    # 2. SlotChanged signal with a representative filekey from corpus.
    "hv_slotchanged": [
        {"id": 0x15000000, "data": bytes.fromhex("01 00 01 00"),
         "extended": True},
    ],
    # 3. Attach handshake step 1 (chair-side: Programmer announce).
    #    First frame of the CXTN_CAN → CXTN_RNET transition.
    "hv_attach_step1": [
        {"id": 0x1E840000, "data": b"", "extended": True},
    ],
    # 4. Transfer Complete sentinel addressed to slot 15 (Programmer).
    #    Marks return from CXTN_UPLOAD/DOWNLOAD to CXTN_RNET.
    "hv_transfer_complete": [
        {"id": 0x1E80000F, "data": b"", "extended": True},
    ],
    # 5. Auth response matching the known M300 xor_table B network.
    #    Verifies the network-identification path surfaces "✓ Table B"
    #    clearly. Per parse's xor_tables B entry: keys[0]=0xD3,
    #    serial[0]=0x50. The CAN ID encoding is
    #    0x1F<seq:4><slot:4><key:8><value:8>:
    #      seq=0, slot=0, key=0xD3, value=0x50 → 0x1F00D350.
    "hv_auth_response_table_b": [
        {"id": 0x1F00D350, "data": b"", "extended": True},
    ],
    # 6. Programmer-active keep-awake heartbeat — primary-source
    #    evidenced (ResetSleepTimer @ 0x100053e0). Verifies the
    #    "Programmer-active" framing is clear.
    "hv_keep_awake": [
        {"id": 0x1C240F01, "data": b"", "extended": True},
    ],
    # 7. RTC broadcast with a fully-populated wall clock. Bit-packed
    #    fields decoded per DecodeRTCBroadcast @ 0x1000f8e0.
    #    Payload: 2026-05-24 14:30:45 (Sunday).
    #    sec=45 (0x2D), min=30 (0x1E), hour=14 (0x0E),
    #    day=24 (0x18), dow=7 (Sun, 0xE0 in high 3 bits of byte 3
    #    = 7<<5 = 0xE0; OR with day = 0xE0|0x18 = 0xF8),
    #    month=5 (0x05), year=26 (0x1A).
    "hv_rtc_broadcast": [
        {"id": 0x1C2C0D00,
         "data": bytes([0x2D, 0x1E, 0x0E, 0xF8, 0x05, 0x1A]),
         "extended": True},
    ],
}

EDGE_CASES = {
    # POP std frame with DLC=0 (truncated payload). Real captures have
    # DLC=8 for POP — what does the dissector do with nothing?
    "pop_std_empty": [
        {"id": 0x780, "data": b""},
    ],
    # POP std frame with DLC=8 but byte 0 unknown (not in legacy opcode
    # map). Tests that decode_pop_std doesn't choke on unfamiliar values.
    "pop_std_unknown_b0": [
        # b0 = 0x77 → TC=1 Quick=1 CRC=1 OtherNode=7 — unusual combination
        {"id": 0x780, "data": bytes.fromhex("77 81 00 00 00 00 00 00")},
    ],
    # CAN ID just outside the POP-ext namespace (0x1E7FFFFF is inside,
    # 0x1E800000 is outside per the (id>>18)&0x7E0 == 0x780 test).
    "pop_ext_boundary": [
        {"id": 0x1E7FFFFF, "data": bytes.fromhex("00 11 22 33 44 55 66 77"),
         "extended": True},
        # Just outside (sentinel namespace, handled elsewhere)
        {"id": 0x1E800001, "data": b"", "extended": True},
    ],
    # Auth challenge frame (0x1F prefix). Real captures only show seq 0-7;
    # synthesize one with seq = 0xF to test out-of-range handling.
    "auth_seq_overflow": [
        # CAN ID = 0x1FFF0000 → seq=F (overflow), slot=F, key=0x00, val=0x00
        {"id": 0x1FFF0000, "data": b"", "extended": True, "rtr": True},
    ],
    # RTC frame with all-zero payload (chair power-on case).
    "rtc_zero": [
        {"id": 0x1C2C0100, "data": bytes(6), "extended": True},
    ],
    # Mode-config frame (0x1EC prefix) with type=0xFF.
    "mode_config_unknown_type": [
        {"id": 0x1EC00000,
         # 8 bytes: pfx_0 pfx_1 BE-addr value... type 0xFF in last byte
         "data": bytes.fromhex("00 00 02 80 00 40 02 FF"),
         "extended": True},
    ],
    # POP COMPLETE with target nibble != F (Programmer).
    "transfer_complete_non_programmer": [
        {"id": 0x1E800001, "data": b"", "extended": True},
    ],
    # 0x1E8X sentinel with subtype N=1 (currently unobserved on wire).
    "sentinel_subtype_1": [
        {"id": 0x1E810000, "data": b"", "extended": True},
    ],
    "sentinel_subtype_2": [
        {"id": 0x1E820000, "data": b"", "extended": True},
    ],
    "sentinel_subtype_3": [
        {"id": 0x1E830000, "data": b"", "extended": True},
    ],
    # R-Net Unlock frame (per RNET_AUTH_PROTOCOL.md, the literal "service
    # mode enable" credential — CAN-ID 0x08280F02, DLC=0). Doesn't appear
    # in any open-rnet capture but the dissector should still recognize
    # it if it shows up in a future capture from a Programmer-attached
    # session that includes the unlock moment.
    "rnet_unlock_frame": [
        {"id": 0x08280F02, "data": b"", "extended": True},
    ],
    # BT-pairing-unlock two-frame protocol. Per
    # rnet-firmware BTMOUSE_UNLOCK_FRAMES_FOR_PARSE.md, the chair-side
    # handler at 0xF50E fires when Pattern A (extended frame, low 16
    # bits of ID == 0x7E57) is followed by Pattern B (standard frame,
    # low byte of ID == 0xA7, DLC=8, DSR1-DSR7 zero) within ~1s and
    # the runtime flag at 0xFF4C4 is set.
    #
    # Pattern A alone:
    "bt_unlock_pattern_a": [
        # Extended frame, low 16 bits of ID == 0x7E57.
        {"id": 0x00007E57, "data": b"\x11\x22\x33\x44",
         "extended": True},
    ],
    # Pattern B alone (canonical: low byte 0xA7, DLC=8, DSR1-DSR7 zero,
    # DSR0 arbitrary):
    "bt_unlock_pattern_b_canonical": [
        {"id": 0x4A7, "data": b"\x99" + b"\x00" * 7},
    ],
    # Pattern B with non-zero data byte 3 (DSR3) — should NOT fire
    # the Pattern B marker because DSR1-DSR7 are not all zero.
    "bt_unlock_pattern_b_nonzero_data": [
        {"id": 0x4A7, "data": b"\x00\x00\x00\x55\x00\x00\x00\x00"},
    ],
    # Full unlock sequence: Pattern A immediately followed by
    # Pattern B within the correlation window. The synthetic pcap
    # writer places frames 1 ms apart by default, so the two frames
    # are <1s apart and the sequence marker should fire on the
    # Pattern B frame.
    "bt_unlock_full_sequence": [
        {"id": 0x00007E57, "data": b"", "extended": True},
        {"id": 0x4A7, "data": b"\x00" * 8},
    ],
    # Normal 0x07A0 — Programmer presence (DLC=0). Used as a
    # regression check that the wrong-CAN-ID magic-marker that
    # previously fired on this frame has been reverted.
    "programmer_presence_normal": [
        {"id": 0x7A0, "data": b""},
    ],
    # Dormant chair-listened STD IDs. Each appears in BTMouse's literal
    # CAN-ID table at FW 0x56E0-0x571B but has 0 corpus observations.
    # Synthesize one to verify the dissector fires the dormant marker.
    "dormant_chair_listened_001": [
        {"id": 0x001, "data": b""},
    ],
}


def write_all(out_dir):
    """Write one pcap per EDGE_CASES + HIGH_VALUE_FRAMES entry into
    out_dir; return mapping {label: path}."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {}
    for catalog in (EDGE_CASES, HIGH_VALUE_FRAMES):
        for label, frames in catalog.items():
            p = out_dir / f"{label}.pcap"
            write_pcap(p, frames)
            result[label] = p
    return result


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/rnet-edge-pcaps"
    paths = write_all(out)
    for label, p in paths.items():
        print(f"{label:35s} {p}")
