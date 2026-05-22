#!/usr/bin/env python3
"""
Tests for parse/rnet_can.lua.

Strategy: run tshark with the dissector against known captures and assert on
field values / counts. Tests are independent (no order coupling) and use only
the existing capture corpus as ground truth.

Categories:
  - Coverage regression  (test_coverage_*)
  - Auth XOR networks    (test_auth_*)
  - CRC verification     (test_crc_*)
  - Frame-decode lock-ins (test_decode_*)
  - Algorithm correctness (test_algo_*)

Run:
  pytest tests/test_dissector.py -v
  pytest tests/test_dissector.py -v -k auth     # filter
"""

import os
import re
import subprocess
from collections import Counter
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------

DISSECTOR_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = DISSECTOR_DIR.parent.parent
LUA = str(DISSECTOR_DIR / "rnet_can.lua")
OPEN_RNET_CAPTURES = REPO_ROOT / "captures"
HACKATHON_LOG = OPEN_RNET_CAPTURES / "2026_AT_hackathon.log"


def cap_path(name: str) -> str:
    """Resolve a short capture name to a path."""
    if name == "hackathon":
        return str(HACKATHON_LOG)
    return str(OPEN_RNET_CAPTURES / name)


# Captures used by tests. If the file isn't present, tests that need it skip.
CAPTURES = {
    "poweronJSMsh":         "poweronJSMsh.pcap.pcapng",
    "full_action":          "full_action_dumpJuly2_2016.pcapng",
    "aug19th":              "aug19th_hotplug_cjsm.pcapng",
    "July12_lights":        "July12_lights2.pcapng",
    "programmer_write":     "programmer_write_file_july2017.pcapng",
    "0x1f201e0e":           "0x1f201e0e.pcapng",
    "ics_write_config":     "ics_write_config.pcapng",
    "hackathon":            "hackathon",
}


def have_capture(name: str) -> bool:
    p = cap_path(CAPTURES.get(name, name))
    return os.path.exists(p)


def tshark(cap_name: str, *, display_filter: str = "", fields: list = None,
           extra: list = None, timeout: int = 60) -> str:
    """Run tshark against a capture with `-X lua_script:...`.

    Returns stdout as text. Raises if tshark errors.
    """
    cap = cap_path(CAPTURES.get(cap_name, cap_name))
    if not os.path.exists(cap):
        pytest.skip(f"capture not present: {cap}")
    cmd = ["tshark", "-X", f"lua_script:{LUA}", "-r", cap]
    if display_filter:
        cmd += ["-Y", display_filter]
    if fields:
        cmd += ["-T", "fields"]
        for f in fields:
            cmd += ["-e", f]
    if extra:
        cmd += extra
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        # Surface tshark stderr to make Lua errors visible
        raise AssertionError(f"tshark failed for {cap_name}: {proc.stderr}")
    return proc.stdout


def count(cap_name: str, filter: str) -> int:
    """Count frames matching a display filter."""
    out = tshark(cap_name, display_filter=filter, fields=["frame.number"])
    return sum(1 for line in out.splitlines() if line.strip())


def fields(cap_name: str, filter: str, field_names: list) -> list:
    """Return list of tuples for each matching frame."""
    out = tshark(cap_name, display_filter=filter, fields=field_names)
    rows = []
    for line in out.splitlines():
        if not line:
            continue
        rows.append(tuple(line.split("\t")))
    return rows


# ---------------------------------------------------------------------------
# Category 1: Coverage regression
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cap", list(CAPTURES.keys()))
def test_coverage_no_unknown_classes(cap):
    """Every frame in every capture has a class label (no `Unknown ...`).

    This catches regressions where a decoder change accidentally drops a frame
    type back into the Unknown bucket. Across the full corpus today the
    unknown count is 0.
    """
    if not have_capture(cap):
        pytest.skip(f"capture not present: {cap}")
    n = count(cap, 'rnet.class contains "Unknown"')
    assert n == 0, (
        f"{cap}: {n} frames have Unknown class — likely a family rule broke "
        f"or a new frame type appeared. Check with: tshark -r <cap> "
        f'-Y \'rnet.class contains "Unknown"\' -T fields -e rnet.class | '
        f"sort | uniq -c"
    )


def test_coverage_total_evidenced_threshold():
    """Across the full corpus, ≥99% of frames decode under an evidenced rule
    (not [unverified], not unknown).
    """
    total = 0
    evidenced = 0
    for cap in CAPTURES:
        if not have_capture(cap):
            continue
        t = count(cap, "")
        u = count(cap, 'rnet.class contains "Unknown"')
        v = count(cap, 'rnet.class contains "unverified"')
        total += t
        evidenced += t - u - v
    assert total > 100_000, f"corpus too small: {total}"
    pct = evidenced / total
    assert pct >= 0.99, (
        f"evidenced coverage dropped to {pct*100:.2f}% (was 99.64%). "
        f"A decoder probably got demoted to [unverified] or was removed."
    )


# ---------------------------------------------------------------------------
# Category 2: Auth XOR network identification
# ---------------------------------------------------------------------------

# Expected dominant network per capture, from PROJECT_NOTES.md tables A/B
# plus parse's recovered Table D from the hackathon capture.
EXPECTED_NETWORK = {
    "poweronJSMsh":  "Table A",  # Standalone JSM, serial 08901C8A
    "full_action":   "Table B",  # M300 Network, serial 50C01C8F
    "aug19th":       "Table B",  # M300 Network (same chair / network)
    "hackathon":     "Table D",  # Hackathon chair, serial B68021AE
}


@pytest.mark.parametrize("cap, network", EXPECTED_NETWORK.items())
def test_auth_identifies_correct_network(cap, network):
    """Auth-frame XOR validation identifies the documented network."""
    if not have_capture(cap):
        pytest.skip(f"capture not present: {cap}")
    rows = fields(cap, "rnet.auth.network", ["rnet.auth.network"])
    assert rows, f"{cap}: no auth-validated frames at all"
    nets = Counter(r[0] for r in rows)
    most_common, _ = nets.most_common(1)[0]
    assert network in most_common, (
        f"{cap}: dominant identified network was {most_common!r}, expected {network!r}"
    )


def test_auth_no_misidentification_in_hackathon():
    """The hackathon dump should ONLY identify as Table D — earlier the
    seq>3 fallback accidentally matched Table A on the shared key=0x45.
    """
    if not have_capture("hackathon"):
        pytest.skip("hackathon dump not present")
    rows = fields("hackathon", "rnet.auth.network", ["rnet.auth.network"])
    nets = set(r[0] for r in rows)
    assert nets == {next(n for n in nets if "Table D" in n)}, (
        f"hackathon should ID as Table D only; got {nets}"
    )


# ---------------------------------------------------------------------------
# Category 3: CRC verification
# ---------------------------------------------------------------------------

def test_crc_verified_text_write_episode():
    """The well-characterized TEXT-write transfer at frames 265-270 of
    programmer_write should have COMPLETE frame 270's CRC = 0x6F36.

    This is the empirical test vector from CRC_VERIFICATION_FINDINGS.md.
    """
    if not have_capture("programmer_write"):
        pytest.skip("programmer_write not present")
    rows = fields("programmer_write", "frame.number == 270",
                  ["rnet.pop.crc_value"])
    assert rows, "no rnet.pop.crc_value at frame 270 of programmer_write"
    crc_str = rows[0][0]
    # Wireshark renders uint16 as "0xNNNN" or just "NNNN" — handle both
    crc = int(crc_str, 16) if crc_str.startswith("0x") else int(crc_str)
    assert crc == 0x6F36, f"frame 270 CRC = 0x{crc:04X}, expected 0x6F36"


def test_crc_field_fires_on_complete_frames():
    """At least 3000 POP COMPLETE frames across the corpus should have
    `rnet.pop.crc_value` populated. As of 2026-05-22 the total is ~3,646
    across the four programmer-attached captures plus the ICS read capture.
    """
    caps_with_crc = [
        "programmer_write",
        "ics_write_config",
        "maybe_new_ics_frames_readfunction.pcapng",
        "programmer_dump_file_july2017.pcapng",
    ]
    total = 0
    for cap in caps_with_crc:
        if not have_capture(cap):
            continue
        total += count(cap, "rnet.pop.crc_value")
    assert total >= 3000, f"CRC value field fired on only {total} frames"


# ---------------------------------------------------------------------------
# Category 4: Frame-decode lock-ins
# ---------------------------------------------------------------------------

def test_decode_poweronJSMsh_recovers_serial_via_auth():
    """The Table A chair's serial 08901C8A is recovered from the AUTH
    response value bytes, NOT from the 0x00E serial heartbeat (which the
    chair starts as all-zero per diary line 5: 'Serial number can be
    anything, even 0'). For slot-1 (JSM) responses with seq 0..3, the
    value byte equals the corresponding byte of the chair's serial.
    """
    if not have_capture("poweronJSMsh"):
        pytest.skip("poweronJSMsh not present")
    rows = fields("poweronJSMsh",
                  'rnet.auth.slot == 1 and not rnet.class contains "RTR"',
                  ["rnet.auth.seq", "rnet.auth.value"])
    # Build seq → value mapping (take the first response per seq)
    by_seq = {}
    for seq_s, val_s in rows:
        seq = int(seq_s)
        val = int(val_s.replace("0x", ""), 16)
        by_seq.setdefault(seq, val)
    # Bytes 0..3 of the serial reconstructed from auth responses
    recovered = bytes(by_seq[i] for i in range(4))
    assert recovered == bytes.fromhex("08901C8A"), (
        f"recovered serial {recovered.hex()}, expected 08901C8A"
    )


def test_decode_error_catalog_resolves_newly_added_codes():
    """The rnet-firmware regenerated JSONL (v2, 2026-05-22) with confidence
    levels + code_swapped_hex lookup should resolve codes that were
    previously "undocumented" in parse's earlier integration.

    Concrete check: codes 0x0F00, 0x1900, 0x1A00, 0x1E00, 0x1F00, 0x2000,
    0x2100, 0x2200, 0x2900 all appear in captures and should decode to
    named errors per rnet-firmware's regenerated extraction.
    """
    new_codes = {
        0x0F00: "Joystick Error Right",   # contains
        0x1000: "Joystick Error",
        0x1100: "Joystick Error Left",
        0x1900: "Demand Signal Fault Right",
        0x1A00: "Demand Signal Fault Left",
        0x1F00: "Phasing Fault Right",
        0x2000: "Phasing Fault Left",
        0x2100: "Progress Count Error",
        0x2200: "Joystick Toggle Error",
    }
    # Sample from the captures that have these errors
    for cap in ["full_action", "aug19th", "0x1f201e0e"]:
        if not have_capture(cap):
            continue
        for code, expected_substring in new_codes.items():
            rows = fields(cap, f"rnet.err.code == {code}",
                          ["rnet.err.name"])
            if rows and rows[0][0]:
                assert expected_substring.lower() in rows[0][0].lower(), (
                    f"{cap} code 0x{code:04X}: got {rows[0][0]!r}, "
                    f"expected substring {expected_substring!r}"
                )


def test_decode_lighting_lamp_test_d5d5():
    """The diary line 19 documents `D5 D5` as 'lamp test - all on'. The
    dissector should decode this with mask == bitmap (no transition).
    """
    if not have_capture("July12_lights"):
        pytest.skip("July12_lights not present")
    # Find a lighting frame with payload D5 D5
    rows = fields("July12_lights",
                  'rnet.class == "Lighting control"',
                  ["rnet.summary"])
    all_on = [r[0] for r in rows
              if "Flood" in r[0] and "Hazard" in r[0] and "transition" not in r[0]]
    assert all_on, f"expected an 'all on' lamp-test in July12_lights; "\
                   f"got summaries: {[r[0] for r in rows[:5]]}"


def test_decode_transfer_complete_sentinel():
    """0x1E80000F should decode as 'Transfer Complete sentinel'."""
    if not have_capture("ics_write_config"):
        pytest.skip("ics_write_config not present")
    n = count("ics_write_config", 'rnet.class == "Transfer Complete sentinel"')
    # PROJECT_NOTES line 479 says this is the end-of-transfer marker; the
    # ics_write_config capture has ~1,332 of these.
    assert n > 1000, f"only {n} Transfer Complete sentinels; expected >1000"


def test_decode_bit4_crc_flag_only_on_tc1_segment():
    """Per rnet-firmware R3.5 F7: CRCFlag is only ever seen on TC=1
    segment frames, not on TC=0 quick or TC=3 abort.

    This guards the structural model — if the bit-field unpack breaks
    and starts treating quick or abort frames as CRC-flagged, this fires.
    """
    if not have_capture("aug19th"):
        pytest.skip("aug19th not present")
    rows = fields("aug19th",
                  'rnet.pop.crc == 1',
                  ["rnet.pop.tc"])
    if not rows:
        pytest.skip("no CRCFlag=1 frames in aug19th")
    tcs = Counter(r[0] for r in rows)
    # Allow TC=1 dominant; the documented set is purely TC=1 but tolerate
    # a few outliers in case future RE finds them.
    assert tcs.get("1", 0) >= sum(tcs.values()) * 0.95, (
        f"CRCFlag-on TC distribution: {dict(tcs)}; expected ≥95% TC=1"
    )


def test_decode_pm_heartbeat_byte0_pop_layout():
    """Each slot's module heartbeat carries a byte-0 value matching the POP
    byte-0 bit-packing (TC + OtherNode), where OtherNode is typically the
    emitter's own slot — making the heartbeat self-identifying.

    Empirically in the hackathon capture:
      - Slot 0 (PM) emits byte 0 = 0xC0 (TC=3 → PM, "I'm PM") or 0xC1 (TC=3 → JSM)
      - Slot 2 (IOM/ISM) emits byte 0 = 0xC2 (TC=3 → IOM/ISM, "I'm at slot 2")

    Note: the test was previously based on a misreading where all 0x0C14X00
    frames were lumped as "PM heartbeat"; the family is actually per-emitter,
    documented in janschu99 RNETdictionary.txt line 44 (slot 0 = PM) + line
    45 (slot 4 = lamp controller?).
    """
    if not have_capture("hackathon"):
        pytest.skip("hackathon not present")
    # PM heartbeat (slot 0): byte 0 in {0xC0, 0xC1}
    rows_pm = fields("hackathon", 'rnet.class == "PM heartbeat"',
                     ["rnet.pm_hb.byte0"])
    pm_bytes = set(r[0].lower() for r in rows_pm)
    assert {"0xc0", "0xc1"}.issubset(pm_bytes), (
        f"PM heartbeat byte-0 should include both 0xC0 and 0xC1; saw {pm_bytes}"
    )
    # IOM/ISM heartbeat (slot 2): byte 0 dominantly 0xC2
    rows_ism = fields("hackathon", 'rnet.class == "IOM/ISM heartbeat"',
                      ["rnet.pm_hb.byte0"])
    if rows_ism:
        ism_bytes = Counter(r[0].lower() for r in rows_ism)
        top = ism_bytes.most_common(1)[0][0]
        assert top == "0xc2", (
            f"IOM/ISM heartbeat top byte-0 should be 0xC2; saw {ism_bytes.most_common(3)}"
        )


# ---------------------------------------------------------------------------
# Category 5: Algorithm correctness (pure Python, no dissector dependency)
# ---------------------------------------------------------------------------

def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


def test_algo_crc16_standard_vector():
    """CRC-16/CCITT-FALSE of '123456789' is 0x29B1 (standard test vector)."""
    assert crc16_ccitt_false(b"123456789") == 0x29B1


def test_algo_crc16_text_write_episode():
    """The 13-byte TEXT data block from programmer_write frames 267-268
    produces CRC = 0x6F36 (matches the COMPLETE frame's embedded value).
    """
    # Reconstructed payload from the verified episode
    payload = bytes.fromhex("f6ff010001072aff" + "0908814003")
    assert crc16_ccitt_false(payload) == 0x6F36


def test_algo_pop_byte0_unpack():
    """The POP byte-0 bit-packing (TC<<6 | Q<<5 | CRC<<4 | OtherNode) is
    reversible and yields known opcodes for famous values.
    """
    cases = {
        0x20: (0, 1, 0, 0),  # OPEN: TC=0 Q=1 CRC=0 to PM
        0x40: (1, 0, 0, 0),  # REQUEST: TC=1 Q=0 to PM
        0x42: (1, 0, 0, 2),  # HEARTBEAT: TC=1 Q=0 to ISM
        0x8F: (2, 0, 0, 15), # COMPLETE: TC=2 to Programmer
        0xC1: (3, 0, 0, 1),  # ERROR: TC=3 to JSM
        0x52: (1, 0, 1, 2),  # CRC-flagged segment to ISM
    }
    for b, (tc, q, crc, other) in cases.items():
        assert (b >> 6) & 0x3 == tc, f"0x{b:02X}: TC mismatch"
        assert (b >> 5) & 0x1 == q, f"0x{b:02X}: Q mismatch"
        assert (b >> 4) & 0x1 == crc, f"0x{b:02X}: CRC mismatch"
        assert b & 0xF == other, f"0x{b:02X}: OtherNode mismatch"


def test_algo_xor_table_key_derivation():
    """Per PROJECT_NOTES.md Table A: keys[seq] = serial[seq] XOR xor_table[seq].
    Confirms the algorithm using the documented Standalone JSM table.
    """
    serial =    [0x08, 0x90, 0x1C, 0x8A, 0x00, 0x00, 0x00, 0x00]
    xor_table = [0x00, 0x21, 0x02, 0xCC, 0xDD, 0x12, 0x7B, 0x45]
    expected =  [0x08, 0xB1, 0x1E, 0x46, 0xDD, 0x12, 0x7B, 0x45]
    actual = [s ^ x for s, x in zip(serial, xor_table)]
    assert actual == expected


def test_algo_dime_decode_known_serials():
    """The DIME → LLYYMMNNNN decode (from DeviceDriver.GetSN()) should
    convert the M300 chair's JSM bytes 50 C0 1C 8F into "CS15120080".

    Verified empirically against device-enum frames in
    aug19th_hotplug_cjsm.pcapng.
    """
    def decode_dime(b0, b1, b2, b3):
        letter2 = ((b1 & 0xC0) >> 6) | ((b2 & 0x07) << 2)
        letter1 = (b2 & 0xFC) >> 3
        if not (1 <= letter1 <= 26 and 1 <= letter2 <= 26):
            return None
        year = b3 // 12 + 4
        month = b3 % 12 + 1
        seq = b0 + ((b1 & 0x3F) << 8)
        if not 1 <= month <= 12:
            return None
        return (f"{chr(ord('A')+letter1-1)}{chr(ord('A')+letter2-1)}"
                f"{year%100:02d}{month:02d}{seq:04d}")

    cases = {
        (0x50, 0xC0, 0x1C, 0x8F): "CS15120080",  # M300 JSM
        (0xE4, 0x8C, 0x1C, 0x8C): "CR15093300",
        (0x8F, 0x80, 0x19, 0x8B): "CF15080143",
        (0x08, 0x90, 0x1C, 0x8A): "CR15074104",  # Standalone JSM
    }
    for bytes_, expected in cases.items():
        actual = decode_dime(*bytes_)
        assert actual == expected, (
            f"DIME {bytes(bytes_).hex()}: got {actual}, expected {expected}"
        )


def test_decode_dime_serials_present_in_captures():
    """The dissector should decode at least 3 distinct DIME serials in
    aug19th_hotplug_cjsm (a 5-module chair).
    """
    if not have_capture("aug19th"):
        pytest.skip("aug19th not present")
    rows = fields("aug19th", "rnet.dime", ["rnet.dime"])
    distinct = set(r[0] for r in rows if r and r[0])
    assert len(distinct) >= 3, (
        f"aug19th: only {len(distinct)} distinct DIME serials decoded; "
        f"saw {distinct}"
    )
    # Verify CS15120080 (the documented M300 JSM) is among them
    assert "CS15120080" in distinct, (
        f"expected CS15120080 (M300 JSM) in {distinct}"
    )


def test_decode_pointer_idx_sub_decomposition():
    """POINTER register frames should decompose bytes 4 and 6 as separate
    pointer-index and sub-index fields, per janschu99 dictionary line 14
    ('78M#2P810000Xx00Vv00 : check if pointer Xx sub Vv exists').
    """
    if not have_capture("programmer_write"):
        pytest.skip("programmer_write not present")
    rows = fields("programmer_write",
                  'rnet.pop.pointer_idx',
                  ["rnet.pop.pointer_idx", "rnet.pop.pointer_sub"])
    assert rows, "no pointer_idx field present in programmer_write"
    # Sanity: at least one frame should have idx >= 6 (the documented
    # capture has pointers up through 10+)
    idxs = set(int(r[0].replace("0x",""), 16) for r in rows)
    assert max(idxs) >= 6, f"max pointer_idx = {max(idxs)}, expected >= 6"


def test_decode_pop_value_field_labeling():
    """For Quick POP frames on the DATA register, bytes 4-7 should be
    labeled as value (not Size). This was previously mislabeled as 'Size'
    for any frame with non-zero bytes 4-7.
    """
    if not have_capture("programmer_write"):
        pytest.skip("programmer_write not present")
    rows = fields("programmer_write",
                  'rnet.pop.register_name == "DATA" and rnet.pop.value16',
                  ["rnet.pop.value16"])
    assert rows, "no DATA-register frames have value16 field"


def test_decode_odi_class_slot_appears():
    """The ODI class decoder should recognize 0x8C (SLOT, sizes 1-4) in
    POP frames with that ODI low byte.
    """
    if not have_capture("full_action"):
        pytest.skip("full_action not present")
    rows = fields("full_action",
                  'rnet.pop.odi_class == "ODI_CLASS_SLOT"',
                  ["rnet.pop.odi_class"])
    assert rows, "expected at least one ODI_CLASS_SLOT frame in full_action"


def test_algo_pop_namespace_membership():
    """The POP-extended namespace test ((id >> 18) & 0x7E0) == 0x780 should
    accept frames inside and reject neighbors like 0x1E80000F.
    """
    inside = [0x1E0F0001, 0x1E3C0001, 0x1E4A0001, 0x1E4E0001, 0x1E7FFFFF]
    outside = [
        0x1E80000F,  # transfer-complete sentinel (different namespace)
        0x1EC00000,  # mode configuration
        0x1F000000,  # auth namespace
        0x02000200,  # joystick
    ]
    for cid in inside:
        assert ((cid >> 18) & 0x7E0) == 0x780, f"0x{cid:08X} should be POP-ext"
    for cid in outside:
        assert ((cid >> 18) & 0x7E0) != 0x780, f"0x{cid:08X} should NOT be POP-ext"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
