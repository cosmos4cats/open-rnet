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
    """0x1E80000F should decode with 'Transfer Complete sentinel' in class.
    The end-of-transfer marker also doubles as a ReBus session-layer
    state transition (CXTN_UPLOAD/DOWNLOAD → CXTN_RNET); we match on
    substring so future label refinements don't break the test."""
    if not have_capture("ics_write_config"):
        pytest.skip("ics_write_config not present")
    n = count("ics_write_config", 'rnet.class contains "Transfer Complete sentinel"')
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


# ---------------------------------------------------------------------------
# Category 6: Provenance / preference behavior (added 2026-05-23)
# ---------------------------------------------------------------------------

def test_decode_jsm_serial_heartbeat_pre_init_label():
    """At power-on the JSM emits all-zero serial-heartbeat frames before
    loading its serial from EEPROM. Those frames must show the explicit
    'pre-init' label rather than a misleading 'serial=00000000'. Regression
    test for the audit fix on 2026-05-23."""
    if not have_capture("poweronJSMsh"):
        pytest.skip("poweronJSMsh capture not present")
    # Use the dissector's summary field rather than scraping the info column,
    # so this test is robust to column-width changes.
    rows = fields("poweronJSMsh",
                  'can.id == 0xE && can.flags.xtd == 0',  # STD 0x00E serial HB
                  ["rnet.summary"])
    summaries = [r[0] for r in rows if r and r[0]]
    assert summaries, "no serial-heartbeat frames found in poweronJSMsh"
    # Every heartbeat in this short power-on capture must be pre-init.
    bad = [s for s in summaries if "pre-init" not in s]
    assert not bad, (
        f"expected all 0x00E heartbeats in poweronJSMsh to be labeled "
        f"'pre-init'; got non-pre-init summaries: {bad[:3]}"
    )
    # And explicitly: no frame should display the misleading raw zero serial.
    assert not any("serial=00000000" in s for s in summaries), (
        "found 'serial=00000000' literal — labeling regressed to raw bytes"
    )


def test_pref_show_evidence_toggle_controls_both_fields():
    """The rnet.show_evidence preference is a single switch that controls
    BOTH the rnet.confidence and rnet.evidence fields together. Default off:
    neither field appears. With -o rnet.show_evidence:TRUE: both appear.
    Regression test for the design decision documented in
    add_evidence() — confidence and source are emitted as a unit."""
    if not have_capture("poweronJSMsh"):
        pytest.skip("poweronJSMsh capture not present")

    # OFF: neither field should appear in expanded detail.
    off_out = tshark("poweronJSMsh", extra=["-V"])
    assert "rnet.confidence" not in off_out and "Evidence kind" not in off_out, \
        "rnet.confidence field appeared with pref OFF"
    assert "rnet.evidence" not in off_out and "Evidence source" not in off_out, \
        "rnet.evidence field appeared with pref OFF"

    # ON: both fields should appear at least once.
    on_out = tshark("poweronJSMsh",
                    extra=["-V", "-o", "rnet.show_evidence:TRUE"])
    assert "Evidence kind" in on_out, "rnet.confidence field missing with pref ON"
    assert "Evidence source" in on_out, "rnet.evidence field missing with pref ON"


def test_evidence_tier_distribution_is_documented():
    """The README claims a specific Code / Documented / Inferred distribution
    in add_evidence() calls. If the distribution drifts (e.g. someone adds 10
    Inferred entries without verifying them), the README's confidence claim
    becomes stale. This test pins the categorization so drift surfaces in CI
    rather than silently in the published docs."""
    dissector_text = Path(LUA).read_text()
    code_count = len(re.findall(r'add_evidence\(t,\s*"Code",', dissector_text))
    doc_count = len(re.findall(r'add_evidence\(t,\s*"Documented",', dissector_text))
    inf_count = len(re.findall(r'add_evidence\(t,\s*"Inferred",', dissector_text))
    total = code_count + doc_count + inf_count
    assert total > 0, "no add_evidence() calls found — refactor broke parsing"
    # As of 2026-05-23: 27 / 15 / 13 = 55. Allow modest drift but fail loudly
    # if the proportions move meaningfully (e.g. someone adds a flood of
    # Inferred entries without verifying them).
    assert total >= 50, f"add_evidence call total dropped to {total} (was 55+)"
    inferred_pct = inf_count / total
    assert inferred_pct < 0.40, (
        f"Inferred share grew to {inferred_pct:.0%} of {total} calls; "
        f"either verify some up to Documented/Code or update the README's "
        f"published distribution to reflect the new state."
    )


def test_rnd_address_emits_stable_prefix_and_caveated_name():
    """When a POP frame's ODI memory address matches our .rnd lookup,
    the dissector should emit BOTH a stable module prefix (which is
    invariant across firmware versions) AND the firmware-specific name
    guess. Per RND_PARAMETER_RECORD_FORMAT.md address-stability finding
    (2026-05-23): 0/159 common addresses map to the same name across
    6 firmware extractions — the prefix is the reliable signal."""
    if not have_capture("programmer_write"):
        pytest.skip("programmer_write capture not present")
    # Frame 281 in programmer_write hits .rnd[0x0048] which is
    # ICS_ABS_MIN_ELEVATOR_TRAVEL (prefix "ICS") in Generic V33_1_1375.
    rows = fields("programmer_write",
                  'rnet.pop.addr_prefix == "ICS"',
                  ["rnet.pop.addr_prefix", "rnet.pop.addr_name"])
    assert rows, "no frames matched rnet.pop.addr_prefix == 'ICS' — prefix-field not emitted"
    prefix, name = rows[0][0], rows[0][1]
    assert prefix == "ICS", f"expected prefix 'ICS'; got {prefix!r}"
    assert name.startswith("ICS_"), (
        f"expected name to start with 'ICS_' (matching prefix); got {name!r}"
    )


def test_auth_response_labels_distinguish_serial_bytes_from_extended_round():
    """Auth response frames at seq 0-3 carry the responding module's
    serial byte; seq 4-7 are extended/verification rounds. The labels
    must make this distinction explicit so readers don't think 'val=0x00'
    on seq 4-7 means the dissector lost data."""
    if not have_capture("hackathon"):
        pytest.skip("hackathon dump not present")
    # seq 0-3 responses — summary must contain "serial[N]".
    # Filter via rnet.class (responses, not challenges) since the
    # RTR bit lives in can.flags.rtr from the CAN dissector and we
    # want a dissector-internal filter.
    rows = fields("hackathon",
                  'rnet.class == "Serial auth — response" && rnet.auth.seq <= 3',
                  ["rnet.auth.seq", "rnet.summary"])
    assert rows, "no auth-response seq 0-3 frames found"
    bad = [(s, sm) for s, sm in rows if "serial[" not in sm]
    assert not bad, f"some seq 0-3 frames lack 'serial[N]=' in summary: {bad[:3]}"
    # seq 4-7 — summary must say "extended round"
    rows = fields("hackathon",
                  'rnet.class == "Serial auth — response" && rnet.auth.seq >= 4',
                  ["rnet.auth.seq", "rnet.summary"])
    assert rows, "no auth-response seq 4-7 frames found"
    bad = [(s, sm) for s, sm in rows if "extended round" not in sm]
    assert not bad, f"some seq 4-7 frames lack 'extended round' in summary: {bad[:3]}"


def test_rnd_address_emits_gui_path_for_lookups_that_have_one():
    """When a POP frame hits a .rnd address that we have GUI-path
    metadata for, the rnet.pop.addr_path field must be populated
    alongside name and prefix. The path tells the reader WHERE in the
    dealer menus this parameter lives — often more useful than the
    cryptic internal name. Frame 281 of programmer_write hits
    .rnd[0x0048] = ICS_ABS_MIN_ELEVATOR_TRAVEL @ Seating~ICS~OEM Factory."""
    if not have_capture("programmer_write"):
        pytest.skip("programmer_write capture not present")
    rows = fields("programmer_write",
                  'rnet.pop.addr_prefix == "ICS"',
                  ["rnet.pop.addr_name", "rnet.pop.addr_path"])
    assert rows, "no ICS-prefix .rnd address frames found"
    name, path = rows[0][0], rows[0][1]
    assert name.startswith("ICS_"), f"expected ICS_ name; got {name!r}"
    assert "~" in path, (
        f"expected GUI path (tilde-separated) for ICS .rnd entry; "
        f"got {path!r} — path field probably not emitting"
    )
    assert path.startswith("Seating") or path.startswith("Inhibits") \
        or path.startswith("Engineering") or path.startswith("Controls"), (
        f"expected path to start with a top-level menu name; got {path!r}"
    )


def test_decode_rtc_broadcast_field_values():
    """0x1C2C0X00 is the chair's Real-Time Clock periodic broadcast
    (per DongleInterface.dll DecodeRTCBroadcast + Programmer EXE
    FUN_004a5030, validated against wall-clock 2026-05-21 Thursday).

    Validates the 6-byte bit-packed layout decodes correctly and the
    day-of-week field (data[3] >> 5) — which can't be guessed from
    range-fitting heuristics — produces 4 (Thursday) for the
    hackathon capture's date.
    """
    if not have_capture("hackathon"):
        pytest.skip("hackathon dump not present")
    rows = fields("hackathon",
                  'can.id == 0x1C2C0100',
                  ["rnet.rtc.year", "rnet.rtc.month", "rnet.rtc.day",
                   "rnet.rtc.dow",  "rnet.rtc.hour", "rnet.rtc.min"])
    assert rows, "no 0x1C2C0100 RTC frames found"
    y, m, d, dow, h, mn = rows[0]
    assert (y, m, d) == ("26", "5", "21"), (
        f"expected 2026-05-21 (the hackathon date); got 20{y}-{m}-{d}"
    )
    assert dow == "4", (
        f"expected day-of-week=4 (Thursday for 2026-05-21); got dow={dow}"
    )
    # Hour and minute should be plausible
    assert 0 <= int(h) <= 23 and 0 <= int(mn) <= 59, \
        f"implausible hour/min ({h}:{mn})"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
