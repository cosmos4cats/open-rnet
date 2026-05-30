#!/usr/bin/env python3
"""
Tests for rnet_can.lua.

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
LUA = str(DISSECTOR_DIR / "rnet_can.lua")

# Auto-detect capture location. The dissector is mirrored between two trees
# with different relative paths to the open-rnet captures, so this preamble
# tries both layouts. Whichever exists wins; the test file stays identical
# in both trees and no manual sync is needed.
_candidates = [
    DISSECTOR_DIR.parent.parent / "captures",        # open-rnet/analysis/wireshark/
    DISSECTOR_DIR.parent / "open-rnet" / "captures", # sibling-repo layout
]
OPEN_RNET_CAPTURES = next((p for p in _candidates if p.exists()), _candidates[0])

# Hackathon log can live next to the captures, or next to the dissector itself
# (older layout). Prefer the in-tree location if both exist.
_hack_candidates = [
    OPEN_RNET_CAPTURES / "2026_AT_hackathon.log",
    DISSECTOR_DIR / "2026_AT_hackathon.log",
]
HACKATHON_LOG = next((p for p in _hack_candidates if p.exists()), _hack_candidates[0])


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
# Session-scoped capture cache (for bulk-corpus tests)
# ---------------------------------------------------------------------------
#
# Tests that count or filter many things across many captures used to
# spawn tshark once per (capture, filter) combination — 90+ tshark
# processes for a single test, ~17s wall-clock. This cache walks each
# CAN-parseable capture in OPEN_RNET_CAPTURES ONCE, extracts the
# union of fields any bulk-corpus test needs, and gives tests an
# in-memory iterable they can filter via Python predicates.
#
# Filtering 30k rows in Python is microseconds; the cost was the
# tshark process spawn (cold-start + Lua plugin reload + capture
# parse, ~150-300ms each). Net effect: ~30 invocations instead of
# 150+, and individual bulk tests drop from 8-17s to <0.5s.

CACHED_FIELDS = [
    "frame.number", "rnet.class", "rnet.summary",
    "rnet.err.code", "rnet.err.name", "rnet.auth.network",
]


@pytest.fixture(scope="session")
def capture_cache():
    """One-tshark-per-capture cache. Returns:
        { Path(capture): [ {field_name: value, ...}, ... ] }
    Captures that tshark can't parse (non-CAN files, malformed) are
    silently skipped — the cache only contains entries for files
    that produced output. If OPEN_RNET_CAPTURES doesn't exist,
    returns an empty dict (tests that depend on the cache should
    skip via `if not capture_cache: pytest.skip(...)`).
    """
    cache = {}
    if not OPEN_RNET_CAPTURES.exists():
        return cache
    field_args = sum([["-e", f] for f in CACHED_FIELDS], [])
    for cap in sorted(OPEN_RNET_CAPTURES.rglob("*")):
        if cap.suffix not in (".pcapng", ".pcap", ".candump", ".log"):
            continue
        try:
            proc = subprocess.run(
                ["tshark", "-r", str(cap), "-T", "fields"] + field_args,
                capture_output=True, text=True, timeout=120,
            )
        except subprocess.TimeoutExpired:
            continue
        if proc.returncode != 0:
            continue
        rows = []
        for line in proc.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            # Pad in case tshark dropped trailing empties
            while len(parts) < len(CACHED_FIELDS):
                parts.append("")
            rows.append(dict(zip(CACHED_FIELDS, parts)))
        if rows:
            cache[cap] = rows
    return cache


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


def test_coverage_total_evidenced_threshold(capture_cache):
    """Across the full corpus, ≥99% of frames decode under an evidenced rule
    (not [unverified], not unknown). Uses the session capture_cache so the
    whole sweep happens via cached rows rather than re-running tshark
    per filter.
    """
    if not capture_cache:
        pytest.skip("capture corpus not present")
    total = 0
    evidenced = 0
    for cap, rows in capture_cache.items():
        for row in rows:
            cls = row.get("rnet.class", "")
            total += 1
            if "Unknown" not in cls and "unverified" not in cls:
                evidenced += 1
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


def test_decode_error_catalog_resolves_newly_added_codes(capture_cache):
    """The upstream-RE regenerated JSONL (v2, 2026-05-22) with confidence
    levels + code_swapped_hex lookup should resolve codes that were
    previously "undocumented" in parse's earlier integration.

    Concrete check: codes 0x0F00, 0x1900, 0x1A00, 0x1E00, 0x1F00, 0x2000,
    0x2100, 0x2200, 0x2900 all appear in captures and should decode to
    named errors per upstream-RE's regenerated extraction.
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
    # Walk via the capture cache so this drops from ~9s of tshark
    # spawns to filtering rows in Python.
    cap_hints = ("full_action", "aug19th", "0x1f201e0e")
    matched_some_code = False
    for cap, rows in capture_cache.items():
        if not any(hint in cap.name for hint in cap_hints):
            continue
        for code, expected_substring in new_codes.items():
            code_hex = f"0x{code:04x}"
            matching = [r for r in rows if r.get("rnet.err.code", "").lower() == code_hex
                        and r.get("rnet.err.name", "")]
            if matching:
                matched_some_code = True
                got = matching[0]["rnet.err.name"]
                assert expected_substring.lower() in got.lower(), (
                    f"{cap.name} code {code_hex}: got {got!r}, "
                    f"expected substring {expected_substring!r}"
                )
    assert matched_some_code, (
        "no captures with the expected fault codes were found — corpus "
        "may have changed"
    )


def test_decode_lighting_lamp_test_d5d5():
    """The diary line 19 documents `D5 D5` as 'lamp test - all on'. The
    dissector should decode this with mask == bitmap (no transition).
    """
    if not have_capture("July12_lights"):
        pytest.skip("July12_lights not present")
    # Find a lighting frame with payload D5 D5
    rows = fields("July12_lights",
                  'rnet.class contains "Lighting"',
                  ["rnet.summary"])
    all_on = [r[0] for r in rows
              if "Flood" in r[0] and "Hazard" in r[0] and "transition" not in r[0]]
    assert all_on, f"expected an 'all on' lamp-test in July12_lights; "\
                   f"got summaries: {[r[0] for r in rows[:5]]}"


def test_decode_transfer_complete_sentinel():
    """0x1E80000F is the canonical Transfer Complete sentinel — fires when
    a transfer ends and the R-Net session returns CXTN_UPLOAD/DOWNLOAD →
    CXTN_RNET. The sentinel's tail byte (0x0F = slot 15 = Programmer)
    encodes which slot the transfer was directed at.

    Verifies (a) the dissector recognizes 0x1E80000F as Transfer Complete,
    (b) the summary names slot 15 / Programmer as the target. Substring
    match on class to allow label refinement (e.g. adding state-machine
    parens); strict equality on the CAN ID."""
    if not have_capture("ics_write_config"):
        pytest.skip("ics_write_config not present")
    rows = fields("ics_write_config",
                  'can.id == 0x1E80000F',
                  ["rnet.class", "rnet.summary"])
    assert rows, "no 0x1E80000F frames found in ics_write_config"
    # Sanity on count — too few suggests filter broke, too many suggests a
    # different ID accidentally matched. Loose range covers capture growth.
    assert 500 <= len(rows) <= 5000, (
        f"got {len(rows)} 0x1E80000F frames; expected ~1,332 — check filter"
    )
    # Class label must contain the canonical phrase
    bad_class = [r for r in rows if "Transfer Complete sentinel" not in r[0]]
    assert not bad_class, (
        f"{len(bad_class)} 0x1E80000F frames missing 'Transfer Complete "
        f"sentinel' in class; first: {bad_class[0]!r}"
    )
    # Summary must identify slot 15 / Programmer as the target
    bad_summary = [r for r in rows
                   if "Programmer" not in r[1] and "slot 15" not in r[1] and "CXTN_RNET" not in r[1]]
    assert not bad_summary, (
        f"{len(bad_summary)} frames lack target/state info in summary; "
        f"first: {bad_summary[0]!r}"
    )


def test_decode_bit4_crc_flag_only_on_tc1_segment():
    """Per upstream-RE R3.5 F7: CRCFlag is only ever seen on TC=1
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
    rows_pm = fields("hackathon", 'rnet.class contains "PM heartbeat"',
                     ["rnet.pm_hb.byte0"])
    pm_bytes = set(r[0].lower() for r in rows_pm)
    assert {"0xc0", "0xc1"}.issubset(pm_bytes), (
        f"PM heartbeat byte-0 should include both 0xC0 and 0xC1; saw {pm_bytes}"
    )
    # IOM/ISM heartbeat (slot 2): byte 0 dominantly 0xC2
    rows_ism = fields("hackathon", 'rnet.class contains "IOM/ISM heartbeat"',
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

    Anchored on programmer_write frame 71 which is a documented POINTER
    setup for param BackUp (idx=6, sub=1, param_id=262 via (sub<<8)|idx).
    """
    if not have_capture("programmer_write"):
        pytest.skip("programmer_write not present")
    rows = fields("programmer_write",
                  'frame.number == 71',
                  ["rnet.pop.pointer_idx", "rnet.pop.pointer_sub",
                   "rnet.pop.pointer_param_id"])
    assert rows, "no frame 71 in programmer_write"
    idx_s, sub_s, pid_s = rows[0]
    idx = int(idx_s.replace("0x", ""), 16)
    sub = int(sub_s.replace("0x", ""), 16)
    pid = int(pid_s)
    assert (idx, sub) == (6, 1), (
        f"frame 71 expected (idx=6, sub=1) for BackUp POINTER setup; "
        f"got (idx={idx}, sub={sub})"
    )
    assert pid == 262, (
        f"frame 71 param_id should be 262 (= (1<<8) | 6 = BackUp); got {pid}"
    )


def test_decode_pop_value_field_labeling():
    """For Quick POP frames on the DATA register, bytes 4-7 should be
    labeled as value (not Size). This was previously mislabeled as 'Size'
    for any frame with non-zero bytes 4-7.

    Two assertions: (a) DATA-register frames DO get value16 populated,
    (b) DATA-register frames do NOT also have pop_size populated — Size
    belongs only on segmented-transfer setup frames (TC=1 + CRCFlag=1).
    """
    if not have_capture("programmer_write"):
        pytest.skip("programmer_write not present")
    with_value = count("programmer_write",
                       'rnet.pop.register_name == "DATA" && rnet.pop.value16')
    assert with_value > 10, (
        f"only {with_value} DATA-register frames have value16; "
        f"value-field labeling is probably broken"
    )
    with_size = count("programmer_write",
                      'rnet.pop.register_name == "DATA" && rnet.pop.size')
    assert with_size == 0, (
        f"{with_size} DATA-register frames have pop_size populated — "
        f"Size should only appear on setup frames (TC=1 + CRCFlag=1). "
        f"The 'bytes 4-7 = Size on any frame' mislabel may have returned."
    )


def test_decode_odi_class_decodes_slot_class_correctly():
    """The ODI class decoder (decode_odi_class in rnet_can.lua, derived from
    IRConfigurator.Device.ODI_CLASS via ilspycmd) maps ODI low bytes in
    0x80-0x8F to ODI_CLASS_SLOT. Verifies (a) frames matching that class
    have ODI values within the documented range, (b) the decoder's address
    extraction matches the low byte for the SLOT class entries we see.

    full_action_dumpJuly2_2016 has 8 ODI_CLASS_SLOT frames (frame 153-160)
    with ODI in {0x85, 0x8C}.
    """
    if not have_capture("full_action"):
        pytest.skip("full_action not present")
    rows = fields("full_action",
                  'rnet.pop.odi_class == "ODI_CLASS_SLOT"',
                  ["rnet.pop.odi", "rnet.pop.odi_address"])
    assert rows, "no ODI_CLASS_SLOT frames in full_action"
    assert len(rows) >= 4, (
        f"only {len(rows)} ODI_CLASS_SLOT frames; expected ~8"
    )
    for odi_s, addr_s in rows:
        odi = int(odi_s.replace("0x", ""), 16)
        # SLOT class lives in the 0x8X register space — low byte must be
        # in 0x80..0x8F.
        low = odi & 0xFF
        assert 0x80 <= low <= 0x8F, (
            f"ODI 0x{odi:08X} classified as SLOT but low byte 0x{low:02X} "
            f"is outside the 0x80-0x8F SLOT register range"
        )


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


def test_evidence_tier_distribution_matches_readme_claim():
    """The README publishes a Code/Documented/Inferred distribution
    table. If a contributor adds new add_evidence() calls and doesn't
    update the README — or if a README update gets out of step with
    the dissector — readers see a misleading confidence claim. This
    test parses the README's published counts and asserts the
    dissector matches.

    Fails when EITHER the dissector OR the README has drifted. The
    fix is the same in both directions: update both together.
    """
    dissector_text = Path(LUA).read_text()
    code_count = len(re.findall(r'add_evidence\(t,\s*"Code",', dissector_text))
    doc_count = len(re.findall(r'add_evidence\(t,\s*"Documented",', dissector_text))
    inf_count = len(re.findall(r'add_evidence\(t,\s*"Inferred",', dissector_text))

    # README is next to test_dissector.py's parent dir
    readme = (DISSECTOR_DIR / "README.md").read_text()
    # Parse rows like "| Code        |    27 | 49%  |"
    row_re = re.compile(r'^\|\s*(Code|Documented|Inferred)\s*\|\s*(\d+)\s*\|',
                        re.MULTILINE)
    claimed = {tier: int(n) for tier, n in row_re.findall(readme)}
    assert set(claimed) == {"Code", "Documented", "Inferred"}, (
        f"README's distribution table missing or malformed; "
        f"parsed: {claimed}"
    )
    actual = {"Code": code_count, "Documented": doc_count, "Inferred": inf_count}
    assert claimed == actual, (
        f"README's published distribution {claimed} doesn't match dissector "
        f"actual {actual}. Update README.md's '#### Current distribution' "
        f"table and this test will pass."
    )


def test_rnd_address_emits_prefix_name_and_path():
    """When a POP frame's ODI memory address matches our .rnd lookup,
    the dissector emits three fields together:
      - rnet.pop.addr_prefix: stable across firmware versions (e.g. "ICS"),
        the reliable signal per the address-stability finding (0/159
        common addresses map to the same name across 6 firmware extractions)
      - rnet.pop.addr_name: firmware-version-specific name guess
      - rnet.pop.addr_path: GUI menu path showing where the parameter lives

    Anchored on programmer_write frame .rnd[0x0048] which is
    ICS_ABS_MIN_ELEVATOR_TRAVEL @ Seating~ICS~OEM Factory in
    Generic V33_1_1375 — all three fields must populate consistently."""
    if not have_capture("programmer_write"):
        pytest.skip("programmer_write capture not present")
    rows = fields("programmer_write",
                  'rnet.pop.addr_prefix == "ICS"',
                  ["rnet.pop.addr_prefix",
                   "rnet.pop.addr_name",
                   "rnet.pop.addr_path"])
    assert rows, "no frames matched rnet.pop.addr_prefix == 'ICS' — prefix-field not emitted"
    prefix, name, path = rows[0]
    assert prefix == "ICS", f"expected prefix 'ICS'; got {prefix!r}"
    assert name.startswith("ICS_"), (
        f"name should start with the prefix 'ICS_'; got {name!r} — "
        f"the prefix/name correspondence is broken"
    )
    assert "~" in path, (
        f"GUI path should be tilde-separated (top~sub~leaf); got {path!r}"
    )
    # The Seating-area parameters are the dominant ICS_ class; if our
    # one-shot anchor ever shifts to a different ICS leaf it's worth
    # noticing rather than silently passing.
    assert path.split("~")[0] in ("Seating", "Inhibits", "Engineering", "Controls"), (
        f"unexpected top-level menu for ICS_ entry; got {path!r}"
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


def test_auth_device_serial_decode():
    """The auth-response value byte carries serial[seq] for seq 0-3 — the
    responding device's own 4-byte DIME serial. parse reassembles the four
    bytes per slot and decodes the human-readable LLYYMMNNNN form (via the
    same DIME algorithm used for device-enum). Validated against the known
    Standalone-JSM serial 0x08901C8A → CR15074104."""
    if not have_capture("poweronJSMsh"):
        pytest.skip("poweronJSMsh capture not present")
    rows = fields("poweronJSMsh", "rnet.auth.device_serial",
                  ["rnet.auth.slot", "rnet.auth.device_serial"])
    assert rows, "no decoded device serials found"
    serials = {r[1] for r in rows}
    assert serials == {"CR15074104"}, (
        f"expected the JSM's serial CR15074104 (from DIME 0x08901C8A), got {serials}"
    )


def test_auth_device_serial_no_splice_across_hotplug():
    """Anti-splice guard: in a hotplug/multi-device capture each slot can be
    occupied by different devices over time. The seq==0 round-reset must keep
    each decoded serial a coherent single-round value, not a Frankenstein
    mix of bytes from different devices. aug19th has exactly the 4 real
    devices; a regression (no reset) inflates this to ~17 spliced serials."""
    if not have_capture("aug19th"):
        pytest.skip("aug19th capture not present")
    rows = fields("aug19th", "rnet.auth.device_serial",
                  ["rnet.auth.device_serial"])
    assert rows, "no decoded device serials found"
    serials = {r[0] for r in rows}
    assert serials == {"CR15074104", "CS15120080", "CF15080143", "BP15080268"}, (
        f"expected exactly the 4 real devices, got {sorted(serials)} "
        "(more than 4 → seq==0 anti-splice reset regressed)"
    )


def test_version_line_present_and_stampable():
    """`make install` rewrites the `local RNET_VERSION = "..."` line in the
    installed copy with a git-derived version (date + short-SHA of the last
    commit that touched rnet_can.lua). If that line is renamed or removed the
    installer silently stops stamping — installed copies would all report
    "dev". Guard the contract: the stampable line exists and is wired into
    set_plugin_info so Wireshark surfaces it."""
    lua = Path(LUA).read_text()
    assert re.search(r'^local RNET_VERSION = "[^"]*"', lua, re.M), (
        'the stampable line `local RNET_VERSION = "..."` is missing — '
        "make install can no longer stamp the version"
    )
    assert "set_plugin_info" in lua and "version = RNET_VERSION" in lua, (
        "RNET_VERSION must be passed to set_plugin_info so the version shows "
        "in Help > About > Plugins"
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


# ---------------------------------------------------------------------------
# Category 7: Companion-artifact smoke tests
# ---------------------------------------------------------------------------

def test_pwc_params_json_well_formed():
    """The vendored pwc_params.json snapshot (loaded by reassemble_transfers.py
    AND embedded as a table in rnet_can.lua) must parse as JSON and have the
    expected structure: numeric-string keys, non-empty string values.
    Includes one anchor check that param_id 262 maps to BackUp — if that
    breaks, every chair-actuator decode regresses silently.
    """
    import json
    p = DISSECTOR_DIR / "pwc_params.json"
    assert p.exists(), f"pwc_params.json missing at {p}"
    data = json.loads(p.read_text())
    assert len(data) > 800, f"pwc_params.json has only {len(data)} entries (expected ~966)"
    bad_keys = [k for k in data if not k.isdigit()]
    assert not bad_keys, f"pwc_params.json non-numeric keys: {bad_keys[:5]}"
    bad_vals = [k for k, v in data.items() if not (isinstance(v, str) and v)]
    assert not bad_vals, f"pwc_params.json entries with bad value: {bad_vals[:5]}"
    assert data.get("262") == "BackUp", (
        f"pwc_params.json[262] should be 'BackUp' (chair-actuator anchor); "
        f"got {data.get('262')!r}"
    )


def test_rnet_dump_wrapper_produces_expected_format():
    """The rnet-dump bash wrapper should emit candump-L-shaped output:
    `(timestamp) iface CAN_ID  decoded-info` per frame, or a no-CAN-ID
    variant for frames without a CAN ID. Catches regressions in the awk
    pipeline (e.g. someone refactoring the field list and breaking the
    printf format)."""
    import subprocess
    wrapper = DISSECTOR_DIR / "rnet-dump"
    if not wrapper.exists() or not os.access(str(wrapper), os.X_OK):
        pytest.skip(f"rnet-dump wrapper not present or not executable at {wrapper}")
    if not have_capture("poweronJSMsh"):
        pytest.skip("poweronJSMsh capture not present")
    proc = subprocess.run(
        [str(wrapper), "-r", cap_path(CAPTURES["poweronJSMsh"])],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, f"rnet-dump exited {proc.returncode}: {proc.stderr}"
    lines = [l for l in proc.stdout.splitlines() if l.strip()]
    assert lines, "rnet-dump produced no output"
    # Every non-blank line should start with (decimal.decimal) timestamp
    line_re = re.compile(r'^\(\d+\.\d+\)\s')
    bad = [l for l in lines if not line_re.match(l)]
    assert not bad, (
        f"{len(bad)} rnet-dump line(s) don't match '(t) ...' format; "
        f"first bad: {bad[0]!r}"
    )


def test_session_state_machine_matches_known_transitions():
    """Plan 1: the per-frame R-Net session-state annotation must match
    the upstream-RE rnet_state_timeline.py tool's transition log
    (different implementation, same algorithm). Anchored on
    programmer_write_file_july2017 whose timeline is fully documented:

      frame 1   → CXTN_CAN       (first observed frame)
      frame 3   → CXTN_RNET      (first 0x7B3 serial exchange)
      frame 55  → CXTN_UPLOAD    (first POP TC=0 open)
      frame 372 → CXTN_RNET      (first Transfer Complete sentinel)

    Also asserts the transfer-id counter increments on each new POP
    open (1 at frame 55, 2 at frame 388)."""
    if not have_capture("programmer_write"):
        pytest.skip("programmer_write capture not present")
    rows = fields("programmer_write",
                  'frame.number in {1,3,55,372,388}',
                  ["frame.number", "rnet.session_state", "rnet.transfer_id"])
    by_num = {r[0]: (r[1], r[2]) for r in rows}
    assert by_num.get("1") == ("CXTN_CAN", ""), \
        f"frame 1 should be CXTN_CAN; got {by_num.get('1')!r}"
    assert by_num.get("3") == ("CXTN_RNET", ""), \
        f"frame 3 should be CXTN_RNET; got {by_num.get('3')!r}"
    assert by_num.get("55") == ("CXTN_UPLOAD", "1"), \
        f"frame 55 should be CXTN_UPLOAD, transfer=1; got {by_num.get('55')!r}"
    assert by_num.get("372") == ("CXTN_RNET", ""), \
        f"frame 372 should be CXTN_RNET (post-complete); got {by_num.get('372')!r}"
    assert by_num.get("388") == ("CXTN_UPLOAD", "2"), \
        f"frame 388 should be CXTN_UPLOAD, transfer=2; got {by_num.get('388')!r}"


def test_pointer_data_binding_carries_parameter_name():
    """Plan 2: when a POP POINTER setup names a parameter and a DATA
    frame follows from the same node-pair within a short window, the
    DATA frame's summary names the parameter being read/written.

    Anchored on programmer_write frames 71 (POINTER ptr=6.1 BackUp)
    and the immediately following DATA frames 75/76. Also verifies the
    invalidation semantics: frame 77 sets an unnamed POINTER (ptr=2),
    so frames 80/81 must NOT inherit the BackUp binding."""
    if not have_capture("programmer_write"):
        pytest.skip("programmer_write capture not present")
    rows = fields("programmer_write",
                  'frame.number in {75,76,80,81,84,85}',
                  ["frame.number", "rnet.pop.binds_param_name"])
    by_num = {r[0]: r[1] for r in rows}
    # Frames 75-76 bind to BackUp (param 262, named via PWC lookup)
    assert by_num.get("75") == "BackUp", (
        f"frame 75 should bind to BackUp; got {by_num.get('75')!r}"
    )
    assert by_num.get("76") == "BackUp", (
        f"frame 76 should bind to BackUp; got {by_num.get('76')!r}"
    )
    # Frames 80-81 must be unbound — frame 77 set an unnamed POINTER
    assert by_num.get("80", "") == "", (
        f"frame 80 should NOT bind (unnamed POINTER at 77 invalidated); "
        f"got {by_num.get('80')!r}"
    )
    assert by_num.get("81", "") == "", (
        f"frame 81 should NOT bind; got {by_num.get('81')!r}"
    )
    # Frame 82 sets BackToggle (named), so 84-85 bind there
    assert by_num.get("84") == "BackToggle", (
        f"frame 84 should bind to BackToggle; got {by_num.get('84')!r}"
    )
    assert by_num.get("85") == "BackToggle", (
        f"frame 85 should bind to BackToggle; got {by_num.get('85')!r}"
    )


# ---------------------------------------------------------------------------
# Negative control — non-R-Net CAN traffic
# ---------------------------------------------------------------------------

NON_RNET_LOG = DISSECTOR_DIR / "non-rnet-canlog.log"


def test_non_rnet_log_produces_no_specific_decodes():
    """Control file: a candump log from some other (non-R-Net) CAN bus,
    with CAN IDs 0x720 and 0x728 that don't intersect any R-Net family
    range. The dissector's heuristic always-claims SocketCAN frames
    (because there's no bit-level way to tell R-Net from other
    proprietary CAN at the heuristic stage — see register_heuristic
    block at end of rnet_can.lua), so it WILL produce per-frame output.
    But it must NOT produce a confidently-named R-Net class — every
    frame should fall through to the generic 'Unknown STD 0xXXX' label
    and no specific rnet.* subfield (pop.odi, joy.x, auth.*, etc.)
    should populate.

    If this fails after a dissector change, either (a) a new STD-ID
    handler accidentally widened its range into 0x720/0x728, or
    (b) a sub-decoder fires on payloads it shouldn't. Both are
    misclassification bugs worth catching."""
    # non-rnet-canlog.log is committed to the repo. Missing-file means
    # someone deleted a tracked file; that's a bug, not a skip condition.
    assert NON_RNET_LOG.exists(), (
        f"non-rnet-canlog.log missing from {NON_RNET_LOG}. This file is "
        f"committed to the repo as a negative-control fixture. Restore "
        f"with `git checkout HEAD -- {NON_RNET_LOG.name}`."
    )
    # 1) Every frame must label as Unknown STD
    proc = subprocess.run(
        ["tshark", "-r", str(NON_RNET_LOG),
         "-T", "fields", "-e", "rnet.class"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    classes = [l for l in proc.stdout.splitlines() if l.strip()]
    assert classes, "no per-frame output — dissector didn't run"
    not_unknown = [c for c in classes if not c.startswith("Unknown STD")]
    assert not not_unknown, (
        f"non-R-Net frames got R-Net-specific labels (sample: "
        f"{Counter(not_unknown).most_common(5)})"
    )
    # 2) No R-Net sub-decoder field should populate
    suspect_fields = [
        "rnet.pop.odi", "rnet.pop.register_name", "rnet.joy.x", "rnet.joy.y",
        "rnet.auth.seq", "rnet.auth.key", "rnet.rtc.year",
        "rnet.pop.binds_param_name", "rnet.summary",
    ]
    proc = subprocess.run(
        ["tshark", "-r", str(NON_RNET_LOG), "-T", "fields"]
        + sum([["-e", f] for f in suspect_fields], []),
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    populated_lines = [
        l for l in proc.stdout.splitlines()
        if l.strip() and any(c.strip() for c in l.split("\t"))
    ]
    assert not populated_lines, (
        f"R-Net sub-decoder fields populated on non-R-Net frames "
        f"(first 3): {populated_lines[:3]}"
    )


# ---------------------------------------------------------------------------
# Structural validation tests (2026-05-24 critique items #1, #3, #4)
# ---------------------------------------------------------------------------
#
# These tests don't exercise wire-decode behavior — they validate the
# integrity of the project's data + documentation against the dissector
# itself, catching the kinds of drift that hand-editing two-source-of-truth
# files inevitably introduces.


def test_pwc_params_json_matches_lua_table():
    """Item #1: the project ships pwc_params.json (canonical, used by
    reassemble_transfers.py) AND embeds the same 966 entries as a Lua
    table inside rnet_can.lua (loaded by the dissector). If they drift,
    parameter names resolve differently between the dissector output
    and the post-processor. This test asserts they stay in lockstep.

    If this fails after a parameter-name update: regenerate the Lua
    table from the JSON (or vice-versa) so they match.
    """
    import json as _json
    json_path = DISSECTOR_DIR / "pwc_params.json"
    # pwc_params.json is a tracked file in this dissector tree and MUST be
    # present. If it isn't, that's a "someone deleted a committed file"
    # bug — fail hard so it's noticed, not silently skipped.
    assert json_path.exists(), (
        f"pwc_params.json missing from {json_path}. This file is "
        f"committed to the repo and is required for the dissector to "
        f"resolve PWC parameter names. If you deleted it, restore from "
        f"`git checkout HEAD -- {json_path.name}`."
    )

    canonical = _json.loads(json_path.read_text())
    # Normalize JSON keys to integers for comparison
    canonical_int = {int(k): v for k, v in canonical.items()}

    # Extract the Lua table from rnet_can.lua. It looks like:
    #     pwc_params = {
    #         [0] = "ALPHA",
    #         [1] = "Abbreviated",
    #         ...
    #     }
    lua_text = Path(LUA).read_text()
    m = re.search(r'^pwc_params = \{(.*?)^\}', lua_text,
                  re.MULTILINE | re.DOTALL)
    assert m, "pwc_params Lua table not found in dissector"
    lua_entries = {}
    for entry in re.finditer(r'\[(\d+)\]\s*=\s*"([^"]*)"', m.group(1)):
        lua_entries[int(entry.group(1))] = entry.group(2)

    assert canonical_int == lua_entries, (
        f"pwc_params.json and Lua table out of sync:\n"
        f"  JSON has {len(canonical_int)} entries, Lua has {len(lua_entries)}\n"
        f"  Only in JSON: {sorted(set(canonical_int) - set(lua_entries))[:10]}\n"
        f"  Only in Lua:  {sorted(set(lua_entries) - set(canonical_int))[:10]}\n"
        f"  Different values for same ID: "
        f"{[(k, canonical_int[k], lua_entries[k]) for k in set(canonical_int) & set(lua_entries) if canonical_int[k] != lua_entries[k]][:5]}"
    )


def test_corpus_zero_unknown_across_all_captures(capture_cache):
    """Item #3b: parse claims '0 Unknown across the full corpus' in
    several places (README headline, commit messages, walkthrough).
    Without this test, a decoder regression could silently start
    labeling frames as Unknown and nobody would notice unless someone
    re-ran the corpus probe by hand.

    Walks every CAN-parsable capture in OPEN_RNET_CAPTURES (via the
    session-scoped capture_cache fixture), asserts zero frames with
    'Unknown' in the rnet.class field.
    """
    if not capture_cache:
        pytest.skip(f"capture corpus not present at {OPEN_RNET_CAPTURES}")
    found_unknown = []
    total_frames = sum(len(rows) for rows in capture_cache.values())
    for cap, rows in capture_cache.items():
        for row in rows:
            if "Unknown" in row.get("rnet.class", ""):
                found_unknown.append((cap.name, row.get("frame.number", "?"),
                                      row.get("rnet.class", "")))
    assert len(capture_cache) >= 20, (
        f"only {len(capture_cache)} CAN-parseable captures found at "
        f"{OPEN_RNET_CAPTURES} — corpus seems incomplete"
    )
    assert not found_unknown, (
        f"{len(found_unknown)} frames labeled 'Unknown' across "
        f"{len(capture_cache)} captures ({total_frames} total frames). "
        f"First 5: {found_unknown[:5]}"
    )


def test_walkthrough_anchors_match_dissector_output():
    """Item #3a: the README's 'A walked-through session' section
    hardcodes specific frame numbers + decoded summary text from
    programmer_write_file_july2017.pcapng. If a future decoder change
    silently shifts those labels, the walkthrough lies to readers.
    This test re-runs the dissector against the cited frames and
    asserts the summaries still contain the phrases the walkthrough
    promises.

    Anchors checked: phase 1 (Network test), phase 2 (Auth response
    Table B serial), phase 3 (POINTER→DATA binding for BackUp),
    phase 4 (R-Net attach handshake 4-step), phase 5 (Transfer
    Complete sentinel), phase 6 (Sleep cmd at end of capture).
    """
    if not have_capture("programmer_write"):
        pytest.skip("programmer_write capture not present")

    def _frame_summary(n):
        proc = subprocess.run(
            ["tshark", "-r", cap_path("programmer_write_file_july2017.pcapng"),
             "-Y", f"frame.number == {n}",
             "-T", "fields", "-e", "rnet.summary"],
            capture_output=True, text=True, timeout=15,
        )
        return proc.stdout.strip()

    # Phase 1 — bus enumeration
    assert "Network test" in _frame_summary(1), \
        "walkthrough phase 1: frame 1 should mention 'Network test'"
    assert "50C01C8F" in _frame_summary(2), \
        "walkthrough phase 1: frame 2 should show JSM serial 50C01C8F"

    # Phase 2 — auth handshake (frame 18 = seq=0 slot=0 serial[0])
    assert "Auth response seq=0 slot=0" in _frame_summary(18), \
        "walkthrough phase 2: frame 18 anchors the auth burst"

    # Phase 3 — POINTER→DATA binding (BackUp parameter)
    assert "BackUp" in _frame_summary(71), \
        "walkthrough phase 3: frame 71 POINTER setup must name BackUp"
    assert "BackUp" in _frame_summary(75), \
        "walkthrough phase 3: frame 75 DATA must inherit BackUp binding"

    # Phase 4 — attach handshake
    s93 = _frame_summary(93)
    assert "attach 1/4" in s93 and "Programmer announce" in s93, \
        f"walkthrough phase 4: frame 93 must label attach step 1; got {s93!r}"
    s96 = _frame_summary(96)
    assert "attach 4/4" in s96 and "CXTN_RNET ready" in s96, \
        f"walkthrough phase 4: frame 96 must label attach step 4 CXTN_RNET ready; got {s96!r}"

    # Phase 5 — Transfer Complete
    assert "transfer complete" in _frame_summary(372).lower(), \
        "walkthrough phase 5: frame 372 must label Transfer Complete"

    # Phase 6 — Sleep cmd at end
    assert "Sleep" in _frame_summary(3223), \
        "walkthrough phase 6: frame 3223 must label as Sleep"


def test_citations_resolve_or_explain():
    """Item #4: every `add_evidence(t, "...", "<citation>")` in
    rnet_can.lua should reference docs that exist somewhere we know
    about. This test extracts every .md filename cited and checks
    each is reachable.

    Public lookup locations always probed: this dissector tree itself,
    open-rnet/docs/, open-rnet/reference/.

    Private upstream-RE locations are probed only if the
    RNET_FIRMWARE_DOCS env var is set to their docs/ directory. Set
    it via Makefile.local for the dev workflow, or in your shell
    rc. When unset (e.g., on a CI runner without the private repo),
    private-only citations are skipped rather than failing — the
    test still validates everything reachable from public sources.
    """
    lua_text = Path(LUA).read_text()
    # Extract .md filenames from add_evidence citations
    cited_docs = set()
    for line_no, line in enumerate(lua_text.splitlines(), 1):
        if 'add_evidence' not in line:
            continue
        for m in re.finditer(r'\b([A-Z][A-Z0-9_]{4,}\.md)\b', line):
            cited_docs.add(m.group(1))

    # Public lookup locations
    search_paths = [
        DISSECTOR_DIR,                                        # this dir
        DISSECTOR_DIR.parent.parent / "docs",                 # repo-root/docs
        DISSECTOR_DIR.parent.parent / "reference",            # repo-root/reference
    ]
    # Private upstream-RE location via env var (optional)
    private_docs = []
    fw_env = os.environ.get('RNET_FIRMWARE_DOCS')
    if fw_env:
        private_docs.append(Path(fw_env))

    def find_doc(name):
        for base in search_paths:
            if base.exists() and (base / name).exists():
                return ("public", base / name)
        for base in private_docs:
            if base.exists() and (base / name).exists():
                return ("private", base / name)
        return (None, None)

    broken = []
    unverifiable = []  # cited but only knowable from private docs we can't reach
    for doc in sorted(cited_docs):
        location, path = find_doc(doc)
        if location is None:
            if private_docs:
                # We had access to private docs and still couldn't find it
                broken.append(doc)
            else:
                # No private docs available — could be either a private-only
                # citation (acceptable) or a genuinely broken ref. We can't
                # tell which without the env var, so report up via skip
                # rather than silently pass.
                unverifiable.append(doc)

    # Skip with an informative message when private-only citations exist
    # and RNET_FIRMWARE_DOCS isn't set — analyst sees what didn't get
    # verified and what to set to fix it, rather than a silent pass.
    if unverifiable:
        pytest.skip(
            f"{len(unverifiable)} cited doc(s) couldn't be located in "
            f"public lookup paths: {unverifiable}.\n"
            f"They may exist in private upstream-RE docs. To verify, set "
            f"RNET_FIRMWARE_DOCS in your shell or Makefile.local to point "
            f"at that tree's docs/ directory and re-run."
        )

    assert not broken, (
        f"{len(broken)} cited docs not found in any known location:\n  "
        + "\n  ".join(broken)
        + "\n\nLikely (a) the doc was renamed/retired upstream and the "
        "citation needs updating, or (b) a new public lookup location "
        "should be added to this test."
    )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
