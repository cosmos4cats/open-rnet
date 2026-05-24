#!/usr/bin/env python3
"""Plan 5: synthetic-capture edge-case tests.

Generates a handful of hand-crafted CAN frames the real corpus doesn't
exercise (truncated POP, out-of-range auth seq, RTC with all-zero
payload, etc.) and asserts the dissector handles each cleanly —
no Lua error, no crash, and produces a non-Unknown class label.

The pcap generator (tests/synthetic/make_captures.py) is regenerated
at test-time, so we don't commit binary fixtures.
"""

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Reuse the harness's path-shim
TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR / "synthetic"))
import make_captures   # noqa: E402

DISSECTOR_DIR = TEST_DIR.parent
LUA = str(DISSECTOR_DIR / "rnet_can.lua")


@pytest.fixture(scope="module")
def edge_pcap_dir():
    """Generate the edge-case pcaps once per test-session, in a temp dir."""
    with tempfile.TemporaryDirectory(prefix="rnet_edge_") as d:
        paths = make_captures.write_all(d)
        yield paths


def _run_dissector(pcap_path):
    """Run tshark with the dissector against one synthetic pcap.
    Returns (stdout, stderr, returncode)."""
    proc = subprocess.run(
        ["tshark", "-X", f"lua_script:{LUA}", "-r", str(pcap_path)],
        capture_output=True, text=True, timeout=15,
    )
    return proc.stdout, proc.stderr, proc.returncode


@pytest.mark.parametrize("label", list(make_captures.EDGE_CASES.keys()))
def test_synthetic_frame_handled_without_lua_error(edge_pcap_dir, label):
    """Each synthetic edge case must:
    - exit tshark cleanly (returncode == 0)
    - emit no Lua traceback in stderr (the dissector didn't crash)
    - produce at least one output line that names R-Net (i.e., the
      heuristic claimed the frame and didn't fall through to raw CAN)

    Whether the resulting LABEL is "right" depends on the case —
    some edge cases are genuinely unknown frames and a generic "Unknown"
    label is acceptable. This test is about not-crashing, not about
    semantic correctness.
    """
    pcap = edge_pcap_dir[label]
    stdout, stderr, rc = _run_dissector(pcap)
    assert rc == 0, f"{label}: tshark exited {rc}; stderr: {stderr[:500]}"
    # Lua errors show up in stderr. The "two protocols with the same
    # description" message is the benign duplicate-plugin warning
    # (installed plugin + -X lua_script: both register the Proto) — the
    # dissector still runs in that case. Any OTHER Lua error means we
    # broke something.
    has_lua_err = "error during loading" in stderr.lower() or \
                  "lua: error" in stderr.lower() or \
                  "stack traceback" in stderr.lower()
    benign = "two protocols with the same description" in stderr
    assert not has_lua_err or benign, (
        f"{label}: dissector emitted Lua error(s):\n{stderr[:500]}"
    )
    lines = [l for l in stdout.splitlines() if l.strip()]
    assert lines, f"{label}: no output at all from tshark"
    # The dissector should claim every frame (no "CAN" protocol column);
    # if R-Net doesn't appear, the dissector didn't run.
    assert any("R-Net" in l for l in lines), (
        f"{label}: no R-Net protocol claim in output; first line: {lines[0]!r}"
    )


def test_rnet_unlock_frame_decoded_with_service_mode_label(edge_pcap_dir):
    """The R-Net Unlock frame (0x08280F02, DLC=0) is the literal
    "service-mode enable" credential per RNET_AUTH_PROTOCOL.md —
    CRnetInterface::SendUnlock @ DongleInterface.dll 0x10010340 (v5)
    transmits this exact extended-29-bit ID and the chair gates
    destructive operations on having received it.

    The dissector must label it as Unlock specifically, not let it
    fall through to "Unknown XTD."""
    proc = subprocess.run(
        ["tshark", "-X", f"lua_script:{LUA}",
         "-r", str(edge_pcap_dir["rnet_unlock_frame"]),
         "-T", "fields", "-e", "rnet.class", "-e", "rnet.summary"],
        capture_output=True, text=True, timeout=10,
    )
    assert proc.returncode == 0, proc.stderr
    rows = [l.split("\t") for l in proc.stdout.splitlines() if l.strip()]
    assert rows, "no output from unlock-frame capture"
    class_, summary = rows[0][0], rows[0][1]
    assert "Unlock" in class_, (
        f"expected 'Unlock' in class; got {class_!r}"
    )
    assert "service" in summary.lower(), (
        f"expected summary to mention service mode; got {summary!r}"
    )


def test_expert_info_fires_on_unknown_sentinel_subtypes(edge_pcap_dir):
    """Plan 6: the 0x1E8X expert-info marker should fire on unknown
    subtypes (N=1, 2, 3) and NOT fire on documented ones (N=0/4/5/6/7).

    Asserts both the positive (fires) and negative (doesn't fire) cases.
    Anchored on synthetic sentinel_subtype_1 (positive) vs
    transfer_complete_non_programmer which is N=0 (negative)."""
    # Positive: subtype 1 should trigger the marker
    stdout, stderr, rc = _run_dissector(edge_pcap_dir["sentinel_subtype_1"])
    assert rc == 0, stderr
    proc = subprocess.run(
        ["tshark", "-X", f"lua_script:{LUA}",
         "-r", str(edge_pcap_dir["sentinel_subtype_1"]), "-V"],
        capture_output=True, text=True, timeout=15,
    )
    assert "session sentinel with subtype deliberately unused" in proc.stdout, (
        "expected expert-info marker on N=1 sentinel; got:\n" + proc.stdout[:600]
    )
    # Negative: subtype 0 (Transfer Complete) should NOT trigger it
    proc = subprocess.run(
        ["tshark", "-X", f"lua_script:{LUA}",
         "-r", str(edge_pcap_dir["transfer_complete_non_programmer"]), "-V"],
        capture_output=True, text=True, timeout=15,
    )
    assert "session sentinel with subtype deliberately unused" not in proc.stdout, (
        "marker should NOT fire on N=0 (Transfer Complete); got expert info "
        "anyway"
    )


def test_bt_unlock_pattern_a_marker(edge_pcap_dir):
    """Pattern A of the BTMouse two-frame unlock protocol: any extended
    CAN frame whose ID's low 16 bits == 0x7E57. Primes the chair-side
    buffer at RAM 0x329A/B/C with the W~ magic bytes. Fires a NOTE-
    severity expert-info marker."""
    proc = subprocess.run(
        ["tshark", "-X", f"lua_script:{LUA}",
         "-r", str(edge_pcap_dir["bt_unlock_pattern_a"]), "-V"],
        capture_output=True, text=True, timeout=15,
    )
    assert "BTMouse unlock-protocol Pattern A" in proc.stdout, (
        "expected Pattern A marker; got:\n" + proc.stdout[:600]
    )


def test_bt_unlock_pattern_b_marker(edge_pcap_dir):
    """Pattern B of the BTMouse two-frame unlock protocol: standard
    CAN frame, ID's low byte == 0xA7, DLC=8, data bytes 1-7 zero
    (byte 0 unconstrained per the PRIMARY_SOURCE doc's IDR3+DSR1-DSR7
    register-list interpretation). Fires a NOTE-severity marker.

    Negative case: standard 0x?A7 frame with non-zero data bytes 1-7
    should NOT fire the marker."""
    # Positive
    proc = subprocess.run(
        ["tshark", "-X", f"lua_script:{LUA}",
         "-r", str(edge_pcap_dir["bt_unlock_pattern_b_canonical"]), "-V"],
        capture_output=True, text=True, timeout=15,
    )
    assert "BTMouse unlock-protocol Pattern B" in proc.stdout, (
        "expected Pattern B marker; got:\n" + proc.stdout[:600]
    )
    # Negative — Pattern B candidate ID but non-zero data byte 3
    proc = subprocess.run(
        ["tshark", "-X", f"lua_script:{LUA}",
         "-r", str(edge_pcap_dir["bt_unlock_pattern_b_nonzero_data"]), "-V"],
        capture_output=True, text=True, timeout=15,
    )
    assert "BTMouse unlock-protocol Pattern B" not in proc.stdout, (
        "Pattern B marker fired on non-zero DSR1-DSR7 (false positive)"
    )


def test_bt_unlock_sequence_marker_fires_on_correlation(edge_pcap_dir):
    """Cross-frame correlation: when Pattern B arrives within ~1s of a
    recent Pattern A on the same bus, the dissector fires a WARN-
    severity bt_unlock_sequence marker on the Pattern B frame in
    addition to the per-frame Pattern A and Pattern B markers. This
    is the actually-interesting case per the rnet-firmware docs."""
    proc = subprocess.run(
        ["tshark", "-X", f"lua_script:{LUA}",
         "-r", str(edge_pcap_dir["bt_unlock_full_sequence"]), "-V"],
        capture_output=True, text=True, timeout=15,
    )
    assert "BTMouse unlock-protocol sequence" in proc.stdout, (
        "expected sequence marker on Pattern B following recent "
        "Pattern A; got:\n" + proc.stdout[:800]
    )


def test_bt_unlock_no_sequence_when_pattern_a_alone(edge_pcap_dir):
    """Negative: Pattern A alone (without a following Pattern B) must
    NOT fire the sequence marker. Same for Pattern B alone (without a
    preceding Pattern A within the window)."""
    proc = subprocess.run(
        ["tshark", "-X", f"lua_script:{LUA}",
         "-r", str(edge_pcap_dir["bt_unlock_pattern_a"]), "-V"],
        capture_output=True, text=True, timeout=15,
    )
    assert "BTMouse unlock-protocol sequence" not in proc.stdout, (
        "sequence marker fired on Pattern A alone (false positive)"
    )
    proc = subprocess.run(
        ["tshark", "-X", f"lua_script:{LUA}",
         "-r", str(edge_pcap_dir["bt_unlock_pattern_b_canonical"]), "-V"],
        capture_output=True, text=True, timeout=15,
    )
    assert "BTMouse unlock-protocol sequence" not in proc.stdout, (
        "sequence marker fired on Pattern B alone (false positive)"
    )


def test_programmer_presence_still_normal_after_revert(edge_pcap_dir):
    """STD 0x07A0 DLC=0 should still decode as 'Programmer presence' —
    confirming the earlier wrong 0x07A0-as-magic-trigger handler has
    been reverted. Pattern B's actual trigger is any STD ID with low
    byte 0xA7, not 0x07A0 (which has low byte 0xA0)."""
    proc = subprocess.run(
        ["tshark", "-X", f"lua_script:{LUA}",
         "-r", str(edge_pcap_dir["programmer_presence_normal"]), "-V"],
        capture_output=True, text=True, timeout=15,
    )
    assert "Programmer presence" in proc.stdout, (
        "expected normal Programmer-presence label on DLC=0 0x7A0; got:\n"
        + proc.stdout[:600]
    )
    # And the old wrong marker name should never appear anywhere
    assert "BT-pairing-unlock magic-frame CANDIDATE" not in proc.stdout, (
        "old marker name still present — revert incomplete"
    )


def test_dormant_chair_listened_marker_fires(edge_pcap_dir):
    """STD 0x001 is in BTMouse's chair-side literal CAN-ID table at
    FW 0x56E0 but has 0 corpus observations. The dissector fires a
    WARN-severity expert-info marker on these IDs (the dormant_chair_
    listened set: 0x001, 0x00A, 0x0F0, 0x7C0, 0x7E0, 0x7E4, 0x7E8,
    0x7EC). A wire frame on any of these means the user has captured
    something the corpus has never seen — flagged loudly so it's not
    missed."""
    proc = subprocess.run(
        ["tshark", "-X", f"lua_script:{LUA}",
         "-r", str(edge_pcap_dir["dormant_chair_listened_001"]), "-V"],
        capture_output=True, text=True, timeout=15,
    )
    assert "Chair-listened (dormant)" in proc.stdout, (
        "expected dormant-family label on STD 0x001; got:\n"
        + proc.stdout[:600]
    )
    assert "first known wire observation" in proc.stdout, (
        "expected 'first known wire observation' phrasing in label"
    )
    assert "please share" in proc.stdout, (
        "expected 'please share' invitation in expert-info or summary"
    )


# ---------------------------------------------------------------------------
# High-value-frame clarity tests
# ---------------------------------------------------------------------------
# These pin the EXACT decoded output for frames where the
# user-facing semantics matter most for a researcher reading a
# capture: security-relevant frames (Unlock, auth), session-state
# transitions (handshake, transfer complete), cross-frame protocols
# (POINTER→DATA binding), and primary-source-evidenced decoders
# (RTC, keep-awake, SlotChanged).
#
# Each test asserts on specific class label, summary phrasing,
# evidence tier, and (where applicable) evidence-source citation.
# If a future change degrades the clarity of the message for one
# of these high-value frames, these tests fail loudly.
#
# Synthetic fixtures defined in make_captures.HIGH_VALUE_FRAMES.


def _hv_fields(pcap_path, *field_names):
    """Run tshark on a high-value-frame synthetic pcap with
    evidence display enabled and return parsed field rows."""
    proc = subprocess.run(
        ["tshark", "-X", f"lua_script:{LUA}",
         "-o", "rnet.show_evidence:TRUE",
         "-r", str(pcap_path),
         "-T", "fields"] + sum([["-e", f] for f in field_names], []),
        capture_output=True, text=True, timeout=15,
    )
    assert proc.returncode == 0, proc.stderr
    rows = [l.split("\t") for l in proc.stdout.splitlines() if l.strip()]
    return rows


def test_hv_clarity_rnet_unlock(edge_pcap_dir):
    """The R-Net Unlock frame (CAN ID 0x08280F02, DLC=0) is the
    literal service-mode credential. The dissector must label it
    unambiguously as 'Unlock', explain in the summary that the
    CAN-ID IS the credential (no crypto auth), and cite the
    primary-source DLL function. A researcher seeing this frame
    should immediately understand its security weight."""
    rows = _hv_fields(
        edge_pcap_dir["hv_rnet_unlock"],
        "rnet.class", "rnet.summary", "rnet.confidence", "rnet.evidence",
    )
    assert len(rows) == 1
    cls, summary, conf, src = rows[0]
    assert cls == "R-Net Unlock — service-mode enable", (
        f"unexpected class: {cls!r}"
    )
    assert "service mode" in summary.lower(), (
        f"summary missing 'service mode': {summary!r}"
    )
    assert "credential" in summary.lower(), (
        f"summary missing 'credential' framing: {summary!r}"
    )
    assert "Not crypto auth" in summary or "not crypto" in summary.lower(), (
        f"summary should clarify this is NOT crypto auth: {summary!r}"
    )
    assert conf == "Code"
    assert "SendUnlock" in src and "0x10010340" in src, (
        f"evidence must cite SendUnlock + address: {src!r}"
    )


def test_hv_clarity_slotchanged(edge_pcap_dir):
    """SlotChanged signal must label the LE u32 filekey clearly
    and cite the chair-side handler primary source."""
    rows = _hv_fields(
        edge_pcap_dir["hv_slotchanged"],
        "rnet.class", "rnet.summary", "rnet.confidence", "rnet.evidence",
    )
    cls, summary, conf, src = rows[0]
    assert cls == "SlotChanged signal", cls
    assert "filekey=0x00010001" in summary, (
        f"summary must show decoded filekey: {summary!r}"
    )
    assert conf == "Code"
    assert "CheckForSlotChanged" in src and "IsSlotChangedMsg" in src
    # Address-correction regression: the fixed address from the audit
    # round must be present, not the old wrong one.
    assert "0x10001630" in src, (
        "expected corrected IsSlotChangedMsg address 0x10001630"
    )
    assert "0x10001b90" not in src, (
        "wrong-address regression: 0x10001b90 should not appear"
    )


def test_hv_clarity_attach_handshake_step1(edge_pcap_dir):
    """First frame of the 4-step attach handshake. The label
    must identify both the step number and operational meaning
    (Programmer announce, CXTN_CAN→CXTN_RNET transition)."""
    rows = _hv_fields(
        edge_pcap_dir["hv_attach_step1"],
        "rnet.class", "rnet.summary", "rnet.session_state",
    )
    cls, summary, sstate = rows[0]
    assert "attach handshake step 1" in cls.lower(), cls
    assert "Programmer announce" in cls, (
        f"class must name the operational role: {cls!r}"
    )
    assert "CXTN_CAN" in summary and "CXTN_RNET" in summary, (
        f"summary must show the session-state transition: {summary!r}"
    )


def test_hv_clarity_transfer_complete_sentinel(edge_pcap_dir):
    """Transfer Complete sentinel — must clearly mark the
    return from CXTN_UPLOAD/DOWNLOAD to CXTN_RNET so a reader
    can spot end-of-transfer in long captures."""
    rows = _hv_fields(
        edge_pcap_dir["hv_transfer_complete"],
        "rnet.class", "rnet.summary",
    )
    cls, summary = rows[0]
    assert "Transfer Complete" in cls, cls
    assert "CXTN_UPLOAD/DOWNLOAD" in cls and "CXTN_RNET" in cls, (
        f"class must show both states of the transition: {cls!r}"
    )
    assert "transfer complete" in summary.lower(), summary


def test_hv_clarity_auth_table_b_match(edge_pcap_dir):
    """Auth response that matches a known XOR network table.
    The dissector must surface the network identity with a
    ✓ glyph for quick visual scan, name the table (e.g.
    'Table B'), and populate the rnet.auth.network field for
    filtering. This is the strongest network-attribution signal
    the dissector has."""
    rows = _hv_fields(
        edge_pcap_dir["hv_auth_response_table_b"],
        "rnet.class", "rnet.summary", "rnet.confidence",
        "rnet.evidence", "rnet.auth.network",
    )
    cls, summary, conf, src, net = rows[0]
    assert cls == "Serial auth — response", cls
    assert "✓" in summary, (
        f"summary must include ✓ glyph for visual scan: {summary!r}"
    )
    assert "Table B" in summary, (
        f"summary must name the matched table: {summary!r}"
    )
    assert "matches known JSM serial" in summary
    assert conf == "Code"
    assert "XOR-table cross-check" in src
    assert net.startswith("Table B"), (
        f"rnet.auth.network must be populated for filtering: {net!r}"
    )


def test_hv_clarity_keep_awake_heartbeat(edge_pcap_dir):
    """Programmer-active keep-awake heartbeat — must clearly
    state its rate-limiting behavior and chair-sleep-prevention
    purpose. Primary-source evidenced from CFTDIInterface::
    ResetSleepTimer."""
    rows = _hv_fields(
        edge_pcap_dir["hv_keep_awake"],
        "rnet.class", "rnet.summary", "rnet.confidence", "rnet.evidence",
    )
    cls, summary, conf, src = rows[0]
    assert "keep-awake" in cls.lower(), cls
    assert "Programmer" in cls
    assert "prevents chair sleep" in summary.lower() \
        or "prevents chair" in summary.lower(), (
        f"summary must state the chair-sleep-prevention purpose: {summary!r}"
    )
    assert conf == "Code"
    assert "ResetSleepTimer" in src and "0x100053e0" in src


def test_hv_clarity_rtc_broadcast_decoded(edge_pcap_dir):
    """RTC broadcast must produce a human-readable wall-clock
    string in the summary so a researcher can correlate frame
    timestamps to chair-side time without bit-twiddling."""
    rows = _hv_fields(
        edge_pcap_dir["hv_rtc_broadcast"],
        "rnet.class", "rnet.summary", "rnet.confidence", "rnet.evidence",
    )
    cls, summary, conf, src = rows[0]
    assert "RTC" in cls, cls
    # Synthetic frame encodes 2026-05-24 14:30:45 Sunday
    assert "2026-05-24" in summary, (
        f"summary must contain decoded date: {summary!r}"
    )
    assert "14:30:45" in summary, (
        f"summary must contain decoded time: {summary!r}"
    )
    assert "Sun" in summary, (
        f"summary must contain decoded day-of-week: {summary!r}"
    )
    assert conf == "Code"
    assert "DecodeRTCBroadcast" in src and "0x1000f8e0" in src


def test_synthetic_pcap_writer_self_check():
    """Sanity: the pcap writer itself should produce files tshark can
    parse as CAN. If this test fails, the synthetic-frame tests above
    aren't testing the dissector — they're testing a broken writer."""
    with tempfile.TemporaryDirectory(prefix="rnet_writer_check_") as d:
        path = Path(d) / "single.pcap"
        make_captures.write_pcap(path, [
            {"id": 0x000C, "data": b""},
        ])
        proc = subprocess.run(
            ["tshark", "-r", str(path), "-T", "fields", "-e", "can.id"],
            capture_output=True, text=True, timeout=10,
        )
        assert proc.returncode == 0, proc.stderr
        lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
        assert lines == ["12"], (
            f"pcap writer self-check: expected can.id=12; got {lines!r}"
        )
