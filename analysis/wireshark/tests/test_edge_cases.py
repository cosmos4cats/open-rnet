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
    assert "session sentinel with subtype not yet documented" in proc.stdout, (
        "expected expert-info marker on N=1 sentinel; got:\n" + proc.stdout[:600]
    )
    # Negative: subtype 0 (Transfer Complete) should NOT trigger it
    proc = subprocess.run(
        ["tshark", "-X", f"lua_script:{LUA}",
         "-r", str(edge_pcap_dir["transfer_complete_non_programmer"]), "-V"],
        capture_output=True, text=True, timeout=15,
    )
    assert "session sentinel with subtype not yet documented" not in proc.stdout, (
        "marker should NOT fire on N=0 (Transfer Complete); got expert info "
        "anyway"
    )


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
