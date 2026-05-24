# Parse → rnet-firmware: open questions (round 2, 2026-05-24)

Follow-up questions from integrating the BTMouse unlock-protocol
patterns into parse. Implementation is shipped with explicit
assumptions documented inline at each point — these are the
verification-gates that would let us tighten the assumptions.

Round 1 questions (the SVC/POP/ODI batch) are archived in
[`QUESTIONS_FOR_RNET_FIRMWARE.md`](QUESTIONS_FOR_RNET_FIRMWARE.md) —
all 7 received definitive answers and are integrated.

---

## Q1 — Pattern B data-byte check: DSR0 included or not?  ✅ ANSWERED

**Resolution (rnet-firmware commit f4197494, T59 datasheet-verified):**
The full 8 data bytes (DSR0-DSR7) must all be zero. The
PRIMARY_SOURCE doc's "IDR3 + DSR1-DSR7" reading was a partial-
disassembly artifact; the datasheet-verified disassembly of
FUN_00430E + the unlock handler's magic check confirms all 8 data
bytes are required to be zero.

Parse updated to all-8-bytes-zero per the answered spec.

### Original question

Two rnet-firmware docs disagree about which data bytes the chair-side
unlock handler at `0xF50E` requires to be zero:

| Source | Claim |
|---|---|
| [`BTMOUSE_POP_DISPATCH_PRIMARY_SOURCE.md` §7](https://) | "All 8 received MSCAN data bytes (IDR3 + DSR1-DSR7) == 0" — for a STANDARD frame, IDR3 is unused, so effectively **DSR1-DSR7 == 0** (data bytes 1-7 zero; **DSR0 unconstrained**) |
| [`BTMOUSE_UNLOCK_FRAMES_FOR_PARSE.md`](https://) | `dlc == 8 AND all(b == 0 for b in data[:8])` — **all 8 data bytes including DSR0 must be zero** |

**Parse's current choice:** the more permissive PRIMARY_SOURCE
interpretation (DSR1-DSR7 zero, DSR0 unconstrained). Reasoning: for a
researcher-facing WARN marker, false negatives (missing real matches)
are worse than false positives.

**The question:** at the actual disassembly level of handler `0xF50E`,
does the data-byte check include DSR0 or not? If DSR0 must also be
zero, parse should tighten the marker to include byte 0 in the check.

---

## Q2 — Cross-frame correlation window: how persistent is the buffer state?

Parse's marker for the full Pattern A → Pattern B sequence fires when
Pattern B arrives within **1.0 seconds** of a recent Pattern A on the
same bus. The 1-second value is a guess.

The chair-side buffer at `0x329A/B/C` is written only by the extended-
frame path of `MSCAN_Rx_dispatch` (verified by exhaustive search per
the doc). So the W~ bytes from Pattern A persist until **the next
extended frame** overwrites them via the bit-shuffle.

**Possible scenarios:**
- On a busy bus with frequent extended-frame traffic, the buffer state
  is likely overwritten in milliseconds — 1s might be much too long
- On a quiet bus or a bus with only standard-ID traffic, the buffer
  could retain Pattern A's bytes indefinitely — 1s would be much too
  short

**The questions:**
1. What's the empirical persistence window for the `0x329A/B/C` buffer
   bytes in a typical capture?
2. Besides "next extended frame overwrites it," are there any other
   events that clear or invalidate those bytes (timer reset, idle
   detection, error recovery, etc.)?
3. Is there a wire-observable signal that would tell parse "the buffer
   was reset," so the correlation window could end exactly when the
   buffer state actually expires rather than on a fixed clock window?

---

## Q3 — Pattern A: complete set of seed-frame IDs?  ✅ ANSWERED (TIGHTENED)

**Resolution (rnet-firmware commit f4197494):** Pattern A was
tightened from `(can_id & 0xFFFF) == 0x7E57` to `(can_id & 0x3FFFF)
== 0x07E57` — the additional bits 17:16 == 0 constraint comes from
the precise bit-shuffle math. Top 11 bits remain unconstrained.

Parse updated to the tightened mask.

### Original question

The doc derives Pattern A as "extended CAN frame, low 16 bits of ID ==
`0x7E57`" from the bit-shuffle formulas:

```
0x329C = (IDR1 >> 1) & 3
0x329B = ((IDR1 & 1) << 7) | (IDR2 >> 1)
0x329A = ((IDR2 & 1) << 7) | (IDR3 >> 1)
```

The handler check is `*(uint16_t*)0x329A == 0x577E` (or similar) AND
`*(uint8_t*)0x329C == 0`. Working backward from those constraints to
IDR1/IDR2/IDR3 values gives the "low 16 bits of ID == 0x7E57" condition
the doc states.

**The questions:**
1. Are there ID bit patterns OTHER than "low 16 bits == 0x7E57" that
   also satisfy the byte-state condition? E.g., does the bit-shuffle
   have multiple input ID patterns that all produce the same 3-byte
   output?
2. If so, parse should match the broader set so it doesn't miss
   alternative seeds.

---

## Q4 — Pattern B: are all 8 candidate IDs actually reachable?  ✅ ANSWERED (NARROWED to 1)

**Resolution (rnet-firmware commit f4197494, T59 datasheet-verified
via HCS12 S12CPUV2 Reference Manual):** the full disassembly of
FUN_00430E (specifically the `LEAX D,X` instruction at firmware
0x432E — which an earlier intermediate pass mis-decoded as LEAY)
reconstructs the full 11-bit CAN ID into the X register. The magic
check requires X == 0x07A0 after `& 7` mask on X high, which
uniquely corresponds to CAN ID 0x07A0. The 8-candidate set was an
artifact of the partial-disassembly pass; the actual reachable
trigger is exactly 0x07A0.

Parse narrowed Pattern B to `cid == 0x7A0` exactly.

### Original question

The doc lists 8 candidate Pattern B IDs `{0x0A7, 0x1A7, 0x2A7, 0x3A7,
0x4A7, 0x5A7, 0x6A7, 0x7A7}` derived from a PARTIAL decode of
`FUN_00430E`. The doc explicitly notes the function does more than
the simplified decompile shows ("two separate IDR0 loads, multiple
shifts in both directions, a page-prefix HCS12X extended instruction,
TFR operations to X").

**The question:** does the full decode of `FUN_00430E` narrow the
8-candidate set further? Parse currently matches all 8; if only some
actually produce `0x07A0` in the buffer, parse should narrow accordingly.

---

## Q5 — The runtime flag at 0xFF4C4: what banked code sets it?

The unlock handler `0xF50E` only fires its banked-call effect if the
runtime flag at RAM `0xFF4C4` is non-zero. Banked code (chip page 0x38,
not in the dump) sets/clears this flag.

**The questions:**
1. Is there ANY wire-observable trigger that correlates with this flag
   being set? E.g., is the flag set in response to:
   - A specific Programmer-session-entry frame sequence
   - A power-cycle / chair-reboot
   - A specific menu navigation
   - A timer-based service-mode entry
2. If we can identify the wire-side trigger, parse could track the
   flag's likely state and only fire the sequence marker when we have
   reason to think the unlock would actually succeed (vs. always
   firing when the pattern matches regardless of flag state).

---

## Q6 — What does banked `0x4E0465` actually do?

The handler at `0xF50E` calls banked `0x4E0465` when all conditions
match. The doc speculates: "BT pairing mode entry, factory-test mode,
calibration access, or service-only parameter writes."

**The question:** can the chair's subsequent behavior on the bus
(within seconds of `0x4E0465` being called) be characterized? Even
without seeing inside the banked function, the chair-side
side-effects might be observable on the wire — e.g., a specific
follow-up frame sent by the chair, or a state-change pattern in
existing telemetry frames.

---

## Q7 — "Please share if you see this" — what should the dissector add to the marker text?

The dissector currently fires WARN markers with text like:

```
RARE+HIGH-INTEREST: BTMouse unlock-protocol sequence — Pattern B
trigger arrived within ~1s of a Pattern A seed; this is the multi-
step service/diagnostic unlock condition (modulo runtime flag at
0xFF4C4); please share this capture
```

**The question:** what additional context would be most useful in the
marker text for a researcher seeing this fire? E.g.:
- A short URL pointing at the docs / a GitHub issue template
- The wire-source-node identification convention (so the researcher
  can immediately note "this came from node X")
- A request for surrounding-context bytes (e.g., "share at least 10
  seconds of bus traffic on either side of this frame")

If you have preferences, parse will incorporate them into the marker
text.

---

**Tag for replies:** when rnet-firmware is available, parse can adjust
its matcher conditions and marker text based on the answers above.
The implementation already-shipped is intentionally on the
conservative-positives side (broader matches, lower severity for the
per-frame markers, WARN only for the full sequence) so any tightening
based on answers won't strand existing observations.
