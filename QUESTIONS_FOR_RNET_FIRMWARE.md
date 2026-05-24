# Parse → rnet-firmware: open decoding questions (2026-05-23)

Following the SVC/POP/ODI cross-validation work that landed today —
four independent PGDT-authored sources agreeing on every ODI_CLASS
value — these are parse's highest-confidence-gap items where another
primary source (HCS12 chair-side firmware, DLR EXE immediates,
IRConfigurator .NET enums, or DLL v6) might validate or falsify
specific parse-empirical guesses.

Each question states: **what parse sees on the wire**, **what parse
guesses**, and **what would resolve it**.

---

## Q1 — STD 0x042 / 0x043 / 0x044 perfect-toggle pattern

`RNET_FAMILY_DECODE_GAPS.md` Gap #8 already names this as
"Partial (parse empirical), zero DLL/EXE hits". Parse observation
across captures:

| CAN ID | Captures it appears in | Pattern |
|---|---|---|
| `0x042` | aug19th, 0x1f201e0e, cJSM+lJSM+dualcan, full_action_dumpJuly2_2016, … | DLC=4, exactly two distinct payloads `00000000` and `80000000`, 1:1 count toggle |
| `0x043` | same | same |
| `0x044` | same | same |

Parse decode: **`Param-page family (fn 0x2/3/4) [unverified]`**, evidence
tier `Inferred`, justification "family-analogy to documented 0x040/0x041".

**What's odd:** the toggle is bit-31 only (MSB of byte 0). The other 31
bits are always zero. Bit-31 toggles in lockstep across all three IDs
in every capture we have. STD 0x040/0x041 (documented as "Open Param /
Close Param") have completely different payload structure.

**The question:**
- Is there an HCS12 chair-side dispatch that handles this ID range as a
  group (e.g., a `(canid & 0x7FC) == 0x040` mask)?
- Does any DLR EXE or IRConfigurator .NET method emit STD 0x042-0x044
  as a TX frame, even if rare?
- Is the bit-31 toggle a `seq parity` / "I am here" alternation, or
  does the MSB carry a different bit name in any decompiled struct?

If the answer is "chair-side only and we don't have HCS12 reach yet",
that's fine — confirming negative findings on the dealer-side has
value too.

---

## Q2 — STD 0x002 and 0x004 zero-payload signals

| CAN ID | Frame count (corpus) | Parse decode |
|---|---:|---|
| `0x002` | ~430 frames across multiple captures | `PM sleep all (alternate) [unverified]` (variant) and `Seen during JSM init [unverified]` |
| `0x004` | ~285 frames | `JSM sleep commencing [unverified]` |

All zero-DLC. Parse decode is **`Inferred`** with justification
"frame_dict §1 family-analogy" (analogy to STD `0x000` sleep). The
`RNET_FRAME_DICTIONARY.md` documents STD `0x000` only; STD `0x002` and
`0x004` are parse extensions.

**The question:**
- Does `CRnetInterface` or `CFTDIInterface` in the v5/v6 DLL ever TX
  zero-DLC STD frames with IDs in `0x000-0x00F`? If not, these are
  chair-emitted; that itself is useful to confirm.
- Does the IRConfigurator `IRMessage` / wire-format C# class enumerate
  any "sleep variants" beyond the single sleep frame parse already
  knows?

Even narrowing this to "STD 0x002/0x004 are chair→bus, not dealer→bus"
would let parse drop the directional `[unverified]` qualifier.

---

## Q3 — STD 0x052 / 0x062 / 0x063 4-byte mode payloads

Parse decode: **`Mode-map family (fn 0x2) [unverified]`** /
**`Mode family (fn 0x2/3) [unverified]`**, evidence tier `Inferred`.
Documented analogues: STD `0x050` (Mode map), STD `0x060/0x061`
(Mode request/control).

Concrete payloads from aug19th_hotplug_cjsm.pcapng:

```
STD 0x052 (14 frames):
  c000ff00   d200ff02   f000ff01   00000000
  12000002   93000000   83000001

STD 0x063 (53 frames):
  90000040   90000000   20000000   30000001
  80000080   60000000   70000009   80000010
```

The byte structure looks like `[op:8][reserved:8][flag:8][enum:8]` —
the third byte is often `0xFF` for 0x052 (suggesting a mask/sentinel)
but the same byte is `0x00` for 0x062/0x063. Byte 3 looks like a small
enum (range 0x00-0x10).

**The question:**
- Does the IRConfigurator `IRMessage` constructor or any DLL function
  named `*ModeMap*` / `*ModeRequest*` reference STD 0x052/0x062/0x063
  as TX targets? If yes, the byte struct is probably decoded there.
- Does `RNETcanframe_diary.txt` or `RNETdictionary.txt` have an entry
  for 0x052/0x062/0x063 that's slipped past parse's import?

The 0xFF in byte 2 of 0x052 is the strongest "this is a parameterized
opcode" hint we have — confirming or refuting that specific bit
position has high leverage.

---

## Q4 — XTD 0x181C0F00 constant 8-byte payload

102 frames in `2026_AT_hackathon.log`, every single one with payload
`01 60 80 00 00 00 00 00`. Parse decode:
**`cJSM/JSM family (function 0x0F) [unverified]`**, evidence tier
`Inferred`, "0x181C family-analogy".

Adjacent documented decodes:
- `0x181C0100` (function 0x01) — Tones (janschu99 dictionary)
- `0x181C0D00` (function 0x0D) — Tones / buzzer

But 0x181C0F00 is functionally distinct: constant payload, sporadic
cadence (irregular 14-27 seconds apart in the hackathon capture).
Parse's hypothesis is "periodic announcement" but with zero supporting
evidence.

**The question:**
- Does `CCANMsg::IsXxxMsg @ DongleInterface.dll` enumerate a
  pattern-match for `(canid >> 8) == 0x181C0F`? (Following the same
  approach that recovered `IsSlotChangedMsg`.)
- Is `0x01 60 80` a recognizable header in any IRConfigurator
  TX-frame constructor — e.g., a "node-announce" or "module-heartbeat"
  fixed-prefix?
- Function-byte X=0x0F is also used by `0x1C240F01` (Programmer
  keep-awake) — is there a pattern that X=0x0F means "session-level
  liveness" across CAN-ID families?

---

## Q5 — XTD 0x0A400201 / 0x0A400401 single-byte BTM sub-variants

Parse decode: **`BTM family (sub 0x0201/0x0401) [unverified]`**,
evidence tier `Inferred`, "family-analogy to documented BTM Control /
Status". Documented siblings: 0x0A400300/01 BTM Control 1/2,
0x0A400002/0102 BTM Status 1/2.

Concrete payloads (aug19th_hotplug_cjsm, 0x0A400401):

```
DLC=1, single-byte values seen: 10, 11, 12, 13, 20, 30, 31
```

The high nibble looks like a channel selector (1x/2x/3x) and the low
nibble like a sub-index, but parse has no source for that
interpretation.

**The question:**
- Does the BTM (Bluetooth Module?) section of the v5 DLL — the
  functions surrounding `BTM Control/Status` decoding — have a
  `sub 0x0201` / `sub 0x0401` switch case or a `BTM_SUBTYPE` enum?
- Are sub-variants `0x0201` and `0x0401` named (e.g., "Pairing"
  vs "RSSI report") in any IRConfigurator BluetoothModule.cs class?
- What's the canonical BTM subtype byte position — bits 16-23 of the
  CAN ID (`0x02` vs `0x04`), or the full 16-bit `0x0201` / `0x0401`
  as a multi-field tag?

---

## Q6 — XTD 0x14300X01 motor scale (quartile %) decode

Parse decode: **"Motor scale (quartile %)"**, evidence tier `Inferred`,
"parse pattern (0/25/50/100) + external RE notes R3". Adjacent decode:
`0x14300X00` (DLC=2 LE u16) — "Motor power" from janschu99 dictionary.

Concrete payloads from aug19th_hotplug_cjsm (0x14300201, slot 2):

```
DLC=1, single byte values: 00, 1b, 64
```

`0x64` = 100. `0x00` = 0. But **`0x1B` = 27** — does not fit the
quartile theory (0/25/50/75/100). The dissector treats `0x1B` as
"idle baseline" for the *parent* 0x14300X00 frame; the question is
whether `0x14300X01` uses the same encoding or a different one.

**The question:**
- Does any DLL function (probably in motor/drive telemetry
  decoders) reference `0x14300X01` and reveal a scaling formula?
- Is the `0x1B = 27` value a fixed magic constant (servo idle? PWM
  duty floor?) or is it a real percentage measurement?
- Is the X-nibble (slot) decoded the same way for `0x14300X00`
  (DLC=2 LE u16) and `0x14300X01` (DLC=1)? Parse currently assumes
  yes, but the DLC mismatch suggests they may be different frames
  in the same family.

---

## Q7 — Negative-finding confirmation: 0x1E8X subtype 1/2/3

Parse synthesizes test frames for `0x1E810000`, `0x1E820000`,
`0x1E830000` (subtype 1/2/3 in the R-Net session-control namespace) —
all return the "session sentinel with subtype not yet documented"
expert-info marker. **Zero of these appear in any of the 19 corpus
captures.**

The documented subtypes are N=0 (Transfer Complete) and N=4-7 (the
4-step attach handshake confirmed via parse + IRConfigurator
`CXTN_STATUS` enum).

**The question:**
- In the v5/v6 DLL, does `CCANMsg::Is*Msg` or any sentinel-related
  pattern matcher cover the 0x1E810000-0x1E830000 range? Or are these
  truly unallocated within the dealer side?
- Does the IRConfigurator session-state machine recognize anything
  beyond the documented N=0/4/5/6/7 transitions?

A clean "subtypes 1, 2, 3 are unallocated on the dealer side" answer
lets parse demote the expert-info marker from "unknown — please
report" to "deliberately unused — skip".

---

## What we're not asking about

Items we believe are well-grounded based on today's work — no need to
re-validate:

- `0x15000000` SlotChanged (just promoted to Code tier — `CheckForSlotChanged @ 0x10008b00` + `IsSlotChangedMsg @ 0x10001b90`)
- POP byte 0 TC/Quick/CRC/OtherNode bit packing (CPOPMsg structural decode is solid)
- ODI_CLASS enum mapping (4-of-4 sources agree)
- 0x1F XOR auth-table semantics (xor_tables A/B/C empirically recovered, 100% match)
- 0x08280F02 R-Net Unlock frame (CRnetInterface::SendUnlock @ 0x10010340)
- 0x1C240F01 Programmer keep-awake (ResetSleepTimer @ 0x100053e0)
- 0x1E84-87 attach handshake (CXTN_STATUS cross-validated)
- 0x14300X00 motor power (janschu99 dictionary + parse cross-check)

---

**Tag for replies:** if rnet-firmware confirms or refutes any of
these, parse will update `evidence` tiers and the README "Known gaps"
section. Negative findings are as valuable as positive ones for the
`[unverified]` annotations.
