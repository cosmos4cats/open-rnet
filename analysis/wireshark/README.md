# rnet_can — Wireshark/tshark dissector for the R-Net CAN protocol

A Lua dissector for the **R-Net** power-wheelchair control protocol
(Curtiss-Wright / PG Drives Technology), running on 125 kbit/s CAN.
Decodes SocketCAN-encapsulated frames in pcap/pcapng captures and
`candump -L` logs.

## Quick start (no install)

From the repo root, against the hackathon capture that ships with this
dissector:

```sh
tshark -X lua_script:analysis/wireshark/rnet_can.lua -V \
       -r captures/2026_AT_hackathon.log
```

That works without installing anything — `-X lua_script:` loads the
dissector for that single invocation. Same flag works with the
Wireshark GUI:

```sh
wireshark -X lua_script:analysis/wireshark/rnet_can.lua \
          captures/2026_AT_hackathon.log
```

For repeated use, install the file once into your Wireshark plugin
directory (next section) and drop the `-X lua_script:...` flag.

## Installation

Copy `rnet_can.lua` into your Wireshark personal plugins directory.
The directory is the same for `tshark` and the `wireshark` GUI — they
share the plugin store.

| OS              | Plugin path                                                          |
|-----------------|----------------------------------------------------------------------|
| Linux           | `~/.local/lib/wireshark/plugins/`                                    |
| macOS           | `~/.local/lib/wireshark/plugins/`                                    |
| Windows         | `%APPDATA%\Wireshark\plugins\`                                       |

```sh
# Linux / macOS:
mkdir -p ~/.local/lib/wireshark/plugins
cp analysis/wireshark/rnet_can.lua ~/.local/lib/wireshark/plugins/
```

Restart Wireshark (or run `tshark` afresh) and the dissector loads
automatically. Verify in Wireshark: **Help → About → Plugins** should
list `rnet_can.lua`.

You can confirm from the command line by running `tshark` against a
capture without any `-X` flag and looking for `R-Net` in the output:

```sh
tshark -r captures/2026_AT_hackathon.log | head -3
#   1   0.000000  ... R-Net 16 [NetTest] ID=0xC
```

If you see `R-Net` in the protocol column, the plugin is loaded.

### Uninstall

Delete `rnet_can.lua` from the same plugin directory and restart
Wireshark.

## Usage

### Filter on dissected fields

The dissector adds an `rnet.*` field namespace. Every field shown in
the expanded frame detail is filterable:

```sh
tshark -r captures/2026_AT_hackathon.log -Y "rnet.joy.x > 30"
tshark -r captures/2026_AT_hackathon.log -Y "rnet.pop.tc == 3"
tshark -r captures/2026_AT_hackathon.log -Y "rnet.mode.index < 6"
tshark -r captures/2026_AT_hackathon.log -Y "rnet.err.code"          # non-zero faults
tshark -r captures/2026_AT_hackathon.log -Y "rnet.auth.network"       # identified XOR networks
tshark -r captures/2026_AT_hackathon.log -Y 'rnet.pop.reg_name == "TEXT"'
```

Same filters work in Wireshark GUI — use the display-filter bar at
the top.

(If you haven't installed the plugin, prepend
`-X lua_script:analysis/wireshark/rnet_can.lua` to each command.)

### `rnet-dump` — candump-L-shaped output with decode

A small wrapper script that produces the dissected equivalent of
`candump can0 -L`. Each frame becomes one line: `(timestamp) iface
CANID  decoded-info`.

```sh
# Live capture (Linux SocketCAN):
sudo ip link set can0 up type can bitrate 125000
analysis/wireshark/rnet-dump -i can0

# From a capture file:
analysis/wireshark/rnet-dump -r captures/2026_AT_hackathon.log
```

Sample output:

```
(0.144131) can0 1F01DAB6  Auth response seq=0 slot=1 key=0xDA val=0xB6 ✓ Table D [JSM serial]
(0.144730) can0 1F113080  Auth response seq=1 slot=1 key=0x30 val=0x80 ✓ Table D [JSM serial]
(0.145325) can0 1F21E121  Auth response seq=2 slot=1 key=0xE1 val=0x21 ✓ Table D [JSM serial]
(0.149302) can0 1F02DAE7  Auth response seq=0 slot=2 key=0xDA val=0xE7 ✓ Table D
```

vs. the raw `candump can0 -L` form of the same frames:

```
(0.144131) can0 1F01DAB6#
(0.144730) can0 1F113080#
(0.145325) can0 1F21E121#
(0.149302) can0 1F02DAE7#
```

`rnet-dump` accepts any tshark argument, so display filters work too:

```sh
analysis/wireshark/rnet-dump -i can0 -Y 'rnet.auth.network'
analysis/wireshark/rnet-dump -i can0 -Y 'rnet.pop.tc == 3'
```

### Info column

Frames are summarized into the Wireshark `Info` column, so scrolling
a capture in the packet list shows decoded semantics at a glance
without expanding each frame:

```
JSM serial=50C01C8F [Table B: M300]
Auth response seq=0 slot=0 key=0xD3 val=0x0C ✓ Table B
Joystick X= -11 Y= -75  ↑←
Battery  85% ████████░░
⚠ FAULT slot=2: Joystick Error: Joystick Error Right (0x0E00)
POP Programmer→JSM  Segment indicator 1 reg=TEXT  text="Hello"
POP-ext to JSM  Segment indicator 2  seg=1
POP JSM→Programmer  COMPLETE reg=TEXT  CRC=0x6F36
PM heartbeat slot=0 byte0=0xC0 (TC=3 → PM)  [steady-state → PM]
Lights mask=Left+Right+Hazard bitmap=Hazard  (transitioning)
```

Filters work as before: `rnet.joy.x > 30` finds aggressive forward
movement, `rnet.err.code` finds non-zero faults, `rnet.pop.crc_value`
finds CRC echoes in COMPLETE responses, `rnet.auth.network` finds
identified auth handshakes.

### Capture formats

The dissector hooks the SocketCAN encapsulation, so it works on:
- **pcap / pcapng** files from `tcpdump`, Wireshark live capture, etc.
- **candump text logs** (the `(timestamp) iface ID#data` format
  produced by `candump -L`). Wireshark parses these natively; the
  dissector picks them up without any adaptation.

## Evidence policy

R-Net's protocol has been reverse-engineered in three streams:

1. **Runnable decoder code** — `tools/rnet_utils.py` and
   `lib/can2RNET.py` in this repo — used live against real captures.
2. **Prose dictionary** — `reference/RNET_FRAME_DICTIONARY.md`
   in this repo and related notes — mix of primary research and inference.
3. **DLL symbol dumps + wire-format facts** recovered from later research
   into the Programmer dongle DLL (`DongleInterface.dll`) and the
   `IRConfigurator.exe` companion app. The names and structures cited
   are facts about the wire protocol; consult the citations in the
   dissector for specific evidence sources.

This dissector takes (1) as its spine for general control frames and
(3) as its spine for the POP (Parameter Object Protocol) wire format.

### Evidence-kind labels

Every decode rule in the dissector is tagged with **how it was derived**.
The labels are hidden by default — most readers want to see the
protocol, not audit it — but a one-click preference reveals them
alongside the source citation when you want to verify a claim.

#### The three labels

- **`Code`** — derived from primary, verifiable sources:
  - Runnable decoder code in this repo (`rnet_utils.py`, `JoyLocal.py`)
    that has been used live against real captures
  - Ghidra decompile of the DLL artifact that actually drives the
    protocol (`DongleInterface.dll`, `IRConfigurator.exe`)
  - Empirical cross-validation across many captured frames
    (XOR-table match against a known network, 500/500 fingerprint
    match against a known constant payload)

  You can verify these by reading the cited code or re-running the
  empirical check. Treat as trustworthy.

- **`Documented`** — derived from a single documented source without
  independent cross-corroboration:
  - Community dictionary entries (janschu99's `RNETdictionary.txt` /
    `RNETcanframe_diary.txt` / categorized dictionary)
  - A single Ghidra finding noted in research notes

  Trustworthy author, careful research, but no second voice has
  confirmed. Treat as likely-correct; verify if your application
  depends on it.

- **`Inferred`** — no direct source backs the decode; the rule
  exists because of one of:
  - Family-analogy from a documented neighbor (`STD 0x051` decoded
    like `STD 0x050` because they're adjacent and look structurally
    similar)
  - Structural hypothesis from observed bit patterns
  - Conjectural positional pairing (e.g., the three Meyra `.rnd`
    error names where the descriptor-to-display pairing isn't yet
    confirmed)
  - Hackathon-only observations not yet matched against another
    source

  Treat as a hint, not a fact. Useful for getting some signal out of
  otherwise-unknown frames; not a basis for safety-critical code.

#### Current distribution (as of 2026-05-23)

Across 55 evidence-tagged decode rules in the dissector:

| Kind        | Count | %    |
|-------------|------:|-----:|
| Code        |    27 | 49%  |
| Documented  |    15 | 27%  |
| Inferred    |    13 | 24%  |

These percentages move as research progresses — `Inferred` entries
tend to become `Documented` or `Code` over time when a wire capture
or firmware dump confirms a hypothesis. (Counts are per *rule*, not
per frame; one `Code` rule might cover thousands of frames while one
`Inferred` rule covers a handful.)

#### Enabling the labels

The labels are off by default. Two equivalent ways to turn them on:

**In Wireshark (GUI):** Edit → Preferences → Protocols → RNET →
check "Show evidence + confidence" → OK. The setting persists.

**In tshark (CLI):** add `-o rnet.show_evidence:TRUE` to any command:

```sh
tshark -o rnet.show_evidence:TRUE \
       -r captures/2026_AT_hackathon.log -V -Y 'frame.number==70'
```

Each frame's expanded detail will then include two extra fields:

```
[Evidence kind (Code/Documented/Inferred): Code]
[Evidence source: rnet_utils.py:279]
```

To turn off again: uncheck the GUI preference, or omit the `-o` flag.

#### Useful filters once enabled

```sh
# Everything the dissector isn't sure about:
tshark -o rnet.show_evidence:TRUE \
       -r capture.pcapng -Y 'rnet.confidence == "Inferred"'

# Show only well-sourced decodes:
tshark -o rnet.show_evidence:TRUE \
       -r capture.pcapng -Y 'rnet.confidence == "Code"'
```

## POP frames — the structural decode

A previous version of this dissector treated POP "byte 0" as a flat
opcode lookup (OPEN / REQUEST / HEARTBEAT / etc.). That treatment was
wrong: those "opcodes" turned out to be conflations of two bit-fields
packed into the same byte. Per
`DongleInterface.dll RE (CPOPMsg class)` (decoded from the
`CPOPMsg::SetTransferCode` / `IsAbortMsg` Ghidra decompile,
2026-05-19):

### Standard-ID POP frame `(CAN_ID & 0x7E0) == 0x780`

```
data[0]:
  bits 7-6 : TransferCode (0..2 = segment indicator; 3 = abort)
  bit  5   : Quick (single-frame transfer)
  bit  4   : possibly CRCFlag (tentative)
  bits 3-0 : OtherNode nibble (Client or Server NOT in CAN ID's low 4 bits)

data[1..3] : ODI (24-bit LE Object Data Identifier)
data[4..6] : Size (24-bit LE)
data[7]    : Block (segment-block counter)

CAN ID:
  bits 10-5 : POP service pattern (0b011110)
  bit  4    : direction discriminator
  bits 3-0  : this-node ID (the Client or Server represented by this frame)
```

### Extended-ID POP frame `((CAN_ID >> 18) & 0x7E0) == 0x780`

```
CAN ID:
  bits 21-18 : Client/Server node
  bits 17-16 : TransferCode
  bits 15-0  : SegmentNumber (16-bit u16)

data[0..7] : 8 bytes of segment payload (no command byte)
```

The "famous" opcode names from the older RE writeups
(`OPEN`/`REQUEST`/`HEARTBEAT`/`SET_ADDR`/`READ`/`WRITE`/`ACK`/`ERROR`/etc.)
are still surfaced as a supplementary `rnet.pop.label` field when a
byte-0 value matches a well-known historical pattern — but the
structural fields (`tc`, `quick`, `other_node`, `odi`, …) are the
primary truth.

## What is decoded (with confidence)

### High-confidence (ported from the runnable decoder)

| Group | Pattern | Evidence |
|---|---|---|
| Joystick position | XTD `0x02000X00`  | `rnet_utils.py:330` |
| Speed setting     | XTD `0x0A040X00`  | `rnet_utils.py:339` |
| Battery level     | XTD `0x1C0C0X00`  | `rnet_utils.py:352` |
| Motor current     | XTD `0x14300X00`  | `rnet_utils.py:359` |
| Distance counter  | XTD `0x1C300X04`  | `rnet_utils.py:415` |
| Motor enable      | XTD `0x0C180X0Y`  | `rnet_utils.py:430` |
| Horn              | XTD `0x0C040X0Y`  | `rnet_utils.py:346` |
| Lights            | XTD `0x0C00XXXX`  | `rnet_utils.py:400` |
| JSM heartbeat     | XTD `0x03C30F0F`  | `rnet_utils.py:368`, `JoyLocal.py:226` |
| PM heartbeat      | XTD `0x0C140X00`  | `rnet_utils.py:372` |
| Tones / buzzer    | XTD `0x181C0D00`  | `rnet_utils.py:377` |
| Status / error    | XTD `0x140C0X0Y`  | `rnet_utils.py:437` |
| Device state      | XTD `0x1C240X0Y`  | `rnet_utils.py:424` |
| Device enum       | XTD `0x1FB000XX`  | `rnet_utils.py:389` |
| Serial auth       | XTD `0x1FSSKKVV`  | `rnet_utils.py:315`, `parse_auth_frame_id:128` |
| Network test      | STD `0x00C`       | `rnet_utils.py:273` |
| Serial heartbeat  | STD `0x00E`       | `rnet_utils.py:275` |
| Sleep             | STD `0x000`       | `rnet_utils.py:271` |
| Open/close param  | STD `0x040/0x041` | `rnet_utils.py:279,281` |
| Mode map / control| STD `0x050/0x061` | `rnet_utils.py:283,285` |
| Config modes      | STD `0x7B0/0x7B1` | `rnet_utils.py:303,305` |
| Serial exchange   | STD `0x7B3`       | `rnet_utils.py:307` |

### High-confidence (from DLL decompiles / corpus docs / community dictionary)

| Group | Pattern | Evidence |
|---|---|---|
| POP std (full structural decode) | STD `(id & 0x7E0) == 0x780`     | `DongleInterface.dll RE (CPOPMsg class)` (CPOPMsg) |
| POP xtd (full structural decode) | XTD `((id>>18) & 0x7E0) == 0x780`| same |
| Mode configuration (with type-0x61 field-level decode) | XTD `0x1EC0XXXX..0x1EC5XXXX` | `cJSM display-protocol notes` |
| BTM Control 1/2                  | XTD `0x0A400300/01`             | `DongleInterface.dll wire-format notes §14.2` |
| BTM Status 1/2                   | XTD `0x0A400002/0102`           | same |
| Transfer Complete sentinel       | XTD `0x1E80000F` (DLC=0)        | `extract_config_data.py:68-69` + `RNET_PROTOCOL_SPECIFICATION.md §1059` |
| CRC flag (bit 4 of POP byte 0)   | per-frame                       | `CPOPMsg::CRC_BIT` + `GetCRCFlag()` (DongleInterface.dll symbol dump) |
| Status / error code (BE u16)     | XTD `0x140C0X0Y` payload [0..1] | `docs/RNET_ERROR_CODES.md` (302 entries) + `.rnd error-catalog extraction` v2 (810+ entries with `confidence` field) |
| Mode request (JSM→PM)            | STD `0x060`                     | `open-rnet RNET_PROTOCOL_SPECIFICATION.md:1036` |
| PM connected sentinel            | XTD `0x0C280000`                | janschu99 `RNETdictionary.txt §0C280000` |
| Tones (also via function 0x01)   | XTD `0x181C0100/0D00`           | janschu99 `RNETcanframe_diary.txt:43` |
| Time of Day (LE u48)             | XTD `0x1C2C0D00` payload        | janschu99 `RNETdictionary.txt §1c2c0D00` |
| Motor power (DLC=2 fix)          | XTD `0x14300X00` LE u16         | janschu99 `RNETdictionary.txt §14300D00` |
| Auth XOR-table validation        | XTD `0x1F.SSKKVV` responses     | 3 known networks: parse-recovered xor_tables A/B/C |
| JSM heartbeat signature check    | XTD `0x03C30F0F` payload        | parse empirical: 500/500 = `87 87 87 87 87 87 87 00` |

### Family-analogy or pattern-inferred [unverified]

| Group | Pattern | Source |
|---|---|---|
| Sleep variants | STD `0x002`, `0x004` | `RNET_FRAME_DICTIONARY.md §1` |
| Param-page family | STD `0x042-0x04F` | analogy to documented `0x040/0x041` |
| Mode-map family | STD `0x051-0x05F` | analogy to documented `0x050` |
| Mode family | STD `0x062-0x06F` | analogy to documented `0x060/0x061` |
| Config-mode family | STD `0x7B2/7B4-0x7BF` | analogy to documented `0x7B0/7B1/7B3` |
| 0x1C2C per-slot telemetry (functions ≠ 0x0D) | XTD `0x1C2C0X00` | parse pattern + dictionary TOD hint |
| cJSM/JSM family (functions ≠ 0x0D/0x01) | XTD `0x181C0X00` | parse pattern + external RE family hint |
| Module connected per-slot | XTD `0x0C280X00` | analogy to PM-connected `0x0C280000` |
| BTM family variants | XTD `0x0A400XXX` (non-documented) | analogy to BTM Control/Status |
| 0x1C20 family | XTD `0x1C200X00` | adjacent to `0x1C0C/0x1C2C/0x1C30` |
| Motor scale (quartile %) | XTD `0x14300X01` | parse pattern (0/25/50/100) + external RE notes R3 |
| Event broadcast | XTD `0x15000000` | parse hackathon only, not in any corpus doc |
| Protocol-control sentinels (subtype 4-7) | XTD `0x1E84-0x1E87....` | parse capture audit; subtype semantics open |

## Coverage across full corpus (~433k CAN frames)

Includes 18 open-rnet captures + the 2026-05-21 hackathon dump.

| Category | Count | Percentage |
|---|---|---|
| Fully decoded, evidenced | 431,411 | **99.64%** |
| Decoded, `[unverified]` | 1,552 | 0.36% |
| Unknown frame class | **0** | **0.00%** |

Every CAN frame in the corpus now has at least a class label. The
`[unverified]` bucket holds frames that decode under family-analogy
rules (e.g. `STD 0x062-0x065 → "Mode family"`, `XTD 0x0C280X00 →
"Module connected per-slot"`) but whose specific semantics aren't
documented in any primary source.

## Independent corroboration during development

Running the dissector against open-rnet's captures independently
reproduced three results from prior RE work, which the dissector
encoded from a different evidence stream:

1. **xor_table B (M300 network)**: keys
   `[0xD3, 0x92, 0xB1, 0x94, 0xED, 0x06, 0x2C, 0x4E]` recovered from
   `full_action_dumpJuly2_2016.pcapng` — matches the dictionary.
2. **xor_table A (Standalone JSM)**: keys
   `[0x08, 0xB1, 0x1E, 0x46, 0xDD, 0x12, 0x7B, 0x45]` recovered from
   `poweronJSMsh.pcap.pcapng` — matches the dictionary.
3. **BTM Control / Status IDs** found live on the wire in 5 captures
   (28 + 31 occurrences in two largest) — corroborates `RNET_PROTOCOL_SPECIFICATION.md §14.2`.

The POP refactor also confirmed something the external RE response
predicted: the previously-unknown POP byte `0xC2` (6,368 occurrences,
all in ICS captures) decodes cleanly as `TC=3 (Abort) → ISM (Slot 2)`.
The "0xC2 mystery" was an artifact of treating two distinct bit-fields
as a single opcode.

### Third XOR network — hackathon capture (2026-05-21)

A 31,043-frame **candump log** from a hackathon
(`2026_AT_hackathon.log`, captured 2026-05-21) yielded a
previously-unknown chair serial and XOR table, beyond the two networks
in the dictionary:

- Chair serial: `B68021AE`
- xor_table:    `[0xDA, 0x30, 0xE1, 0x55, 0x36, 0x20, 0x79, 0x45]`

The dissector decoded 98.95% of this capture on first contact, without
adaptation — Wireshark reads candump logs natively, and the dissector
hooks the SocketCAN encapsulation that Wireshark uses for both pcap
and candump sources.

Two new frame families were also added as `[unverified]` decoders
based on the structural patterns visible in this capture:

- **XTD `0x1C2C0X00`** (198 frames): 6-byte payload comprising a
  per-burst sample counter (byte 0), a slow LE u16 counter
  (bytes 1-2, advanced from 3129 to 3329 over 197 seconds), and a
  3-byte constant tail. Arrives in 10-frame bursts every ~20s.
  Looks like periodic telemetry from a slot-1 device.
- **XTD `0x181C0F00`** (102 frames): function `0x0F` in the
  `0x181C` cJSM/JSM device-class family (where `0x0D` is the known
  audio-tones function). Fully constant 8-byte payload
  `01 60 80 00 00 00 00 00`, fired irregularly every 1-30s. Looks
  like a periodic cJSM/JSM announcement.

Net coverage on the hackathon dump after the additions: **98.95%
evidenced + 0.97% `[unverified]` + 0.08% unknown** (the remaining
25 frames are scattered across 9 different rare IDs, none worth a
dedicated decoder).

## Known gaps

These show as `Unknown ...` in dissector output and are good targets
for future RE work:

| ID pattern | Frame count | Note |
|---|---|---|
| STD `0x05X` (051-054) | 208 | Cluster near mode-map `0x050` |
| STD `0x06X` (060-065) | 291 | Cluster near mode-control `0x061` |
| STD `0x04X` (042-045) | 94 | Cluster near param-page `0x040` |
| STD `0x7BX` (7B2, 7B6) | 52 | Cluster near config-mode `0x7B0/7B1` |
| XTD `0x181C0X00` (X≠D) | ~91 | Family prefix matches tones (`0x181C0D00`); cJSM firmware not yet dumped, so other functions are uncharacterized |
| XTD `0x1C2C0X00` | ~54 | Adjacent to distance-counter family |
| XTD `0x14300X01` | ~42 | Variant of motor-current pattern |
| XTD `0x0A400X0Y` (other slots) | ~46 | BTM family, slots 02+ not documented |

Per the external RE reply, several of these (especially the STD
neighborhoods) are likely per-profile or per-target-device variants of
their documented neighbors. Validating that needs a live capture
correlating profile/mode switching with frame timestamps.

## File layout

```
analysis/wireshark/
  rnet_can.lua             — the dissector
  rnet-dump                — candump-L-shaped wrapper, dissected output
  README.md                — this file
  reassemble_transfers.py  — POP transfer reassembly companion
  pwc_params.json          — vendored Permobil PWC param_id → name snapshot
  tests/test_dissector.py  — pytest suite (32 tests)

../../captures/
  2026_AT_hackathon.log    — hackathon candump (source for Table D)
  *.pcapng                 — the DEFCON 24 captures the dissector decodes
```

## Related work

- DEFCON 24 R-Net research (Stephen Chavez & Specter, 2016) — the
  runnable decoder, captures, and frame dictionary in this repo.
- janschu99's `RNETdictionary.txt` + `RNETcanframe_diary.txt` —
  community-contributed dictionary of additional frame meanings, cited
  inline as evidence in `rnet_can.lua`.
- Later RE work on the Programmer dongle DLL and IRConfigurator
  companion app — surfaced the POP wire format, ODI class encoding,
  CRC algorithm, and parameter address layouts cited throughout.
