# rnet_can — Wireshark/tshark dissector for the R-Net CAN protocol

A Lua dissector for the **R-Net** power-wheelchair control protocol
(Curtiss-Wright / PG Drives Technology), running on 125 kbit/s CAN.
Decodes SocketCAN-encapsulated frames in pcap/pcapng captures and
`candump -L` logs.

## What this is, honestly

**R-Net is not open.** There is no public specification. Curtiss-Wright
(formerly PG Drives Technology) doesn't publish wire documentation, and
the dealer Programmer that configures chairs ships as a stripped,
encrypted binary. We're dissecting a protocol whose spec we don't have.

What we DO have:

- **A lot of wire traffic** — hundreds of thousands of CAN frames
  across 18 DEFCON-24-era captures plus a 31,043-frame hackathon dump.
  Whatever the spec is, the wire actually does this — observable,
  reproducible, cross-checkable.
- **The software that generates and receives R-Net messages.** The
  dealer Programmer DLL (`DongleInterface.dll`) and companion app
  (`IRConfigurator.exe`) have been decompiled. Interpreting binaries
  is hard — names get inferred, control flow is partial, some things
  remain opaque — but we've made solid progress recovering class
  structures, wire formats, and named constants.
- **Prior reverse-engineering** — the DEFCON 24 talk, the runnable
  `rnet_utils.py` decoder, and community-contributed dictionaries.

What we DON'T have:

- The spec
- Vendor acknowledgment of any of the names or structures we use
- Decompiles of most chair-side firmware modules

Some claims in this dissector are well-grounded — code we can read,
traffic we can reproduce, empirical cross-checks against multiple
captures. Others are educated guesses from patterns and adjacent
neighbors. The `rnet.confidence` field (see "Evidence policy" below)
tells you which is which on a per-rule basis. Today the rules break
down as **49% Code, 27% Documented, 24% Inferred** — we try to be
honest about that uncertainty so you can decide what to trust.

**If you can help, especially with new capture logs, please do.** See
"Contributing" near the bottom — logs that demonstrate a wrong decode
(or a correct-but-better one) are the single highest-leverage thing
anyone can send us.

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

## R-Net, ReBus, POP — three names, three different things

These three terms get conflated everywhere (including in PGDT's own
marketing material). They're not synonyms. The dissector's labels
follow the engineering distinction from
`DongleInterface.dll`'s class structure:

| Name      | What it is                                                              | DLL class                |
|-----------|-------------------------------------------------------------------------|--------------------------|
| **R-Net** | The umbrella protocol / system. Session management, device enumeration, slot assignment, authentication, time, event log, AND data transfer. | `CRnetInterface` (~100 methods) |
| **ReBus** | ONE sub-protocol within R-Net: data transfer (Download / Upload / SegmentedDownload / QuickReadE / QuickWriteE). Not session management. Not auth. | `CRebusInterface` (~28 methods) |
| **POP**   | A wire-message FORMAT. ReBus uses POP frames to serialize its data-transfer operations onto the CAN bus. Lives in CAN ID ranges 0x78X/0x79X (POP-std) and 0x1E0XXXXX-0x1E7FFFFF (POP-ext). | `CPOPMsg` (~30 wire-format accessors) |

Concretely:

- **All POP frames are R-Net frames; not all R-Net frames are POP
  frames.** Joystick, heartbeat, motor, lights, status, faults — all
  R-Net but none POP. The dissector's per-frame-class taxonomy
  reflects this distinction.
- **POP is NOT a layer above ReBus.** It's the wire format ReBus
  serializes its operations into. ReBus → uses CPOPMsg → rides on
  CCANMsg → CAN 2.0B physical. The smoking-gun evidence:
  `CRebusInterface::Download` (decompile at `DongleInterface.dll`
  offset `0x10008300`) literally calls `CPOPMsg::CPOPMsg()` to
  construct a POP message, sets its ODI / Size / CRC fields, hands
  it to `CTransactionBase`, and sends it via `CFTDIInterface::TxCANMsg`.
  ReBus is the caller; POP is the wire format. This relationship is
  cross-validated against four independent code sources (v5 + v6
  DLL symbol dumps, the Programmer EXE which instantiates both
  classes, and the Download decompile itself) and has been stable
  in the binary since 2013.
- **The R-Net session state machine** (`CXTN_NONE → CXTN_CAN →
  CXTN_RNET → CXTN_UPLOAD/CXTN_DOWNLOAD`) lives on
  `CRnetInterface`, not on `CRebusInterface`. The chair-attach
  4-frame handshake (0x1E84/85/86/87) and the Transfer Complete
  sentinel (0x1E80000F) are R-Net session-control markers, NOT
  ReBus messages and NOT POP frames — they're in the 0x1E8XXXXX
  range, OUTSIDE the POP-ext namespace by design.

PGDT marketing/dealer material uses "ReBus" loosely to mean "the
R-Net protocol" — that's not wrong at the dealer-facing level of
abstraction, but it conflates the umbrella class with one of its
components. This dissector uses the engineering-precise meaning.

> **Known discrepancy with this repo's `docs/POP_PROTOCOL.md`.**
> The 2026 protocol spec (and its layered-stack diagram) presents
> POP as "operating on top of REBUS." Per the four-source code
> validation above — particularly the `CRebusInterface::Download`
> decompile — the relationship is the opposite: ReBus constructs
> and emits POP messages. The dissector's labels follow the
> code-verified model. A spec update to match is a separate
> follow-up; the discrepancy is documented here so reviewers
> don't conclude the dissector's labels are wrong.

A few labels in the dissector reference these distinctions explicitly:

- `R-Net attach handshake step 1..4` on 0x1E84..87 frames
  (R-Net session control, NOT a ReBus operation)
- `Transfer Complete sentinel (R-Net CXTN_UPLOAD/DOWNLOAD → CXTN_RNET)`
  on 0x1E80000F (R-Net state transition that wraps up a ReBus transfer)
- `POP (standard-ID)` / `POP (extended-ID)` for actual POP-formatted
  application-layer frames

For a deeper view of the R-Net session state transitions in a
specific capture (when each transfer opens, completes, and returns
to CXTN_RNET), see the `rnet_state_timeline.py` companion tool in
the underlying R-Net research repository.

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

## Reading the output — things that look weird but aren't bugs

A few labels you'll see in real captures that surprise people. None
are decoder bugs — they're either real protocol behavior or
explicit-uncertainty markers doing their job.

### `JSM serial heartbeat (pre-init — serial not yet loaded)`

At power-on the JSM emits all-zero serial-heartbeat frames (ID `0x00E`,
8 bytes of `0x00`) before it loads its serial from EEPROM. This is
real protocol behavior, not the dissector dropping bytes. Visible in
`captures/poweronJSMsh.pcap.pcapng`. The chair's actual serial
appears a few milliseconds later in the auth-response handshake.

### `.rnd[0x0048] ICS module (Generic-fw guess: ICS_ABS_MIN_ELEVATOR_TRAVEL)`

POP frames sometimes carry a wire address that matches a parameter in
our extracted `.rnd` database. We show both:

- **`ICS module`** — the **prefix**, which is stable across firmware
  versions. ICS, PPP, SCX, FN, ESP, etc. identify the emitting
  module. Reliable signal — filter on it via
  `rnet.pop.addr_prefix == "ICS"`.
- **`(Generic-fw guess: ICS_ABS_MIN_ELEVATOR_TRAVEL)`** — the
  **specific parameter name** from our extracted Generic V33_1_1375
  catalog. **This name is firmware-version-specific** — per the
  rnet-firmware address-stability study (2026-05-23), of 159 wire
  addresses common across 6 firmware extractions, zero map to the
  same name across them. The name is a hint, not ground truth.

If you're decoding traffic from a chair you know is running a
specific firmware version that we have a catalog for, the
firmware-version-aware lookup is documented under "Planned" below.

### `[CONJECTURAL: Meyra .rnd descriptor #N positional pairing]`

Three error codes (`0x1C00`, `0x2500`, `0x2E00`) carry a
`[CONJECTURAL]` tag in their decoded names. These wire codes are
**confirmed real** (they appear in Meyra's `.rnd` descriptor table)
but the names assigned to them come from positional pairing with
Meyra's English error display table — a heuristic, not a verified
mapping. Same wire code can mean different things on different
modules. We ship the names with the tag so readers can see "here's
a candidate, verify before relying."

### `✓ Table B` next to auth-response frames

Means the dissector cryptographically validated the auth-response
bytes against XOR Table B's key sequence. Auth handshake = the chair
proving it knows its serial number XOR'd with a per-network key
table. A `✓` means the math worked out — strong identification of
which R-Net network the chair belongs to. Tables A through D are
documented in `rnet_can.lua`; B is by far the most common (M300
networks).

### `[unverified]` vs `[CONJECTURAL]`

Both flag uncertainty, in different ways:

- **`[unverified]`** in a frame-class label: the structural pattern
  is observed but the semantic is family-analogy (e.g., STD 0x051
  is decoded like STD 0x050 because they're adjacent and look
  structurally identical, but we haven't seen documentation
  confirming the layout).
- **`[CONJECTURAL]`** in a parameter / error name: the wire code is
  real but the specific name attached to it is a positional guess
  from a derived data source (currently just the Meyra
  descriptor→display pairing).

Both turn into `Inferred` in the `rnet.confidence` field (when
that pref is enabled).

### `99.64% evidenced coverage` is per-frame-class, not per-frame

The headline coverage number counts frames, not decode rules. Some
decode rules cover many thousands of frames (joystick, heartbeats),
others cover a handful (rare faults). The README's separate
**49% Code / 27% Documented / 24% Inferred** distribution counts
**rules**, not frames. A capture can be 99% evidenced even though
most of its rules are Documented or Inferred, because the few Code-
tier rules cover the bulk of the wire traffic.

### Filter quick reference

The most useful display filters that aren't immediately obvious:

```sh
# Show everything inferred (the "what is the dissector unsure about" view)
-Y 'rnet.confidence == "Inferred"'

# All traffic addressed to one module (stable across firmware versions)
-Y 'rnet.pop.addr_prefix == "ICS"'

# Auth frames that DID validate against a known network
-Y 'rnet.auth.network'

# Non-zero faults
-Y 'rnet.err.code'

# CRC echoes in COMPLETE responses
-Y 'rnet.pop.crc_value'
```

(All require the `rnet.show_evidence:TRUE` pref for the
`rnet.confidence` filter; the others work always.)

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
| XTD `0x0A400X0Y` (other slots) | ~46 | BTM family, slots 02+ not documented |

(Two previous "gap" entries — `XTD 0x1C2C0X00` and `XTD 0x14300X01` —
were promoted to **Documented** in 2026-05-23 after empirical
cross-checks across the corpus. See the relevant decoder comments
for the structural model.)

Several of the remaining gaps (especially the STD neighborhoods) are
likely per-profile or per-target-device variants of their documented
neighbors. Validating that needs a live capture correlating
profile/mode switching with frame timestamps.

## Planned: firmware-version-aware parameter lookup

The current `.rnd` address lookup uses a single Generic-V33_1_1375
catalog and emits the resolved name with a `Generic-fw guess` caveat
plus a stable module prefix (see "Reading the output" above). A
firmware-version-aware lookup would remove the caveat.

### What it would unlock

- **Accurate parameter names** in `.rnd[0xNNNN]` labels, with no
  Generic-fw caveat — the dissector would know whether to read the
  Generic V33_1_1375 catalog, the Amylior catalog, the ETAC catalog,
  or another firmware-specific catalog.
- **Per-firmware error catalog routing** — some OEM-specific error
  codes (e.g., `0x4D00`, `0x9E00` from the Pride / SwitchIt / HMC
  domains) likely have different names per firmware too. Same
  approach would apply.

### What it would require

Three things, none of which are solved today:

1. **A reliable signal in wire traffic that identifies firmware
   version.** Candidate signals:
   - The `0x1E86`/`0x1E87` chair-fingerprint bytes (chair 50C01C8F
     consistently produces `0x8314`/`0x0166`; chair B68021AE
     produces `0x3D16`/`0x0006`). These look like persistent
     per-chair hashes — possibly include firmware version, possibly
     pure pairing IDs.
   - The DIME serial — encodes a YYMM-style manufacturing-batch
     prefix, which correlates loosely with firmware era but isn't
     a direct version field.
   - Startup enumeration frames (`0x1FB0` device-enum), if they
     contain a firmware-version sub-field.
   - Mode-config startup payloads.
2. **A captured mapping** of `firmware-version → fingerprint
   bytes`. Today we have two chairs in the corpus with known
   fingerprints but unknown firmware versions. To build the map
   we'd need captures explicitly labeled with their chair's
   firmware build (via a Programmer connection that read the
   firmware ID, or vendor documentation).
3. **The bundled JSONLs**: ~10MB of parameter catalogs (the 6
   existing extractions plus any new firmware versions). Today the
   dissector is a single ~250KB Lua file. Adding the JSONLs is
   straightforward but bumps the install size 40×, and adds a
   load-time JSON parser the dissector currently doesn't need.

### Why we aren't doing this now

- **Blocker #1 (fingerprint → firmware mapping) is the hard one.**
  Until we have multiple chairs in the corpus with KNOWN firmware
  versions, we can't validate any fingerprint hypothesis. The
  prefix proxy already gives readers the stable module
  identification piece, so the marginal value of disambiguating
  the specific name is small for typical use.
- **Install-size jump is real.** Going from one 250KB Lua file to a
  Lua file + 10MB of JSONLs changes the deployment story (drop-in
  file → manage a directory of bundled data). Worth doing if the
  feature lands; not worth doing speculatively.
- **The bundled-data path doesn't help if firmware detection
  fails.** If the dissector can't identify firmware version from
  wire traffic, the fallback behavior is exactly what the prefix
  proxy already does — fall through multiple catalogs, surface
  ambiguity. The added 10MB buys nothing in the no-firmware-ID
  case.

### What would unblock this

The order of operations:

1. Find a chair-fingerprint signal that correlates one-to-one with
   firmware version. Requires captures + firmware-version labels.
2. Build the `fingerprint → firmware-key` lookup table (likely
   small — a few dozen entries).
3. Ship the firmware-version JSONLs alongside the dissector,
   either bundled or as an optional separate install
   (`~/.local/lib/wireshark/plugins/rnet_can_catalogs/`).
4. Add a JSONL loader to the dissector init path.
5. Promote the `Generic-fw guess` caveat to `Verified for firmware
   <X>` when the lookup succeeds; keep the prefix as the fallback.

If you have **captures from chairs whose firmware version you know**
(from a Programmer connection or vendor info), that's the single
highest-leverage contribution toward this work — see "Contributing"
below.

## File layout

```
analysis/wireshark/
  rnet_can.lua             — the dissector
  rnet-dump                — candump-L-shaped wrapper, dissected output
  README.md                — this file
  reassemble_transfers.py  — POP transfer reassembly companion
  pwc_params.json          — vendored Permobil PWC param_id → name snapshot
  tests/test_dissector.py  — pytest suite (38 tests)

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

## Contributing

Without the spec, the way this dissector gets better is **more
captures and more eyes on the decodes**. Specific high-leverage
things you can send:

1. **Capture logs**, ideally with context — what chair/modules were
   on the bus, what you were doing during the capture (driving,
   programming, lamp test, sleeping). `.pcapng` from Wireshark,
   `candump -L` text logs, or raw SocketCAN dumps all work. Captures
   from chairs/modules not yet in the corpus (Pride, SwitchIt, HMC,
   newer Permobil) are especially valuable.

   Even if you can't share a capture publicly, a private trace plus
   a description of what was happening helps us re-test
   `Inferred`-tier decodes.

2. **Corrections to wrong decodes.** If a frame is mislabeled or
   under-decoded — especially anything tagged `rnet.confidence ==
   "Inferred"` — open an issue or PR with the better interpretation.
   Pair the change with a test case in `tests/test_dissector.py`
   that pins down the new behavior.

3. **Tier promotions.** Any decode that moves up
   `Inferred → Documented → Code` because someone found a community
   dictionary entry, decompiled a chair module, or empirically
   verified a structural hypothesis against a real capture is a real
   improvement — even without adding new field names.

Submissions that come with **a log file that demonstrates the
change** are the highest-value form. The log proves the claim and
becomes a regression test for future work touching the same code
path.
