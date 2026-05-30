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
  across 29 open-rnet captures plus a 31,043-frame hackathon dump
  (30 total).
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
down as **29% Code, 58% Documented, 13% Inferred** — we try to be
honest about that uncertainty so you can decide what to trust.

**If you can help, especially with new capture logs, please do.** See
"Contributing" near the bottom — logs that demonstrate a wrong decode
(or a correct-but-better one) are the single highest-leverage thing
anyone can send us.

## Contents

- [Quick start (no install)](#quick-start-no-install)
- [Installation](#installation)
- [Usage](#usage) — basic filters, `rnet-dump`, Info column, capture formats
- [CAN, briefly — what you need to know to read R-Net captures](#can-briefly--what-you-need-to-know-to-read-r-net-captures)
- [Evidence policy](#evidence-policy) — Code / Documented / Inferred tiers
- [R-Net, ReBus, POP — three names, three different things](#r-net-rebus-pop--three-names-three-different-things)
- [POP frames — the structural decode](#pop-frames--the-structural-decode)
- [What is decoded (with confidence)](#what-is-decoded-with-confidence)
- [Coverage across full corpus (~455k CAN frames)](#coverage-across-full-corpus-455k-can-frames)
- [Independent corroboration during development](#independent-corroboration-during-development)
- [Authentication and access control — the whole story](#authentication-and-access-control--the-whole-story)
- [Reading the output — things that look weird but aren't bugs](#reading-the-output--things-that-look-weird-but-arent-bugs) — quirky labels explained
- [A walked-through session](#a-walked-through-session--programmer_write_file_july2017pcapng) — one real capture, frame by frame, showing how labels and cross-frame state tell a story
- [Filters, recipes, and field reference](#filters-recipes-and-field-reference) — filter examples, **common investigations**, recommended Wireshark columns, complete `rnet.*` field catalog
- [Known gaps](#known-gaps)
- [Interesting frames worth sharing](#interesting-frames-worth-sharing) — "if you see this, please share" expert-info markers
- [Planned: firmware-version-aware parameter lookup](#planned-firmware-version-aware-parameter-lookup)
- [File layout](#file-layout)
- [Related work](#related-work)
- [Contributing](#contributing)

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
list `rnet_can.lua` with its version — the commit date plus a short SHA of
the last change to the dissector (format `YYYY-MM-DD <short-sha>`), which
`make install` stamps into the installed copy so a bug report can be tied
to an exact tree state. A copy installed from a modified working tree is
marked `-dirty`.

### For development — the Makefile

If you're working from the dissector's development tree, a Makefile
wraps the common workflows so you can stop reaching for the same
three commands every commit:

```sh
make help      # list targets
make install   # copy rnet_can.lua into the Wireshark plugin dir
make test      # run the 82-test pytest suite
make verify    # tests + full-corpus 0-Unknown regression check
make sync      # install + mirror the dissector files to open-rnet
```

#### How `make install` finds the plugin dir

Wireshark's per-user Lua plugin path varies by OS, Wireshark version,
and install method. There's no single hardcodable answer. The Makefile
asks `tshark` itself:

```sh
tshark -G folders | awk -F'\t' '/^Personal Lua Plugins:/ {print $2}'
```

That returns the path Wireshark expects user-installed Lua dissectors
to live in (e.g. `/Users/you/.local/lib/wireshark/plugins` on macOS
with Homebrew, `~/snap/wireshark/.../...` on Snap-installed Linux,
etc.). The Makefile uses that value; if `tshark` isn't on PATH, it
falls back to the historical Linux/macOS default. You can also force
a specific path:

```sh
INSTALL_DIR=~/some/other/path make install
```

#### How `make sync` mirrors to open-rnet

The convention is **source-first**: edit the development tree, never
edit the mirror directly. `make sync` then copies the dissector files
(`rnet_can.lua`, `pwc_params.json`, `reassemble_transfers.py`,
`rnet-dump`, the negative-control log, all tests, and the README)
into `$(OPEN_RNET)/analysis/wireshark/` so the public-facing copy
stays in lockstep. Default `OPEN_RNET` is `~/src/open-rnet`; override
the same way as `INSTALL_DIR`:

```sh
OPEN_RNET=~/code/open-rnet make sync
```

If the open-rnet tree isn't present at `OPEN_RNET`, `make sync`
gracefully skips the mirror step but still does the local Wireshark
install.

#### Per-user paths via `Makefile.local`

Rather than retyping env vars, create `Makefile.local` (gitignored)
with the values you want to pin:

```make
# Makefile.local — pins for this checkout, never committed
OPEN_RNET          := $(HOME)/code/open-rnet
INSTALL_DIR        := /opt/wireshark/plugins
RNET_FIRMWARE_DOCS := $(HOME)/code/upstream-re/docs   # optional; see below
```

`RNET_FIRMWARE_DOCS` is optional. The citation-validator test
(`test_citations_resolve_or_explain`) probes a set of public locations
for every `.md` doc cited in `add_evidence()` calls. Some citations
reference upstream-RE docs that aren't always available locally; if
you have that tree checked out, point `RNET_FIRMWARE_DOCS` at its
`docs/` directory and the validator will probe it too. When unset
(e.g., on a CI runner without the private tree), private-only
citations are reported as "can't verify from this checkout" rather
than failing the test.

The Makefile does `-include Makefile.local` after its defaults, so
your local config wins. The file is in `.gitignore` so it never lands
in version control.

#### What `make verify` actually checks

Beyond `make test` (the pytest suite), `make verify` walks every
CAN-parseable capture in `$(OPEN_RNET)/captures/` and asserts **zero
frames are labeled "Unknown"** by the dissector. This is the
load-bearing coverage claim that lives in the README headline; the
verify target ensures a code change can't silently regress it. If
the open-rnet capture corpus isn't present, the corpus check is
skipped (the pytest suite is the floor).

#### No GitHub Actions for the canonical tree

The canonical development tree lives on a private git server, so
GitHub Actions doesn't run for it. The `make verify` workflow
gives equivalent regression coverage as a pre-push discipline. The
open-rnet mirror (the public fork at `github.com/cosmos4cats/open-rnet`)
**does** have a GitHub Actions workflow at
`.github/workflows/wireshark-dissector-tests.yml` that runs the same
pytest suite on every push affecting `analysis/wireshark/`.

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
the expanded frame detail is filterable. A few quick examples here;
the **complete field reference + common-investigation recipes** are
under [`Field reference`](#field-reference) and
[`Common investigations`](#common-investigations) below.

```sh
tshark -r captures/2026_AT_hackathon.log -Y "rnet.joy.x > 30"
tshark -r captures/2026_AT_hackathon.log -Y "rnet.pop.tc == 3"
tshark -r captures/2026_AT_hackathon.log -Y "rnet.mode.index < 6"
tshark -r captures/2026_AT_hackathon.log -Y "rnet.err.code"          # non-zero faults
tshark -r captures/2026_AT_hackathon.log -Y "rnet.auth.network"       # identified XOR networks
tshark -r captures/2026_AT_hackathon.log -Y 'rnet.pop.register_name == "TEXT"'
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
Auth response seq=3 slot=1 serial[3]=0x8A ✓ Table A  device-serial=CR15074104
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
identified auth handshakes, and `rnet.auth.device_serial` lists every
chair/module serial decoded off the auth handshake (`CR15074104`, …).

### Capture formats

The dissector hooks the SocketCAN encapsulation, so it works on:
- **pcap / pcapng** files from `tcpdump`, Wireshark live capture, etc.
- **candump text logs** (the `(timestamp) iface ID#data` format
  produced by `candump -L`). Wireshark parses these natively; the
  dissector picks them up without any adaptation.

## CAN, briefly — what you need to know to read R-Net captures

R-Net runs on CAN (Controller Area Network), the same in-vehicle bus
that powers cars, industrial machinery, and a lot of robotics. You
don't need to understand CAN deeply to use this dissector — but a few
specific CAN facts dramatically change how you read R-Net captures.
This section is the minimum.

### The core idea: CAN frames have no source or destination address

A CAN frame is just a numeric **ID** (the "arbitration ID") plus up to
8 bytes of data. There is no "from this node, to that node" — every
node sees every frame, and each one decides whether it cares based on
the ID. In practice the ID does triple duty:

- **Priority** (lower numeric ID wins bus arbitration when two nodes
  transmit simultaneously)
- **Topic** (a frame ID like `0x002` means "this is a sleep signal")
- **Routing key** (the ID encodes who's *meant* to handle it, even
  though it's broadcast to everyone)

R-Net leans into this hard. Almost everything you need to understand
about why R-Net structures its CAN IDs the way it does flows from
those three roles.

### 11-bit vs 29-bit IDs — R-Net's priority taxonomy

CAN has two ID formats: **11-bit standard** (`0x000-0x7FF`, 2048 IDs)
and **29-bit extended** (over 500 million IDs). Standard IDs are
shorter, so they take less bandwidth AND win arbitration over extended
IDs of similar numeric value. R-Net uses this as a deliberate priority
scheme:

| Range | Use |
|---|---|
| STD `0x000` | **Sleep command** — wins everything, can be sent during any traffic to put the bus to sleep |
| STD `0x002-0x00E` | Sleep variants, joystick init signals, network test, serial heartbeats — high-priority lifecycle traffic |
| STD `0x040-0x07F` | Parameter pages, mode/profile changes — user actions that need fast response |
| STD `0x780-0x79F` | POP standard requests/responses — Programmer↔chair config protocol |
| STD `0x7B0-0x7BF` | Config-mode signals, serial exchange — Programmer session control |
| XTD `0x02000000` | Joystick position broadcasts (high cadence, but moved out of STD because the namespace is full) |
| XTD `0x0A4000XX` | BT-Mouse Control/Status |
| XTD `0x0C000000`+ | Per-slot device telemetry (battery, motor, lamp, motion state) |
| XTD `0x140C0000` | Status / error codes (302 known codes) |
| XTD `0x14300000` | Motor current/power per slot |
| XTD `0x1C0C0000` | Battery level per slot |
| XTD `0x1C2C0X00` | Real-Time Clock broadcast (bit-packed date/time) |
| XTD `0x1E000000`+ | POP extended (ReBus data transfers, multi-frame segments) |
| XTD `0x1E80000F` | Transfer Complete sentinel (R-Net `CXTN_UPLOAD/DOWNLOAD → CXTN_RNET`) |
| XTD `0x1E84-0x1E87` | R-Net attach handshake (4-step `CXTN_CAN → CXTN_RNET`) |
| XTD `0x1F000000`-`0x1FFFFFFF` | XOR-based serial-auth challenges and responses |

Once you see the pattern: **STD = "you need to react now"**, **XTD =
"this is data or a longer-running protocol."** Joystick position is
the one exception in the other direction (XTD despite high cadence) —
it was probably moved out of STD because the STD namespace was
already full of higher-priority module traffic.

### Per-module filtering: a frame can be on the wire but invisible to a module

CAN has no addressing, so each R-Net module decides for itself which
frames it acts on. Two mechanisms do this, both grounded in chair-module
firmware:

- **A software CAN-ID match table.** BTMouse (MC9S12X) carries a literal
  CAN-ID table at flash `0x56E0-0x571B`; LEDJSM (HCS12) carries the same
  byte sequence at `0x57C8+` — cross-firmware verified byte-exact. A
  module's dispatch handlers consult this table; an ID that isn't in it
  has no handler on that module.
- **An MSCAN hardware acceptance filter** (`CANIDAR0-7`/`CANIDMR0-7`),
  programmed at boot, which can reject off-target frames before the CPU
  sees them. The exact filter constant each module loads isn't resolved
  in the current dumps, so treat the hardware-rejection step as real but
  not fully characterized.

The consequence is what matters here:

> **A per-module firmware byte-search for a frame ID will return zero
> if that frame isn't handled by that module — even if the frame is on
> the wire and the module sees it physically.**

This is the most common source of "I can't find this anywhere"
confusion when cross-validating decodes. If a frame is meant for the
PM and you search the LEDJSM dump for its ID, you'll find nothing.
That's correct behavior, not a missing decode.

> **Retracted (per upstream-RE audit, 2026-05-29).** An earlier
> version of this section claimed the 29-bit ID encodes a
> "Device-Type-ID" in its high bits (`0x6380` = LEDJSM, `0x0000` =
> BT-Mouse), sourced from a LEDJSM `MSCAN_RX_ISR @ 0x449C` plate
> comment. That comment was a fabricated narrative on a *misidentified*
> ISR — `0x449C` is the CRG self-clock ISR (vector `0xFFC4`); the real
> LEDJSM MSCAN Rx ISR is `0x429F` (vector `0xFFB2`) — and the cited
> banked dispatch at `0x3A9010` was an address-mapping artifact (a
> halt-stub; the real page isn't in the dump). The Device-Type-ID
> encoding is unverified and no longer claimed.

### DLC, RTR, and 125 kbit/s — the constraints that matter

- **DLC (Data Length Code, 0-8)** is the payload byte count. R-Net
  uses DLC as a sub-function selector in some families: `XTD
  0x14300X00` (DLC=2, motor power LE u16) and `XTD 0x14300X01`
  (DLC=1, motor state byte) are *different sub-functions* of the
  motor-telemetry family despite the near-identical IDs. When you see
  two frames at very similar IDs with different DLCs, expect different
  payload semantics.

- **RTR (Remote Transmission Request)** is a 1-bit flag that flips a
  frame from "here is data" to "send me data of this type." R-Net
  uses RTR as a *challenge trigger* — `STD 0x7B3 RTR` is a
  serial-exchange request, the non-RTR `0x7B3` that follows is the
  response. `STD 0x000 RTR` is "sleep all devices" vs `STD 0x000`
  (non-RTR) which is "sleep command." The dissector surfaces this
  via the `is_rtr` distinction in its labels.

- **125 kbit/s** is R-Net's bus rate (slower than the more common
  500 kbit/s automotive or 1 Mbit/s industrial CAN). After framing
  overhead this caps the bus at roughly 6,000-8,000 frames/second
  total. Periodic telemetry like RTC (~1 Hz) and motor intensity
  gauge frames are dimensioned against this budget. If you see a
  capture where one signal dominates the bandwidth, the chair will
  feel laggy.

### How CAN frames reach the dissector — SocketCAN, pcapng, candump

CAN captures don't have a "TCP" or "UDP" layer to wrap them. The
de-facto encapsulation in Linux is **SocketCAN**, a small per-frame
header that bundles the CAN ID, DLC, and a few flag bits into the
pcap payload. The dissector hooks into the SocketCAN dissector via
heuristic registration:

```lua
rnet:register_heuristic("can", function(tvb, pinfo, tree) ... end)
```

The heuristic **always claims the frame** (`return true`). There is no
bit-level signature for "this is R-Net" — proprietary CAN payloads
look identical at the framing layer. The expectation is that you load
this dissector against captures you already know are R-Net. (For
non-R-Net traffic, every frame gets the honest label "Unknown STD
0xXXX" or "Unknown XTD 0xXXXXXXXX" — see the
`tests/test_dissector.py::test_non_rnet_log_produces_no_specific_decodes`
regression that uses a non-R-Net candump as a negative control.)

Two on-disk formats work out of the box:

- **pcap / pcapng** with SocketCAN linktype 227 — produced by Wireshark
  live capture on `can0`, by `tcpdump -i can0 -w`, by `dumpcap`, etc.
- **candump `-L` text logs** — the `(unix-timestamp) iface ID#hexdata`
  format. Wireshark 1.12+ parses these natively as if they were
  SocketCAN pcaps.

Both behave identically from the dissector's standpoint.

### Why this matters for reading R-Net

Once you internalize the CAN basics:

- The namespace ranges stop looking random; you can predict whether
  a new ID you've never seen is "module telemetry" or "Programmer
  protocol" or "session sentinel" from its prefix alone.
- The hardware-filter trick means **a missing reference isn't a
  missing decode** — it's often correct module-targeting.
- The 11-bit vs 29-bit choice tells you R-Net's intended priority for
  that traffic, which in turn tells you what it competes with on a
  busy bus.
- The `[unverified]` family-extension labels in this dissector exist
  because each chair module decides its own payload semantics from
  CAN's standpoint — the bus just delivers bytes.

## Evidence policy

Every decode is tagged with **how it was derived** — so you can tell a
firmware-confirmed fact from an educated guess. The tags are hidden by default
(most readers want the protocol, not the audit); a one-click preference reveals
them with their source citation.

| Tier | Rules | What it means | Trust |
|------|------:|---------------|-------|
| Code | 18 | Primary source — a vendor-binary decompile (`DongleInterface.dll`, the Programmer EXE, `IRConfigurator.exe`, LEDJSM/BTMouse firmware) cited as `Func @ 0xNNNN`, or a match against the wire itself (e.g. a known XOR table). | Authoritative — the vendor's own code. |
| Documented | 36 | Community RE — open-rnet's decoders and specs (`rnet_utils.py`, `RNET_PROTOCOL_SPECIFICATION.md`, …) plus field dictionaries. Independently seen to work, but derivative; community RE (open-rnet included) has known errors. | Likely correct — verify if you depend on it. |
| Inferred | 8 | No direct source — family-analogy from a documented neighbor, a structural guess from bit patterns, or a hackathon-only observation. | A hint, not a fact — never for safety-critical use. |

Counts are per *rule*, not per frame — one `Code` rule may cover thousands of
frames, one `Inferred` rule a handful. `Inferred` entries graduate to
`Documented`/`Code` as captures and firmware dumps confirm them.

**Turn the tags on** (off by default):

- **Wireshark:** Edit → Preferences → Protocols → RNET → check "Show evidence + confidence".
- **tshark:** add `-o rnet.show_evidence:TRUE`. Each frame then carries
  `[Evidence kind: Code]` + `[Evidence source: rnet_utils.py:279]`, so you can
  filter `rnet.confidence == "Inferred"` (everything uncertain) or `"Code"`
  (only firmware-confirmed).

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
  ReBus is the caller; POP is the wire format. The `Download`
  decompile above is byte-stable across the v5 and v6 DLL builds
  (present since 2013). The Programmer EXE independently carries its
  own `CRebusInterface` (RTTI-confirmed) — separate evidence that
  ReBus is a real engineering construct — though, per upstream-RE's
  2026-05-25 audit, the EXE does **not** import DongleInterface.dll
  (it drives `FTD2XX.dll` directly; the DLL's actual consumer is
  IRConfigurator.exe via P/Invoke). So the EXE corroborates the class
  *design*, not this specific DLL code path.
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
| Serial auth (+ DIME serial reassembly) | XTD `0x1FSSKKVV`  | `rnet_utils.py:315`, `parse_auth_frame_id:128`; serial decode `IRConfigurator.exe DeviceDriver.GetSN` |
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
| SlotChanged signal (LE u32 filekey + raw trailing metadata) | XTD `0x15000000`             | `DongleInterface.dll v5 CheckForSlotChanged @ 0x10008b00` + `IsSlotChangedMsg @ 0x10001630` |
| Profile change family            | STD `0x050-0x05F`               | `DongleInterface.dll IsProfileChangeMsg @ 0x10001610` (StdIDMatches(0x50)) |
| Mode change family (data[0]≠0x90)| STD `0x060-0x06F`               | `DongleInterface.dll IsModeChangeMsg @ 0x100015e0` (StdIDMatches(0x60) + data[0] guard) |
| Config-mode family               | STD `0x7B0-0x7BF`               | BTMouse MC9S12X CAN-ID match table @ FW `0x56F2` (interior slice of the §4 table at `0x56E0`; chair-side primary source) |
| CRC flag (bit 4 of POP byte 0)   | per-frame                       | `CPOPMsg::CRC_BIT` + `GetCRCFlag()` (DongleInterface.dll symbol dump) |
| Status / error code (BE u16)     | XTD `0x140C0X0Y` payload [0..1] | `docs/RNET_ERROR_CODES.md` (302 entries) + `.rnd error-catalog extraction` v2 (810+ entries with `confidence` field) |
| Mode request (JSM→PM)            | STD `0x060`                     | `open-rnet RNET_PROTOCOL_SPECIFICATION.md:1036` |
| PM connected sentinel            | XTD `0x0C280000`                | janschu99 `RNETdictionary.txt §0C280000` |
| Tones (also via function 0x01)   | XTD `0x181C0100/0D00`           | janschu99 `RNETcanframe_diary.txt:43` |
| RTC date/time (7-field bit-packed) | XTD `0x1C2C0X00` payload      | DLL `DecodeRTCBroadcast @ 0x1000f8e0` (byte-identical layout) + janschu99 `§1c2c0D00`; 463/463 corpus frames in-range |
| Motor power (DLC=2 fix)          | XTD `0x14300X00` LE u16         | janschu99 `RNETdictionary.txt §14300D00` |
| Auth XOR-table validation        | XTD `0x1F.SSKKVV` responses     | 4 known networks: Tables A/B/C/D |
| JSM heartbeat signature check    | XTD `0x03C30F0F` payload        | parse empirical: DLC=7, 7×`0x87`, no trailing byte (1,978/1,978 hackathon frames; upstream-RE two-corpus verified) |

### Family-analogy or pattern-inferred [unverified]

| Group | Pattern | Source |
|---|---|---|
| Sleep variants | STD `0x002`, `0x004` | `RNET_FRAME_DICTIONARY.md §1` |
| Param-page family | STD `0x042-0x04F` | analogy to documented `0x040/0x041`; chair-emitted confirmed by 4-source DLL/EXE/HCS12 zero-hit sweep |
| `0x06X data[0]=0x90` sibling family | STD `0x060-0x06F` payloads starting `90` | DLL `IsModeChangeMsg` excludes data[0]=0x90 as a different family; handler not yet traced |
| Per-slot motor state byte | XTD `0x14300X01` | discrete states across 12+ captures; `0x1B` likely magic constant (not 27%); PM firmware (MC56F83) unavailable |
| cJSM/JSM family (functions ≠ 0x0D/0x01) | XTD `0x181C0X00` | parse pattern + external RE family hint |
| Module connected per-slot | XTD `0x0C280X00` | analogy to PM-connected `0x0C280000` |
| BTM family variants | XTD `0x0A400XXX` (non-documented) | analogy to BTM Control/Status |
| 0x1C20 family | XTD `0x1C200X00` | adjacent to `0x1C0C/0x1C2C/0x1C30` |

## Coverage across full corpus (~455k CAN frames)

Includes 29 open-rnet captures + the 2026-05-21 hackathon dump
(30 total). The 29 open-rnet captures span the original top-level set
plus the `july19_2016/dual_joysticks/` (5), `july19_2016/led_jsm_revision06`,
and `m300_powerup/` (3) subdirectories.

| Category | Count | Percentage |
|---|---|---|
| Fully decoded, evidenced | 454,440 | **99.78%** |
| Decoded, `[unverified]` | 1,017 | 0.22% |
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

### Fourth XOR network — hackathon capture (2026-05-21)

A 31,043-frame **candump log** from a hackathon
(`2026_AT_hackathon.log`, captured 2026-05-21) yielded a
previously-unknown chair serial and XOR table, beyond the three
networks parse already knew (Tables A/B/C):

- Chair serial: `B68021AE` (vendor `GetSN` renders the wire bytes as
  `DF18070182` — the dissector reassembles the seq 0-3 serial bytes and
  surfaces this via `rnet.auth.device_serial`; wire-order confirmed, not
  yet checked against a physical device label)
- xor_table:    `[0xDA, 0x30, 0xE1, 0x55, 0x36, 0x20, 0x79, 0x45]`

The dissector decoded 98.95% of this capture on first contact, without
adaptation — Wireshark reads candump logs natively, and the dissector
hooks the SocketCAN encapsulation that Wireshark uses for both pcap
and candump sources.

Two new frame families surfaced in this capture:

- **XTD `0x1C2C0X00`** (198 frames): first read as a telemetry burst —
  a "per-burst sample counter" (byte 0) plus a "slow LE u16 counter"
  (bytes 1-2, 3129→3329 over 197 s). That was a misread: the frames are
  the chair's **real-time clock**, decoding to a clean 1 Hz progression
  `2026-05-21 12:57:45 → 13:01:02`. The apparent "counter" is just
  `minutes + hour×256` read as a u16 (`12:57` → `57+12·256 = 3129`;
  `13:01` → `1+13·256 = 3329`). The bits-11:8 nibble is the broadcasting
  slot, not a function selector. See the RTC decode under "What is decoded."
- **XTD `0x181C0F00`** (102 frames): function `0x0F` in the
  `0x181C` cJSM/JSM device-class family (where `0x0D` is the known
  audio-tones function). Fully constant 8-byte payload
  `01 60 80 00 00 00 00 00`, fired irregularly every 1-30s. Looks
  like a periodic cJSM/JSM announcement.

Net coverage on the hackathon dump after the additions: **98.95%
evidenced + 0.97% `[unverified]` + 0.08% unknown** (the remaining
25 frames are scattered across 9 different rare IDs, none worth a
dedicated decoder).

## Authentication and access control — the whole story

R-Net's "auth" is **not cryptographic** and the wire shows two
distinct things the dissector decodes. This section ties together
what the dissector labels as "Serial auth" vs the Unlock frame vs
repository discovery, so the per-frame labels make sense at the
protocol level.

### Per the v5/v6 `DongleInterface.dll` decompile

Per `RNET_AUTH_PROTOCOL.md`'s decode of `CRnetInterface::SendUnlock`
and friends, R-Net's chair-side access control has three pieces:

1. **CAN-bus presence** = the primary credential. Anyone who can
   transmit on the bus can speak the protocol.
2. **A single broadcast Unlock frame** — extended CAN ID `0x08280F02`,
   DLC=0. The CAN-ID *is* the credential. The chair gates
   destructive service-mode operations (parameter writes, fault
   clearing) on having recently received this exact frame.
3. **Repository ownership tokens** — one-byte tokens per chair-side
   repository, mediated via service-discovery messages. Cooperative
   ownership; chair enforces by broadcast contention, not crypto.

Notably absent: challenge-response, per-message signing, session
keys, certificates. *Zero* "Auth/Authenticate/Challenge/Verify"
strings appear in the DLL. The "auth" model is designed against
**accidental cross-talk between programmers on a shared bus**, not
against an adversary with bus access.

### What the dissector shows you, frame by frame

| Frame family            | Meaning                                          | What "successful" / "failed" looks like |
|---|---|---|
| `Serial auth — response` (CAN ID `0x1F<seq><slot><key><val>`) | Per-device serial-byte broadcast in response to a JSM challenge. Each device emits its 4-byte DIME serial directly in the `val` field across `seq=0..3` (`val = serial[seq]`); the `key` field carries the network-wide XOR-table constant (`key = xor_table[seq]`), identical across every device on the network. | **Validated**: `✓ Table B` next to the label = `key[seq]` matches a known XOR table at that position. **Not validated**: no `✓` tag = the network's XOR table isn't one of our four known (A/B/C/D). The "validation" is just a network-identity match, not crypto — both sides know the table and the serial. |
| `Serial auth — RTR challenge` (same CAN ID with RTR bit set) | The JSM asking each device "tell me byte N of your serial." | **In progress**: each challenge precedes the matching response by milliseconds. |
| `R-Net Unlock — service-mode enable` (`0x08280F02`, DLC=0) | The Programmer flipping the chair into service mode. **The actual gate** for parameter writes / fault clearing chair-side. | **Successful** by emission: if the frame is on the wire, the chair's `CServiceManager` `+0x7b` "active" flag is presumed set. **No failure mode visible on wire** — the chair either accepts (silent) or ignores (also silent). |
| `Transfer Complete sentinel` (`0x1E80000F`) and ReBus attach handshake (`0x1E84..87`) | R-Net session-layer state transitions (see "Protocol layering" above). | Distinct from "auth" — these are session-state transitions, not access-control events. |

### The two "auth"-shaped wire flows aren't the same thing

The `0x1F` Serial-auth handshake decoded by this dissector existed in
the open-rnet DEFCON 24 research and is called "auth" by convention.
The `RNET_AUTH_PROTOCOL.md` decode makes clear that:

- The XOR exchange is **node-identity assertion** (each device proves
  it knows its own serial), **not authentication** in the security
  sense
- The actual chair-side access-control gate is the **separate**
  `0x08280F02` Unlock frame
- The "Serial auth" label is retained because it's what readers
  searching prior work will look for; the `✓ Table B` tag means
  "this matches a known R-Net network configuration"

### What "in progress" looks like

The XOR handshake plays out as 8 challenge frames (JSM → bus) followed
by 8 response frames (chair-side device → bus), per device. You'll see:

```
Auth challenge seq=0 slot=0 key=0xD3 (RTR — chair, please respond)
Auth challenge seq=1 slot=0 key=0x92 (RTR — chair, please respond)
... 6 more challenges
Auth response seq=0 slot=0 serial[0]=0x50 ✓ Table B (matches known JSM serial)
Auth response seq=1 slot=0 serial[1]=0xC0 ✓ Table B (matches known JSM serial)
... 6 more responses
```

Filter `rnet.auth.network` to see only the successfully-validated
responses; filter `rnet.class contains "challenge"` to see the
in-progress challenge phase.

### Service operations — now mapped (upstream-RE ANSWERS Q1)

The earlier "service opcodes 0x00–0x07 ride inside service frames"
framing was imprecise. Per the `CServiceManager::ServiceCANMsg @
0x10010140` decompile:

- **PARAM_R/W and FAULT_R/W are POP request/reply operations, not
  standalone service frames.** They ride on the standard POP frame
  (`0x780 | (dir<<4) | node`) as a read (TYPE=5) or write (TYPE=3) of a
  specific ODI. The ODI **class** is a memory region — `E2` (EEPROM) /
  `PORT` / `RAM` / `ROM` / `ADC` / `SLOT` / `EVENT` — **not** a
  PARAM/FAULT class (an earlier answer's "parameter-class/fault-class"
  framing was a service-op force-fit, refuted 2026-05-30 against the
  DLL's typed enum; the PARAM/FAULT service ops are real but their
  mapping to ODI classes is unverified). The dissector already decodes
  the POP ODI + class correctly, so these surface as POP frames with
  their ODI. Version
  reads are a concrete example, **now auto-flagged**: a `Read request`
  (`POP_MSG_TYPE` 5) of ODI `0xC4` = SW version, `0xC3` = HW version. The
  dissector derives `POP_MSG_TYPE` from the (TC, Quick, CRC) bits, so it
  distinguishes a true version *read* from a segmented transfer that
  merely carries ODI `0xC4` — 8 real SW-version reads in the corpus, zero
  false positives.
- **Service *status* frames** — `0x080` (repository discovery),
  `0x290` (KEYS → `SetKeyPress`), `0x305` (per-node status), `0x703`
  (status byte) — now have decoders (Code-tier from the DLL dispatch).
  None appear in parse's corpus yet; they fire on future
  Programmer/service captures.

Still open: the **repository ownership token** (1 byte:
`TAKEN_BIT 0x10 | NODE_MASK 0x0F`) is chair-internal state that
surfaces on the wire only as a side-effect of ownership negotiation;
and the per-sub-ID payload semantics of the `0x05X`/`0x06X` families
(family confirmed via the DLL predicates — the low-nibble meaning is
decided chair-side / in the DLR-EXE send path; see Known gaps).

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
  upstream-RE address-stability study (2026-05-23), of 159 wire
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

Means the dissector matched the auth-response frame's `key` byte
against XOR Table B's key sequence at that seq position — confirming
which R-Net network the chair belongs to. It's a direct byte match,
not a cryptographic check: the `key` field carries the network's
XOR-table constant in clear, and `val` carries the device's serial
byte. A `✓` is a strong network-identity signal. Tables A through D
are documented in `rnet_can.lua`; B is by far the most common (M300
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

### `99.78% evidenced coverage` is per-frame-class, not per-frame

The headline coverage number counts frames, not decode rules. Some
decode rules cover many thousands of frames (joystick, heartbeats),
others cover a handful (rare faults). The README's separate
**29% Code / 58% Documented / 13% Inferred** distribution counts
**rules**, not frames. A capture can be 99% evidenced even though
most of its rules are Documented or Inferred, because the few Code-
tier rules cover the bulk of the wire traffic.

## A walked-through session — `programmer_write_file_july2017.pcapng`

Reference material tells you what each frame means in isolation. This
section shows the frames *working together* across one real capture
— a Programmer dongle attaching to a chair, authenticating, writing
parameter values, and shutting down. Frame numbers below are real
positions in the 3,227-frame `programmer_write_file_july2017.pcapng`
shipped with `open-rnet`. To follow along live:

```sh
wireshark -X lua_script:rnet_can.lua \
  open-rnet/captures/programmer_write_file_july2017.pcapng
```

### Phase 1 — Bus enumeration (frames 1-17)

Before any session-level activity, the chair side of the bus is
already doing two periodic things:

```
1   Network test (STD 0x00C, periodic bus-presence probe)
2   JSM serial=50C01C8F
3   Serial exchange (STD 0x7B3, chair-side enum response)
```

`Network test` on STD `0x00C` is the chair's "is anyone alive" ping
— it goes out on a timer regardless of session state. `JSM serial`
on STD `0x00E` is the periodic 8-byte state-vector broadcast (per
the BTMouse change-detect handler at FW `0x854C`) — the first 4
bytes are the joystick module's serial number, the rest zero in
practice. From this one frame parse already knows the chair-side
identity: **JSM serial `50C01C8F`** matches the M300 network entry
in parse's XOR-table (Table B), which means subsequent auth-response
frames will get a `✓ Table B` annotation automatically.

`Serial exchange` (STD `0x7B3`) traffic with RTR challenges (frames
9, 12, 14) is the chair-side module-enumeration protocol —
modules announce themselves on demand. This is normal pre-session
chatter; the dissector labels it cleanly so you can tell at a glance
that the Programmer hasn't actually started doing anything yet.

### Phase 2 — Auth handshake (frames 18-40)

This is where things get interesting. The chair runs an 8-step
XOR-table challenge-response across multiple slots:

```
18  Auth response seq=0 slot=0 serial[0]=0x0C
19  Auth response seq=1 slot=0 serial[1]=0x01
20  Auth response seq=2 slot=0 serial[2]=0x14
21  Auth response seq=3 slot=0 serial[3]=0x8B
...
26  Auth challenge seq=0 slot=1 key=0x95 (RTR — chair, please respond)
...
34  Auth response seq=0 slot=2 serial[0]=0x50
35  Auth response seq=1 slot=2 serial[1]=0xC0
36  Auth response seq=2 slot=2 serial[2]=0x1C
37  Auth response seq=3 slot=2 serial[3]=0x8F
```

Two device serials surface here: `0C01148B` (slot 0) and `50C01C8F`
(slot 2 — matches the JSM serial from Phase 1). The seq 4-7 frames
are "extended round" responses — same protocol, just past the
4-byte serial boundary. Auth-response frames 34-37 cross-check
against parse's known XOR networks and ID this bus as **Table B
(M300 network)**. See [`Authentication and access control`](#authentication-and-access-control--the-whole-story)
for the full structural model — but in the wire, this whole phase
is a ~25-frame burst that happens once at the start of every
Programmer session.

### Phase 3 — POP parameter exchange (frames 71-92)

This is the heart of "the Programmer is doing something to the
chair." POP uses a two-frame pattern: one frame **names a parameter
via the POINTER register**, the next **reads or writes the value
via the DATA register**. Frame 71 sets up:

```
71  POP PM→JSM  DATA reg=POINTER  ptr=6.1 (param 262: BackUp)
```

The dissector resolves `ptr=6.1` to `BackUp` (a seat-back actuator
parameter) using parse's `pwc_params.json` registry. Then:

```
74  POP JSM→PM  REQUEST reg=POINTER          ← "tell me about ptr"
75  POP PM→JSM  ACK reg=DATA  value=0x0000 (0) → param 262: BackUp
76  POP JSM→PM  OPEN reg=DATA  value=0x9288 (37512) → param 262: BackUp
```

Notice how the DATA-register frames at 75 and 76 don't carry the
parameter name on the wire — but the dissector's per-frame summary
includes `→ param 262: BackUp` because of the POINTER binding from
frame 71. This is parse's cross-frame state at work; the `rnet.pop.
binds_param_name` field is filterable on its own:

```
tshark -Y 'rnet.pop.binds_param_name == "BackUp"' ...
```

Frames 84-92 repeat the pattern for `BackToggle` and `BackUpLatch`
— the chair gets reconfigured for these three actuator parameters
in rapid succession.

### Phase 4 — R-Net session promotion (frames 93-96)

Right after the Programmer is satisfied that the chair is in a
state it can talk to, it sends the **4-step attach handshake** that
promotes the connection from `CXTN_CAN` (raw CAN) to `CXTN_RNET`
(full R-Net session state machine):

```
93  R-Net attach 1/4 — Programmer announce (CXTN_CAN→CXTN_RNET begin)
94  R-Net attach 2/4 — chair ack
95  R-Net attach 3/4 — chair fingerprint #1 = 0x8314
96  R-Net attach 4/4 — chair fingerprint #2 = 0x0166 (CXTN_RNET ready)
```

After frame 96, every subsequent frame in the dissector's output
carries an `R-Net session state: CXTN_RNET` annotation in the
detail tree (or `CXTN_UPLOAD` / `CXTN_DOWNLOAD` during transfer
episodes). The fingerprints `0x8314` and `0x0166` are
chair-specific — they repeat across captures of the same physical
chair, making them useful as an identity tag.

### Phase 5 — Sustained parameter operations (frames 100-3000+)

The bulk of the capture is variations on Phase 3 — POINTER→DATA
binding for parameters like `BackDownLatch`, `BackToggleLatch`,
`LegRestRDown`, `TiltUp`, `TiltDown`, `LegRestDown`, `TiltToggle`,
`LegRestToggle`. Each cluster ends with a **Transfer Complete
sentinel** marking the return from `CXTN_UPLOAD/DOWNLOAD` to
`CXTN_RNET`:

```
372  ReBus transfer complete — R-Net returns to CXTN_RNET
618  ReBus transfer complete — R-Net returns to CXTN_RNET
897  ReBus transfer complete — R-Net returns to CXTN_RNET
1145 ReBus transfer complete — R-Net returns to CXTN_RNET
... (10 transfer episodes total)
```

If you wanted to count "how many parameter-write operations happened
in this capture" the answer is simply: **filter on the Transfer
Complete sentinel.**

```
tshark -r programmer_write_file_july2017.pcapng \
  -Y 'rnet.class contains "Transfer Complete"' \
  | wc -l
```

Each episode contains a mix of POP traffic (parameter writes),
joystick-position broadcasts (`X=+0 Y=+0 (idle)` — the user
isn't moving), motor-enable telemetry, and occasional `POP
PM→Programmer Abort` frames where the chair-side declines a
request (parameter probably read-only in the chair's current state).

### Phase 6 — Shutdown (frames 3218-3227)

The session ends cleanly:

```
3218  Seen during JSM init (STD 0x002, chair→bus payload-less signal)
3219  JSM sleep commencing (STD 0x004, chair→bus payload-less signal)
3220  Seen during JSM init (STD 0x002, chair→bus payload-less signal)
3221  JSM sleep commencing (STD 0x004, chair→bus payload-less signal)
3222  Seen during JSM init (STD 0x002, chair→bus payload-less signal)
3223  Sleep cmd
3224  Sleep all (RTR)
3225  Sleep cmd
3226  Sleep cmd
3227  ReBus transfer complete — R-Net returns to CXTN_RNET
```

The chair's JSM module oscillates between "init" and "sleep
commencing" states briefly, then `STD 0x000` Sleep commands take
the whole bus down. Frame 3227's Transfer Complete is the residual
end-of-last-transfer sentinel — the bus is functionally idle.

### What this session tells you about R-Net

This is a 3,227-frame Programmer-attached configuration session.
End-to-end:

1. **The chair is always pinging** — Phase 1's STD `0x00C` Network
   test, STD `0x00E` JSM serial heartbeat, and STD `0x7B3` Serial
   exchange traffic happen whether or not anything's connected.
2. **Auth is structurally distinct from access control** — Phase 2's
   8-step XOR challenge-response is a node-identity validation, NOT
   a security check (the chair's actual access gate is the separate
   `0x08280F02` R-Net Unlock frame; this capture happens to not
   send one because it's only writing actuator parameters, not
   destructive operations). See [`Authentication and access control`](#authentication-and-access-control--the-whole-story).
3. **Session promotion is explicit** — Phase 4's 4-step handshake
   is the dividing line between "we share a bus" and "we share a
   protocol session." Before frame 96, the dissector emits
   `CXTN_CAN`; after, `CXTN_RNET`.
4. **Parameter access is two-frame** — Phase 3/5's POINTER→DATA
   pattern is the spine of POP-level parameter R/W. parse's
   cross-frame binding makes the parameter name visible on the
   DATA frame too.
5. **Transfer Complete is the punctuation** — every meaningful
   chunk of work ends with `0x1E80000F`. Counting them gives you
   "how many distinct things did the Programmer do."

Try this approach on any other capture in the corpus: identify the
Phase-1 chatter (always there), find the Phase-2 auth burst (start
of session), look for Phase-4 attach if a session was actually
established, then read the Phase-5 episodes by Transfer-Complete
boundaries. The labels and cross-frame fields parse adds carry the
story.

## Filters, recipes, and field reference

What the dissector lets you ask of a capture: quick-reference filter
examples, task-oriented recipes, recommended columns for at-a-glance
scanning, and the complete catalog of `rnet.*` fields the dissector
emits.

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

# All frames inside a specific POP transfer (per-frame session state)
-Y 'rnet.transfer_id == 7'

# All frames during a download or upload (R-Net session state)
-Y 'rnet.session_state matches "UPLOAD|DOWNLOAD"'

# DATA frames bound to a specific parameter (cross-frame POINTER binding)
-Y 'rnet.pop.binds_param_name == "BackUp"'

# Just the chair-attach handshake (4 frames at session start)
-Y 'rnet.class contains "R-Net attach"'
```

(`rnet.confidence` requires the `rnet.show_evidence:TRUE` preference;
the others work always.)

### Common investigations

Task-oriented recipes that combine multiple filters to answer real
questions about a capture. Adapt the capture path to your file.

**"Was the chair reporting any fault during this capture?"**

```sh
tshark -r capture.pcapng -Y 'rnet.err.fault' \
       -T fields -e frame.time_relative -e rnet.slot \
                 -e rnet.err.code -e rnet.err.name
```

Filters to status/error frames where the code is non-zero; columns
out the slot, hex code, and decoded name.

**"Did a parameter write succeed?"** (chair-side acked + CRC OK)

```sh
tshark -r capture.pcapng \
       -Y 'rnet.pop.binds_param_name == "BackUp"' \
       -T fields -e frame.number -e rnet.session_state \
                 -e rnet.transfer_id -e rnet.pop.value16
# Then check for the matching Transfer Complete:
tshark -r capture.pcapng -Y 'rnet.transfer_id == N && rnet.pop.crc_value'
```

Plan 2's POINTER→DATA binding means every DATA frame is tagged with
the parameter it's accessing. Pair with `rnet.pop.crc_value` to
confirm the transfer ended cleanly.

**"What network / chair is this capture from?"**

```sh
tshark -r capture.pcapng -Y 'rnet.auth.network' \
       -T fields -e rnet.auth.network | sort -u
tshark -r capture.pcapng -Y 'rnet.dime' \
       -T fields -e rnet.slot -e rnet.dime | sort -u
```

XOR-table identification plus DIME serial enumeration tells you the
network's identity and which modules are on the bus.

**"Trace the dealer-Programmer attach session"**

```sh
tshark -r capture.pcapng \
       -Y 'rnet.class contains "R-Net attach" || rnet.class contains "Transfer Complete"'
```

Surfaces the 4-frame chair-attach handshake + every transfer end.
Use `rnet.session_state` to see the CXTN state per frame.

**"What's the dissector unsure about in this capture?"**

```sh
# First enable evidence display, then filter on Inferred-tier decodes:
tshark -o rnet.show_evidence:TRUE -r capture.pcapng \
       -Y 'rnet.confidence == "Inferred"' \
       -T fields -e rnet.class | sort -u
```

Surfaces all family-analogy / hackathon-only decodes — useful for
deciding what's safe to act on and what to investigate further.

**"Reconstruct the chair's wall clock from RTC frames"**

```sh
tshark -r capture.pcapng -Y 'rnet.rtc.year' \
       -T fields -e frame.time_relative \
                 -e rnet.rtc.year -e rnet.rtc.month -e rnet.rtc.day \
                 -e rnet.rtc.hour -e rnet.rtc.min -e rnet.rtc.sec \
       | head
```

The 0x1C2C0X00 frames broadcast the chair's clock at ~1Hz.

### Recommended Wireshark columns

The dissector populates a rich set of fields. For at-a-glance reading
of a capture, the most useful columns to add (Edit → Preferences →
Columns → New, choose `Custom`, paste the field name):

| Column title | Field                       | Why useful                            |
|---|---|---|
| Network      | `rnet.auth.network`         | Surfaces "Table A/B/D" when auth validates    |
| Reg          | `rnet.pop.register_name`    | POINTER / DATA / TEXT / PAGE0 at a glance     |
| Param        | `rnet.pop.binds_param_name` | Parameter the DATA frame is writing/reading   |
| State        | `rnet.session_state`        | CXTN_RNET / UPLOAD / DOWNLOAD                 |
| Xfer         | `rnet.transfer_id`          | Which POP transfer episode this frame is in   |
| Fault        | `rnet.err.name`             | Decoded fault name on status frames           |

The default `Info` column already carries the per-frame summary so
you don't need to add anything to get a usable view — these columns
make scanning long captures faster by surfacing specific fields in
dedicated slots.

### Field reference

Complete list of `rnet.*` fields the dissector emits, grouped by
purpose. All are usable as display filters (`-Y 'rnet.foo'`) and as
column fields (paste the name into the Columns preferences dialog).

#### Universal — present on every R-Net frame

| Field | Type | What it is |
|---|---|---|
| `rnet.class` | string | Frame class label (e.g. "PM heartbeat", "POP (standard-ID)") |
| `rnet.summary` | string | Human-readable summary line (mirrored into the Info column) |
| `rnet.slot` | uint8 | Device slot nibble (0=PM, 1=JSM, 2=IOM/ISM, etc.) |

#### Session state — every frame in an R-Net conversation

| Field | Type | What it is |
|---|---|---|
| `rnet.session_state` | string | CXTN_NONE / CXTN_CAN / CXTN_RNET / CXTN_UPLOAD / CXTN_DOWNLOAD |
| `rnet.transfer_id` | uint32 | POP transfer episode counter (increments per UPLOAD/DOWNLOAD) |

#### POP application protocol (`rnet.pop.*`)

| Field | Type | What it is |
|---|---|---|
| `rnet.pop.tc` | uint8 | Transfer code: 0/1/2 = segment indicator N; 3 = abort (standard-ID) / last segment (extended-ID) |
| `rnet.pop.tc_str` | string | TC name ("Segment indicator 0" / "Abort" / ...) |
| `rnet.pop.quick` | bool | Quick (single-frame) flag |
| `rnet.pop.crc` | bool | CRC flag (bit 4 of data[0]) |
| `rnet.pop.this_node` / `.other_node` | uint8 | Source / destination slot nibbles |
| `rnet.pop.this_node_str` / `.other_node_str` | string | Slot names |
| `rnet.pop.register_name` | string | Register: POINTER / DATA / TEXT / PAGE0 |
| `rnet.pop.odi` | uint32 | 24-bit Object Data Identifier |
| `rnet.pop.odi_class` | string | ODI class (ODI_CLASS_SLOT etc.) |
| `rnet.pop.odi_address` | uint16 | Address within class |
| `rnet.pop.pointer_param_id` | uint16 | Permobil PWC param ID derived as (sub<<8)\|idx |
| `rnet.pop.param_name` | string | Resolved param name (PWC registry) |
| `rnet.pop.addr_name` / `.addr_prefix` / `.addr_path` | string | `.rnd` address-table name, stable-module prefix, GUI menu path |
| `rnet.pop.binds_param_id` / `.binds_param_name` | uint32 / string | Param this DATA frame writes/reads (from prior POINTER setup) |
| `rnet.pop.binds_pointer_frame` | framenum | Frame number of the POINTER setup that bound this DATA |
| `rnet.pop.value16` / `.value32` | uint | Bytes 4-5 LE u16 / bytes 4-7 LE u32 (raw value) |
| `rnet.pop.crc_value` | uint16 | CRC echo embedded in COMPLETE responses |
| `rnet.pop.segment` | uint16 | Segment number in POP-ext segmented transfers |
| `rnet.pop.size` | uint32 | Size field on segmented-transfer setup frames |
| `rnet.pop.is_abort` | bool | True when TC=3 (abort frame, standard-ID) |
| `rnet.pop.is_last` | bool | True when TC=3 on an **extended-ID** POP frame (last segment — the extended-ID counterpart of `is_abort`) |
| `rnet.pop.label` | string | Legacy opcode name (OPEN/REQUEST/ACK/COMPLETE/...) when recognized |
| `rnet.pop.msg_type` | string | `POP_MSG_TYPE` derived from (TC, Quick, CRC): Quick write (3) / Read request (5) / Download req (7) / Upload req (0xE) / Reply-ACK (0xC/0x14) / Abort (2) — per `CPOPMsg::SetType` |
| `rnet.pop.dir` | uint8 | Direction discriminator (CAN ID bit 4) |
| `rnet.pop.block` | uint8 | Segment-block counter (data[7] on standard-ID setup frames) |
| `rnet.pop.pointer` | uint16 | Raw POINTER register value (bytes 4-5 LE u16) |
| `rnet.pop.pointer_idx` / `.pointer_sub` | uint8 | POINTER index (data[4]) / sub-index (data[6]); combined into `pointer_param_id` |

#### Auth handshake (`rnet.auth.*`)

| Field | Type | What it is |
|---|---|---|
| `rnet.auth.seq` | uint8 | 0..7 position in the 8-frame auth round |
| `rnet.auth.slot` | uint8 | Slot whose serial byte is being asserted |
| `rnet.auth.key` | uint8 | XOR-table key for this seq position |
| `rnet.auth.value` | uint8 | Responding module's serial byte at seq (or 0 on RTR challenge) |
| `rnet.auth.valid` | bool | Key matched a known XOR network table |
| `rnet.auth.network` | string | Identified network name ("Table A: ..." etc.) when valid |
| `rnet.auth.device_serial` | string | Device serial (`LLYYMMNNNN`), reassembled from the seq 0-3 serial bytes and rendered through the vendor's own `GetSN`/DIME algorithm (Code-tier; IRConfigurator `DeviceDriver.GetSN`). Works for **any** network — the raw serial byte is on the wire whether or not parse knows the chair's XOR table. Resolves once all four bytes of a single auth round are seen; the seq-0 round boundary prevents byte-splicing across devices on hotplug/re-attach. **Caveat:** wire byte-order is empirically confirmed, but the rendered string is *not yet ground-truthed against a physically-labeled device* — it's the canonical rendering of the wire bytes, not a label-verified identifier (`DIME_SERIAL_DECODE.md`: "need confirmation from labeled devices") |

#### Joystick / motor / drive

| Field | Type | What it is |
|---|---|---|
| `rnet.joy.x` / `.joy.y` | int8 | Joystick X/Y (-128..127, signed) |
| `rnet.motor.left` / `.right` | uint16 | Motor power LE u16 per side |
| `rnet.motor.en_l` / `.en_r` | uint8 | Motor enable byte per side |
| `rnet.speed.percent` | uint8 | Speed setting % |
| `rnet.horn.state` | string | Horn on/off |
| `rnet.dist.left` / `.right` | uint32 | Wheel encoder counts LE u32 per side |

#### Battery, lights, indicators

| Field | Type | What it is |
|---|---|---|
| `rnet.batt.percent` | uint8 | Battery level % |
| `rnet.lights.bitmap` | uint8 | Indicator bitmap byte (raw) |
| `rnet.lights.left` / `.right` / `.hazard` / `.flood` | bool | Individual indicator-bit booleans (bits `0x01` / `0x04` / `0x10` / `0x80`) |
| `rnet.lights.bit6` | bool | Bitmap bit `0x40` — `[Inferred]` co-occurs with the full "all lamps active" state (5-capture sweep); specific indicator name unconfirmed (upstream-RE `RNET_FRAME_GLOSSARY.md` `0x0C000400`, needs ILM dump) |
| `rnet.lights.bit1` / `.bit3` / `.bit5` | bool | Bitmap bits `0x02` / `0x08` / `0x20` — defined and filterable but semantics still **open** (no source yet) |

#### Audio and misc

| Field | Type | What it is |
|---|---|---|
| `rnet.tones` | string | Decoded tone/buzzer sequence as (length, note) pairs (XTD `0x181C0D00`) |
| `rnet.note` | string | Free-form analyst note attached to certain frames (provenance caveats, magic-pattern flags) — not present on every frame |

#### RTC broadcast (`rnet.rtc.*`)

| Field | Type | What it is |
|---|---|---|
| `rnet.rtc.year` | uint8 | Years since 2000 (add 2000) |
| `rnet.rtc.month` / `.day` | uint8 | Calendar date |
| `rnet.rtc.dow` | uint8 | Day-of-week (1=Mon..7=Sun) |
| `rnet.rtc.hour` / `.min` / `.sec` | uint8 | Wall-clock time |

#### Mode configuration (`rnet.mode.*`)

| Field | Type | What it is |
|---|---|---|
| `rnet.mode.index` | uint8 | Mode index 0-5 |
| `rnet.mode.subaddr` | uint8 | Sub-address |
| `rnet.mode.type` / `.type_str` | uint8 / string | Data type byte + decoded name |

#### Faults (`rnet.err.*`)

| Field | Type | What it is |
|---|---|---|
| `rnet.err.code` | uint16 | BE u16 error code (non-zero = fault active) |
| `rnet.err.name` | string | Decoded error name from catalog |
| `rnet.err.fault` | bool | True iff code != 0 |

#### Module identity

| Field | Type | What it is |
|---|---|---|
| `rnet.dime` | string | Decoded DIME serial (LLYYMMNNNN format) |
| `rnet.serial` | bytes | Raw 4-byte serial from STD 0x00E heartbeat |
| `rnet.jsm_hb.valid` | bool | JSM 87×7 heartbeat signature matched |
| `rnet.pm_hb.byte0` | uint8 | Per-slot heartbeat byte 0 (encodes TC + emitter slot) |

#### Audit + provenance (`rnet.confidence`, `rnet.evidence`)

Only emitted when the `rnet.show_evidence` preference is enabled.

| Field | Type | What it is |
|---|---|---|
| `rnet.confidence` | string | Evidence kind: Code / Documented / Inferred |
| `rnet.evidence` | string | Source citation |

## Known gaps

These show as `Unknown ...` in dissector output and are good targets
for future RE work:

| ID pattern | Frame count | Note |
|---|---|---|
| STD `0x05X` (051-054) | 208 | Profile-change family member — family ID confirmed via DLL `IsProfileChangeMsg`, per-payload semantic still open |
| STD `0x06X` (060-065) | 291 | Mode-change family member — family ID confirmed via DLL `IsModeChangeMsg`, per-payload semantic still open |
| STD `0x04X` (042-045) | 94 | Param-page family — direction (chair-emitted) confirmed via 4-source dealer-side zero-hit sweep, semantic still open |
| XTD `0x181C0X00` (X≠D) | ~91 | Family prefix matches tones (`0x181C0D00`); cJSM-emitted confirmed by 4-source zero-hit sweep; cJSM firmware not yet dumped |
| XTD `0x0A400X0Y` (other slots) | ~46 | BTM family, slots 02+ not documented; chair-emitted confirmed via 5-source dealer+chair-side zero-hit sweep (incl. BTMouse MC9S12X firmware); emitter module not yet identified |

(`XTD 0x1C2C0X00` was promoted to **Documented** in 2026-05-23 after
empirical cross-checks. `XTD 0x14300X01` was previously promoted but
re-tiered to **Inferred** after upstream-RE's multi-source negative
finding suggested the `0x1B` value is a magic constant rather than a
27% measurement. PM-side firmware (MC56F83) would settle it but isn't
obtainable; the realistic path is a live capture correlating
speed/profile changes with the byte.)

### Why dealer-side zero-hit ≠ "we got it wrong"

A recurring pattern in cross-validation: parse identifies a frame
family by analogy or capture-pattern, then upstream-RE searches the
dealer-side sources (DLL v5/v6, DLR EXE, IRConfigurator) and finds
**zero literal hits**. That used to feel like a negative result, but
it's usually scope, not a wrong decode. The dealer Programmer is a
USB/FTDI bridge that speaks only the **dealer-facing subset** of
R-Net — chair-internal module-to-module traffic (motor telemetry,
inter-module heartbeats, per-slot state) is never in its dispatch
tables, so a chair-internal frame ID produces zero hits in the
Programmer binaries by construction.

This means the right next step when dealer-side comes up empty is to
**look at the target module's firmware**, not assume the decode is
wrong. The catch: most chair modules' firmware isn't in our dump set
(PM MC56F83, cJSM audio MCU, BT-Mouse application). And even within the
two chair modules we do have (LEDJSM, BTMouse), a frame addressed to a
*different* module won't appear in this one's CAN-ID match table — see
the *Per-module filtering* note in the CAN primer above. So "zero hits"
propagates as scope at two layers — dealer-software, then per-module —
before it ever means "wrong."

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
   version.** Largely resolved (upstream-RE ANSWERS Q3): the chair
   answers a deterministic on-wire version query —
   **`ReadSWVersion` = a POP read of ODI `0xC4`** returning a u16
   software version, with **`ReadHWVersion` = ODI `0xC3`** for hardware
   (`CRnetInterface::ReadSWVersion @ 0x1000b950` / `ReadHWVersion @
   0x1000b8c0`). The dissector **auto-flags** these: it derives
   `POP_MSG_TYPE` from the (TC, Quick, CRC) bits and labels a `Read
   request` (type 5) of ODI `0xC4`/`0xC3` as a SW/HW version read — 8 real
   SW-version reads in the corpus, zero false positives (the other ODI-
   `0xC4` frames are segmented transfers, correctly *not* flagged). One
   caveat remains: it's a **solicited**
   read (only present when a Programmer session is in the capture, not an
   unsolicited broadcast). Signals that did **not** pan out:
   - The `0x1E86`/`0x1E87` chair-fingerprint bytes (chair 50C01C8F →
     `0x8314`/`0x0166`; B68021AE → `0x3D16`/`0x0006`) are **unverified
     as a version signal** — they have zero references in the dealer
     DLL, so they read as persistent per-chair identity tags. (Absence
     in the DLL isn't proof a chair-side generator doesn't encode
     version, but the ODI read is the reliable route.)
   - The DIME serial encodes a YYMM manufacturing-batch prefix —
     correlates loosely with firmware era, not a direct version field.
2. **A mapping** from the version-read u16 (ODI `0xC4`) to a catalog
   key. The wire now hands us the version directly when a Programmer is
   present; what's still needed is the `version → .rnd catalog` table
   (which build maps to which extraction).
3. **The bundled JSONLs**: ~10MB of parameter catalogs (the 6
   existing extractions plus any new firmware versions). Today the
   dissector is a single ~325KB Lua file. Adding the JSONLs is
   straightforward but bumps the install size 40×, and adds a
   load-time JSON parser the dissector currently doesn't need.

   (As of 2026-05-24, upstream-RE's parameter **registry v2** exposes
   verified per-parameter `factory_default` / `absolute_min` /
   `absolute_max` / `step` as named fields — 5,329 records — instead of a
   raw uint32 tail. If this feature lands, v2 is the catalog source to
   pull from; the named fields simplify the loader and let the dissector
   surface parameter bounds, not just names.)

### Why we aren't doing this now

- **Blocker #1 (fingerprint → firmware mapping) is the hard one.**
  Until we have multiple chairs in the corpus with KNOWN firmware
  versions, we can't validate any fingerprint hypothesis. The
  prefix proxy already gives readers the stable module
  identification piece, so the marginal value of disambiguating
  the specific name is small for typical use.
- **Install-size jump is real.** Going from one 325KB Lua file to a
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
  tests/test_dissector.py  — pytest suite (46 tests)
  tests/test_edge_cases.py — synthetic edge-case test harness (36 tests)
  tests/synthetic/         — pcap generator for edge-case fixtures

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

## Interesting frames worth sharing

Some frames are interesting precisely because nobody has ever captured
them. Chair-side firmware (BTMouse MC9S12X, LEDJSM HCS12) contains
dispatch handlers for a small set of CAN IDs that **parse's entire
30-capture corpus has zero observations of**. If you ever see one
in your own captures, you've recorded something the dissector has
never seen.

The dissector flags these loudly in Wireshark's Expert Information
panel (severity: Warning) so you can't miss them. The current
"please share if you see this" set:

| What | Pattern | Why it's interesting |
|---|---|---|
| **BT-pairing-unlock Pattern A (seed frame)** | Extended CAN frame, `(id & 0x3FFFF) == 0x07E57` (DLC and data unconstrained; bits 17:16 must be 0, top 11 bits free) | First frame of a TWO-frame unlock sequence per BTMouse handler `0xF50E`. The chair-side bit-shuffle leaves the magic bytes `0x57 0x7E 0x00` in the firmware's internal buffer at RAM `0x329A/B/C`. NOTE-severity marker on its own (the pattern could be incidental in some traffic) — pair with Pattern B below to see the full sequence. Datasheet-verified per `BTMOUSE_UNLOCK_FRAMES_FOR_PARSE.md` (upstream-RE T59). |
| **BT-pairing-unlock Pattern B (trigger frame)** | Standard CAN frame, ID == `0x07A0` EXACTLY, DLC=8, ALL 8 data bytes zero | Second frame of the sequence — fires the unlock IF Pattern A primed the buffer recently AND the runtime flag at `0xFF4C4` is set (banked code decides this). NOTE-severity marker per-frame. The frame's class label is also re-flagged from the default "Programmer presence" to make the magic-pattern match visible without expert-info enabled. (Earlier interpretations listed 8 candidate IDs with low byte 0xA7; the datasheet-verified disassembly of FUN_00430E narrows the trigger to exactly 0x07A0.) |
| **BT-pairing-unlock full sequence (Pattern A → Pattern B)** | Pattern B arrives within ~1s of a Pattern A on the same bus | The actually-interesting case. WARN-severity marker fires on the Pattern B frame. The handler then calls a banked function whose effect we can't statically see — likely BT pairing enable, factory test mode, or service-only parameter writes. |
| **Dormant chair-listened STD CAN IDs** | STD `0x001`, `0x00A`, `0x0F0`, `0x7C0`, `0x7E0`, `0x7E4`, `0x7E8`, `0x7EC` | All appear in BTMouse's literal CAN-ID table at flash `0x56E0-0x571B` (cross-validated against LEDJSM HCS12 at flash `0x57C8+`) — the chair has CAN-ID match-table / dispatch entries ready to react. But none of these IDs has ever appeared in any of the 30 captures in parse's corpus. Likely candidates: factory/diagnostic frames, service-tool triggers, or planned-but-not-shipped variants. |
| **0x1E8X session sentinel with subtype 1, 2, or 3** | XTD `0x1E810000`-`0x1E830000` (the rare subtypes) | Multi-source negative confirmation across 4 dealer-side binaries and the 30-capture corpus says these subtypes are deliberately unused (parse handles N=0 Transfer Complete and N=4-7 attach handshake — the rest were never seen). If a wire frame uses one, that means a chair module we don't have a primary source for. |
| **Fault code with no catalog entry** | Status/error frame (XTD `0x140C0X0Y`) carrying a code parse doesn't recognize | Parse has ~830 known fault codes from `open-rnet/docs/RNET_ERROR_CODES.md` + Generic V33_1_1375 .rnd extraction. A code outside both catalogs likely means an OEM-specific .rnd (Amylior / Permobil / Pride / SwitchIt) or a chair firmware generation we don't have. NOTE-severity marker. When a paramtree-coincidence hint is available, the summary includes it with explicit "almost certainly NOT the fault name" framing — a hint for analysts, not a claim. |

If you capture any of these:
1. Save the pcap/pcapng (or `candump -L` text log) — even a few minutes around the event is useful
2. Note what you were doing on the chair when it happened (just powered up? entering a particular menu? after a Programmer session? during a BT pair attempt?)
3. File an issue or share the capture with us — see "Contributing" below

The dissector will tell you which kind it saw. In Wireshark, look for the **Warning-level Expert Info** items in the bottom-right status bar, or use the `Analyze → Expert Information` menu. In tshark, the markers appear in `-V` output alongside the frame.

Each marker is also a filterable expert-info field, so you can sweep a
capture for any of them without reading every frame:

| Marker | Filter field |
|---|---|
| BT-pairing-unlock Pattern A (seed) | `rnet.expert.bt_unlock_pattern_a` |
| BT-pairing-unlock Pattern B (trigger) | `rnet.expert.bt_unlock_pattern_b` |
| BT-pairing-unlock full sequence (A→B) | `rnet.expert.bt_unlock_sequence` |
| Dormant chair-listened STD CAN ID | `rnet.expert.dormant_chair_listened` |
| 0x1E8X session sentinel, unused subtype | `rnet.expert.sentinel_unknown_subtype` |
| Fault code with no catalog entry | `rnet.expert.unresolved_fault_code` |
| Fault-code paramtree coincidence hint | `rnet.expert.fault_code_paramtree_hint` |

```sh
# e.g. find the full BT-unlock sequence anywhere in a capture:
tshark -r capture.pcapng -Y 'rnet.expert.bt_unlock_sequence'
```

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
