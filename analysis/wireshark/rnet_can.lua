-- rnet_can.lua — Wireshark/tshark dissector for the R-Net CAN protocol
--
-- R-Net is the Curtiss-Wright (formerly PG Drives Technology) power-wheelchair
-- control protocol. Runs on 125 kbit/s CAN. This dissector decodes payloads
-- of SocketCAN-encapsulated frames where the CAN ID matches an R-Net pattern.
--
-- USAGE:
--   tshark -X lua_script:rnet_can.lua -V -r capture.pcapng
--   tshark -X lua_script:rnet_can.lua -r capture.pcapng -Y rnet.joy
--   wireshark -X lua_script:rnet_can.lua capture.pcapng
--
-- EVIDENCE BASIS:
--   Frame interpretations are taken from runnable code that has been used
--   against real captures:
--     * open-rnet/tools/rnet_utils.py:decode_frame()  (line ~260) — the spine
--     * open-rnet/lib/can2RNET.py — wire format primitives
--     * open-rnet/contrib/can2RNET/JoyLocal.py — joystick frame use
--     * open-rnet/tools/rnet_utils.py:parse_auth_frame_id() — serial-auth layout
--
--   Entries derived only from the prose reference RNET_FRAME_DICTIONARY.md
--   (no corroborating runnable code) are marked "[unverified]" so users can
--   tell at a glance which interpretations are well-grounded.

local rnet = Proto("rnet", "R-Net (Curtiss-Wright / PGDT)")

-- ProtoFields -----------------------------------------------------------------
local pf = {
    class       = ProtoField.string("rnet.class",       "Frame class"),
    summary     = ProtoField.string("rnet.summary",     "Summary"),
    slot        = ProtoField.uint8 ("rnet.slot",        "Device slot", base.HEX),
    note        = ProtoField.string("rnet.note",        "Note"),

    -- joystick (rnet_utils.py:330)
    joy_x       = ProtoField.int8  ("rnet.joy.x",       "Joystick X (signed)"),
    joy_y       = ProtoField.int8  ("rnet.joy.y",       "Joystick Y (signed)"),

    -- speed (rnet_utils.py:339)
    speed_pct   = ProtoField.uint8 ("rnet.speed.percent","Speed (%)"),

    -- battery (rnet_utils.py:352)
    batt_pct    = ProtoField.uint8 ("rnet.batt.percent","Battery (%)"),

    -- motor current (rnet_utils.py:359)
    motor_left  = ProtoField.uint16("rnet.motor.left",  "Motor current L", base.DEC),
    motor_right = ProtoField.uint16("rnet.motor.right", "Motor current R", base.DEC),

    -- distance counter (rnet_utils.py:415)
    dist_left   = ProtoField.uint32("rnet.dist.left",   "Distance L (ticks)", base.DEC),
    dist_right  = ProtoField.uint32("rnet.dist.right",  "Distance R (ticks)", base.DEC),

    -- motor enable (rnet_utils.py:430)
    motor_en_l  = ProtoField.uint8 ("rnet.motor.en_l",  "Motor enable L", base.HEX),
    motor_en_r  = ProtoField.uint8 ("rnet.motor.en_r",  "Motor enable R", base.HEX),

    -- horn (rnet_utils.py:346)
    horn_state  = ProtoField.string("rnet.horn.state",  "Horn state"),

    -- lights (rnet_utils.py:400)
    light_left  = ProtoField.bool  ("rnet.lights.left", "Left indicator",  8, nil, 0x01),
    light_right = ProtoField.bool  ("rnet.lights.right","Right indicator", 8, nil, 0x04),
    light_haz   = ProtoField.bool  ("rnet.lights.hazard","Hazard",         8, nil, 0x10),
    light_flood = ProtoField.bool  ("rnet.lights.flood","Flood",           8, nil, 0x80),

    -- serial heartbeat (rnet_utils.py:275)
    serial_bytes = ProtoField.bytes("rnet.serial",      "Serial number"),
    -- DIME human-readable serial (decoded via DeviceDriver.GetSN()).
    dime_serial  = ProtoField.string("rnet.dime",       "DIME-decoded serial (LLYYMMNNNN)"),

    -- serial-auth frames 0x1F.. (rnet_utils.py:315 + parse_auth_frame_id)
    auth_seq    = ProtoField.uint8 ("rnet.auth.seq",    "Sequence (0..7)", base.DEC),
    auth_slot   = ProtoField.uint8 ("rnet.auth.slot",   "Slot",            base.HEX),
    auth_key    = ProtoField.uint8 ("rnet.auth.key",    "Derived key",     base.HEX),
    auth_value  = ProtoField.uint8 ("rnet.auth.value",  "Serial byte / challenge", base.HEX),

    -- POP (Parameter Object Protocol) frames — see decode_pop_std/decode_pop_xtd.
    -- Evidence: DONGLE_INTERFACE_DLL_TYPES.md §"POP wire-format
    -- bit layout" (recovered from Ghidra decompile of CPOPMsg::SetTransferCode /
    -- IsAbortMsg / GetClientFromMsg / GetServerFromMsg, 2026-05-19).
    -- The previously-documented "POP opcode table" (OPEN/REQUEST/HEARTBEAT/etc.)
    -- turned out to conflate two fields packed into byte 0: TransferCode (bits 7-6)
    -- and OtherNode (bits 3-0). The fields below decode that structure rigorously.
    pop_tc        = ProtoField.uint8 ("rnet.pop.tc",         "Transfer Code",      base.DEC),
    pop_tc_str    = ProtoField.string("rnet.pop.tc_str",     "Transfer Code (decoded)"),
    pop_quick     = ProtoField.bool  ("rnet.pop.quick",      "Quick (single-frame) flag", 8, nil, 0x20),
    pop_crc       = ProtoField.bool  ("rnet.pop.crc",        "CRC flag (data[0] bit 4)", 8, nil, 0x10),
    pop_other     = ProtoField.uint8 ("rnet.pop.other_node", "Other-node nibble (in data[0])", base.HEX),
    pop_other_str = ProtoField.string("rnet.pop.other_node_str","Other-node device"),
    pop_this      = ProtoField.uint8 ("rnet.pop.this_node",  "This-node nibble (in CAN ID)",   base.HEX),
    pop_this_str  = ProtoField.string("rnet.pop.this_node_str","This-node device"),
    pop_dir       = ProtoField.uint8 ("rnet.pop.dir",        "Direction bit (CAN ID bit 4)",   base.DEC),
    pop_odi       = ProtoField.uint32("rnet.pop.odi",        "ODI (Object Data Id, 24-bit LE)", base.HEX),
    pop_reg_name  = ProtoField.string("rnet.pop.register_name","Register name (ODI low byte)"),
    pop_odi_class = ProtoField.string("rnet.pop.odi_class",  "ODI class (from ODI_CLASS enum)"),
    pop_odi_addr  = ProtoField.uint16("rnet.pop.odi_address","Address-within-class", base.HEX),
    -- Value field at bytes 4-7. For Quick-style POP frames operating on
    -- documented registers, bytes 4-7 are the value being read/written,
    -- not a Size. Bytes 4-5 LE u16 is the typical pointer/parameter ID;
    -- bytes 4-7 LE u32 is the full value field.
    pop_value16   = ProtoField.uint16("rnet.pop.value16",     "Value (bytes 4-5 LE u16)", base.HEX),
    pop_value32   = ProtoField.uint32("rnet.pop.value32",     "Value (bytes 4-7 LE u32)", base.HEX),
    pop_pointer   = ProtoField.uint16("rnet.pop.pointer",     "POINTER register raw value (bytes 4-5 LE u16)", base.HEX),
    pop_ptr_idx   = ProtoField.uint8 ("rnet.pop.pointer_idx", "Pointer index (data[4])", base.HEX),
    pop_ptr_sub   = ProtoField.uint8 ("rnet.pop.pointer_sub", "Pointer sub-index (data[6])", base.HEX),
    pop_ptr_pid   = ProtoField.uint16("rnet.pop.pointer_param_id", "Permobil PWC param_id (sub<<8 | idx)", base.DEC),
    pop_ptr_name  = ProtoField.string("rnet.pop.param_name",  "Parameter name (registry cross-reference)"),
    pop_addr_name = ProtoField.string("rnet.pop.addr_name",   "Parameter name (.rnd memory-address lookup)"),
    pop_size      = ProtoField.uint32("rnet.pop.size",       "Size (24-bit LE)", base.DEC),
    pop_block     = ProtoField.uint8 ("rnet.pop.block",      "Block (segment-block counter)", base.DEC),
    pop_segment   = ProtoField.uint16("rnet.pop.segment",    "SegmentNumber (extended-ID POP)", base.DEC),
    pop_crc_value = ProtoField.uint16("rnet.pop.crc_value",  "Embedded CRC-16/CCITT-FALSE (LE u16 at bytes 4-5 of POP COMPLETE)", base.HEX),
    pop_is_abort  = ProtoField.bool  ("rnet.pop.is_abort",   "Is Abort message"),
    pop_is_last   = ProtoField.bool  ("rnet.pop.is_last",    "Is Last Segment"),
    pop_label     = ProtoField.string("rnet.pop.label",      "Legacy opcode label (if any)"),

    -- tones (rnet_utils.py:377)
    tones       = ProtoField.string("rnet.tones",       "Tone sequence"),

    -- Mode configuration (XTD 0x1ECXXXXX). Evidence: cJSM display-protocol
    -- "Mode Configuration Frames", corroborated by DongleInterface.dll
    -- wire-format notes §11 and PROJECT_NOTES.md.
    mode_idx     = ProtoField.uint8 ("rnet.mode.index",   "Mode index (0-5)", base.DEC),
    mode_subaddr = ProtoField.uint8 ("rnet.mode.subaddr", "Sub-address",      base.HEX),
    mode_type    = ProtoField.uint8 ("rnet.mode.type",    "Data type",        base.HEX),
    mode_type_s  = ProtoField.string("rnet.mode.type_str","Data type (decoded)"),

    -- Status/error code lookup (BE u16 in bytes 0-1). Evidence:
    -- open-rnet/docs/RNET_ERROR_CODES.md (302-entry table, sourced from
    -- "PGDT R-net Error Code List with Remedies v1", Rev 1, 2009-06-01).
    err_code     = ProtoField.uint16("rnet.err.code",     "Error code (BE u16)", base.HEX),
    err_name     = ProtoField.string("rnet.err.name",     "Error name"),
    err_state    = ProtoField.bool  ("rnet.err.fault",    "Has fault (code != 0)"),

    -- JSM heartbeat: payload is constant 87×7 + 00 across all observed
    -- frames; treat as a static "alive signature" with a validation flag.
    jsm_signature = ProtoField.bool ("rnet.jsm_hb.valid","JSM heartbeat signature valid"),

    -- PM heartbeat byte 0 cycles through 0xC0/0xC1/0xC2 (one per OtherNode
    -- destination in the documented POP bit-packing scheme).
    pm_status_byte = ProtoField.uint8("rnet.pm_hb.byte0","PM heartbeat status byte", base.HEX),

    -- Lights: byte 0 = mask (commanded indicators), byte 1 = bitmap (current
    -- indicator state). Per janschu99 RNETdictionary.txt:40 (0C000E00 entry):
    --   "Xx=mask Yy=bitmap of 4 indicators. 01=left, 04=right, 80=flood, 10=hazard"
    -- Bits 1, 3, 5, 6 not named in the dictionary (bit 6 seen during "lamp
    -- test - all on" so is some indicator, identity TBD).
    light_bit1  = ProtoField.bool  ("rnet.lights.bit1", "Bit 1 (TBD)",            8, nil, 0x02),
    light_bit3  = ProtoField.bool  ("rnet.lights.bit3", "Bit 3 (TBD)",            8, nil, 0x08),
    light_bit5  = ProtoField.bool  ("rnet.lights.bit5", "Bit 5 (TBD)",            8, nil, 0x20),
    light_bit6  = ProtoField.bool  ("rnet.lights.bit6", "Bit 6 (TBD — observed during 'all on' lamp test)", 8, nil, 0x40),
    light_b1    = ProtoField.uint8 ("rnet.lights.bitmap","Bitmap byte (current indicator state)", base.HEX),

    -- Auth-frame XOR validation: when xor_table for the recovered serial is
    -- known, the response 'value' XORed with the corresponding key should
    -- yield the serial byte. We recognize three networks empirically.
    auth_valid  = ProtoField.bool  ("rnet.auth.valid",  "Auth response validates against known xor_table"),
    auth_net    = ProtoField.string("rnet.auth.network","Identified xor_table network"),

    -- 0x1C2C0X00 telemetry-burst family [unverified, structure-inferred].
    -- Pattern observed in 2026-05-21 hackathon candump: 10-frame bursts every
    -- ~20s with byte 0 as a fast counter and bytes 1-2 as a slow LE u16
    -- counter, bytes 3-5 constant. Slot byte (bits 11-8 of ID) per the 0x1C
    -- family convention.
    tlm_sample   = ProtoField.uint8 ("rnet.tlm.sample",   "Sample counter (byte 0)", base.HEX),
    tlm_counter  = ProtoField.uint16("rnet.tlm.counter",  "Slow counter (bytes 1-2 LE u16)", base.DEC),
    tlm_const    = ProtoField.bytes ("rnet.tlm.const",    "Constant tail (bytes 3-5)"),

    confidence  = ProtoField.string("rnet.confidence",  "Evidence kind (Code/Documented/Inferred)"),
    evidence    = ProtoField.string("rnet.evidence",    "Evidence source"),
}
rnet.fields = {}
for _, v in pairs(pf) do table.insert(rnet.fields, v) end

-- User preference: show provenance info (evidence kind + source citation)
-- for each frame. Off by default — most users running the dissector want to
-- read the protocol, not audit it. Enable when verifying the dissector's
-- claims or chasing a specific decode.
-- Toggle in Wireshark: Edit → Preferences → Protocols → RNET.
-- Toggle in tshark:    -o rnet.show_evidence:TRUE
rnet.prefs.show_evidence = Pref.bool(
    "Show evidence + confidence",
    false,
    "When enabled, each frame's expanded detail view includes a "..
    "Code/Documented/Inferred evidence-kind label AND the raw evidence-"..
    "source citation (e.g. 'rnet_utils.py:330'). When disabled, neither "..
    "is shown.")

-- Fields from the underlying SocketCAN dissector -----------------------------
local f_id  = Field.new("can.id")
local f_xtd = Field.new("can.flags.xtd")
local f_rtr = Field.new("can.flags.rtr")
local f_len = Field.new("can.len")
-- Field reference for our own rnet.summary so the main dissector can echo it
-- into the Info column (gives users decoded semantics at a glance in the
-- packet list, without needing to expand each frame).
local f_summary = Field.new("rnet.summary")

-- Slot-to-device-name map.
-- Important caveat: only slot 0 (PM) and slot 15 (Programmer) are fixed by
-- protocol. Slot 1 is conventionally JSM (primary input) and slots 2+ are
-- assigned dynamically during enumeration. The names below reflect the
-- *typical* assignment from RNET_PROTOCOL_GUIDE.md §108-125 — they may
-- differ in any given chair configuration (e.g. ICS-equipped chairs have
-- ISM at slot 2 instead of IOM). A future enhancement could fingerprint
-- the actual occupant per capture by watching for class-specific frames
-- (joystick from JSM, motor-current from PM, BTM Control from BTM, etc.).
-- Evidence: external RE notes (R2) citing RNET_PROTOCOL_GUIDE.md:108-125.
local function slot_name(n)
    local m = {
        [0]  = "PM",          -- fixed
        [1]  = "JSM",         -- conventional
        [2]  = "IOM/ISM",     -- IOM typical, ISM on ICS-equipped chairs
        [3]  = "BTM/Slot 3",  -- BTM typical
        [4]  = "ILM/Slot 4",  -- ILM (Indicator Light Module) typical
        [15] = "Programmer",  -- fixed
    }
    return m[n] or string.format("Slot %X", n)
end

-- Transfer-code semantic names (from DONGLE_INTERFACE_DLL_TYPES.md sentinel
-- table). TC=3 means "Abort" on a standard-ID POP frame, "Last Segment" on
-- an extended-ID one.
local function tc_name(tc, is_extended)
    if tc == 0 or tc == 1 or tc == 2 then return string.format("Segment indicator %d", tc) end
    if tc == 3 then return is_extended and "Last segment" or "Abort" end
    return "?"
end

-- Friendly legacy-opcode labels for the byte-0 patterns that have well-known
-- names in the historical RE writeups. Kept as a *supplementary* annotation —
-- the structural (TC, OtherNode) decode is the primary truth.
-- Source: open-rnet rnet_utils.py:445 + §8.2.
local function legacy_label(byte0)
    local m = {
        [0x20] = "OPEN",       [0x21] = "DATA",     [0x2F] = "HB_ACK",
        [0x40] = "REQUEST",    [0x41] = "ACK",      [0x42] = "HEARTBEAT",
        [0x43] = "WRITE",      [0x4F] = "READ_RSP",
        [0x83] = "SET_ADDR",   [0x8F] = "COMPLETE",
        [0x03] = "READ",       [0x0F] = "WRITE_RSP",
        [0xC1] = "ERROR",
    }
    return m[byte0]
end

-- Evidence kinds — what KIND of source backs each decode:
--   "Code"        — runnable decoder code in this repo (rnet_utils.py,
--                   JoyLocal.py), Ghidra decompile of the DLL artifact
--                   that actually drives the protocol, or empirical
--                   observation cross-validated across many frames
--                   (XOR-table match, 500/500 fingerprint match).
--                   Verifiable by reading the cited code/decompile or
--                   re-running the empirical check.
--   "Documented"  — a single documented source (community dictionary
--                   entries from janschu99, a single Ghidra finding
--                   without independent cross-corroboration, cJSM
--                   display-protocol notes). Trustworthy author but
--                   not independently verified by this project.
--   "Inferred"    — family-analogy from a documented neighbor (e.g.
--                   STD 0x051 ≈ STD 0x050 structure), structural
--                   hypothesis, [CONJECTURAL] positional pairing, or
--                   hackathon-only observations not yet matched
--                   against another source. Treat as a hint, not a
--                   fact.
--
-- Both fields are shown only when the rnet.show_evidence preference is
-- enabled — showing the kind without the source is unfalsifiable, and
-- showing the source without the kind loses the quick-scan summary.
local function add_evidence(t, conf, src)
    if rnet.prefs.show_evidence then
        t:add(pf.confidence, conf):set_generated()
        t:add(pf.evidence, src):set_generated()
    end
end

-- Known XOR tables for the auth-frame validator. Evidence:
--   Tables A, B, C: PROJECT_NOTES.md
--     §"Verified XOR Tables" (line 180+)
--   Table D (hackathon): recovered by parse from
--     2026_AT_hackathon.log auth frames (chair serial B68021AE).
-- When `serial` is nil, validation matches on key alone (BTM table C has
-- documented keys but no serial published).
local known_xor_tables = {
    {name = "Table A: Standalone JSM (serial 08901C8A)",
     keys = {[0]=0x08, [1]=0xB1, [2]=0x1E, [3]=0x46, [4]=0xDD, [5]=0x12, [6]=0x7B, [7]=0x45},
     serial = {[0]=0x08, [1]=0x90, [2]=0x1C, [3]=0x8A}},
    {name = "Table B: M300 Network (serial 50C01C8F)",
     keys = {[0]=0xD3, [1]=0x92, [2]=0xB1, [3]=0x94, [4]=0xED, [5]=0x06, [6]=0x2C, [7]=0x4E},
     serial = {[0]=0x50, [1]=0xC0, [2]=0x1C, [3]=0x8F}},
    {name = "Table C: BTM Network",
     keys = {[0]=0x47, [1]=0xA1, [2]=0x62, [3]=0xAD, [4]=0x2E, [5]=0x05, [6]=0xB3, [7]=0xEC},
     serial = nil},
    {name = "Table D: Hackathon 2026-05-21 (serial B68021AE)",
     keys = {[0]=0xDA, [1]=0x30, [2]=0xE1, [3]=0x55, [4]=0x36, [5]=0x20, [6]=0x79, [7]=0x45},
     serial = {[0]=0xB6, [1]=0x80, [2]=0x21, [3]=0xAE}},
}

-- Auto-generated error catalog: 526 entries merged from:
--   open-rnet/docs/RNET_ERROR_CODES.md (PGDT 2009-06-01)
--   rnd_errors_Generic_V*.jsonl (.rnd dealer-programmer extraction)
-- Error codes (812 total) — confidence-filtered merge of:
--   open-rnet/docs/RNET_ERROR_CODES.md (PGDT 2009-06-01 catalog)
--   rnd_errors_Generic_V*.jsonl v2 (regenerated)
-- Breakdown: HIGH=689, MEDIUM=123.
-- MEDIUM entries: multi-word + contain a known error keyword + display
-- field populated. Lookup via wire-code OR code_swapped_hex per
-- RND_ERROR_PARSER_FIXES_2026-05-22.md (different .rnd sub-tables use
-- different byte-order conventions; both candidate keys checked).
local error_codes = {
    -- (0x0000 omitted — code=0 means 'no fault' on the wire)
    [0x0001] = "KERNEL WATCHDOG TIME OUT: Kernel task stopped responding",
    [0x0002] = "KERNEL APP. TOO SLOW: Application function took too long",
    [0x0003] = "KERNEL BUFFER OVERFLOW: ERB full when trying to add",
    [0x0004] = "KERNEL BUFFER UNDERFLOW: ERB empty when trying to read",
    [0x0005] = "KERNEL MQ OVERFLOW: TMQ full when trying to add",
    [0x0006] = "KERNEL MQ UNDERFLOW: TMQ empty when trying to read",
    [0x0007] = "KERNEL HW MONITOR FAIL: Hardware monitor test failed",
    [0x0008] = "KERNEL UNEXPECTED SCID: Received scid while SCID_ENABLED",
    [0x0009] = "KERNEL PROFILEMODE FAIL: Failed profile/mode transaction",
    [0x000A] = "KERNEL DIME FAILED: DIME Error",
    [0x000B] = "KERNEL HW ISOLATE FAIL: Hardware monitor signals isolated",
    [0x000C] = "KERNEL WRONG WAKE SOURCE: WAKEUP message with different DIME-ID",
    [0x000D] = "KERNEL STAGE MANAGEMENT: Bad sync in stage management",
    [0x000E] = "KERNEL NODE IS BUS OFF: CAN controller is bus off",
    [0x000F] = "KERNEL PROG OBJECT FAIL: Programming object error",
    [0x0010] = "KERNEL NODE IS DISARMED: Signal 'Armed' transitioned to low",
    [0x0011] = "KERNEL UNKNOWN CAN INT: Unknown CAN interrupt",
    [0x0012] = "KERNEL SERIAL OVERFLOW: Serial port transmit buffers full",
    [0x0013] = "KERNEL REP. FILE FORMAT: Unknown or invalid file format",
    [0x0014] = "KERNEL REP. FILE MISSING: Required file not present",
    [0x0015] = "KERNEL REP. SUPPORT FAIL: Repository support fault",
    [0x0016] = "Overvoltage Comparator Failed To Reset",  -- [MEDIUM]
    [0x0017] = "Relay Driver Fault",
    [0x0018] = "Watchdog Startup Failure",
    [0x0019] = "Demand Signal Fault Right",
    [0x001A] = "Demand Signal Fault Left",
    [0x001D] = "Switch Input Pullup Circuit Failure",
    [0x001E] = "Inhibit Input Short",
    [0x001F] = "Phasing Fault Right",
    [0x0020] = "Phasing Fault Left",
    [0x0021] = "Progress Count Error",
    [0x0022] = "Joystick Toggle Error",
    [0x0023] = "No Pacesetter Reply",  -- [MEDIUM]
    [0x0024] = "Bad Pacesetter Reply",  -- [MEDIUM]
    [0x0027] = "Output Setup Parameter Data Error",
    [0x0028] = "Right Output Setup Error",
    [0x0029] = "Left Output Setup Error",
    [0x002A] = "Right Reverse Pin Faulty",
    [0x002B] = "Left Reverse Pin Faulty",
    [0x002C] = "Low Battery Voltage",  -- [MEDIUM]
    [0x002D] = "Demand Drive Mismatch",  -- [MEDIUM]
    [0x002F] = "Input Recentering Fault",
    [0x0031] = "Short Across Bridge",  -- [MEDIUM]
    [0x0032] = "Port 9 Verification Error",
    [0x0033] = "Mode Fault Right",
    [0x0034] = "Mode Fault Left",
    [0x0035] = "Demand Out Of Range",  -- [MEDIUM]
    [0x0036] = "Failed To Trip When Watchdog Not Pumped",
    [0x003A] = "Limit Range Error",
    [0x003B] = "Motor Open Circuit",
    [0x003C] = "M2 Motor Open Circuit",
    [0x003D] = "Motor Shorted Low",
    [0x003E] = "M2 Motor Shorted Low",
    [0x003F] = "Current Limit Calculation Error",
    [0x0041] = "Error During Configuration Transfer",
    [0x0043] = "Failed To Read Error Code",
    [0x0044] = "Module Error: Module reporting Error may need repair.",
    [0x0048] = "Writing Verification Error",
    [0x0049] = "Repeated Paged Write Errors",
    [0x004A] = "Reply Error",
    [0x004E] = "Get Acknowledgement Error",
    [0x0051] = "Repeated Paged Read Errors",
    [0x0052] = "Preset Checksum Error",
    [0x0056] = "No Right Pulse Width Data",  -- [MEDIUM]
    [0x0057] = "Bad Right Pulse Width Data",  -- [MEDIUM]
    [0x0058] = "No Left Pulse Width Data",  -- [MEDIUM]
    [0x0059] = "Bad Left Pulse Width Data",  -- [MEDIUM]
    [0x005D] = "Programmer Selection Limit Range Error",
    [0x005E] = "Programmer Found Original Checksum Error",
    [0x0060] = "Programmer EEPROM Not Busy Fault",
    [0x0061] = "Port Read Error",
    [0x0062] = "Failed To Read Unit Type",  -- [MEDIUM]
    [0x0063] = "Selection Limit Range Error",
    [0x007A] = "Channel Current Amplifier Failure",
    [0x007B] = "Gyro Disconnected",
    [0x007C] = "Thermistor 4 Error",
    [0x007D] = "Horn Internal Short",  -- [MEDIUM]
    [0x007E] = "PM Memory Error: Running Repository Error",
    [0x007F] = "Bad Cable: CAN Transceiver in fault tolerent mode",
    [0x0081] = "DIME Error",
    [0x0088] = "Brake Lamp Short Circuit",
    [0x008E] = "User App Data Write Range Error",
    [0x0094] = "Servo Pot Error",
    [0x0096] = "Hosted Application Error 0",
    [0x0097] = "ASM Self Test failed",  -- [MEDIUM]
    [0x0099] = "Left Jack 2 Cap Fault: Module reporting Error may need repair.",
    [0x009B] = "Module Error",
    [0x0100] = "ISM8 Inhibit",
    [0x0101] = "OTP Data Corrupt: Module reporting Error may need repair.",
    [0x0104] = "Error Converting 5V Mux 1 Connection: Module Error",
    [0x0106] = "Error Converting 0V Mux 1 Connection: Module Error",
    [0x0116] = "High Battery Voltage: Overvoltage Comparator Tripped",
    [0x011F] = "Motor 2 Position Sensing Error: Check position encoder wiring is not disconnected or rever",
    [0x0120] = "Motor 1 Position Sensing Error: Check position encoder wiring is not disconnected or rever",
    [0x012C] = "Low Battery Voltage: Very Low Battery Voltage",  -- [MEDIUM]
    [0x0144] = "Module Error: Module reporting Error may need repair.",
    [0x017E] = "PM Memory Error: Unable to Open PM Req File",
    [0x017F] = "Bad Cable: Rebus High Speed Bus Error",
    [0x0190] = "FW Update Error",
    [0x0196] = "Bad Channel Value: Channel Setting Error.",
    [0x0199] = "Left Jack 1 Cap Fault: Module reporting Error may need repair.",
    [0x019A] = "USB Charging Error",
    [0x019B] = "Module Error",
    [0x0200] = "PM Memory Error: EEPROM Check Error",
    [0x0203] = "Calibration Error: EEPROM Calibration Data Check Error",
    [0x0204] = "Memory Error: EEPROM Programming Data Check Error",
    [0x0206] = "Error Converting 0V Mux 2 Connection: Module Error",
    [0x0208] = "Memory Error: EEPROM Persistent Data Check Error",
    [0x020E] = "Joystick Error: Joystick Error ForwardJoystick Error Forward",
    [0x0212] = "Joystick Error: Dual Path Comparison Forward Error",
    [0x022C] = "Low Battery Voltage: Low Battery Lockout",  -- [MEDIUM]
    [0x0244] = "Module Error: Module reporting Error may need repair.",
    [0x027E] = "Memory Error: Unable to synchronise with Repository",
    [0x0296] = "Bad Caster Lock: Caster Lock Setting Error.",
    [0x0299] = "HHK Supply Failure: Module reporting Error may need repair.",
    [0x029A] = "USB Internal Fault: USB charging port has failed",
    [0x029B] = "Module Error",
    [0x0300] = "Speed Control Reference Bad",  -- [MEDIUM]
    [0x0302] = "Calibration Error: EEPROM Calibration Data Check Error",
    [0x0303] = "Speed Control Hall Switch 1 Out of Bounds: Module Error",
    [0x0304] = "Speed Control Hall Switch 2 Out of Bounds: Module Error",
    [0x0306] = "Error Converting 0V Mux 3 Connection: Module Error",
    [0x031F] = "Motor 2 Position Sensing Error: Check position encoder wiring is not shorting",
    [0x0320] = "Motor 1 Position Sensing Error: Check position encoder wiring is not shorting",
    [0x0344] = "Module Error: Module reporting Error may need repair.",
    [0x037E] = "Memory Error: Failed to cancel queued message",
    [0x0381] = "Memory Error: Rebus Tx Queue Full",
    [0x0396] = "Bad PRAR Setting: Pressure Relief Alerts and Recording Setting Error.",
    [0x0399] = "HHK Current Monitor: Module reporting Error may need repair.",
    [0x039B] = "Module Error",
    [0x0400] = "Error Converting 5V Mux 3 Connection",
    [0x0401] = "Error Converting 5V Mux 1 Connection: Module Error",
    [0x0402] = "Memory Error: EEPROM Programming Data Check Error",
    [0x0403] = "Speed Control Hall Switch 2 Out of Bounds: Module Error",
    [0x0404] = "Mux Droop Leakage: Module Error",
    [0x0406] = "Mux Ground Out Of Range: Module Error",
    [0x0410] = "Error Converting 3.3V Mux 0 Connection: Module Error",
    [0x0411] = "Error Converting 3.3V Mux 1 Connection: Module Error",
    [0x0412] = "Error Converting 3.3V Mux 2 Connection: Module Error",
    [0x0413] = "Error Converting 3.3V Mux 3 Connection: Module Error",
    [0x0414] = "Error Converting 3.3V Mux 4 Connection: Module Error",
    [0x0444] = "Module Error: Module reporting Error may need repair.",
    [0x047E] = "Memory Error: Repository aborted transfer",
    [0x0481] = "System Error: Rx DLC Not As Expected",
    [0x0496] = "Bad Virtual Inh: Virtual Inhibit Setting Error.",
    [0x0499] = "Profile Jack Test Fault: Module reporting Error may need repair.",
    [0x0500] = "Reference Hold Error",
    [0x0544] = "Module Error: Module reporting Error may need repair.",
    [0x057E] = "Memory Error: Repository timeout during transfer",
    [0x0596] = "Bad Gnd Clearance: Ground Clearance Setting Error.",
    [0x0600] = "Error Converting 0V Mux 0 Connection",
    [0x0601] = "Error Converting 0V Mux 1 Connection",
    [0x0602] = "Error Converting 0V Mux 2 Connection",
    [0x0603] = "Error Converting 0V Mux 3 Connection",
    [0x0604] = "Mux Ground Out Of Range: Module Error",
    [0x0644] = "Module Error: Module reporting Error may need repair.",
    [0x067E] = "Memory Error: Invalid Repository node number detected",
    [0x0681] = "System Error: Config Failure",
    [0x0700] = "Bias Voltage Error",
    [0x0703] = "Joystick Supply Failure",
    [0x0704] = "12V Supply Failure",
    [0x0707] = "Regulator Supply Failure",
    [0x070B] = "5V Supply Failure: Module Error",
    [0x070D] = "1.5V Rail Failure: Module Error",
    [0x0742] = "Module Error",
    [0x0743] = "Module Error",
    [0x0744] = "Module Error: Module reporting Error may need repair.",
    [0x0745] = "Module Error",
    [0x0746] = "Module Error",
    [0x0747] = "Module Error",
    [0x0748] = "Module Error",
    [0x077E] = "Memory Error: Incompatible file format",
    [0x0781] = "System Error: Rebus Event Queue Overflow",
    [0x0800] = "Mid Reference Calculation Error",
    [0x0802] = "Memory Error: EEPROM Persistent Data Check Error",
    [0x0808] = "Joystick Error: Mid Reference Error",
    [0x080A] = "Joystick Error: Mid Reference Comparison Error",
    [0x080B] = "Joystick Error: Mid Reference Comparison Startup Error",
    [0x0844] = "Module Error: Module reporting Error may need repair.",
    [0x087A] = "Overtemperature (Actuators): Actuator Driver Over Temperature",
    [0x087E] = "Memory Error: Bad data in Repository file",
    [0x0881] = "System Error: Config Data Access Error",
    [0x0900] = "Low Reference Calculation Error",
    [0x0905] = "SID Detached: OMNI Input Device Disconnected",
    [0x0944] = "Module Error: Module reporting Error may need repair.",
    [0x097E] = "Memory Error: Bad descriptor in Repository file",
    [0x0981] = "System Error: Pre-Op Failure",
    [0x09B0] = "Joystick Port 1 Mid Reference Error",
    [0x09D0] = "Joystick Port 2 Mid Reference Error",
    [0x0A00] = "Gone To Sleep",
    [0x0A08] = "Joystick Error: Mid Reference Comparison Error",
    [0x0A44] = "Module Error: Module reporting Error may need repair.",
    [0x0A7E] = "Memory Error: Old file format in Repository cannot restore corrupt file",
    [0x0A81] = "PM Memory Error: SCF File Read Failure",
    [0x0B00] = "EEPROM: Write Error",
    [0x0B01] = "EEPROM: Not Busy Fault",
    [0x0B02] = "EEPROM: Write Timeout",
    [0x0B07] = "5V Supply Failure: Module Error",
    [0x0B08] = "EEPROM: Address Out Of Range",
    [0x0B44] = "Module Error: Module reporting Error may need repair.",
    [0x0B7E] = "Memory Error: File Slot CRC does not match",
    [0x0B81] = "PM Memory Error: DCF File Read Failure",
    [0x0C00] = "Right Bk8 Error",
    [0x0C1E] = "Switch Short: The CJSM2 has detects a short in the switch connected to the On/Off jack.",  -- [MEDIUM]
    [0x0C44] = "Module Error: Module reporting Error may need repair.",
    [0x0C7E] = "Language Error: Auxiliary File sequence error",
    [0x0C81] = "System Error: Failed to Init DCF Tables by Pre-Op End",
    [0x0D00] = "Left Bk8 Error",
    [0x0D07] = "1.5V Rail Failure: Module Error",
    [0x0D1E] = "Switch Short: The CJSM2 has detects a short in the switch connected to the Profile/Mode ja",  -- [MEDIUM]
    [0x0D44] = "Module Error: Module reporting Error may need repair.",
    [0x0D7E] = "Language Error: Incompatible Auxiliary File format",
    [0x0D81] = "System Error: Config Failure - No Repository Node",
    [0x0E00] = "Joystick Error: Joystick Error Right",
    [0x0E02] = "Joystick Error: Joystick Error Forward",
    [0x0E44] = "Module Error: Module reporting Error may need repair.",
    [0x0E7E] = "Language Error: Unable to repair corrupt Auxiliary File",
    [0x0E81] = "System Error: Config Failure - Too Many Repository Nodes",
    [0x0F00] = "Joystick Error Right 2",
    [0x0F44] = "Module Error: Module reporting Error may need repair.",
    [0x0F7E] = "Language Error: Invalid Auxiliary File version in Repository",
    [0x1000] = "Joystick Error Spin",
    [0x1004] = "Error Converting 3.3V Mux 0 Connection: Module Error",
    [0x101E] = "Module Error",
    [0x107E] = "Language Error: Invalid System Variant File",
    [0x1100] = "Joystick Error Left 2",
    [0x1101] = "CJ MODULE ERROR: Unrecoverable error (watchdog timeout)",
    [0x1102] = "CJ JOYSTICK REFERENCE VOLTAGE: Reference voltage (VCC/2) out of range",
    [0x1103] = "CJ JOYSTICK CENTER: Joystick out of center",
    [0x1104] = "CJ JOYSTICK OUTPUT: Joystick signal Out of Range",
    [0x1105] = "CJ TEST FAILED: Module Tested Flag not set in EEPROM",
    [0x1106] = "CJ EEPROM: Calibrate EEPROM section corrupted",
    [0x1107] = "CJ OBJ READ: Can not read Programming object in time",
    [0x1108] = "CJ TIMING: ADC not synchronised",
    [0x1109] = "CJ CODE: Non existing code entered",
    [0x110A] = "CJ KERNEL: Kernel error",
    [0x1132] = "Bad Settings: Parameter Range Error",
    [0x117E] = "Language Error: Upgrade would mix Auxiliary File variants",
    [0x1181] = "System Error: Config Failure - No Repository Node",
    [0x1200] = "Joystick Error: Dual Path Comparison Right Error",
    [0x1201] = "ESP PM LATCHED MODE: Power module entered Latched Drive Mode",
    [0x1202] = "ESP REFERENCE VOLTAGE: Reference voltage (VCC/2) out of range",
    [0x1203] = "ESP OFFSET VOLTAGE: PWM Offset regulation out of range",
    [0x1204] = "ESP SENSOR OUTPUT: Gyro Sensor Out of Range",
    [0x1205] = "ESP TEST FAILED: Module Tested Flag not set in EEPROM",
    [0x1206] = "ESP EEPROM: Calibrate EEPROM section corrupted",
    [0x1207] = "ESP OBJ READ: Can not read Programming object in time",
    [0x1208] = "ESP TIMING: ADC not synchronised",
    [0x1209] = "ESP CODE: Non existing code entered",
    [0x120A] = "ESP KERNEL: Kernel error",
    [0x127E] = "Language Error: Unable to repair corrupt Auxiliary File set",
    [0x1300] = "Current Limit Startup Fault",
    [0x1302] = "Current Limit: Reference Fault",
    [0x1304] = "Current Limit: Failed To Operate When Positive Input",
    [0x1308] = "Current Limit: Left Sense Trip",
    [0x1309] = "Current Limit: Right Sense Trip",
    [0x130A] = "Current Limit: Startup Fault",
    [0x1310] = "Current Limit: Sense Trip",
    [0x1320] = "Current Timed Timeout: Current limit reduced due to over temperature motor",  -- [MEDIUM]
    [0x137E] = "Language Error: Failed to delete Auxiliary File in order to repair set",
    [0x1400] = "Negative Open Circuit Low",
    [0x1401] = "CJA MODULE ERROR: Unrecoverable error (watchdog timeout)",
    [0x1402] = "CJA JOYSTICK REFERENCE VOLTAGE: Reference voltage (VCC/2) out of range",
    [0x1403] = "CJA JOYSTICK CENTER: Joystick out of center",
    [0x1404] = "CJA JOYSTICK OUTPUT: Joystick signal Out of Range",
    [0x1405] = "CJA TEST FAILED: Module Tested Flag not set in EEPROM",
    [0x1406] = "CJA EEPROM: Calibrate EEPROM section corrupted",
    [0x1407] = "CJA OBJ READ: Can not read Programming object in time",
    [0x1408] = "CJA TIMING: ADC not synchronised",
    [0x1409] = "CJA CODE: Non existing code entered",
    [0x140A] = "CJA KERNEL: Kernel error",
    [0x147E] = "Language Error: Repository aborted tranfer - Auxiliary File",
    [0x1500] = "Solenoid Brake Over Current",
    [0x1501] = "MD MODULE ERROR: Unrecoverable error (watchdog timeout)",
    [0x1502] = "MD COM_OFFLINE: Communication Offline",
    [0x1503] = "MD COM_DATA: Communication Bad data",
    [0x1504] = "MD COM VERSION: Communication Incorrect version",
    [0x1505] = "MD TEST FAILED: Module Tested Flag not set in EEPROM",
    [0x1506] = "MD EEPROM: Calibrate EEPROM section corrupted",
    [0x1507] = "MD OBJ READ: Can not read Programming object in time",
    [0x1508] = "MD COM_TIMEOUT: Communication timeout",
    [0x1509] = "MD CODE: Non existing code entered",
    [0x150A] = "MD KERNEL: Kernel error",
    [0x157E] = "Language Error: Repository timeout during tranfer - Auxiliary File",
    [0x1599] = "On/Off Switch Invalid: On/Off Switch Error",
    [0x1600] = "High Battery Voltage",
    [0x1601] = "COP MODULE ERROR: Unrecoverable error (watchdog timeout)",
    [0x1602] = "COP JOYSTICK REFERENCE VOLTAGE: Reference voltage (VCC/2) out of range",
    [0x1603] = "COP JOYSTICK CENTER: Joystick out of center",
    [0x1604] = "COP JOYSTICK OUTPUT: Joystick signal Out of Range",
    [0x1605] = "COP TEST FAILED: Module Tested Flag not set in EEPROM",
    [0x1606] = "COP EEPROM: Calibrate EEPROM section corrupted",
    [0x1607] = "COP OBJ READ: Can not read Programming object in time",
    [0x1608] = "COP TIMING: ADC not synchronised",
    [0x1609] = "COP CODE: Non existing code entered",
    [0x160A] = "COP KERNEL: Kernel error",
    [0x1680] = "COP2 INT VOLTAGE ERROR: Internal voltages out of range",
    [0x1681] = "COP2 LATCHED ENABLED: Latched drive enabled in configuration",
    [0x1682] = "COP2 HIGH FORCE: High force detected",
    [0x1683] = "COP2 LOADCELL ERROR: Load cell signal out of range",
    [0x1684] = "COP2 DMS TEST ERROR: DMS is activated during test",
    [0x1685] = "COP2 ACCEL ERROR: Accelerometer values out of range",
    [0x1686] = "COP2 ANGLE ERROR: Incorrect handle angle",
    [0x1687] = "COP2 SYST FAULT1: Control fault 1",
    [0x1688] = "COP2 SYST FAULT2: Control fault 2",
    [0x1689] = "COP2 SYST FAULT3: Control fault 3",
    [0x168A] = "COP2 SYSTEM FAULT4: Control fault 4",  -- [MEDIUM]
    [0x168B] = "COP2 SYSTEM FAULT5: Control fault 5",  -- [MEDIUM]
    [0x168C] = "COP2 SYSTEM FAULT6: Control fault 6",  -- [MEDIUM]
    [0x168D] = "COP2 SYSTEM FAULT7: Control fault 7",  -- [MEDIUM]
    [0x168E] = "COP2 SYSTEM FAULT8: Control fault 8",  -- [MEDIUM]
    [0x168F] = "COP2 SYSTEM FAULT9: Control fault 9",  -- [MEDIUM]
    [0x1700] = "Relay On In Standby",
    [0x1701] = "ER MODULE ERROR: Unrecoverable error (watchdog timeout)",
    [0x1702] = "ER COM_OFFLINE: Communication Offline",
    [0x1703] = "ER COM_DATA: Communication Bad data",
    [0x1704] = "ER COM VERSION: Communication Incorrect version",
    [0x1705] = "ER TEST FAILED: Module Tested Flag not set in EEPROM",
    [0x1706] = "ER EEPROM: Calibrate EEPROM section corrupted",
    [0x1707] = "ER OBJ READ: Can not read Programming object in time",
    [0x1708] = "ER COM_TIMEOUT: Communication timeout",
    [0x1709] = "ER CODE: Non existing code entered",
    [0x170A] = "ER KERNEL: Kernel error",
    [0x177E] = "Language Error: Bad Auxiliary file variant",
    [0x1800] = "Watchdog Startup Failure",
    [0x1801] = "RBI MODULE ERROR: Unrecoverable error (watchdog timeout)",
    [0x1802] = "RBI 12V WRONG OUTPUT: 12Volt Regulator defect",
    [0x1803] = "RBI 12V ON/OFF PROBLEM: 12Volt on/off switch circuit problem",
    [0x1805] = "RBI TEST FAILED: Module test flag not set in EEPROM",
    [0x1806] = "RBI EEPROM: Calibrate EEPROM section corrupted",
    [0x1807] = "RBI OBJ READ: Can not read Programming object in time",
    [0x1809] = "RBI CODE: Non existing code entered",
    [0x180A] = "RBI KERNEL: Kernel error",
    [0x187E] = "Restore Error",
    [0x1900] = "Demand Signal Fault Right",
    [0x1901] = "MJ MODULE ERROR: Unrecoverable error (watchdog timeout)",
    [0x1902] = "MJ JOYSTICK REFERENCE VOLTAGE: Reference voltage (VCC/2) out of range",
    [0x1903] = "MJ JOYSTICK CENTER: Joystick out of center",
    [0x1904] = "MJ JOYSTICK OUTPUT: Joystick signal Out of Range",
    [0x1905] = "MJ TEST FAILED: Module Tested Flag not set in EEPROM",
    [0x1906] = "MJ EEPROM: Calibrate EEPROM section corrupted",
    [0x1907] = "MJ OBJ READ: Can not read Programming object in time",
    [0x1908] = "MJ TIMING: ADC not synchronised",
    [0x1909] = "MJ CODE: Non existing code entered",
    [0x190A] = "MJ KERNEL: Kernel error",
    [0x1911] = "MJ DEVICE FAILURE: Mini Joystick Failure",
    [0x1912] = "MJ DEVICE CONNECTION: Communication problems URIB - Mini-JS",
    [0x1915] = "MJ DEVICE NOT TESTED: Not Calibrated",
    [0x1A00] = "Demand Signal Fault Left",
    [0x1B01] = "Right Forward Current Null Bad",
    [0x1B02] = "Right Reverse Current Null Bad",
    [0x1B10] = "Positive Current Feedback Null Bad",
    [0x1C00] = "M2 Motor Error [CONJECTURAL: Meyra .rnd descriptor #19 positional pairing]",  -- external RE notes commit faee2675
    [0x1C01] = "Left Forward Current Null Bad",
    [0x1C02] = "Left Reverse Current Null Bad",
    [0x1C10] = "Negative Current Feedback Null Bad",
    [0x1D00] = "Front End Fault",
    [0x1D03] = "Switch Input: Pullup Circuit Failure",
    [0x1E00] = "Inhibit Input Short",
    [0x1E03] = "Inhibit Active: Charger Connected",
    [0x1E07] = "User Switch Detached",
    [0x1E0C] = "Switch Short: The CJSM2 has detects a short in the switch connected to the On/Off jack.",  -- [MEDIUM]
    [0x1E0D] = "Switch Short: The CJSM2 has detects a short in the switch connected to the Profile/Mode ja",  -- [MEDIUM]
    [0x1E10] = "Module Error",
    [0x1E40] = "User Switch 1 Open Circuit",
    [0x1E41] = "User Switch 1 Short Circuit",  -- [MEDIUM]
    [0x1E42] = "User Switch 2 Open Circuit",
    [0x1E43] = "User Switch 2 Short Circuit",  -- [MEDIUM]
    [0x1E4C] = "User Switch 1 Jack 1 Invalid: Module Error",
    [0x1E4D] = "User Switch 1 Jack 2 Invalid: Module Error",
    [0x1E4E] = "User Switch 2 Jack 1 Invalid: Module Error",
    [0x1E4F] = "User Switch 2 Jack 2 Invalid: Module Error",
    [0x1E50] = "Right Signal 1 Open Circuit",
    [0x1E51] = "Left Signal 1 Open Circuit",
    [0x1E52] = "Forward Signal 1 Open Circuit",
    [0x1E53] = "Reverse Signal 1 Open Circuit",
    [0x1E54] = "Fifth Switch 1 Open Circuit",
    [0x1E55] = "Right Signal 1 Short Circuit",  -- [MEDIUM]
    [0x1E56] = "Left Signal 1 Short Circuit",  -- [MEDIUM]
    [0x1E57] = "Forward Signal 1 Short Circuit",  -- [MEDIUM]
    [0x1E58] = "Reverse Signal 1 Short Circuit",  -- [MEDIUM]
    [0x1E59] = "Fifth Switch 1 Short Circuit",  -- [MEDIUM]
    [0x1E5A] = "Port 1 Right Channel Invalid: Module Error",
    [0x1E5B] = "Port 1 Left Channel Invalid: Module Error",
    [0x1E5C] = "Port 1 Forward Channel Invalid: Module Error",
    [0x1E5D] = "Port 1 Reverse Channel Invalid: Module Error",
    [0x1E5E] = "Port 1 Switch 5 Channel Invalid: Module Error",
    [0x1E60] = "Right Signal 2 Open Circuit",
    [0x1E61] = "Left Signal 2 Open Circuit",
    [0x1E62] = "Forward Signal 2 Open Circuit",
    [0x1E63] = "Reverse Signal 2 Open Circuit",
    [0x1E64] = "Fifth Switch 2 Open Circuit",
    [0x1E65] = "Right Signal 2 Short Circuit",  -- [MEDIUM]
    [0x1E66] = "Left Signal 2 Short Circuit",  -- [MEDIUM]
    [0x1E67] = "Forward Signal 2 Short Circuit",  -- [MEDIUM]
    [0x1E68] = "Reverse Signal 2 Short Circuit",  -- [MEDIUM]
    [0x1E69] = "Fifth Switch 2 Short Circuit",  -- [MEDIUM]
    [0x1E6A] = "Port 2 Right Channel Invalid: Module Error",
    [0x1E6B] = "Port 2 Left Channel Invalid: Module Error",
    [0x1E6C] = "Port 2 Forward Channel Invalid: Module Error",
    [0x1E6D] = "Port 2 Reverse Channel Invalid: Module Error",
    [0x1E6E] = "Port 2 Switch 5 Channel Invalid: Module Error",
    [0x1E72] = "Forward Signal 1 Dual Path Invalid: Module Error",
    [0x1E73] = "Reverse Signal 1 Dual Path Invalid: Module Error",
    [0x1E7A] = "Forward Signal 2 Dual Path Invalid: Module Error",
    [0x1E7B] = "Reverse Signal 2 Dual Path Invalid: Module Error",
    [0x1F00] = "Phasing Fault Right",
    [0x1F01] = "Motor 2 Position Sensing Error: Check position encoder wiring is not disconnected or rever",
    [0x1F03] = "Motor 2 Position Sensing Error: Check position encoder wiring is not shorting",
    [0x2000] = "Phasing Fault Left",
    [0x2001] = "Motor 1 Position Sensing Error: Check position encoder wiring is not disconnected or rever",
    [0x2003] = "Motor 1 Position Sensing Error: Check position encoder wiring is not shorting",
    [0x2011] = "Master: Model or UI has incorrect checksum or firmware mismatch",
    [0x2012] = "Master: Over current in idle mode",
    [0x2013] = "Master: Problems with internal SPI communication",
    [0x2014] = "Master: Cannot write to internal flash",
    [0x2015] = "Master: Cannot update node parameters",
    [0x2017] = "Master: ICS needs restart, cycle wheelchair power",
    [0x201D] = "Master: Unused actuator or module attached to ICS",
    [0x2038] = "Sets the time the input needs to be in a band before the inhibit is updated",  -- [MEDIUM]
    [0x207E] = "Memory Error: Get Repository Timeout",
    [0x209B] = "Module Error",
    [0x2100] = "Progress Count Error",
    [0x217E] = "Memory Error: Release Repository Timeout",
    [0x219B] = "Module Error",
    [0x2200] = "Joystick Toggle Error",
    [0x227E] = "Memory Error: Check Repository Timeout",
    [0x229B] = "Smart Fuse Trip",
    [0x2300] = "No Pacesetter Reply",  -- [MEDIUM]
    [0x237E] = "Memory Error: Repository Taken",
    [0x2400] = "Bad Pacesetter Reply",  -- [MEDIUM]
    [0x2500] = "Over Pressure [CONJECTURAL: Meyra .rnd descriptor #10 positional pairing]",  -- external RE notes commit faee2675
    [0x247E] = "Memory Error: Repository Not Released",
    [0x257E] = "Memory Error: Set Values Get File Slot Error",
    [0x267E] = "Memory Error: Set Values Set Slot Location Error",
    [0x2600] = "Output Setup Parameter Time Out",  -- [MEDIUM] Amylior/ETAC .rnd
    [0x2700] = "Output Setup Parameter Data Error",
    [0x277E] = "Memory Error: Slot Write Error",
    [0x2800] = "Right Output Setup Error",
    [0x287E] = "Memory Error: Set Values Slot Data Error",
    [0x2900] = "Left Output Setup Error",
    [0x2967] = "Set the voltage at which a low battery timer starts counting",  -- [MEDIUM]
    [0x297E] = "Memory Error: Set Values Get File Slot Error",
    [0x2A00] = "Feedback Voltage Fault Right",
    [0x2A01] = "Right Voltage Null Bad",
    [0x2A7E] = "Memory Error: Get Values Get File Slot Error",
    [0x2B00] = "Feedback Voltage Fault Left",
    [0x2B01] = "Left Voltage Null Bad",
    [0x2B7E] = "Memory Error: Get Values Set Slot Location Error",
    [0x2C00] = "Low Battery Voltage",
    [0x2C01] = "Low Battery Voltage: Very Low Battery Voltage (<16v)",
    [0x2C02] = "Low Battery Voltage: Low Battery Lockout (<16v)",
    [0x2C7E] = "Memory Error: Get Values Slot Data Error",
    [0x2D00] = "Demand Drive Mismatch",  -- [MEDIUM]
    [0x2E00] = "Overtemp. (Lamps) [CONJECTURAL: Meyra .rnd descriptor #27 positional pairing]",  -- external RE notes commit faee2675
    [0x2E68] = "Sets the time the input needs to be in a band before the inhibit is updated",  -- [MEDIUM]
    [0x2E7E] = "Memory Error: Get Size Get File Slot Error",
    [0x2F00] = "Input Recentering Fault",
    [0x2F01] = "Center Joystick",
    [0x2F7E] = "Memory Error: Get Slot Size Error",
    [0x3056] = "LED Indicator Fault Current Point 4",
    [0x307E] = "Memory Error: Get Operating Time Error",
    [0x3000] = "Joystick 2 Displaced",  -- [MEDIUM] Amylior/ETAC/Generic .rnd
    [0x3100] = "Low Bridge Voltage",
    [0x3101] = "Bridge To Battery Short",
    [0x3200] = "Port 9 Verification Error",
    [0x3203] = "Port 2 Verification Error",
    [0x3211] = "Bad Settings: Parameter Range Error",
    [0x3215] = "ADC Storage Error",
    [0x3300] = "Mode Fault Right",
    [0x3400] = "Mode Fault Left",
    [0x347E] = "Memory Error: Get Eventlog Event Error",
    [0x3500] = "Demand Out Of Range",  -- [MEDIUM]
    [0x3556] = "LED Indicator Fault Current Point 3",
    [0x357E] = "Memory Error: Get Org Number Error",
    [0x3600] = "Failed To Trip When Watchdog Not Pumped",
    [0x3611] = "Failed To Arm Trip Latch",
    [0x367E] = "Memory Error: Get Attributes Get File Slot Error",
    [0x377E] = "Memory Error: Get Slot Check Error",
    [0x3820] = "Sets the time the input needs to be in a band before the inhibit is updated",  -- [MEDIUM]
    [0x387E] = "Memory Error: Set Slot Verify Error",
    [0x397E] = "Memory Error: Get File Attributes Error",
    [0x3A00] = "Bad Settings",
    [0x3A05] = "System Power Cycle Required",
    [0x3A7E] = "Memory Error: Repository Data Corrupt",
    [0x3B00] = "M1 Motor Open Circuit",
    [0x3C00] = "M2 Motor Open Circuit",
    [0x3C88] = "Indicators Open Circuit: Indicators Single Bulb Failure",
    [0x3D00] = "M1 Motor Shorted High",
    [0x3D01] = "M1 Motor Shorted Low",
    [0x3E00] = "M2 Motor Shorted High",
    [0x3E01] = "M2 Motor Shorted Low",
    [0x3F00] = "Current Limit Calculation Error",
    [0x401E] = "User Switch 1 Open Circuit",
    [0x4081] = "Memory Error: Tx Confirm Timeout",
    [0x4098] = "Error Multi-Core Interface Startup Fail: Module Error",
    [0x4100] = "Error During Configuration Transfer",
    [0x411E] = "User Switch 1 Short Circuit",  -- [MEDIUM]
    [0x4181] = "System Error: Config Failure - No PG Input Device",
    [0x4198] = "Error Multi-Core Interface Incomining lock fail: Module Error",
    [0x4207] = "Module Error",
    [0x421E] = "User Switch 2 Open Circuit",
    [0x4281] = "System Error: Config Failure - Invalid PG Input Devices Param",
    [0x4298] = "Error Multi-Core Interface Outgoing lock fail: Module Error",
    [0x4300] = "Failed To Read Error Code",
    [0x4307] = "Module Error",
    [0x431E] = "User Switch 2 Short Circuit",  -- [MEDIUM]
    [0x4381] = "System Error: Config Failure - Unexpected Non PG Input Device",
    [0x4398] = "Error Multi-Core Interface Heart Beat Error: Module Error",
    [0x4400] = "Module Error: Module reporting Error may need repair.",
    [0x4401] = "Module Error: Module reporting Error may need repair.",
    [0x4402] = "Module Error: Module reporting Error may need repair.",
    [0x4403] = "Module Error: Module reporting Error may need repair.",
    [0x4404] = "Module Error: Module reporting Error may need repair.",
    [0x4405] = "Module Error: Module reporting Error may need repair.",
    [0x4406] = "Module Error: Module reporting Error may need repair.",
    [0x4407] = "Module Error: Module reporting Error may need repair.",
    [0x4408] = "Module Error: Module reporting Error may need repair.",
    [0x4409] = "Module Error: Module reporting Error may need repair.",
    [0x440A] = "Module Error: Module reporting Error may need repair.",
    [0x440B] = "Module Error: Module reporting Error may need repair.",
    [0x440C] = "Module Error: Module reporting Error may need repair.",
    [0x440D] = "Module Error: Module reporting Error may need repair.",
    [0x440E] = "Module Error: Module reporting Error may need repair.",
    [0x440F] = "Module Error: Module reporting Error may need repair.",
    [0x4498] = "Error Multi-Core Checksum Fail: Module Error",
    [0x4507] = "Module Error",
    [0x4607] = "Module Error",
    [0x4681] = "Configuration Error: Modules Failed To Pair Successfully",
    [0x4707] = "Module Error",
    [0x4781] = "Configuration Error: Paired Module Tripped",
    [0x4800] = "Writing Verification Error",
    [0x4807] = "Module Error",
    [0x4881] = "Configuration Error: Paired Module Stopped Responding",
    [0x4900] = "Repeated Paged Write Errors",
    [0x4A00] = "Reply Error",
    [0x4C1E] = "User Switch 1 Jack 1 Invalid: Module Error",
    [0x4D1E] = "User Switch 1 Jack 2 Invalid: Module Error",
    [0x4E00] = "Get Acknowledgement Error",
    [0x4E1E] = "User Switch 2 Jack 1 Invalid: Module Error",
    [0x4F1E] = "User Switch 2 Jack 2 Invalid: Module Error",
    [0x501E] = "Right Signal 1 Open Circuit",
    [0x5100] = "Repeated Paged Read Errors",
    [0x511E] = "Left Signal 1 Open Circuit",
    [0x5194] = "Turning test mode error: Gyro signal detected in environ. Mode",  -- [MEDIUM]
    [0x5200] = "Preset Checksum Error",
    [0x521E] = "Forward Signal 1 Open Circuit",
    [0x531E] = "Reverse Signal 1 Open Circuit",
    [0x541E] = "Fifth Switch 1 Open Circuit",
    [0x551E] = "Right Signal 1 Short Circuit",  -- [MEDIUM]
    [0x5500] = "Bad Joystick Data",  -- [MEDIUM] Amylior/ETAC/Generic .rnd
    [0x5600] = "No Right Pulse Width Data",  -- [MEDIUM]
    [0x561E] = "Left Signal 1 Short Circuit",  -- [MEDIUM]
    [0x5630] = "LED Indicator Fault Current Point 4",
    [0x5635] = "LED Indicator Fault Current Point 3",
    [0x5700] = "Bad Right Pulse Width Data",  -- [MEDIUM]
    [0x571E] = "Forward Signal 1 Short Circuit",  -- [MEDIUM]
    [0x5800] = "No Left Pulse Width Data",  -- [MEDIUM]
    [0x581E] = "Reverse Signal 1 Short Circuit",  -- [MEDIUM]
    [0x5900] = "Bad Left Pulse Width Data",  -- [MEDIUM]
    [0x591E] = "Fifth Switch 1 Short Circuit",  -- [MEDIUM]
    [0x5A1E] = "Port 1 Right Channel Invalid: Module Error",
    [0x5B1E] = "Port 1 Left Channel Invalid: Module Error",
    [0x5C1E] = "Port 1 Forward Channel Invalid: Module Error",
    [0x5D00] = "Programmer Selection Limit Range Error",
    [0x5D1E] = "Port 1 Reverse Channel Invalid: Module Error",
    [0x5E00] = "Programmer Found Original Checksum Error",
    [0x5E1E] = "Port 1 Switch 5 Channel Invalid: Module Error",
    [0x6000] = "Programmer EEPROM Not Busy Fault",
    [0x601E] = "Right Signal 2 Open Circuit",
    [0x6100] = "Port Read Error",
    [0x611E] = "Left Signal 2 Open Circuit",
    [0x6170] = "Exchanges the Power Module's M1 and M2 output",  -- [MEDIUM]
    [0x6178] = "Sets the maximum current limit in Amps for the servo motor",  -- [MEDIUM]
    [0x6200] = "Failed To Read Unit Type",  -- [MEDIUM]
    [0x621E] = "Forward Signal 2 Open Circuit",
    [0x6300] = "Selection Limit Range Error",
    [0x631E] = "Reverse Signal 2 Open Circuit",
    [0x6365] = "Sets Footrest Ground Clearance for Lockout Speed.",  -- [MEDIUM]
    [0x636B] = "Sets the joystick left/right deflection required to reach full servo lock",  -- [MEDIUM]
    [0x6374] = "Adjusts the left and right Motor Outputs to compensate for mis-matched motors.",  -- [MEDIUM]
    [0x6401] = "Latched Drive Timeout: Latched drive timeout expired",
    [0x641E] = "Fifth Switch 2 Open Circuit",
    [0x6465] = "Sets the rated motor speed at 24V. This is used to calibrate encoders to motors",  -- [MEDIUM]
    [0x646C] = "Sets the level of resistance between Band 2 and Band 3 for each PM Inhibit Input",
    [0x646E] = "Inhibit Band to set for Virtual Inhibit Lockout",
    [0x6473] = "Inhibit bands within inhibit assignment that controls Backrest Inhibit",
    [0x651E] = "Right Signal 2 Short Circuit",  -- [MEDIUM]
    [0x6563] = "Sets Footrest Ground Clearance for Lockout Speed.",  -- [MEDIUM]
    [0x6564] = "Sets the rated motor speed at 24V. This is used to calibrate encoders to motors",  -- [MEDIUM]
    [0x6567] = "Sets whether the StLM is to operate with 6V, 12V 24V or unregulated brake lights",  -- [MEDIUM]
    [0x656C] = "Identifies the inhibit style for the channel",  -- [MEDIUM]
    [0x656D] = "Sets the debounce time for each PM Inhibit Input",
    [0x656E] = "Factory Default Memory Position for Recline actuators",
    [0x6570] = "Sets whether a short beep occurs when the controller is turned On.",  -- [MEDIUM]
    [0x6572] = "Sets Fault detection power for Indicators for LM",
    [0x6574] = "Dummy byte in LSM module to allow for movement to PM of Low Battery Alarm",  -- [MEDIUM]
    [0x6576] = "Sets the occasion(s) on which Inhibit 3 is interrogated.",
    [0x661E] = "Left Signal 2 Short Circuit",  -- [MEDIUM]
    [0x6674] = "Sets the OEM Icon associated with assignable function Short Cut Key Top Left",  -- [MEDIUM]
    [0x671E] = "Forward Signal 2 Short Circuit",  -- [MEDIUM]
    [0x6729] = "Set the voltage at which a low battery timer starts counting",  -- [MEDIUM]
    [0x6765] = "Sets whether the StLM is to operate with 6V, 12V 24V or unregulated brake lights",  -- [MEDIUM]
    [0x676E] = "Sets whether the charger inhibit on Inhibit 1 input on the JSM is latching",
    [0x681E] = "Reverse Signal 2 Short Circuit",  -- [MEDIUM]
    [0x682E] = "Sets the time the input needs to be in a band before the inhibit is updated",  -- [MEDIUM]
    [0x6874] = "Sets the OEM Icon associated with assignable function Short Cut Key Top Right",  -- [MEDIUM]
    [0x691E] = "Fifth Switch 2 Short Circuit",  -- [MEDIUM]
    [0x6973] = "Memory Axis to go to before referenced Memory Axis",
    [0x6974] = "Inhibit channel to be associated with each channel",
    [0x6A1E] = "Port 2 Right Channel Invalid: Module Error",
    [0x6B1E] = "Port 2 Left Channel Invalid: Module Error",
    [0x6B63] = "Sets the joystick left/right deflection required to reach full servo lock",  -- [MEDIUM]
    [0x6C1E] = "Port 2 Forward Channel Invalid: Module Error",
    [0x6C64] = "Sets the level of resistance between Band 2 and Band 3 for each PM Inhibit Input",
    [0x6C65] = "Identifies the inhibit style for the channel",  -- [MEDIUM]
    [0x6C74] = "Factory Default Memory Position for Lift or FWD Tilt actuator",
    [0x6D1E] = "Port 2 Reverse Channel Invalid: Module Error",
    [0x6D65] = "Sets the debounce time for each PM Inhibit Input",
    [0x6D72] = "Sets whether an audible alarm sounds while the battery gauge is flashing",  -- [MEDIUM]
    [0x6E1E] = "Port 2 Switch 5 Channel Invalid: Module Error",
    [0x6E64] = "Inhibit Band to set for Virtual Inhibit Lockout",
    [0x6E65] = "Factory Default Memory Position for Recline actuators",
    [0x6E67] = "Sets whether the charger inhibit on Inhibit 1 input on the JSM is latching",
    [0x6E6F] = "Adjusts the Power Module to suit the drive motors",  -- [MEDIUM]
    [0x6E72] = "Selects the function of the ISM's brake light / horn output",  -- [MEDIUM]
    [0x6E74] = "Motor voltage constant",  -- [MEDIUM]
    [0x6F6E] = "Adjusts the Power Module to suit the drive motors",  -- [MEDIUM]
    [0x6F72] = "Sets whether tilted position will inhibit local joystick activity",  -- [MEDIUM]
    [0x7061] = "Exchanges the Power Module's M1 and M2 output",  -- [MEDIUM]
    [0x7065] = "Sets whether a short beep occurs when the controller is turned On.",  -- [MEDIUM]
    [0x721E] = "Forward Signal 1 Dual Path Invalid: Module Error",
    [0x7265] = "Sets Fault detection power for Indicators for LM",
    [0x726D] = "Sets whether an audible alarm sounds while the battery gauge is flashing",  -- [MEDIUM]
    [0x726E] = "Selects the function of the ISM's brake light / horn output",  -- [MEDIUM]
    [0x726F] = "Sets whether tilted position will inhibit local joystick activity",  -- [MEDIUM]
    [0x731E] = "Reverse Signal 1 Dual Path Invalid: Module Error",
    [0x7364] = "Inhibit bands within inhibit assignment that controls Backrest Inhibit",
    [0x7369] = "Memory Axis to go to before referenced Memory Axis",
    [0x7374] = "Factory Default Memory Position for Right/Extend Legrest Actuator",
    [0x7463] = "Adjusts the left and right Motor Outputs to compensate for mis-matched motors.",  -- [MEDIUM]
    [0x7465] = "Dummy byte in LSM module to allow for movement to PM of Low Battery Alarm",  -- [MEDIUM]
    [0x7466] = "Sets the OEM Icon associated with assignable function Short Cut Key Top Left",  -- [MEDIUM]
    [0x7468] = "Sets the OEM Icon associated with assignable function Short Cut Key Top Right",  -- [MEDIUM]
    [0x7469] = "Inhibit channel to be associated with each channel",
    [0x746C] = "Factory Default Memory Position for Lift or FWD Tilt actuator",
    [0x746E] = "Motor voltage constant",  -- [MEDIUM]
    [0x7473] = "Factory Default Memory Position for Right/Extend Legrest Actuator",
    [0x7475] = "Set the voltage at which a low battery timer starts counting",  -- [MEDIUM]
    [0x7574] = "Set the voltage at which a low battery timer starts counting",  -- [MEDIUM]
    [0x7665] = "Sets the occasion(s) on which Inhibit 3 is interrogated.",
    [0x7861] = "Sets the maximum current limit in Amps for the servo motor",  -- [MEDIUM]
    [0x7902] = "High Temperature",
    [0x7A00] = "Channel Current Amplifier Failure",
    [0x7A08] = "Overtemperature (Actuators): Actuator Driver Over Temperature",
    [0x7A09] = "Actuator Driver Error: Enabled In Standby",
    [0x7A0A] = "Actuator Driver Error: Disabled In Drive",
    [0x7A0B] = "Actuator Driver Failure",
    [0x7A0C] = "Over-current Actuator: Channel Current Exceeded",
    [0x7A0D] = "Channel Current Amplifier Failure",
    [0x7A0E] = "Over-current Actuator Channel: Actuator Current Sensor Temperature",
    [0x7A12] = "Actuator 1 Shorted High",
    [0x7A13] = "Actuator 1 Shorted Low",
    [0x7A1E] = "Forward Signal 2 Dual Path Invalid: Module Error",
    [0x7A22] = "Actuator 2 Shorted High",
    [0x7A23] = "Actuator 2 Shorted Low",
    [0x7A32] = "Actuator 3 Shorted High",
    [0x7A33] = "Actuator 3 Shorted Low",
    [0x7A42] = "Actuator 4 Shorted High",
    [0x7A43] = "Actuator 4 Shorted Low",
    [0x7A52] = "Actuator 5 Shorted High",
    [0x7A53] = "Actuator 5 Shorted Low",
    [0x7A62] = "Actuator 6 Shorted High",
    [0x7A63] = "Actuator 6 Shorted Low",
    [0x7A90] = "Over-current Actuator Channel: Common Current Exceeded",
    [0x7A91] = "Total Current Amplifier Failure",
    [0x7B00] = "Gyro Disconnected",
    [0x7B1E] = "Reverse Signal 2 Dual Path Invalid: Module Error",
    [0x7C00] = "Thermistor Fault: Thermistor measurement is out of range",
    [0x7D00] = "Horn Internal Short",  -- [MEDIUM]
    [0x7E00] = "PM Memory Error: Running Repository Error",
    [0x7E01] = "PM Memory Error: Unable to Open PM Req File",
    [0x7E02] = "Memory Error: Unable to synchronise with Repository",
    [0x7E03] = "Memory Error: Failed to cancel queued message",
    [0x7E04] = "Memory Error: Repository aborted transfer",
    [0x7E05] = "Memory Error: Repository timeout during transfer",
    [0x7E06] = "Memory Error: Invalid Repository node number detected",
    [0x7E07] = "Memory Error: Incompatible file format",
    [0x7E08] = "Memory Error: Bad data in Repository file",
    [0x7E09] = "Memory Error: Bad descriptor in Repository file",
    [0x7E0A] = "Memory Error: Old file format in Repository cannot restore corrupt file",
    [0x7E0B] = "Memory Error: File Slot CRC does not match",
    [0x7E0C] = "Memory Error: Special File sequence error",
    [0x7E0D] = "Memory Error: Incompatible Special File format",
    [0x7E0E] = "Memory Error: Unable to repair corrupt Special File",
    [0x7E0F] = "Memory Error: Invalid Special File version in Repository",
    [0x7E10] = "Memory Error: Invalid Special File variant",
    [0x7E11] = "Memory Error: Upgrade would mix Special File variants",
    [0x7E12] = "Memory Error: Unable to repair corrupt Special File set",
    [0x7E13] = "Memory Error: Failed to delete Special File in order to repair set",
    [0x7E14] = "Memory Error: Repository aborted transfer - Special File",
    [0x7E15] = "Memory Error: Repository timeout during transfer - Special File",
    [0x7E17] = "Language Error: Bad Auxiliary file variant",
    [0x7E18] = "Restore Error",
    [0x7E20] = "Memory Error: Get Repository Timeout",
    [0x7E21] = "Memory Error: Release Repository Timeout",
    [0x7E22] = "Memory Error: Check Repository Timeout",
    [0x7E23] = "Memory Error: Repository Taken",
    [0x7E24] = "Memory Error: Repository Not Released",
    [0x7E25] = "Memory Error: Set Values Get File Slot Error",
    [0x7E26] = "Memory Error: Set Values Set Slot Location Error",
    [0x7E27] = "Memory Error: Slot Write Error",
    [0x7E28] = "Memory Error: Set Values Slot Data Error",
    [0x7E29] = "Memory Error: Set Values Get File Slot Error",
    [0x7E2A] = "Memory Error: Get Values Get File Slot Error",
    [0x7E2B] = "Memory Error: Get Values Set Slot Location Error",
    [0x7E2C] = "Memory Error: Get Values Slot Data Error",
    [0x7E2E] = "Memory Error: Get Size Get File Slot Error",
    [0x7E2F] = "Memory Error: Get Slot Size Error",
    [0x7E30] = "Memory Error: Get Operating Time Error",
    [0x7E34] = "Memory Error: Get Eventlog Event Error",
    [0x7E35] = "Memory Error: Get Org Number Error",
    [0x7E36] = "Memory Error: Get Attributes Get File Slot Error",
    [0x7E37] = "Memory Error: Get Slot Check Error",
    [0x7E38] = "Memory Error: Set Slot Verify Error",
    [0x7E39] = "Memory Error: Get File Attributes Error",
    [0x7E3A] = "Memory Error: Repository Data Corrupt",
    [0x7F00] = "Bad Cable: CAN Transceiver in fault tolerant mode",
    [0x7F01] = "Bad Cable: Rebus High Speed Bus Error",
    [0x8016] = "COP2 INT VOLTAGE ERROR: Internal Voltages out of Range",  -- [MEDIUM]
    [0x8081] = "Bad Settings: Unable to Select Profile",  -- [MEDIUM]
    [0x8100] = "System Error: CAN Device Off-line",
    [0x8101] = "Bus Off",
    [0x8102] = "CAN Receiver Overrun",
    [0x8103] = "Memory Error: Rebus Tx Queue Full",
    [0x8104] = "System Error: Rx DLC Not As Expected",
    [0x8105] = "DIME Error",
    [0x8106] = "System Error: Config Failure",
    [0x8107] = "System Error: Rebus Event Queue Overflow",
    [0x8108] = "System Error: Config Data Access Error",
    [0x8109] = "System Error: Pre-Op Failure",
    [0x810A] = "PM Memory Error: SCF File Read Failure",
    [0x810B] = "PM Memory Error: DCF File Read Failure",
    [0x810C] = "System Error: Failed to Init DCF Tables by Pre-Op End",
    [0x810D] = "System Error: Config Failure - No Repository Node",
    [0x810E] = "System Error: Config Failure - Too Many Repository Nodes",
    [0x8110] = "SCID Received by Waking Node",
    [0x8111] = "System Error: Config Failure - No Repository Node",
    [0x8140] = "Memory Error: Tx Confirm Timeout",
    [0x8141] = "System Error: Config Failure - No PG Input Device",
    [0x8142] = "System Error: Config Failure - Invalid PG Input Devices Param",
    [0x8143] = "System Error: Config Failure - Unexpected Non PG Input Device",
    [0x8146] = "Configuration Error: Modules Failed To Pair Successfully",
    [0x8147] = "Configuration Error: Paired Module Tripped",
    [0x8148] = "Configuration Error: Paired Module Stopped Responding",
    [0x8180] = "Bad Settings: Unable to Select Profile",
    [0x8181] = "Memory Error: Invalid AIM Indicated",
    [0x8182] = "Memory Error: Invalid Mode or Profile Message",
    [0x8183] = "Bad Settings: No Modes Available",
    [0x8184] = "Focus Mask Access Error",
    [0x8281] = "Memory Error: Invalid Mode or Profile Message",
    [0x8316] = "COP2 LOADCELL ERROR: Load cell signal out of range",  -- [MEDIUM]
    [0x8381] = "Bad Settings: No Modes Available",  -- [MEDIUM]
    [0x8416] = "COP2 DMS TEST ERROR: DMS is activated during test",  -- [MEDIUM]
    [0x8516] = "COP2 ACCEL ERROR: Accelerometer values out of range",  -- [MEDIUM]
    [0x8616] = "COP2 ANGLE ERROR: Incorrect handle angle",  -- [MEDIUM]
    [0x8716] = "COP2 SYSTEM FAULT1: Control fault 1",  -- [MEDIUM]
    [0x8800] = "Overtemperature (Lamps): Lighting Driver Over Temperature",
    [0x8811] = "Left Lamp Short Circuit",
    [0x8812] = "Right Lamp Short Circuit",
    [0x8816] = "COP2 SYSTEM FAULT2: Control fault 2",  -- [MEDIUM]
    [0x8819] = "Brake Lamp Short Circuit",
    [0x881D] = "Left Indicators Short Circuit",
    [0x881E] = "Right Indicators Short Circuit",
    [0x882C] = "Indicators Open Circuit",
    [0x883C] = "Indicators Open Circuit: Indicators Single Bulb Failure",
    [0x8916] = "COP2 SYSTEM FAULT3: Control fault 3",  -- [MEDIUM]
    [0x8A16] = "COP2 SYSTEM FAULT4: Control fault 4",  -- [MEDIUM]
    [0x8B16] = "COP2 SYSTEM FAULT5: Control fault 5",  -- [MEDIUM]
    [0x8C16] = "COP2 SYSTEM FAULT6: Control fault 6",  -- [MEDIUM]
    [0x8D16] = "COP2 SYSTEM FAULT7: Control fault 7",  -- [MEDIUM]
    [0x8E00] = "Statemachine Queue Overflow",
    [0x8E01] = "Event Queue Overflow",
    [0x8E16] = "COP2 SYSTEM FAULT8: Control fault 8",  -- [MEDIUM]
    [0x8F16] = "COP2 SYSTEM FAULT9: Control fault 9",  -- [MEDIUM]
    [0x9001] = "FW Update Error",
    [0x9400] = "Servo Pot Error",
    [0x9451] = "Turning test mode error: Gyro signal detected in environ. Mode",  -- [MEDIUM]
    [0x9600] = "Hosted Application Error 0",
    [0x9601] = "Bad Channel Value: Channel Setting Error.",
    [0x9602] = "Bad Caster Lock: Caster Lock Setting Error.",
    [0x9603] = "Bad PRAR Setting: Pressure Relief Alerts and Recording Setting Error.",
    [0x9604] = "Bad Virtual Inh: Virtual Inhibit Setting Error.",
    [0x9605] = "Bad Gnd Clearance: Ground Clearance Setting Error.",
    [0x9700] = "ASM Self Test failed",  -- [MEDIUM]
    [0x9840] = "Error Multi-Core Interface Startup Fail: Module Error",
    [0x9841] = "Error Multi-Core Interface Incomining lock fail: Module Error",
    [0x9842] = "Error Multi-Core Interface Outgoing lock fail: Module Error",
    [0x9843] = "Error Multi-Core Interface Heart Beat Error: Module Error",
    [0x9844] = "Error Multi-Core Checksum Fail: Module Error",
    [0x9900] = "Left Jack 2 Cap Fault: Module reporting Error may need repair.",
    [0x9901] = "Left Jack 1 Cap Fault: Module reporting Error may need repair.",
    [0x9902] = "HHK Supply Failure: Module reporting Error may need repair.",
    [0x9903] = "HHK Current Monitor: Module reporting Error may need repair.",
    [0x9904] = "Profile Jack Test Fault: Module reporting Error may need repair.",
    [0x9915] = "On/Off Switch Invalid: On/Off Switch Error",
    [0x9A01] = "USB Charging Error",
    [0x9A02] = "USB Internal Fault: USB charging port has failed",
    [0x9B00] = "Module Error",
    [0x9B01] = "Module Error",
    [0x9B02] = "Module Error",
    [0x9B03] = "Module Error",
    [0x9B20] = "Module Error",
    [0x9B21] = "Module Error",
    [0x9B22] = "Smart Fuse Trip",
    [0xB009] = "Joystick Port 1 Mid Reference Error",
    [0xD009] = "Joystick Port 2 Mid Reference Error",
    [0xFFFF] = "Module Error: Module reporting Error may need repair",
}


-- Mode-config payload format per Type byte. Evidence:
-- CJSM_DISPLAY_PROTOCOL.md
-- "Mode Configuration Frames" §"Data Types".
local mode_type_names = {
    [0x00] = "Initialization",
    [0x40] = "Configuration header",
    [0x60] = "Mode parameters",
    [0x61] = "Extended mode data",
    [0x62] = "Mode serial / XOR data",
    [0x80] = "Status",
    [0xC0] = "Flags",
    [0xF0] = "End-flags",
}

-- POP register-byte names (data[1] = low byte of ODI). Per
-- RNET_PROTOCOL_SPECIFICATION.md §8.3 Register Types. Most-common values
-- in the corpus are 0x80 PAGE0, 0x81 POINTER, 0x8C TEXT, 0x8F DATA;
-- other 0x8X values appear (0x84, 0x85, 0x88, 0x89, 0x8A, 0x8B) but
-- aren't documented in §8.3.
local pop_register_names = {
    [0x80] = "PAGE0",
    [0x81] = "POINTER",
    [0x8C] = "TEXT",
    [0x8F] = "DATA",
}
-- POP register bytes seen empirically but not in §8.3.
local pop_register_undocumented = {
    [0x84] = true, [0x85] = true, [0x86] = true, [0x88] = true,
    [0x89] = true, [0x8A] = true, [0x8B] = true,
}

-- Permobil PWC param_id → parameter name map (966 entries)
-- Source: parameters.json bindings with
--         space='permobil-pwc-param-id'
-- Wire mapping (parse discovery): param_id = (byte 6 << 8) | byte 4
--   of POINTER-register POP frames (data[0]_low_nibble=0x1).
local pwc_params = {
    [0] = "ALPHA",
    [1] = "Abbreviated",
    [2] = "ALPHANUMERIC",
    [3] = "All",
    [4] = "ALPHA_SHIFT",
    [5] = "ALLOWED_LENGTHS",
    [6] = "ASSUME_CODE_39_CHECK_DIGIT",
    [7] = "AlternativeSwitchBox",
    [8] = "C3G",
    [9] = "AnimateChild",
    [10] = "ALLOWED_EAN_EXTENSIONS",
    [11] = "Back",
    [12] = "ChildActivationEnd",
    [13] = "ActivationStart",
    [14] = "ActivationEnd",
    [15] = "AltSwitchBox",
    [16] = "CurrencySymbol",
    [17] = "Cp1250",
    [18] = "Cp1251",
    [19] = "Cp1252",
    [20] = "Cp1256",
    [21] = "ExtraData",
    [22] = "ArticulationLegs",
    [23] = "ASCII",
    [24] = "Axis1Down",
    [25] = "Axis1Toggle",
    [26] = "Axis2Up",
    [27] = "Axis2Down",
    [28] = "Axis2Toggle",
    [29] = "Axis3Up",
    [30] = "Axis3Down",
    [31] = "Axis3Toggle",
    [32] = "Axis4Up",
    [33] = "Axis4Down",
    [34] = "Axis4Toggle",
    [35] = "Axis5Up",
    [36] = "Axis5Down",
    [37] = "Axis5Toggle",
    [38] = "Axis6Up",
    [39] = "Axis6Down",
    [40] = "Axis6Toggle",
    [41] = "ArmAccessory1",
    [42] = "ArmAccessory2",
    [43] = "ArmAccessory3",
    [44] = "ArmAccessory4",
    [45] = "Axis8Down",
    [46] = "Axis8Toggle",
    [47] = "Axis9Up",
    [48] = "Axis9Down",
    [49] = "Axis9Toggle",
    [50] = "Axis10Up",
    [51] = "Axis10Down",
    [52] = "Axis10Toggle",
    [53] = "Accessory1",
    [54] = "Accessory2",
    [55] = "Accessory3",
    [56] = "Accessory4",
    [57] = "Accessory5",
    [58] = "Accessory6",
    [59] = "Accessory7",
    [60] = "Accessory8",
    [61] = "Accessory9",
    [62] = "Accessory10",
    [63] = "Accessory11",
    [64] = "Accessory12",
    [65] = "Accessory13",
    [66] = "Accessory14",
    [67] = "Accessory15",
    [68] = "Accessory16",
    [69] = "Accessory17",
    [70] = "Accessory18",
    [71] = "Accessory19",
    [72] = "Accessory20",
    [73] = "Accessory21",
    [74] = "Accessory22",
    [75] = "IrShortcut7",
    [76] = "IrShortcut8",
    [77] = "Axis1UpLatch",
    [78] = "Axis1DownLatch",
    [79] = "Axis2UpLatch",
    [80] = "Axis2DownLatch",
    [81] = "Axis3UpLatch",
    [82] = "Axis3DownLatch",
    [83] = "Axis4UpLatch",
    [84] = "Axis4DownLatch",
    [85] = "Axis5UpLatch",
    [86] = "Axis5DownLatch",
    [87] = "Axis6UpLatch",
    [88] = "Axis6DownLatch",
    [89] = "Axis7UpLatch",
    [90] = "Axis7DownLatch",
    [91] = "Axis8UpLatch",
    [92] = "Axis8DownLatch",
    [93] = "Axis9UpLatch",
    [94] = "Axis9DownLatch",
    [95] = "Axis10UpLatch",
    [96] = "Axis10DownLatch",
    [97] = "Axis11UpLatch",
    [98] = "Axis11DownLatch",
    [99] = "Axis12UpLatch",
    [100] = "Axis12DownLatch",
    [101] = "MemoryPage",
    [102] = "Axis1ToggleLatch",
    [103] = "Axis2ToggleLatch",
    [104] = "Axis3ToggleLatch",
    [105] = "Axis4ToggleLatch",
    [106] = "Axis5ToggleLatch",
    [107] = "Axis6ToggleLatch",
    [108] = "Axis7ToggleLatch",
    [109] = "Axis8ToggleLatch",
    [110] = "Axis9ToggleLatch",
    [111] = "Axis10ToggleLatch",
    [112] = "Axis11ToggleLatch",
    [113] = "Axis12ToggleLatch",
    [114] = "Output3Forward",
    [115] = "Output3Reverse",
    [116] = "Output3Left",
    [117] = "Output3Right",
    [118] = "Output3SpeedDown",
    [119] = "Output3SpeedUp",
    [120] = "Output3Horn",
    [121] = "Output4Forward",
    [122] = "Output4Reverse",
    [123] = "Output4Left",
    [124] = "Output4Right",
    [125] = "Output4SpeedDown",
    [126] = "Output4SpeedUp",
    [127] = "Output4Horn",
    [128] = "Softkey1",
    [129] = "Softkey2",
    [130] = "Softkey3",
    [131] = "Softkey4",
    [132] = "Axis13Up",
    [133] = "Axis13Down",
    [134] = "Axis13Toggle",
    [135] = "Axis13UpLatch",
    [136] = "Axis13DownLatch",
    [137] = "Axis13ToggleLatch",
    [138] = "Axis14Up",
    [139] = "Axis14Down",
    [140] = "Axis14Toggle",
    [141] = "Axis14UpLatch",
    [142] = "Axis14DownLatch",
    [143] = "Axis14ToggleLatch",
    [144] = "Axis15Up",
    [145] = "Axis15Down",
    [146] = "Axis15Toggle",
    [147] = "Axis15UpLatch",
    [148] = "Axis15DownLatch",
    [149] = "Axis15ToggleLatch",
    [150] = "Axis16Up",
    [151] = "Axis16Down",
    [152] = "Axis16Toggle",
    [153] = "Axis16UpLatch",
    [154] = "Axis16DownLatch",
    [155] = "Axis16ToggleLatch",
    [156] = "DoubleLeftClickMouse",
    [157] = "DoubleRightClickMouse",
    [158] = "AndroidOsHome",
    [159] = "AndroidOsBack",
    [160] = "AndroidOsVolumeUp",
    [161] = "AndroidOsVolumeDown",
    [162] = "AndroidOsZoom",
    [163] = "IDeviceShortcut1",
    [164] = "IDeviceShortcut2",
    [165] = "IDeviceShortcut3",
    [166] = "IDeviceShortcut4",
    [167] = "IDeviceShortcut5",
    [168] = "IDeviceShortcut6",
    [169] = "IDeviceShortcut7",
    [170] = "IDeviceShortcut8",
    [255] = "None",
    [256] = "LiftUp",
    [257] = "LiftDown",
    [258] = "LiftToggle",
    [259] = "LiftUpLatch",
    [260] = "LiftDownLatch",
    [261] = "LiftToggleLatch",
    [262] = "BackUp",
    [263] = "BackDown",
    [264] = "BackToggle",
    [265] = "BackUpLatch",
    [266] = "BackDownLatch",
    [267] = "BackToggleLatch",
    [268] = "TiltUp",
    [269] = "TiltDown",
    [270] = "TiltToggle",
    [271] = "TiltUpLatch",
    [272] = "TiltDownLatch",
    [273] = "TiltToggleLatch",
    [274] = "LegRestUp",
    [275] = "LegRestDown",
    [276] = "LegRestToggle",
    [277] = "LegRestUpLatch",
    [278] = "LegRestDownLatch",
    [279] = "LegRestToggleLatch",
    [280] = "LegRestRUp",
    [281] = "LegRestRDown",
    [282] = "LegRestRToggle",
    [283] = "LegRestRUpLatch",
    [284] = "LegRestRDownLatch",
    [285] = "BoostDriveCurrent",
    [286] = "BoostDriveTime",
    [287] = "CurrentFoldbackThreshold",
    [288] = "CurrentFoldbackTime",
    [289] = "LegRestLUpLatch",
    [290] = "LegRestLDownLatch",
    [291] = "LegRestLToggleLatch",
    [292] = "FootplateUp",
    [293] = "FootplateDown",
    [294] = "FootplateToggle",
    [295] = "Compensation",
    [296] = "FootplateDownLatch",
    [297] = "FootplateToggleLatch",
    [298] = "FootplateRUp",
    [299] = "FootplateRDown",
    [300] = "FootplateRToggle",
    [301] = "FootplateRUpLatch",
    [302] = "FootplateRDownLatch",
    [303] = "FootplateRToggleLatch",
    [304] = "FootplateLUp",
    [305] = "FootplateLDown",
    [306] = "FootplateLToggle",
    [307] = "FootplateLUpLatch",
    [308] = "FootplateLDownLatch",
    [309] = "FootplateLToggleLatch",
    [310] = "Stand1Up",
    [311] = "Stand1Down",
    [312] = "MaximumForwardSpeed",
    [313] = "Stand1UpLatch",
    [314] = "Stand1DownLatch",
    [315] = "Stand1ToggleLatch",
    [316] = "Stand2Up",
    [317] = "Stand2Down",
    [318] = "MinimumForwardSpeed",
    [319] = "Stand2UpLatch",
    [320] = "Stand2DownLatch",
    [321] = "Stand2ToggleLatch",
    [322] = "Sequence1Up",
    [323] = "Sequence1Down",
    [324] = "MaximumReverseSpeed",
    [325] = "Sequence1UpLatch",
    [326] = "Sequence1DownLatch",
    [327] = "Sequence1ToggleLatch",
    [328] = "Sequence2Up",
    [329] = "Sequence2Down",
    [330] = "MinimumReverseSpeed",
    [331] = "Sequence2UpLatch",
    [332] = "Sequence2DownLatch",
    [333] = "Sequence2ToggleLatch",
    [334] = "Sequence3Up",
    [335] = "Sequence3Down",
    [336] = "MaximumTurningSpeed",
    [337] = "Sequence3UpLatch",
    [338] = "Sequence3DownLatch",
    [339] = "Sequence3ToggleLatch",
    [340] = "Sequence4Up",
    [341] = "Sequence4Down",
    [342] = "Sequence4Toggle",
    [343] = "Sequence4UpLatch",
    [344] = "Sequence4DownLatch",
    [345] = "MinimumTurningSpeed",
    [346] = "Sequence5Up",
    [347] = "Sequence5Down",
    [348] = "Sequence5Toggle",
    [349] = "Sequence5UpLatch",
    [350] = "Sequence5DownLatch",
    [351] = "MaximumForwardAcceleration",
    [352] = "Sequence6Up",
    [353] = "Sequence6Down",
    [354] = "Sequence6Toggle",
    [355] = "Sequence6UpLatch",
    [356] = "Sequence6DownLatch",
    [357] = "Sequence6ToggleLatch",
    [358] = "MinimumForwardAcceleration",
    [359] = "Sequence7Down",
    [360] = "Sequence7Toggle",
    [361] = "Sequence7UpLatch",
    [362] = "Sequence7DownLatch",
    [363] = "Sequence7ToggleLatch",
    [364] = "Sequence8Up",
    [365] = "MaximumForwardDeceleration",
    [366] = "Sequence8Toggle",
    [367] = "Sequence8UpLatch",
    [368] = "Sequence8DownLatch",
    [369] = "Sequence8ToggleLatch",
    [370] = "Sequence9Up",
    [371] = "MinimumForwardDeceleration",
    [372] = "Sequence9Toggle",
    [373] = "Sequence9UpLatch",
    [374] = "Sequence9DownLatch",
    [375] = "Sequence9ToggleLatch",
    [376] = "Sequence10Up",
    [377] = "MaximumTurnAcceleration",
    [378] = "MinimumTurnAcceleration",
    [379] = "Sequence10UpLatch",
    [380] = "MaximumTurnDeceleration",
    [381] = "MinimumTurnDeceleration",
    [382] = "Memory0",
    [385] = "Memory0Latch",
    [388] = "Memory1",
    [391] = "Memory1Latch",
    [394] = "Memory2",
    [397] = "Memory2Latch",
    [400] = "Memory3",
    [403] = "Memory3Latch",
    [406] = "Memory4",
    [409] = "Memory4Latch",
    [412] = "Memory5",
    [415] = "Memory5Latch",
    [418] = "SaveMemory0",
    [424] = "SaveMemory1",
    [430] = "SaveMemory2",
    [433] = "LatchedDrive",
    [436] = "SaveMemory3",
    [439] = "LatchedTimeoutBeep",
    [442] = "SaveMemory4",
    [445] = "LatchedTimeout",
    [448] = "SaveMemory5",
    [451] = "SleepTimer",
    [454] = "HeadAccessory1Up",
    [455] = "HeadAccessory1Down",
    [456] = "HeadAccessory1Toggle",
    [457] = "HeadAccessory1UpLatch",
    [458] = "HeadAccessory1DownLatch",
    [459] = "HeadAccessory1ToggleLatch",
    [460] = "HeadAccessory2Up",
    [461] = "HeadAccessory2Down",
    [462] = "HeadAccessory2Toggle",
    [463] = "HeadAccessory2UpLatch",
    [464] = "HeadAccessory2DownLatch",
    [465] = "HeadAccessory2ToggleLatch",
    [466] = "HeadAccessory3Up",
    [467] = "HeadAccessory3Down",
    [468] = "HeadAccessory3Toggle",
    [469] = "HeadAccessory3UpLatch",
    [470] = "HeadAccessory3DownLatch",
    [471] = "HeadAccessory3ToggleLatch",
    [472] = "HeadAccessory4Up",
    [473] = "HeadAccessory4Down",
    [474] = "HeadAccessory4Toggle",
    [475] = "HeadAccessory4UpLatch",
    [476] = "HeadAccessory4DownLatch",
    [477] = "HeadAccessory4ToggleLatch",
    [478] = "BackAccessory1Up",
    [479] = "BackAccessory1Down",
    [480] = "BackAccessory1Toggle",
    [481] = "BackAccessory1UpLatch",
    [482] = "BackAccessory1DownLatch",
    [483] = "BackAccessory1ToggleLatch",
    [484] = "BackAccessory2Up",
    [485] = "BackAccessory2Down",
    [486] = "BackAccessory2Toggle",
    [487] = "BackAccessory2UpLatch",
    [488] = "BackAccessory2DownLatch",
    [489] = "BackAccessory2ToggleLatch",
    [490] = "BackAccessory3Up",
    [491] = "BackAccessory3Down",
    [492] = "BackAccessory3Toggle",
    [493] = "BackAccessory3UpLatch",
    [494] = "BackAccessory3DownLatch",
    [495] = "BackAccessory3ToggleLatch",
    [496] = "BackAccessory4Up",
    [497] = "BackAccessory4Down",
    [498] = "BackAccessory4Toggle",
    [499] = "BackAccessory4UpLatch",
    [500] = "BackAccessory4DownLatch",
    [501] = "BackAccessory4ToggleLatch",
    [502] = "ArmAccessory1Up",
    [503] = "ArmAccessory1Down",
    [504] = "ArmAccessory1Toggle",
    [505] = "ArmAccessory1UpLatch",
    [506] = "ArmAccessory1DownLatch",
    [507] = "ArmAccessory1ToggleLatch",
    [508] = "ArmAccessory2Up",
    [509] = "ArmAccessory2Down",
    [510] = "ArmAccessory2Toggle",
    [511] = "ArmAccessory2UpLatch",
    [512] = "ArmAccessory2DownLatch",
    [513] = "ArmAccessory2ToggleLatch",
    [514] = "ArmAccessory3Up",
    [515] = "ArmAccessory3Down",
    [516] = "ArmAccessory3Toggle",
    [517] = "ArmAccessory3UpLatch",
    [518] = "ArmAccessory3DownLatch",
    [519] = "ArmAccessory3ToggleLatch",
    [520] = "ArmAccessory4Up",
    [521] = "ArmAccessory4Down",
    [522] = "ArmAccessory4Toggle",
    [523] = "ArmAccessory4UpLatch",
    [524] = "ArmAccessory4DownLatch",
    [525] = "ArmAccessory4ToggleLatch",
    [526] = "LegAccessory1Up",
    [527] = "LegAccessory1Down",
    [528] = "LegAccessory1Toggle",
    [529] = "LegAccessory1UpLatch",
    [530] = "LegAccessory1DownLatch",
    [531] = "LegAccessory1ToggleLatch",
    [532] = "LegAccessory2Up",
    [533] = "LegAccessory2Down",
    [534] = "LegAccessory2Toggle",
    [535] = "LegAccessory2UpLatch",
    [536] = "LegAccessory2DownLatch",
    [537] = "LegAccessory2ToggleLatch",
    [538] = "LegAccessory3Up",
    [539] = "LegAccessory3Down",
    [540] = "AbsoluteMinPower",
    [541] = "AbsoluteMaxForwardSpeed",
    [542] = "AbsoluteMinForwardSpeed",
    [543] = "AbsoluteMaxReverseSpeed",
    [544] = "AbsoluteMinReverseSpeed",
    [545] = "AbsoluteMaxTurningSpeed",
    [546] = "AbsoluteMinTurningSpeed",
    [547] = "AbsoluteMaxForwardAcceleration",
    [548] = "AbsoluteMinForwardAcceleration",
    [549] = "AbsoluteMaxForwardDeceleration",
    [550] = "AbsoluteMinForwardDeceleration",
    [551] = "AbsoluteMaxTurnAcceleration",
    [552] = "AbsoluteMinTurnAcceleration",
    [553] = "AbsoluteMaxTurnDeceleration",
    [554] = "AbsoluteMinTurnDeceleration",
    [555] = "AbsoluteMaxReverseAcceleration",
    [556] = "AbsoluteMinReverseAcceleration",
    [557] = "JoystickAccessory2Down",
    [558] = "JoystickAccessory2Toggle",
    [559] = "JoystickAccessory2UpLatch",
    [560] = "JoystickAccessory2DownLatch",
    [561] = "JoystickAccessory2ToggleLatch",
    [562] = "JoystickAccessory3Up",
    [563] = "JoystickAccessory3Down",
    [564] = "JoystickAccessory3Toggle",
    [565] = "JoystickAccessory3UpLatch",
    [566] = "JoystickAccessory3DownLatch",
    [567] = "JoystickAccessory3ToggleLatch",
    [568] = "JoystickAccessory4Up",
    [569] = "JoystickAccessory4Down",
    [570] = "JoystickAccessory4Toggle",
    [571] = "JoystickAccessory4UpLatch",
    [572] = "JoystickAccessory4DownLatch",
    [573] = "JoystickAccessory4ToggleLatch",
    [574] = "Accessory1Up",
    [575] = "Accessory1Down",
    [576] = "Accessory1Toggle",
    [577] = "Accessory1UpLatch",
    [578] = "Accessory1DownLatch",
    [579] = "Accessory1ToggleLatch",
    [580] = "Accessory2Up",
    [581] = "Accessory2Down",
    [582] = "AbsoluteMaxReverseDeceleration",
    [583] = "AbsoluteMinReverseDeceleration",
    [584] = "Accessory2DownLatch",
    [585] = "Accessory2ToggleLatch",
    [586] = "Accessory3Up",
    [587] = "Accessory3Down",
    [588] = "Accessory3Toggle",
    [589] = "Accessory3UpLatch",
    [590] = "Accessory3DownLatch",
    [591] = "Accessory3ToggleLatch",
    [592] = "Accessory4Up",
    [593] = "Accessory4Down",
    [594] = "Accessory4Toggle",
    [595] = "Accessory4UpLatch",
    [596] = "Accessory4DownLatch",
    [597] = "Accessory4ToggleLatch",
    [598] = "Accessory5Up",
    [599] = "Accessory5Down",
    [600] = "Accessory5Toggle",
    [601] = "Accessory5UpLatch",
    [602] = "Accessory5DownLatch",
    [603] = "Accessory5ToggleLatch",
    [604] = "Accessory6Up",
    [605] = "Accessory6Down",
    [606] = "Accessory6Toggle",
    [607] = "Accessory6UpLatch",
    [608] = "Accessory6DownLatch",
    [609] = "Accessory6ToggleLatch",
    [610] = "Accessory7Up",
    [611] = "Accessory7Down",
    [612] = "Accessory7Toggle",
    [613] = "Accessory7UpLatch",
    [614] = "Accessory7DownLatch",
    [615] = "Accessory7ToggleLatch",
    [616] = "Accessory8Up",
    [617] = "Accessory8Down",
    [618] = "Accessory8Toggle",
    [619] = "Accessory8UpLatch",
    [620] = "Accessory8DownLatch",
    [621] = "Accessory8ToggleLatch",
    [622] = "Accessory9Up",
    [623] = "Accessory9Down",
    [624] = "Accessory9Toggle",
    [625] = "Accessory9UpLatch",
    [626] = "Accessory9DownLatch",
    [627] = "Accessory9ToggleLatch",
    [628] = "Accessory10Up",
    [629] = "Accessory10Down",
    [630] = "Accessory10Toggle",
    [631] = "Accessory10UpLatch",
    [632] = "Accessory10DownLatch",
    [633] = "Accessory10ToggleLatch",
    [634] = "Accessory11Up",
    [635] = "Accessory11Down",
    [636] = "Accessory11Toggle",
    [637] = "Accessory11UpLatch",
    [638] = "Accessory11DownLatch",
    [639] = "Accessory11ToggleLatch",
    [640] = "Accessory12Up",
    [641] = "Accessory12Down",
    [642] = "Accessory12Toggle",
    [643] = "Accessory12UpLatch",
    [644] = "Accessory12DownLatch",
    [645] = "Accessory12ToggleLatch",
    [646] = "Accessory13Up",
    [647] = "Accessory13Down",
    [648] = "Accessory13Toggle",
    [649] = "Accessory13UpLatch",
    [650] = "Accessory13DownLatch",
    [651] = "Accessory13ToggleLatch",
    [652] = "Accessory14Up",
    [653] = "Accessory14Down",
    [654] = "Accessory14Toggle",
    [655] = "Accessory14UpLatch",
    [656] = "Accessory14DownLatch",
    [657] = "Accessory14ToggleLatch",
    [658] = "Accessory15Up",
    [659] = "Accessory15Down",
    [660] = "Accessory15Toggle",
    [661] = "Accessory15UpLatch",
    [662] = "Accessory15DownLatch",
    [663] = "Accessory15ToggleLatch",
    [664] = "Accessory16Up",
    [665] = "Accessory16Down",
    [666] = "Accessory16Toggle",
    [667] = "Accessory16UpLatch",
    [668] = "Accessory16DownLatch",
    [669] = "Accessory16ToggleLatch",
    [670] = "Accessory17Up",
    [671] = "Accessory17Down",
    [672] = "Accessory17Toggle",
    [673] = "Accessory17UpLatch",
    [674] = "Accessory17DownLatch",
    [675] = "Accessory17ToggleLatch",
    [676] = "Accessory18Up",
    [677] = "Accessory18Down",
    [678] = "Accessory18Toggle",
    [679] = "Accessory18UpLatch",
    [680] = "Accessory18DownLatch",
    [681] = "Accessory18ToggleLatch",
    [682] = "Accessory19Up",
    [683] = "Accessory19Down",
    [684] = "Accessory19Toggle",
    [685] = "Accessory19UpLatch",
    [686] = "Accessory19DownLatch",
    [687] = "Accessory19ToggleLatch",
    [688] = "Accessory20Up",
    [689] = "Accessory20Down",
    [690] = "Accessory20Toggle",
    [691] = "Accessory20UpLatch",
    [692] = "Accessory20DownLatch",
    [693] = "Accessory20ToggleLatch",
    [694] = "Accessory21Up",
    [695] = "Accessory21Down",
    [696] = "Accessory21Toggle",
    [697] = "Accessory21UpLatch",
    [698] = "Accessory21DownLatch",
    [699] = "Accessory21ToggleLatch",
    [700] = "Accessory22Up",
    [701] = "Accessory22Down",
    [702] = "Accessory22Toggle",
    [703] = "Accessory22UpLatch",
    [704] = "Accessory22DownLatch",
    [705] = "Accessory22ToggleLatch",
    [735] = "RemoteSelection",
    [737] = "ModeSelectionInStandby",
    [738] = "StandbyInModes",
    [740] = "StandbyTime",
    [750] = "CurrentFoldbackLevel",
    [954] = "ChangeModeWhileDriving",
    [957] = "ProfileButton",
    [1054] = "ChangeProfileWhileDriving",
    [1056] = "MomentaryScreensEnabled",
    [1196] = "Enabled",
    [1198] = "InputDeviceSubtype",
    [1201] = "EnabledModes",
    [1204] = "Input",
    [1207] = "StandbyForward",
    [1208] = "StandbyReverse",
    [1209] = "StandbyLeft",
    [1210] = "StandbyRight",
    [1211] = "EmergencyStopSwitch",
    [1225] = "SwitchToStandby",
    [1226] = "SeatReversalProfile",
    [1228] = "SeatReversalProfiles",
    [1235] = "Name",
    [1243] = "AbsoluteMaxTorque",
    [1244] = "Port",
    [1246] = "FwdRevAutoToggle",
    [1247] = "NineWayDetect",
    [1248] = "UserControl",
    [1249] = "ActuatorSelection",
    [1251] = "UserSwitch",
    [1252] = "SwitchDetect",
    [1253] = "SwitchDebounce",
    [1254] = "SwitchLong",
    [1255] = "DoubleClick",
    [1259] = "Sleep12V",
    [1265] = "Position1",
    [1267] = "Position2",
    [1269] = "Position3",
    [1271] = "Position4",
    [1272] = "Position5",
    [1273] = "Position6",
    [1274] = "Position7",
    [1275] = "Position8",
    [1276] = "Position9",
    [1277] = "Position10",
    [1278] = "Position11",
    [1279] = "Position12",
    [1280] = "Position13",
    [1281] = "Position14",
    [1282] = "Position15",
    [1284] = "Position16",
    [1285] = "ReturnTo",
    [1286] = "TimeoutToMenu",
    [1287] = "AutoRepeat",
    [1318] = "Position1Type",
    [1319] = "Position2Type",
    [1320] = "Position3Type",
    [1321] = "Position4Type",
    [1322] = "Position5Type",
    [1323] = "Position6Type",
    [1324] = "Position7Type",
    [1325] = "Position8Type",
    [1326] = "Position9Type",
    [1327] = "Position10Type",
    [1328] = "Position11Type",
    [1329] = "Position12Type",
    [1330] = "Position13Type",
    [1331] = "Position14Type",
    [1332] = "Position15Type",
    [1333] = "Position16Type",
    [1343] = "MaximumRatedSpeed",
    [1346] = "ActuatorAxes",
    [1347] = "MenuNavigation",
    [1348] = "DisplaySpeed",
    [1350] = "MaximumDisplayedSpeed",
    [1357] = "SwitchMedium",
    [1359] = "AutoToggleTime",
    [1360] = "PowerUpMode",
    [1372] = "MenuScanRate",
    [1376] = "Background",
    [1433] = "AllowGrab",
    [1446] = "ScanSpeed",
    [1850] = "SecondFunctionTime",
    [1945] = "ProfileModeJack",
    [1954] = "Type",
    [1983] = "AxisDirectionToggleTime",
    [1995] = "Output",
    [2192] = "ActuatorSwitches",
    [2205] = "JoystickStationaryTime",
    [2206] = "JoystickStationaryRange",
    [2214] = "AssignButtonLatchedSeatingTimeout",
    [2254] = "InputDeviceType",
    [2265] = "ScanFreezeInMode",
    [2318] = "Displays",
    [2457] = "GyroModuleFitted",
    [2458] = "GyroErrorSpeedLimit",
    [2459] = "AngularSpeedScaler",
    [2462] = "ProportionalGain",
    [2463] = "IntegralGain",
    [2466] = "Orientation",
    [2527] = "ActuatorSwitchesWhileDriving",
    [2528] = "StartUpBeep",
    [2529] = "ExternalProfileJackDetect",
    [2530] = "ExternalOnOffJackDetect",
    [2557] = "DynamicGains",
    [2558] = "LowSpeedProportionalGain",
    [2559] = "LowSpeedIntegralGain",
    [2821] = "HornVolume",
    [3036] = "SoftKeyTimedFunctionTime",
    [3049] = "SoftKeyEnable",
    [3061] = "BluetoothExternalSwitches",
    [3062] = "Intermediate",
    [3162] = "UserSwitchDetect",
    [3163] = "NineWaySidSwitchDetect",
    [3164] = "ExternalOnOffSwitchDetect",
    [4541] = "WheelchairSerialNo",
    [4542] = "WheelchairLocation",
    [4544] = "WheelchairChassisType",
    [4545] = "WheelchairSeatType",
    [4547] = "Visible",
    [4548] = "Invert",
    [4550] = "LatchTime",
    [4630] = "SaveEnable",
    [4640] = "Mode",
    [4641] = "Axis1",
    [4642] = "Axis2",
    [4643] = "Axis3",
    [4644] = "Axis4",
    [4645] = "Axis5",
    [4646] = "Axis6",
    [4647] = "Axis7",
    [4648] = "Axis8",
    [4649] = "Mode",
    [4650] = "Axis1",
    [4651] = "Axis2",
    [4652] = "Axis3",
    [4653] = "Axis4",
    [4654] = "Axis5",
    [4655] = "Axis6",
    [4656] = "Axis7",
    [4657] = "Axis8",
    [4658] = "Checkpoint1Position1",
    [4659] = "Checkpoint1Position2",
    [4660] = "Checkpoint1Position3",
    [4661] = "Checkpoint1Position4",
    [4662] = "Checkpoint1Position5",
    [4663] = "Checkpoint1Position6",
    [4664] = "Checkpoint1Position7",
    [4665] = "Checkpoint1Position8",
    [4666] = "Checkpoint2Position1",
    [4667] = "Checkpoint2Position2",
    [4668] = "Checkpoint2Position3",
    [4669] = "Checkpoint2Position4",
    [4670] = "Checkpoint2Position5",
    [4671] = "Checkpoint2Position6",
    [4672] = "Checkpoint2Position7",
    [4673] = "Checkpoint2Position8",
    [4674] = "Checkpoint3Position1",
    [4675] = "Checkpoint3Position2",
    [4676] = "Checkpoint3Position3",
    [4677] = "Checkpoint3Position4",
    [4678] = "Checkpoint3Position5",
    [4679] = "Checkpoint3Position6",
    [4680] = "Checkpoint3Position7",
    [4681] = "Checkpoint3Position8",
    [4682] = "Checkpoint4Position1",
    [4683] = "Checkpoint4Position2",
    [4684] = "Checkpoint4Position3",
    [4685] = "Checkpoint4Position4",
    [4686] = "Checkpoint4Position5",
    [4687] = "Checkpoint4Position6",
    [4688] = "Checkpoint4Position7",
    [4689] = "Checkpoint4Position8",
    [4690] = "Checkpoint5Position1",
    [4691] = "Checkpoint5Position2",
    [4692] = "Checkpoint5Position3",
    [4693] = "Checkpoint5Position4",
    [4694] = "Checkpoint5Position5",
    [4695] = "Checkpoint5Position6",
    [4696] = "Checkpoint5Position7",
    [4697] = "Checkpoint5Position8",
    [4698] = "Checkpoint6Position1",
    [4699] = "Checkpoint6Position2",
    [4700] = "Checkpoint6Position3",
    [4701] = "Checkpoint6Position4",
    [4702] = "Checkpoint6Position5",
    [4703] = "Checkpoint6Position6",
    [4704] = "Checkpoint6Position7",
    [4705] = "Checkpoint6Position8",
    [4706] = "Checkpoint7Position1",
    [4707] = "Checkpoint7Position2",
    [4708] = "Checkpoint7Position3",
    [4709] = "Checkpoint7Position4",
    [4710] = "Checkpoint7Position5",
    [4711] = "Checkpoint7Position6",
    [4712] = "Checkpoint7Position7",
    [4713] = "Checkpoint7Position8",
    [4714] = "Checkpoint8Position1",
    [4715] = "Checkpoint8Position2",
    [4716] = "Checkpoint8Position3",
    [4717] = "Checkpoint8Position4",
    [4718] = "Checkpoint8Position5",
    [4719] = "Checkpoint8Position6",
    [4720] = "Checkpoint8Position7",
    [4721] = "Checkpoint8Position8",
    [4747] = "UserWeight",
    [4748] = "SeatDepth",
    [4750] = "LegsStartPosition",
    [4751] = "LegsStopPosition",
    [4752] = "LegsCompAtStop",
    [4753] = "LegsStandStart",
    [4754] = "LegsStandStop",
    [4755] = "LegsStandCompAtStop",
    [4756] = "MinLegLength",
    [4757] = "GroundTouchAdjust",
    [4758] = "GroundTouchClearance",
    [4759] = "InhibitTiltNeg",
    [4760] = "InhibitLegsNeg",
    [4761] = "PausePositionTilt",
    [4762] = "PausePositionLegs",
    [4763] = "Checkpoint0UpBack",
    [4764] = "Checkpoint0UpLegs",
    [4765] = "Checkpoint1UpBack",
    [4766] = "Checkpoint1UpLegs",
    [4767] = "Checkpoint3DownBack",
    [4768] = "Checkpoint3DownLegs",
    [4769] = "Checkpoint2StandingBack",
    [4770] = "Checkpoint2StandingTilt",
    [4771] = "Checkpoint2StandingLegs",
    [4781] = "LiftMin",
    [4782] = "LiftMax",
    [4783] = "BackMin",
    [4784] = "BackMax",
    [4785] = "TiltMin",
    [4786] = "TiltMax",
    [4787] = "LegsMin",
    [4788] = "LegsMax",
    [4789] = "ArticulationLegsMin",
    [4790] = "ArticulationLegsMax",
    [4801] = "LiftLow",
    [4802] = "LiftXLow",
    [4803] = "LiftInhibit",
    [4804] = "BackLow",
    [4805] = "BackXLow",
    [4806] = "BackInhibit",
    [4807] = "TiltLow",
    [4808] = "TiltXLow",
    [4809] = "TiltInhibit",
    [4810] = "LegsLow",
    [4811] = "LegsXLow",
    [4812] = "LegsInhibit",
    [4825] = "Position1",
    [4826] = "Position2",
    [4827] = "Position3",
    [4828] = "Position4",
    [4829] = "Position5",
    [4830] = "Position6",
    [4831] = "Position7",
    [4832] = "Position8",
    [4833] = "PauseEnable",
    [4834] = "PushLegsEnable",
    [4835] = "PushBackEnable",
    [4836] = "StandAndDriveEnable",
    [4872] = "AudibleDirectionIndicator",
    [4874] = "SupportWheelsInstalled",
    [4903] = "WideFootPlate",
    [4906] = "Checkpoint4DownBack",
    [4907] = "Checkpoint4DownTilt",
    [4908] = "Checkpoint4DownLegs",
    [4909] = "Checkpoint4DownHeight",
    [5192] = "ProfileButton",
    [5193] = "ModeButton",
    [5194] = "ExternalProfileJack1",
    [5195] = "ExternalProfileJack2",
    [5196] = "SpeedDownButton",
    [5197] = "SpeedUpButton",
    [5198] = "HornButton",
    [5199] = "SoftKey1",
    [5200] = "SoftKey2",
    [5201] = "SoftKey3",
    [5202] = "SoftKey4",
    [5203] = "AssignableButtonsEnabled",
    [5204] = "ForwardButton",
    [5205] = "ReverseButton",
    [5206] = "LeftButton",
    [5207] = "RightButton",
    [5208] = "FifthButton",
    [5209] = "UserSwitch",
    [5210] = "SoftKey1Function",
    [5211] = "SoftKey1TimedFunction",
    [5212] = "SoftKey2Function",
    [5213] = "SoftKey2TimedFunction",
    [5214] = "SoftKey3Function",
    [5215] = "SoftKey3TimedFunction",
    [5216] = "SoftKey4Function",
    [5217] = "SoftKey4TimedFunction",
    [5623] = "IndicationLevel",
    [5624] = "Action",
    [5625] = "Direction",
    [5626] = "Speed",
    [5628] = "LatchTime",
    [5629] = "Action",
    [5630] = "Direction",
    [5631] = "Speed",
    [5632] = "LatchTime",
    [5633] = "Action",
    [5634] = "Direction",
    [5635] = "Speed",
    [5636] = "LatchTime",
    [5637] = "Action",
    [5638] = "Direction",
    [5639] = "Speed",
    [5640] = "LatchTime",
    [5641] = "Action",
    [5642] = "Direction",
    [5643] = "Speed",
    [5644] = "LatchTime",
    [5645] = "Action",
    [5646] = "Direction",
    [5647] = "Speed",
    [5648] = "LatchTime",
    [5649] = "Action",
    [5650] = "Direction",
    [5651] = "Speed",
    [5652] = "LatchTime",
    [5653] = "Action",
    [5654] = "Direction",
    [5655] = "Speed",
    [5656] = "LatchTime",
    [5657] = "Action",
    [5658] = "Direction",
    [5659] = "Speed",
    [5660] = "LatchTime",
    [5661] = "Action",
    [5662] = "Direction",
    [5663] = "Speed",
    [5664] = "LatchTime",
    [5665] = "Action",
    [5666] = "Direction",
    [5667] = "Speed",
    [5668] = "LatchTime",
    [5669] = "Action",
    [5670] = "Direction",
    [5671] = "Speed",
    [5672] = "LatchTime",
    [5673] = "Action",
    [5674] = "Direction",
    [5675] = "Speed",
    [5676] = "LatchTime",
    [5677] = "Action",
    [5678] = "Direction",
    [5679] = "Speed",
    [5680] = "LatchTime",
    [5681] = "Action",
    [5682] = "Direction",
    [5683] = "Speed",
    [5684] = "LatchTime",
    [5685] = "Action",
    [5686] = "Direction",
    [5687] = "Speed",
    [5688] = "LatchTime",
    [5699] = "Enabled",
    [5700] = "Name",
    [5703] = "TransferEnable",
    [5706] = "AntiTippersInstalled",
    [5774] = "Enabled",
    [5777] = "CustomAxes",
    [5778] = "ActuatorIndex",
    [5779] = "Position1",
    [5780] = "Position2",
    [5781] = "Position3",
    [5782] = "Position4",
    [5783] = "MinPosition",
    [5784] = "MaxPosition",
    [5785] = "MinPositionOEM",
    [5786] = "MaxPositionOEM",
    [5787] = "Axis",
    [5788] = "Type",
    [5789] = "Subtype",
    [5790] = "Position1",
    [5791] = "Position2",
    [5792] = "Axis",
    [5793] = "Type",
    [5794] = "Subtype",
    [5795] = "Position1",
    [5796] = "Position2",
    [5797] = "Axis",
    [5798] = "FirstId",
    [5799] = "LastId",
    [5800] = "Axis",
    [5801] = "FirstId",
    [5802] = "LastId",
    [458758] = "PlugAndPlayFile",
    [589824] = "JoystickLanguage",
    [589825] = "PlugAndPlayConfiguration",
}


-- .rnd memory-address lookup. Extracted from the PGDT dealer-Programmer
-- parameter database (Generic_V33_1_1375 = 2,397 records, plus the
-- Amylior dealer variant = 2,006 records) via Blowfish decryption +
-- parameter-record parser.
-- Wire mapping (parse empirical): POP frames with non-register
-- ODI (data[1] not in 0x80-0x8F or with non-zero upper bytes)
-- where data[3]=0 carry a 16-bit memory address at data[1..2] LE.
-- Hit rate: 5/35 (14%) on 4-capture corpus — sparse because most
-- ODIs in the corpus aren't real parameter addresses, but the
-- hits that do land are real (consecutive Amy/SCX channels etc).
-- ODI_CLASS device-class disambiguation still TBD (limitation
-- #5 in RND_PARAMETER_RECORD_FORMAT.md) — names here are
-- best-effort across both Generic+Amylior namespaces.
local rnd_address_names = {
    [7] = "SPEED_START_ACCEL",
    [15] = "INDICATOR_FAULT_POWER",
    [53] = "ICS_ELEVATOR_DRV_INHIBIT_HEIGHT",
    [68] = "ICS_ABS_MIN_BACK_ANGLE",
    [69] = "ICS_ABS_MAX_BACK_ANGLE",
    [70] = "ICS_ABS_MIN_LEG_ANGLE",
    [71] = "ICS_ABS_MAX_LEG_ANGLE",
    [72] = "ICS_ABS_MIN_ELEVATOR_TRAVEL",
    [73] = "ICS_ABS_MAX_ELEVATOR_TRAVEL",
    [74] = "ICS_ABS_MIN_TILT_LOW_SPEED_ANGLE",
    [75] = "ICS_ABS_MAX_TILT_LOW_SPEED_ANGLE",
    [77] = "ICS_ABS_MAX_TILT_DRV_INHIBIT_ANGLE",
    [78] = "ICS_ABS_MIN_BACK_LOW_SPD_ANGLE",
    [156] = "CXSM_INH_C1_DN_ASSIGN",
    [157] = "CXSM_INH_C2_DN_ASSIGN",
    [158] = "CXSM_INH_C3_DN_ASSIGN",
    [159] = "CXSM_INH_C4_DN_ASSIGN",
    [160] = "CXSM_INH_C5_DN_ASSIGN",
    [161] = "CXSM_INH_C6_DN_ASSIGN",
    [162] = "CXSM_INH_C1_DN_BANDS",
    [163] = "CXSM_INH_C2_DN_BANDS",
    [165] = "CXSM_INH_C4_DN_BANDS",
    [167] = "CXSM_INH_C6_DN_BANDS",
    [168] = "CXSM_INH_C1_DN_ALARM",
    [171] = "CXSM_INH_C4_DN_ALARM",
    [172] = "CXSM_INH_C5_DN_ALARM",
    [173] = "CXSM_INH_C6_DN_ALARM",
    [174] = "CXSM_INH_C7_UP_ASSIGN",
    [175] = "CXSM_INH_C7_UP_BANDS",
    [176] = "CXSM_INH_C7_UP_ALARM",
    [177] = "CXSM_INH_C7_DN_ASSIGN",
    [178] = "CXSM_INH_C7_DN_BANDS",
    [179] = "CXSM_INH_C7_DN_ALARM",
    [180] = "CXSM_INH_C8_UP_ASSIGN",
    [181] = "CXSM_INH_C8_UP_BANDS",
    [182] = "CXSM_INH_C8_UP_ALARM",
    [183] = "CXSM_INH_C8_DN_ASSIGN",
    [184] = "CXSM_INH_C8_DN_BANDS",
    [185] = "CXSM_INH_C8_DN_ALARM",
    [190] = "MAX_DISPLAY_CURRENT",
    [191] = "ARC_FUNCTION_CJSM",
    [192] = "ARC_FUNCTION_OMNI",
    [193] = "ACTUATOR_SWITCHES",
    [199] = "ASSIGNABLE_BUTTON_USER",
    [288] = "RESERVED_FEATURE_1",
    [289] = "RESERVED_FEATURE_2",
    [290] = "RESERVED_FEATURE_3",
    [291] = "RESERVED_FEATURE_4",
    [292] = "RESERVED_FEATURE_5",
    [293] = "RESERVED_FEATURE_6",
    [294] = "RESERVED_FEATURE_7",
    [306] = "RESERVED_FEATURE_19",
    [324] = "GYRO_FWD_DECEL",
    [330] = "GYRO_TURN_DECEL",
    [345] = "CXSM_INH_C5_UP_ACTIVE_IN_AXIS",
    [351] = "RESERVED_FEATURE_64",
    [358] = "CXSM_INH_C2_DOWN_ACTIVE_IN_AXIS",
    [365] = "CXSM_CHANNEL_INVERT",
    [371] = "RESERVED_FEATURE_84",
    [377] = "ACCELEROMETER_MAX_ACCEL_THRESHOLD",
    [378] = "ACCELEROMETER_FORWARD_SPEED_SCALER",
    [409] = "RESERVED_FEATURE_122",
    [415] = "RESERVED_FEATURE_128",
    [433] = "RESERVED_FEATURE_146",
    [439] = "RESERVED_FEATURE_152",
    [458] = "GYRO_MODULE_FITTED",
    [464] = "GYRO_INTGRAL_GAIN",
    [477] = "RESERVED_FEATURE_190",
    [514] = "SPEED_UP_ACTION",
    [532] = "RESERVED_FEATURE_245",
    [538] = "SPEED_PADDLE_OPERATION",
    [539] = "SPEED_STEP_SIZE",
    [540] = "SPEED_STEP_RATE",
    [541] = "SPEED_WRAP_TIME",
    [542] = "SPEED_WRAP_DELAY",
    [543] = "SPEED_WRAP_BEEP",
    [544] = "DISABLE_MODE_BUTTON",
    [545] = "DISABLE_PROFILE_BUTTON",
    [546] = "DISABLE_HORN_BUTTON",
    [551] = "DISABLE_LEFT_PADDLE_FORWARD",
    [552] = "DISABLE_LEFT_PADDLE_BACKWARD",
    [553] = "AMY_INH_CH1_UP_ASSIGN",
    [554] = "DISABLE_RIGHT_PADDLE_FORWARD",
    [555] = "DISABLE_RIGHT_PADDLE_BACKWARD",
    [556] = "AMY_INH_CH4_UP_ASSIGN",
    [557] = "AMY_INH_CH5_UP_ASSIGN",
    [570] = "AMY_INH_C6_UP_ALARMS",
    [576] = "AMY_INH_CH6_DOWN_ASSIGN",
    [582] = "SCX_LIFT_FWD_TILT_DSN",
    [583] = "SCX_RIGHT_EXT_DSN",
    [585] = "SCX_PRESSURE_RELIEF_AXIS",
    [591] = "SCX_SPECIAL_AXIS",
    [597] = "SCX_CHANNEL_END",
    [603] = "SCX_TILT_VALUE",
    [723] = "SCX_INH_VIRTUAL_INH_CREEP_BAND",
    [724] = "SCX_INH_VIRTUAL_INH_LOCKOUT_BAND",
    [740] = "SCX_INH_LIFT_UP_MIN_ANGLE",
    [742] = "PPP_SWBOX3_LAYOUT_LATCHTIMER",
    [745] = "SCX_INH_LIFT_UP_ASSIGN",
    [748] = "SCX_INH_LIFT_UP_INH_ACTIVE_IN_AXIS",
    [749] = "SCX_INH_LIFT_UP_DRIVE_INHIBIT_BAND",
    [750] = "SCX_INH_LIFT_DN_MAX_ANGLE",
    [751] = "SCX_INH_LIFT_DN_ASSIGN",
    [754] = "SCX_INH_LIFT_DN_INH_ACTIVE_IN_AXIS",
    [755] = "SCX_INH_LIFT_DN_DRIVE_INHIBIT_BAND",
    [756] = "SCX_AB_MOD1_ASS_BTN1_UP",
    [757] = "SCX_AB_MOD1_ASS_BTN1_DOWN",
    [758] = "SCX_AB_MOD1_ASS_BTN2_UP",
    [767] = "SCX_AB_MOD2_ASS_BTN1_DOWN",
    [768] = "SCX_AB_MOD2_ASS_BTN2_UP",
    [769] = "SCX_AB_MOD2_ASS_BTN2_DOWN",
    [771] = "SCX_AB_MOD2_ASS_BTN3_DOWN",
    [772] = "SCX_AB_MOD2_ASS_BTN4_UP",
    [773] = "SCX_AB_MOD2_ASS_BTN4_DOWN",
    [774] = "SCX_AB_MOD2_ASS_BTN5_UP",
    [775] = "SCX_AB_MOD2_ASS_BTN5_DOWN",
    [783] = "PPP_PLGN1_AXISRANGE_LIMIT_LIFT_MIN",
    [786] = "PPP_PLGN1_AXISRANGE_LIMIT_BACK_MAX",
    [810] = "PPP_PLGN1_DRVSPEED_LIMIT_TILT_XLOW",
    [811] = "ILEVEL_INH_ASSIGN",
    [812] = "ILEVEL_AUTOMATIC_DRIVE",
    [813] = "ILEVEL_AUTOMATIC_ACT_AXIS",
    [814] = "ILEVEL_AUTOMATIC_ACT_CHANNEL",
    [815] = "ILEVEL_AUTOMATIC_ENDSTOP_CURRENT",
    [816] = "ILEVEL_AUTOMATIC_ENDSTOP_TIMEOUT",
    [817] = "ILEVEL_AUTOMATIC_DRIVE_TIMEOUT",
    [818] = "ILEVEL_AUTOMATIC_EXTERNAL_SWITCH",
    [820] = "ILEVEL_ACTUATOR_LATCHING",
    [822] = "PPP_PLGN1_DRVSPEED_LIMIT_OEM_TILT_XLOW",
    [823] = "ILEVEL_AUTOMATIC_OVERRUN_TIMEOUT",
    [824] = "ASSIGNABLE_BUTTON_SHORTCUT_3_4_PERMOBIL",
    [825] = "PPP_PLGN1_DRVSPEED_LIMIT_OEM_LEGS_XLOW",
    [826] = "ASSIGNABLE_BUTTON_SHORTCUT_4_3_PERMOBIL",
    [839] = "FN_ICON_133",
    [840] = "FN_ICON_136",
    [841] = "FN_ICON_134",
    [842] = "SM_AXIS_UP_AWAY_SPEED",
    [846] = "FN_ICON_142",
    [847] = "SCREEN_BUTTON_SHORTCUT_1",
    [849] = "SCREEN_BUTTON_SHORTCUT_2",
    [850] = "FN_ICON_141",
    [851] = "SCREEN_BUTTON_SHORTCUT_3",
    [852] = "SCREEN_BUTTON_SHORTCUT_4",
    [891] = "AMY_GEN_SET_ACT_SW_WH_DRV",
    [904] = "FN_ICON_122",
    [906] = "FN_ICON_124",
    [907] = "FN_ICON_125",
    [908] = "PPP_PLGN1_STAND_CP4DOWN_BACK",
    [909] = "PPP_PLGN1_STAND_CP4DOWN_TILT",
    [910] = "PPP_PLGN1_STAND_CP4DOWN_LEGS",
    [911] = "PPP_PLGN1_STAND_CP4DOWN_HEIGHT",
    [912] = "SCX_AB_MOD1_ASS_BTN1_UP_WP",
    [913] = "SCX_AB_MOD1_ASS_BTN1_DOWN_WP",
    [914] = "SCX_AB_MOD1_ASS_BTN2_UP_WP",
    [915] = "SCX_AB_MOD1_ASS_BTN2_DOWN_WP",
    [916] = "SCX_AB_MOD1_ASS_BTN3_UP_WP",
    [917] = "SCX_AB_MOD1_ASS_BTN3_DOWN_WP",
    [918] = "SCX_AB_MOD1_ASS_BTN4_UP_WP",
    [919] = "SCX_AB_MOD1_ASS_BTN4_DOWN_WP",
    [920] = "SCX_AB_MOD1_ASS_BTN5_UP_WP",
    [921] = "SCX_AB_MOD1_ASS_BTN5_DOWN_WP",
    [922] = "SCX_AB_MOD2_ASS_BTN1_UP_WP",
    [923] = "SCX_AB_MOD2_ASS_BTN1_DOWN_WP",
    [924] = "SCX_AB_MOD2_ASS_BTN2_UP_WP",
    [925] = "SCX_AB_MOD2_ASS_BTN2_DOWN_WP",
    [926] = "SCX_AB_MOD2_ASS_BTN3_UP_WP",
    [955] = "ALM_INH_C1_UP_ALARM",
    [957] = "STABILITY_LIMITING",
    [967] = "ARMATURE_RESISTANCE",
    [973] = "SM_AXIS_DN_HOME_SPEED",
    [996] = "SCREEN_BUTTON_2_FUNCTION",
    [1002] = "IDV2_SHORT_RIGHT_ACTION",
    [1003] = "IDV2_SHORT_EXT_1_ACTION",
    [1008] = "IDV2_MID_RIGHT_ACTION",
    [1009] = "IDV2_MID_EXT_1_ACTION",
    [1014] = "IDV2_LONG_RIGHT_ACTION",
    [1015] = "IDV2_LONG_EXT_1_ACTION",
    [1020] = "IDV2_SPEED_DOWN_KEY_ACTION",
    [1051] = "SCX_MVMNT_LFT_LEGR_MAX",
    [1052] = "STEERING_LUT_10",
    [1053] = "SCX_MEM_RESET_INH",
    [1054] = "SCX_SUSLOCK_CH_DSGNTN",
    [1057] = "SCX_LIFT_LOCKOUT_POS",
    [1058] = "SCX_BACKREST_EXC_ANGLE",
    [1059] = "SCX_VIRT_INH_SLOW_SPEED_BAND",
    [1060] = "STEERING_LUT_18",
    [1061] = "STEERING_LUT_19",
    [1064] = "STEERING_POT_LIMIT_HIGH",
    [1069] = "ENHANCED_STEER_CORRECT",
    [1072] = "AIM_GENERAL_MODE",
    [1073] = "AIM_9_WAY_DSUB_IP1_TYPE",
    [1074] = "AIM_9_WAY_DSUB_IP2_TYPE",
    [1075] = "AIM_9_WAY_DSUB_IP3_TYPE",
    [1076] = "AIM_9_WAY_DSUB_IP4_TYPE",
    [1077] = "AIM_9_WAY_DSUB_IP5_TYPE",
    [1078] = "AIM_9_WAY_DSUB_IP5_FUNCTION",
    [1079] = "AIM_9_WAY_DSUB_IP6_TYPE",
    [1080] = "AIM_9_WAY_DSUB_IP6_FUNCTION",
    [1085] = "AIM_WHITE_CONN_IP1_TYPE",
    [1086] = "AIM_WHITE_CONN_IP1_FUNCTION",
    [1087] = "AIM_WHITE_CONN_IP2_TYPE",
    [1088] = "AIM_WHITE_CONN_IP2_FUNCTION",
    [1089] = "SCX_SUS_LOCK_MAX_RUN_TIME",
    [1092] = "SCX_STANDER_LIFT_UP_MIN",
    [1094] = "SCX_STANDER_STANDING_AXIS",
    [1095] = "SCX_GND_CLR_ENABLE",
    [1102] = "SCX_GND_CLR_TILT_OFFSET_DEG",
    [1106] = "SCX_INH_SUS_LOCK_BACKREST_ADV",
    [1107] = "SCX_INH_SUS_LOCK_LIFT_ADV",
    [1108] = "SCX_CHANNELS_BY_AXIS_ENABLE_IOT",
    [1162] = "ACTSNGPM_INH_C5_DN_ASSIGN",
    [1163] = "OMN_ISO_USER_SWITCH_DETECT",
    [1164] = "OMNI_ISO_SID_SWITCH_DETECT",
    [1165] = "ACTSNGPM_INH_C6_UP_ASSIGN",
    [1167] = "ACTSNGPM_INH_C6_UP_ALARM",
    [1168] = "ACTSNGPM_INH_C6_DN_ASSIGN",
    [1169] = "ACTSNGPM_INH_C6_DN_BANDS",
    [1170] = "ACTSNGPM_INH_C6_DN_ALARM",
    [1177] = "SNGPM_LAMP_VOLTAGE",
    [1178] = "SNGPM_LIGHTS_WATTAGE",
    [1179] = "SNGPM_INDICATOR_WATTAGE",
    [1182] = "RESERVED_FEATURE_142",
    [1187] = "RESERVED_FEATURE_147",
    [1188] = "STALL_TIME",
    [1189] = "STALL_BEEP",
    [1190] = "SN_GPM_ACT_CONTROL_EN",
    [1191] = "STLM_POSITION_LOOP_KP",
    [1192] = "STLM_POSITION_LOOP_KI",
    [1193] = "STLM_POSITION_LOOP_KD",
    [1194] = "EXT_ASSIGNABLE_BUTTON_PROFILE",
    [1195] = "EXT_ASSIGNABLE_BUTTON_MODE",
    [1196] = "EXT_ASSIGNABLE_BUTTON_JACK_1",
    [1197] = "EXT_ASSIGNABLE_BUTTON_JACK_2",
    [1198] = "EXT_ASSIGNABLE_BUTTON_SPEED_DOWN",
    [1199] = "EXT_ASSIGNABLE_BUTTON_SPEED_UP",
    [1200] = "EXT_ASSIGNABLE_BUTTON_HORN",
    [1201] = "EXT_ASSIGNABLE_BUTTON_SHORTCUT_1",
    [1202] = "EXT_ASSIGNABLE_BUTTON_SHORTCUT_2",
    [1203] = "EXT_ASSIGNABLE_BUTTON_SHORTCUT_3",
    [1204] = "EXT_ASSIGNABLE_BUTTON_SHORTCUT_4",
    [1205] = "HMC_RBN_INPUT2_ASSIGN",
    [1206] = "EXT_ASSIGNABLE_BUTTON_FORWARD",
    [1207] = "EXT_ASSIGNABLE_BUTTON_REVERSE",
    [1208] = "EXT_ASSIGNABLE_BUTTON_LEFT",
    [1209] = "EXT_ASSIGNABLE_BUTTON_RIGHT",
    [1210] = "EXT_ASSIGNABLE_BUTTON_FIFTH",
    [1211] = "HMC_RBN_INPUT5_ASSIGN",
    [1212] = "EXT_SHORTCUT_KEY_1_FUNCTION",
    [1213] = "HMC_RBN_INPUT6_ASSIGN",
    [1216] = "GYRO_PROPORTIONAL_GAIN",
    [1218] = "HMC_RBN_LATCHED_AXIS",
    [1219] = "GYRO_ORIENTATION",
    [1228] = "ASSIGNABLE_BUTTON_PROFILE",
    [1229] = "ASSIGNABLE_BUTTON_MODE",
    [1230] = "ASSIGNABLE_BUTTON_JACK_1",
    [1231] = "ASSIGNABLE_BUTTON_JACK_2",
    [1232] = "DATA_LOG_DP1_DATA_RESOLUTION_2",
    [1233] = "ASSIGNABLE_BUTTON_SPEED_UP",
    [1234] = "DATA_LOG_DP1_DATA_RESOLUTION_3",
    [1235] = "ASSIGNABLE_BUTTON_LIGHTS",
    [1237] = "ASSIGNABLE_BUTTON_RIGHT_INDICATOR",
    [1238] = "DATA_LOG_DP1_DATA_RESOLUTION_5",
    [1239] = "SECOND_FUNCTION_TIME_2",
    [1240] = "DATA_LOG_DP1_DATA_RESOLUTION_6",
    [1241] = "ASSIGNABLE_BUTTON_REVERSE",
    [1242] = "DATA_LOG_DP1_DATA_RESOLUTION_7",
    [1243] = "ASSIGNABLE_BUTTON_RIGHT",
    [1244] = "DATA_LOG_DP1_DATA_RESOLUTION_8",
    [1246] = "DATA_LOG_DP1_DATA_RESOLUTION_9",
    [1248] = "DATA_LOG_DP1_DATA_RESOLUTION_10",
    [1250] = "DATA_LOG_DP1_DATA_RESOLUTION_11",
    [1252] = "DATA_LOG_DP1_DATA_RESOLUTION_12",
    [1254] = "DATA_LOG_DP1_DATA_RESOLUTION_13",
    [1258] = "DATA_LOG_DP1_DATA_RESOLUTION_15",
    [1259] = "HMC_CJA_OUTPUTS_GROUP_1",
    [1260] = "DATA_LOG_DP1_DATA_RESOLUTION_16",
    [1261] = "HMC_CJA_OUTPUTS_GROUP_3",
    [1262] = "HMC_CJA_OUTPUTS_GROUP_4",
    [1263] = "LONG_EXT_1_ACTION",
    [1267] = "HMC_CJA_OUTPUTS_GROUP_1_DRIVE_AXIS",
    [1269] = "HMC_CJA_OUTPUTS_GROUP_3_DRIVE_AXIS",
    [1278] = "ALM_INH_C1_AWAY_ASSIGN",
    [1279] = "ALM_INH_C1_HOME_ASSIGN",
    [1280] = "ALM_INH_C2_AWAY_ASSIGN",
    [1281] = "ALM_INH_C2_HOME_ASSIGN",
    [1282] = "ALM_INH_C3_AWAY_ASSIGN",
    [1284] = "ALM_INH_C4_AWAY_ASSIGN",
    [1285] = "ALM_INH_C4_HOME_ASSIGN",
    [1286] = "ALM_INH_C5_AWAY_ASSIGN",
    [1287] = "ALM_INH_C5_HOME_ASSIGN",
    [1288] = "ALM_INH_C6_AWAY_ASSIGN",
    [1289] = "ALM_INH_C6_HOME_ASSIGN",
    [1290] = "ASSIGNABLE_BUTTON_SHORTCUT_4",
    [1294] = "SM_AXIS_AWAY_ASSIGN",
    [1296] = "ALM_INH_C1_AWAY_ALARM",
    [1297] = "ALM_INH_C2_AWAY_ALARM",
    [1298] = "ALM_INH_C3_AWAY_ALARM",
    [1299] = "ALM_INH_C4_AWAY_ALARM",
    [1300] = "ALM_INH_C5_AWAY_ALARM",
    [1301] = "ALM_INH_C6_AWAY_ALARM",
    [1302] = "ALM_INH_C1_HOME_ALARM",
    [1303] = "ALM_INH_C2_HOME_ALARM",
    [1304] = "ALM_INH_C3_HOME_ALARM",
    [1305] = "ALM_INH_C4_HOME_ALARM",
    [1306] = "ALM_INH_C5_HOME_ALARM",
    [1307] = "ALM_INH_C6_HOME_ALARM",
    [1308] = "ALM_INH_C1_AWAY_BANDS",
    [1309] = "ALM_INH_C1_HOME_BANDS",
    [1310] = "ALM_INH_C2_AWAY_BANDS",
    [1311] = "ALM_INH_C2_HOME_BANDS",
    [1312] = "ALM_INH_C3_AWAY_BANDS",
    [1313] = "ALM_INH_C3_HOME_BANDS",
    [1314] = "ALM_INH_C4_AWAY_BANDS",
    [1315] = "ALM_INH_C4_HOME_BANDS",
    [1317] = "ALM_INH_C5_HOME_BANDS",
    [1318] = "ALM_INH_C6_AWAY_BANDS",
    [1319] = "ALM_INH_C6_HOME_BANDS",
    [1320] = "SM_AXIS_AWAY_INHIBIT_IN_BANDS",
    [1321] = "SM_AXIS_HOME_INHIBIT_IN_BANDS",
    [1322] = "PROFILE_MODE_JACK",
    [1325] = "SM_AXIS_END_FORCE",
    [1326] = "SM_AXIS_ENDSTOP_TIMEOUT",
    [1330] = "AMY_INH_C1_DOWN_BANDS",
    [1348] = "SCX_CHANNEL_INHIBIT",
    [1351] = "SCX_HOME_DIRECTION",
    [1357] = "SCX_TILT_DEGREES",
    [1360] = "AXIS_DIRECTION_TOGGLE_TIME",
    [1381] = "GYRO_FEATURE",
    [1383] = "CHANGE_PROFILE_WHILST_DRIVING",
    [1385] = "FN_ICON_159",
    [1386] = "FN_ICON_158",
    [1387] = "FN_ICON_161",
    [1388] = "FN_ICON_160",
    [1389] = "FN_ICON_162",
    [1390] = "FN_ICON_24",
    [1391] = "FN_ICON_78",
    [1392] = "FN_ICON_25",
    [1393] = "FN_ICON_102",
    [1395] = "FN_ICON_77",
    [1396] = "FN_ICON_27",
    [1397] = "FN_ICON_80",
    [1398] = "FN_ICON_28",
    [1399] = "FN_ICON_103",
    [1400] = "FN_ICON_26",
    [1401] = "FN_ICON_79",
    [1402] = "FN_ICON_30",
    [1403] = "FN_ICON_82",
    [1405] = "FN_ICON_104",
    [1406] = "FN_ICON_29",
    [1407] = "FN_ICON_81",
    [1408] = "FN_ICON_33",
    [1409] = "FN_ICON_84",
    [1410] = "FN_ICON_34",
    [1411] = "FN_ICON_105",
    [1412] = "FN_ICON_32",
    [1413] = "FN_ICON_83",
    [1414] = "FN_ICON_36",
    [1415] = "FN_ICON_86",
    [1416] = "FN_ICON_37",
    [1417] = "FN_ICON_106",
    [1418] = "FN_ICON_35",
    [1419] = "FN_ICON_85",
    [1420] = "FN_ICON_39",
    [1422] = "FN_ICON_40",
    [1423] = "FN_ICON_107",
    [1424] = "FN_ICON_38",
    [1425] = "FN_ICON_87",
    [1426] = "FN_ICON_42",
    [1427] = "FN_ICON_90",
    [1428] = "FN_ICON_43",
    [1433] = "FN_ICON_92",
    [1435] = "FN_ICON_109",
    [1436] = "FN_ICON_44",
    [1437] = "FN_ICON_91",
    [1438] = "FN_ICON_48",
    [1439] = "FN_ICON_94",
    [1440] = "FN_ICON_49",
    [1441] = "FN_ICON_110",
    [1442] = "FN_ICON_47",
    [1443] = "FN_ICON_93",
    [1444] = "FN_ICON_51",
    [1445] = "FN_ICON_96",
    [1446] = "FN_ICON_52",
    [1783] = "RESERVED_FEATURE_120",
    [1790] = "RESERVED_FEATURE_127",
    [1792] = "RESERVED_FEATURE_129",
    [1793] = "RESERVED_FEATURE_130",
    [1801] = "RESERVED_FEATURE_138",
    [1803] = "RESERVED_FEATURE_140",
    [1804] = "RESERVED_FEATURE_141",
    [1806] = "RESERVED_FEATURE_143",
    [1807] = "RESERVED_FEATURE_144",
    [1808] = "RESERVED_FEATURE_145",
    [1811] = "RESERVED_FEATURE_148",
    [1812] = "RESERVED_FEATURE_149",
    [1813] = "RESERVED_FEATURE_150",
    [1814] = "RESERVED_FEATURE_151",
    [1823] = "ESP_FW_XFD_SLOPE",
    [1824] = "RESERVED_FEATURE_161",
    [1825] = "RESERVED_FEATURE_162",
    [1831] = "RESERVED_FEATURE_168",
    [1833] = "RESERVED_FEATURE_170",
    [1835] = "GYRO_ERROR_SPEED_LIMIT",
    [1836] = "GYRO_ANGULAR_SPEED_SCALER",
    [1837] = "GYRO_RESPONSIVENESS",
    [1841] = "GYRO_PROFILE_SELECT",
    [1843] = "GYRO_ORIENTATION_G",
    [1852] = "RESERVED_FEATURE_189",
    [1854] = "GYRO_FOLDBACK_LEVEL",
    [1856] = "MAXIMUM_HEATSINK_TEMPERATURE",
    [1870] = "SHORT_FORWARD_ACTION",
    [1871] = "SHORT_REVERSE_ACTION",
    [1872] = "SHORT_LEFT_ACTION",
    [1873] = "SHORT_RIGHT_ACTION",
    [1874] = "SHORT_EXT_1_ACTION",
    [1875] = "SHORT_EXT_2_ACTION",
    [1876] = "MID_FORWARD_ACTION",
    [1877] = "MID_REVERSE_ACTION",
    [1878] = "MID_LEFT_ACTION",
    [1879] = "MID_RIGHT_ACTION",
    [1880] = "MID_EXT_1_ACTION",
    [1881] = "MID_EXT_2_ACTION",
    [1882] = "LONG_FORWARD_ACTION",
    [1883] = "LONG_REVERSE_ACTION",
    [1884] = "LONG_LEFT_ACTION",
    [1885] = "LONG_RIGHT_ACTION",
    [1887] = "LONG_EXT_2_ACTION",
    [1891] = "SPEED_DOWN_KEY_ACTION",
    [1904] = "ACTUATOR_SWITCHES_WHILE_DRIVING",
    [1905] = "STARTUP_BEEP",
    [1906] = "EXTERNAL_PROFILE_JACK_DETECT",
    [1907] = "ON_OFF_JACK_DETECT",
    [1908] = "FRONT_WHEEL_DRIVE",
    [1909] = "RESERVED_FEATURE_246",
    [1910] = "ASSIGNABLE_BUTTON_SHORTCUT_1",
    [1911] = "ASSIGNABLE_BUTTON_SHORTCUT_2",
    [1912] = "ASSIGNABLE_BUTTON_SHORTCUT_3",
    [1932] = "HAZARD_LIGHT_OPERATION",
    [1934] = "GYRO_DYNAMIC_GAINS",
    [1935] = "GYRO_LOW_SPEED_PROP_GAIN",
    [1936] = "GYRO_LOW_SPEED_INT_GAIN",
    [1937] = "AMY_INH_C3_UP_BANDS",
    [1941] = "AMY_INH_C1_UP_ALARMS",
    [1942] = "AMY_INH_C2_UP_ALARMS",
    [1943] = "AMY_INH_C3_UP_ALARMS",
    [1944] = "AMY_INH_C4_UP_ALARMS",
    [1945] = "AMY_INH_C5_UP_ALARMS",
    [1947] = "AMY_INH_CH1_DOWN_ASSIGN",
    [1948] = "AMY_INH_CH2_DOWN_ASSIGN",
    [1949] = "AMY_INH_CH3_DOWN_ASSIGN",
    [1950] = "AMY_INH_CH4_DOWN_ASSIGN",
    [1951] = "AMY_INH_CH5_DOWN_ASSIGN",
    [1954] = "AMY_INH_C2_DOWN_BANDS",
    [1955] = "AMY_INH_C3_DOWN_BANDS",
    [1956] = "AMY_INH_C4_DOWN_BANDS",
    [1957] = "AMY_INH_C5_DOWN_BANDS",
    [1960] = "SCX_SUSPENSION_LOCK_FITTED",
    [1962] = "SCX_PRESSURE_RELIEF_PER_HOUR",
    [1963] = "SCX_PRESSURE_RELIEF_DURATION",
    [1964] = "SCX_SUCCESS_PRESSURE_RELEASE_PERIODS",
    [1965] = "SCX_IGNORE_PRESSURE_RELEASE_PERIODS",
    [1966] = "SCX_ADV_JOYSTICK_FITTED",
    [1968] = "SCX_CHANNEL",
    [1972] = "SCX_CHANNEL_START",
    [1975] = "SCX_STOP_DIRECTION",
    [1976] = "SCX_INHIBIT_STYLE",
    [1977] = "SCX_RECLINE_VALUE",
    [1978] = "SCX_RECLINE_DEGREES",
    [2004] = "SPEED_END_ACCEL",
    [2008] = "SPEED_END_RATE_ACCEL",
    [2010] = "SPEED_START_RATE_ACCEL",
    [2034] = "ALLOW_ACTUATOR",
    [2050] = "PG_ID_ONLY",
    [2070] = "SCX_STPCH_FAIL_TIME",
    [2071] = "SCX_STPCH_FAIL_COUNTS",
    [2078] = "SCX_OEM_RESERVED_1",
    [2080] = "SCX_OEM_RESERVED_3",
    [2081] = "SCX_OEM_RESERVED_4",
    [2082] = "SCX_CHANNELS_BY_AXIS",
    [2083] = "SCX_OEM_RESERVED_6",
    [2084] = "SCX_OEM_RESERVED_7",
    [2085] = "SCX_OEM_RESERVED_8",
    [2086] = "SCX_DLR_RESERVED_1",
    [2087] = "SCX_DLR_RESERVED_2",
    [2088] = "SCX_INH_BCK_CREEP",
    [2089] = "SCX_INH_BCK_LOCKOUT",
    [2090] = "SCX_INH_MAX_BCK_ANGLE",
    [2091] = "SCX_INH_LIFT_CREEP_POSITION",
    [2092] = "SCX_INH_FWD_TILT_BACK_EXCLUSION",
    [2094] = "SCX_INH_SUS_LOCK_RECLINE_ANGLE",
    [2095] = "SCX_INH_SUS_LOCK_FWD_TILT_ANGLE",
    [2102] = "BRAKE_LIGHTS",
    [2112] = "PPP_SWBOX2_LAYOUT_LATCHTIMER",
    [2117] = "BRIDGE_CALIBRATION",
    [2128] = "SCX_INH_LIFT_DN_INHIBIT_IN_BANDS",
    [2129] = "SCX_INH_LIFT_DN_ALARM",
    [2135] = "SCX_AB_MOD1_ASS_BTN2_DOWN",
    [2136] = "SCX_AB_MOD1_ASS_BTN3_UP",
    [2137] = "SCX_AB_MOD1_ASS_BTN3_DOWN",
    [2138] = "SCX_AB_MOD1_ASS_BTN4_UP",
    [2139] = "SCX_AB_MOD1_ASS_BTN4_DOWN",
    [2140] = "SCX_AB_MOD1_ASS_BTN5_UP",
    [2141] = "SCX_AB_MOD1_ASS_BTN5_DOWN",
    [2142] = "SCX_AB_MOD2_ASS_BTN1_UP",
    [2146] = "SCX_AB_MOD2_ASS_BTN3_UP",
    [2161] = "BATTERY_VOLTAGE",
    [2162] = "BRIDGE_VOLTAGE",
    [2198] = "HORN_VOLUME",
    [2202] = "DRIVE_WHEEL_MASS",
    [2208] = "GEARBOX_COG_COUNT_1",
    [2209] = "GEARBOX_COG_COUNT_2",
    [2211] = "MOTOR_TORQUE_CONST",
    [2221] = "ARMATURE_INERTIA",
    [2222] = "ARMATURE_DAMPING",
    [2223] = "WHEEL_DAMPING",
    [2224] = "FN_ICON_143",
    [2231] = "FN_ICON_144",
    [2234] = "FN_ICON_154",
    [2236] = "AMY_CHANNEL_INVERT",
    [2237] = "FN_ICON_150",
    [2238] = "SCREEN_BUTTON_ENABLE",
    [2239] = "SCREEN_BUTTON_SECOND_FUNCTION_TIME",
    [2240] = "SCREEN_BUTTON_1_FUNCTION",
    [2241] = "SCREEN_BUTTON_1_TIMED_FUNCTION",
    [2243] = "SCREEN_BUTTON_2_TIMED_FUNCTION",
    [2244] = "SCREEN_BUTTON_3_FUNCTION",
    [2245] = "SCREEN_BUTTON_3_TIMED_FUNCTION",
    [2246] = "SCREEN_BUTTON_4_FUNCTION",
    [2247] = "SCREEN_BUTTON_4_TIMED_FUNCTION",
    [2248] = "FN_ICON_168",
    [2249] = "FN_ICON_169",
    [2254] = "OPERATING_VOLTAGE",
    [2258] = "SURFACE_ADHESION_COEFF_MAX",
    [2294] = "RESERVED_FEATURE_8",
    [2295] = "RESERVED_FEATURE_9",
    [2296] = "RESERVED_FEATURE_10",
    [2297] = "RESERVED_FEATURE_11",
    [2298] = "RESERVED_FEATURE_12",
    [2299] = "RESERVED_FEATURE_13",
    [2300] = "RESERVED_FEATURE_14",
    [2301] = "RESERVED_FEATURE_15",
    [2302] = "RESERVED_FEATURE_16",
    [2303] = "RESERVED_FEATURE_17",
    [2304] = "RESERVED_FEATURE_18",
    [2308] = "RESERVED_FEATURE_22",
    [2309] = "RESERVED_FEATURE_23",
    [2310] = "RESERVED_FEATURE_24",
    [2311] = "RESERVED_FEATURE_25",
    [2312] = "RESERVED_FEATURE_26",
    [2313] = "RESERVED_FEATURE_27",
    [2314] = "RESERVED_FEATURE_28",
    [2315] = "RESERVED_FEATURE_29",
    [2316] = "RESERVED_FEATURE_30",
    [2317] = "RESERVED_FEATURE_31",
    [2318] = "RESERVED_FEATURE_32",
    [2319] = "RESERVED_FEATURE_33",
    [2320] = "RESERVED_FEATURE_34",
    [2321] = "RESERVED_FEATURE_35",
    [2322] = "RESERVED_FEATURE_36",
    [2323] = "RESERVED_FEATURE_37",
    [2324] = "RESERVED_FEATURE_38",
    [2325] = "RESERVED_FEATURE_39",
    [2326] = "RESERVED_FEATURE_40",
    [2327] = "RESERVED_FEATURE_41",
    [2328] = "RESERVED_FEATURE_42",
    [2329] = "RESERVED_FEATURE_43",
    [2330] = "RESERVED_FEATURE_44",
    [2331] = "RESERVED_FEATURE_45",
    [2332] = "RESERVED_FEATURE_46",
    [2333] = "RESERVED_FEATURE_47",
    [2334] = "RESERVED_FEATURE_48",
    [2335] = "RESERVED_FEATURE_49",
    [2336] = "RESERVED_FEATURE_50",
    [2337] = "RESERVED_FEATURE_51",
    [2338] = "RESERVED_FEATURE_52",
    [2339] = "RESERVED_FEATURE_53",
    [2340] = "RESERVED_FEATURE_54",
    [2341] = "RESERVED_FEATURE_55",
    [2342] = "RESERVED_FEATURE_56",
    [2343] = "RESERVED_FEATURE_57",
    [2344] = "RESERVED_FEATURE_58",
    [2345] = "RESERVED_FEATURE_59",
    [2346] = "RESERVED_FEATURE_60",
    [2347] = "RESERVED_FEATURE_61",
    [2356] = "RESERVED_FEATURE_70",
    [2357] = "RESERVED_FEATURE_71",
    [2358] = "RESERVED_FEATURE_72",
    [2359] = "RESERVED_FEATURE_73",
    [2360] = "RESERVED_FEATURE_74",
    [2361] = "RESERVED_FEATURE_75",
    [2362] = "RESERVED_FEATURE_76",
    [2363] = "RESERVED_FEATURE_77",
    [2364] = "RESERVED_FEATURE_78",
    [2365] = "RESERVED_FEATURE_79",
    [2366] = "RESERVED_FEATURE_80",
    [2367] = "RESERVED_FEATURE_81",
    [2368] = "RESERVED_FEATURE_82",
    [2369] = "RESERVED_FEATURE_83",
    [2371] = "RESERVED_FEATURE_85",
    [2373] = "RESERVED_FEATURE_87",
    [2374] = "RESERVED_FEATURE_88",
    [2375] = "RESERVED_FEATURE_89",
    [2376] = "RESERVED_FEATURE_90",
    [2377] = "RESERVED_FEATURE_91",
    [2378] = "RESERVED_FEATURE_92",
    [2379] = "RESERVED_FEATURE_93",
    [2380] = "RESERVED_FEATURE_94",
    [2381] = "RESERVED_FEATURE_95",
    [2382] = "RESERVED_FEATURE_96",
    [2383] = "RESERVED_FEATURE_97",
    [2384] = "RESERVED_FEATURE_98",
    [2385] = "RESERVED_FEATURE_99",
    [2386] = "RESERVED_FEATURE_100",
    [2387] = "RESERVED_FEATURE_101",
    [2388] = "RESERVED_FEATURE_102",
    [2389] = "RESERVED_FEATURE_103",
    [2398] = "RESERVED_FEATURE_112",
    [2399] = "RESERVED_FEATURE_113",
    [2400] = "RESERVED_FEATURE_114",
    [2401] = "RESERVED_FEATURE_115",
    [2402] = "RESERVED_FEATURE_116",
    [2403] = "RESERVED_FEATURE_117",
    [2404] = "RESERVED_FEATURE_118",
    [2405] = "RESERVED_FEATURE_119",
    [2407] = "RESERVED_FEATURE_121",
    [2409] = "RESERVED_FEATURE_123",
    [2410] = "RESERVED_FEATURE_124",
    [2411] = "RESERVED_FEATURE_125",
    [2412] = "RESERVED_FEATURE_126",
    [2417] = "RESERVED_FEATURE_131",
    [2418] = "RESERVED_FEATURE_132",
    [2419] = "RESERVED_FEATURE_133",
    [2420] = "RESERVED_FEATURE_134",
    [2421] = "RESERVED_FEATURE_135",
    [2422] = "RESERVED_FEATURE_136",
    [2423] = "RESERVED_FEATURE_137",
    [2425] = "RESERVED_FEATURE_139",
    [2439] = "RESERVED_FEATURE_153",
    [2440] = "RESERVED_FEATURE_154",
    [2441] = "RESERVED_FEATURE_155",
    [2442] = "RESERVED_FEATURE_156",
    [2443] = "RESERVED_FEATURE_157",
    [2444] = "RESERVED_FEATURE_158",
    [2446] = "RESERVED_FEATURE_160",
    [2449] = "RESERVED_FEATURE_163",
    [2450] = "RESERVED_FEATURE_164",
    [2451] = "RESERVED_FEATURE_165",
    [2452] = "RESERVED_FEATURE_166",
    [2453] = "RESERVED_FEATURE_167",
    [2455] = "RESERVED_FEATURE_169",
    [2457] = "RESERVED_FEATURE_171",
    [2458] = "RESERVED_FEATURE_172",
    [2459] = "RESERVED_FEATURE_173",
    [2460] = "RESERVED_FEATURE_174",
    [2461] = "RESERVED_FEATURE_175",
    [2462] = "RESERVED_FEATURE_176",
    [2463] = "RESERVED_FEATURE_177",
    [2464] = "RESERVED_FEATURE_178",
    [2465] = "RESERVED_FEATURE_179",
    [2466] = "RESERVED_FEATURE_180",
    [2467] = "RESERVED_FEATURE_181",
    [2468] = "RESERVED_FEATURE_182",
    [2469] = "RESERVED_FEATURE_183",
    [2470] = "RESERVED_FEATURE_184",
    [2471] = "RESERVED_FEATURE_185",
    [2472] = "RESERVED_FEATURE_186",
    [2473] = "RESERVED_FEATURE_187",
    [2474] = "RESERVED_FEATURE_188",
    [2477] = "RESERVED_FEATURE_191",
    [2478] = "RESERVED_FEATURE_192",
    [2479] = "RESERVED_FEATURE_193",
    [2480] = "RESERVED_FEATURE_194",
    [2481] = "RESERVED_FEATURE_195",
    [2482] = "RESERVED_FEATURE_196",
    [2483] = "RESERVED_FEATURE_197",
    [2484] = "RESERVED_FEATURE_198",
    [2485] = "RESERVED_FEATURE_199",
    [2486] = "RESERVED_FEATURE_200",
    [2487] = "RESERVED_FEATURE_201",
    [2488] = "RESERVED_FEATURE_202",
    [2489] = "RESERVED_FEATURE_203",
    [2490] = "RESERVED_FEATURE_204",
    [2491] = "RESERVED_FEATURE_205",
    [2492] = "RESERVED_FEATURE_206",
    [2493] = "RESERVED_FEATURE_207",
    [2494] = "RESERVED_FEATURE_208",
    [2495] = "RESERVED_FEATURE_209",
    [2496] = "RESERVED_FEATURE_210",
    [2497] = "RESERVED_FEATURE_211",
    [2498] = "RESERVED_FEATURE_212",
    [2499] = "RESERVED_FEATURE_213",
    [2500] = "RESERVED_FEATURE_214",
    [2501] = "RESERVED_FEATURE_215",
    [2502] = "RESERVED_FEATURE_216",
    [2503] = "RESERVED_FEATURE_217",
    [2504] = "RESERVED_FEATURE_218",
    [2505] = "RESERVED_FEATURE_219",
    [2506] = "RESERVED_FEATURE_220",
    [2507] = "RESERVED_FEATURE_221",
    [2508] = "RESERVED_FEATURE_222",
    [2509] = "RESERVED_FEATURE_223",
    [2510] = "RESERVED_FEATURE_224",
    [2511] = "RESERVED_FEATURE_225",
    [2512] = "RESERVED_FEATURE_226",
    [2513] = "RESERVED_FEATURE_227",
    [2514] = "RESERVED_FEATURE_228",
    [2515] = "RESERVED_FEATURE_229",
    [2516] = "RESERVED_FEATURE_230",
    [2517] = "RESERVED_FEATURE_231",
    [2518] = "RESERVED_FEATURE_232",
    [2519] = "RESERVED_FEATURE_233",
    [2520] = "RESERVED_FEATURE_234",
    [2521] = "RESERVED_FEATURE_235",
    [2522] = "RESERVED_FEATURE_236",
    [2523] = "RESERVED_FEATURE_237",
    [2524] = "RESERVED_FEATURE_238",
    [2525] = "RESERVED_FEATURE_239",
    [2526] = "RESERVED_FEATURE_240",
    [2527] = "RESERVED_FEATURE_241",
    [2528] = "RESERVED_FEATURE_242",
    [2529] = "RESERVED_FEATURE_243",
    [2530] = "RESERVED_FEATURE_244",
    [2533] = "RESERVED_FEATURE_247",
    [2534] = "RESERVED_FEATURE_248",
    [2535] = "RESERVED_FEATURE_249",
    [2536] = "RESERVED_FEATURE_250",
    [2541] = "OMNI_ISO_POWER_JACK_DETECT",
    [2551] = "PPP_JSM_LATCH_TIME",
    [2553] = "AMY_INH_CH2_UP_ASSIGN",
    [2554] = "AMY_INH_CH3_UP_ASSIGN",
    [2557] = "AMY_INH_CH6_UP_ASSIGN",
    [2558] = "AMY_INH_C1_UP_BANDS",
    [2559] = "AMY_INH_C2_UP_BANDS",
    [2561] = "AMY_INH_C4_UP_BANDS",
    [2562] = "AMY_INH_C5_UP_BANDS",
    [2563] = "AMY_INH_C6_UP_BANDS",
    [2581] = "AMY_INH_C6_DOWN_BANDS",
    [2582] = "AMY_INH_C1_DOWN_ALARMS",
    [2583] = "AMY_INH_C2_DOWN_ALARMS",
    [2584] = "AMY_INH_C3_DOWN_ALARMS",
    [2585] = "AMY_INH_C4_DOWN_ALARMS",
    [2586] = "AMY_INH_C5_DOWN_ALARMS",
    [2587] = "AMY_INH_C6_DOWN_ALARMS",
    [2588] = "COMPENSATION_FACTOR",
    [2589] = "EXT_SHORTCUT_KEY_1_TIMED_FUNCTION",
    [2590] = "EXT_SHORTCUT_KEY_2_FUNCTION",
    [2612] = "DATA_LOG_DP1_DATA_RESOLUTION_4",
    [2626] = "ACTUATOR_AXIS_1",
    [2632] = "DATA_LOG_DP1_DATA_RESOLUTION_14",
    [2635] = "SLEEP_12V",
    [2636] = "MODE_CHANGE",
    [2637] = "MODES_MENU_ENTRY",
    [2638] = "PROFILE_CHANGE",
    [2639] = "PROFILE_IDENTIFIER",
    [2640] = "AXIS_IDENTIFIER",
    [2726] = "PPP_SWBOX1_LAYOUT_SPEED",
    [2729] = "PPP_SWBOX1_LAYOUT_LATCHTIMER",
    [2732] = "PPP_SWBOX2_LAYOUT_SPEED",
    [2738] = "PPP_SWBOX3_LAYOUT_SPEED",
    [2744] = "PPP_SWBOX4_LAYOUT_SPEED",
    [2747] = "PPP_SWBOX4_LAYOUT_LATCHTIMER",
    [2748] = "PPP_PLGN1_USER_WEIGHT",
    [2749] = "PPP_PLGN1_SEAT_DEPTH",
    [2750] = "PUFF_FSD",
    [2751] = "PPP_PLGN1_ART_LEG_START",
    [2752] = "PPP_PLGN1_ART_LEG_STOP",
    [2753] = "PPP_PLGN1_ART_LEG_COMPATSTOP",
    [2754] = "PPP_PLGN1_ART_LEG_STAND_START",
    [2755] = "PPP_PLGN1_ART_LEG_STAND_STOP",
    [2756] = "PPP_PLGN1_ART_LEG_STAND_COMPATSTOP",
    [2757] = "PPP_PLGN1_MIN_LEG_LENGTH",
    [2758] = "PPP_PLGN1_GROUND_TOUCH_ADJUST",
    [2759] = "PPP_PLGN1_GROUND_TOUCH_CLEARANCE",
    [2760] = "PPP_PLGN1_INHIBIT_TILT_NEG",
    [2761] = "PPP_PLGN1_INHIBIT_LEGS_NEG",
    [2762] = "PPP_PLGN1_PAUSE_POS_TILT",
    [2763] = "PPP_PLGN1_PAUSE_POS_LEGS",
    [2764] = "PPP_PLGN1_STAND_CP0SIT_BACK",
    [2765] = "PPP_PLGN1_STAND_CP0SIT_LEGS",
    [2766] = "PPP_PLGN1_STAND_CP1UP_BACK",
    [2767] = "PPP_PLGN1_STAND_CP1UP_LEGS",
    [2768] = "PPP_PLGN1_STAND_CP1DOWN_BACK",
    [2769] = "PPP_PLGN1_STAND_CP1DOWN_LEGS",
    [2770] = "PPP_PLGN1_STAND_CP2STAND_BACK",
    [2771] = "PPP_PLGN1_STAND_CP2STAND_TILT",
    [2772] = "PPP_PLGN1_STAND_CP2STAND_LEGS",
    [2773] = "ESP_MAX_REV_SPEED",
    [2774] = "ESP_MIN_REV_SPEED",
    [2775] = "ESP_MAX_TURN_SPEED",
    [2776] = "ESP_MIN_TURN_SPEED",
    [2777] = "ESP_MAX_FWD_ACC",
    [2778] = "ESP_MIN_FWD_ACC",
    [2779] = "ESP_MAX_FWD_DEC",
    [2780] = "FN_ICON_31",
    [2781] = "ESP_MIN_FWD_DEC",
    [2783] = "PPP_PLGN1_AXISRANGE_LIMIT_LIFT_MAX",
    [2784] = "PPP_PLGN1_AXISRANGE_LIMIT_BACK_MIN",
    [2786] = "PPP_PLGN1_AXISRANGE_LIMIT_TILT_MIN",
    [2787] = "PPP_PLGN1_AXISRANGE_LIMIT_TILT_MAX",
    [2788] = "PPP_PLGN1_AXISRANGE_LIMIT_LEGS_MIN",
    [2789] = "PPP_PLGN1_AXISRANGE_LIMIT_LEGS_MAX",
    [2790] = "PPP_PLGN1_AXISRANGE_LIMIT_ARTLEGS_MIN",
    [2791] = "PPP_PLGN1_AXISRANGE_LIMIT_ARTLEGS_MAX",
    [2792] = "PPP_PLGN1_AXISRANGE_LIMIT_OEM_LIFT_MIN",
    [2793] = "PPP_PLGN1_AXISRANGE_LIMIT_OEM_LIFT_MAX",
    [2794] = "PPP_PLGN1_AXISRANGE_LIMIT_OEM_BACK_MIN",
    [2795] = "PPP_PLGN1_AXISRANGE_LIMIT_OEM_BACK_MAX",
    [2796] = "PPP_PLGN1_AXISRANGE_LIMIT_OEM_TILT_MIN",
    [2797] = "PPP_PLGN1_AXISRANGE_LIMIT_OEM_TILT_MAX",
    [2798] = "PPP_PLGN1_AXISRANGE_LIMIT_OEM_LEGS_MIN",
    [2799] = "PPP_PLGN1_AXISRANGE_LIMIT_OEM_LEGS_MAX",
    [2800] = "PPP_PLGN1_AXISRANGE_LIMIT_OEM_ARTLEGS_MIN",
    [2801] = "PPP_PLGN1_AXISRANGE_LIMIT_OEM_ARTLEGS_MAX",
    [2802] = "PPP_PLGN1_DRVSPEED_LIMIT_LIFT_LOW",
    [2803] = "PPP_PLGN1_DRVSPEED_LIMIT_LIFT_XLOW",
    [2804] = "PPP_PLGN1_DRVSPEED_LIMIT_LIFT_INHIBIT",
    [2805] = "PPP_PLGN1_DRVSPEED_LIMIT_BACK_LOW",
    [2806] = "PPP_PLGN1_DRVSPEED_LIMIT_BACK_XLOW",
    [2807] = "PPP_PLGN1_DRVSPEED_LIMIT_BACK_INHIBIT",
    [2808] = "PPP_PLGN1_DRVSPEED_LIMIT_TILT_LOW",
    [2810] = "PPP_PLGN1_DRVSPEED_LIMIT_TILT_INHIBIT",
    [2811] = "PPP_PLGN1_DRVSPEED_LIMIT_LEGS_LOW",
    [2812] = "PPP_PLGN1_DRVSPEED_LIMIT_LEGS_XLOW",
    [2813] = "PPP_PLGN1_DRVSPEED_LIMIT_LEGS_INHIBIT",
    [2814] = "PPP_PLGN1_DRVSPEED_LIMIT_OEM_LIFT_LOW",
    [2815] = "PPP_PLGN1_DRVSPEED_LIMIT_OEM_LIFT_XLOW",
    [2816] = "PPP_PLGN1_DRVSPEED_LIMIT_OEM_LIFT_INHIBIT",
    [2817] = "PPP_PLGN1_DRVSPEED_LIMIT_OEM_BACK_LOW",
    [2818] = "PPP_PLGN1_DRVSPEED_LIMIT_OEM_BACK_XLOW",
    [2819] = "PPP_PLGN1_DRVSPEED_LIMIT_OEM_BACK_INHIBIT",
    [2820] = "PPP_PLGN1_DRVSPEED_LIMIT_OEM_TILT_LOW",
    [2822] = "PPP_PLGN1_DRVSPEED_LIMIT_OEM_TILT_INHIBIT",
    [2823] = "PPP_PLGN1_DRVSPEED_LIMIT_OEM_LEGS_LOW",
    [2825] = "PPP_PLGN1_DRVSPEED_LIMIT_OEM_LEGS_INHIBIT",
    [2998] = "DISABLE_INHIBIT_3_IN_DRIVE_PROTO",
    [3004] = "FN_ICON_69",
    [3018] = "SCAN_FREEZE",
    [3022] = "INDICATOR_FAULT_CURRENT_2",
    [3023] = "INDICATOR_FAULT_CURRENT_3",
    [3024] = "INDICATOR_FAULT_CURRENT_4",
    [3025] = "INDICATOR_FAULT_CURRENT_5",
    [3035] = "LOCK_METHODS",
    [3039] = "CURRENT_THRESHOLD",
    [3040] = "CURRENT_TIME",
    [3041] = "STEERING_LUT_0",
    [3042] = "STEERING_LUT_1",
    [3043] = "STEERING_LUT_2",
    [3044] = "STEERING_LUT_3",
    [3045] = "STEERING_LUT_4",
    [3046] = "STEERING_LUT_5",
    [3047] = "STEERING_LUT_6",
    [3048] = "STEERING_LUT_7",
    [3049] = "STEERING_LUT_8",
    [3050] = "STEERING_LUT_9",
    [3052] = "STEERING_LUT_11",
    [3053] = "STEERING_LUT_12",
    [3054] = "STEERING_LUT_13",
    [3055] = "STEERING_LUT_14",
    [3056] = "STEERING_LUT_15",
    [3057] = "STEERING_LUT_16",
    [3058] = "STEERING_LUT_17",
    [3061] = "STEERING_LUT_20",
    [3062] = "STEERING_POT_LIMIT_LOW",
    [3074] = "GYRO_FWD_SPEED",
    [3075] = "GYRO_FWD_ACCEL",
    [3077] = "GYRO_REV_SPEED",
    [3078] = "GYRO_REV_ACCEL",
    [3079] = "GYRO_REV_DECEL",
    [3080] = "GYRO_TURN_SPEED",
    [3081] = "GYRO_TURN_ACCEL",
    [3083] = "GYRO_FAST_BRAKE_RATE",
    [3093] = "CXSM_INH_C1_UP_ACTIVE_IN_AXIS",
    [3094] = "CXSM_INH_C2_UP_ACTIVE_IN_AXIS",
    [3095] = "CXSM_INH_C3_UP_ACTIVE_IN_AXIS",
    [3096] = "CXSM_INH_C4_UP_ACTIVE_IN_AXIS",
    [3098] = "CXSM_INH_C6_UP_ACTIVE_IN_AXIS",
    [3099] = "CXSM_INH_C7_UP_ACTIVE_IN_AXIS",
    [3100] = "CXSM_INH_C8_UP_ACTIVE_IN_AXIS",
    [3101] = "RESERVED_FEATURE_62",
    [3102] = "RESERVED_FEATURE_63",
    [3104] = "RESERVED_FEATURE_65",
    [3105] = "RESERVED_FEATURE_66",
    [3106] = "RESERVED_FEATURE_67",
    [3107] = "RESERVED_FEATURE_68",
    [3108] = "RESERVED_FEATURE_69",
    [3109] = "CXSM_INH_C1_DOWN_ACTIVE_IN_AXIS",
    [3111] = "CXSM_INH_C3_DOWN_ACTIVE_IN_AXIS",
    [3112] = "CXSM_INH_C4_DOWN_ACTIVE_IN_AXIS",
    [3113] = "CXSM_INH_C5_DOWN_ACTIVE_IN_AXIS",
    [3114] = "CXSM_INH_C6_DOWN_ACTIVE_IN_AXIS",
    [3115] = "CXSM_INH_C7_DOWN_ACTIVE_IN_AXIS",
    [3116] = "CXSM_INH_C8_DOWN_ACTIVE_IN_AXIS",
    [3118] = "EXTERNAL_PROFILE_JACK_FUNCTION_MEYRA",
    [3121] = "ACTSNGPM_END_STOP_AUTO_DETECT",
    [3123] = "ACTSNGPM_INHIBIT_INPUT_DEBOUNCE",
    [3124] = "ACTSNGPM_INHIBIT_INPUT_LOW_TH",
    [3125] = "ACTSNGPM_INHIBIT_INPUT_MID_TH",
    [3126] = "ACTSNGPM_INHIBIT_INPUT_HI_TH",
    [3128] = "ACCELEROMETER_MIN_ACCEL_THRESHOLD",
    [3131] = "ACCELEROMETER_ANTI_SPIN",
    [3134] = "ACTSNGPM_INH_C1_UP_ASSIGN",
    [3135] = "ACTSNGPM_INH_C1_UP_BANDS",
    [3136] = "ACTSNGPM_INH_C1_UP_ALARM",
    [3137] = "ACTSNGPM_INH_C1_DN_ASSIGN",
    [3138] = "ACTSNGPM_INH_C1_DN_BANDS",
    [3139] = "ACTSNGPM_INH_C1_DN_ALARM",
    [3140] = "ACTSNGPM_INH_C2_UP_ASSIGN",
    [3141] = "ACTSNGPM_INH_C2_UP_BANDS",
    [3142] = "ACTSNGPM_INH_C2_UP_ALARM",
    [3143] = "ACTSNGPM_INH_C2_DN_ASSIGN",
    [3144] = "ACTSNGPM_INH_C2_DN_BANDS",
    [3145] = "ACTSNGPM_INH_C2_DN_ALARM",
    [3146] = "ACTSNGPM_INH_C3_UP_ASSIGN",
    [3147] = "ACTSNGPM_INH_C3_UP_BANDS",
    [3148] = "ACTSNGPM_INH_C3_UP_ALARM",
    [3149] = "ACTSNGPM_INH_C3_DN_ASSIGN",
    [3150] = "ACTSNGPM_INH_C3_DN_BANDS",
    [3151] = "ACTSNGPM_INH_C3_DN_ALARM",
    [3152] = "ACTSNGPM_INH_C4_UP_ASSIGN",
    [3153] = "ACTSNGPM_INH_C4_UP_BANDS",
    [3154] = "ACTSNGPM_INH_C4_UP_ALARM",
    [3155] = "ACTSNGPM_INH_C4_DN_ASSIGN",
    [3156] = "ACTSNGPM_INH_C4_DN_BANDS",
    [3157] = "ACTSNGPM_INH_C4_DN_ALARM",
    [3158] = "ACTSNGPM_INH_C5_UP_ASSIGN",
    [3159] = "ACTSNGPM_INH_C5_UP_BANDS",
    [3160] = "ACTSNGPM_INH_C5_UP_ALARM",
    [3162] = "ACTSNGPM_INH_C5_DN_BANDS",
    [3163] = "ACTSNGPM_INH_C5_DN_ALARM",
    [3165] = "ACTSNGPM_INH_C6_UP_BANDS",
    [3380] = "LIGHTS_RATED_VOLTAGE",
    [3384] = "INDICATOR_RATED_VOLTAGE",
    [3385] = "BRAKE_LIGHT_RATED_VOLTAGE",
    [3386] = "LIGHTS_WATTAGE",
    [3387] = "INDICATOR_WATTAGE",
    [3388] = "BRAKE_LIGHT_WATTAGE",
    [3391] = "INDICATOR_TIMEOUT",
    [3412] = "ICS_MIN_TILT_ANGLE",
    [3413] = "ICS_MAX_TILT_ANGLE",
    [3414] = "ICS_MIN_BACK_ANGLE",
    [3415] = "ICS_MAX_BACK_ANGLE",
    [3416] = "ICS_MIN_LEG_ANGLE",
    [3417] = "ICS_MAX_LEG_ANGLE",
    [3418] = "ICS_MIN_ELEV_TRAVEL",
    [3419] = "ICS_MAX_ELEV_TRAVEL",
    [3420] = "ICS_TILT_LOW_SP_ANGLE",
    [3421] = "ICS_TILT_DRV_INHIBIT_ANGLE",
    [3422] = "ICS_BACK_LOW_SPD_ANGLE",
    [3423] = "ICS_BACK_DRV_INHIBIT_ANGLE",
    [3424] = "ICS_LEG_LOW_SPD_ANGLE",
    [3425] = "ICS_LEG_DRV_INHIBIT_ANGLE",
    [3426] = "ICS_ELEVATOR_LOW_SPD_HEIGHT",
    [3441] = "ICS_ABS_MIN_TILT_ANGLE",
    [3442] = "ICS_ABS_MAX_TILT_ANGLE",
    [3443] = "OBP_ENTRY",
    [3451] = "ICS_ABS_MIN_TILT_DRV_INHIBIT_ANGLE",
    [3454] = "ICS_ABS_MAX_BACK_LOW_SPD_ANGLE",
    [3455] = "ICS_ABS_MIN_BACK_DRV_INHIBIT_ANGLE",
    [3456] = "ICS_ABS_MAX_BACK_DRV_INHIBIT_ANGLE",
    [3457] = "ICS_ABS_MIN_LEG_LOW_SPD_ANGLE",
    [3458] = "ICS_ABS_MAX_LEG_LOW_SPD_ANGLE",
    [3459] = "ICS_ABS_MIN_LEG_DRV_INHIBIT_ANGLE",
    [3460] = "ICS_ABS_MAX_LEG_DRV_INHIBIT_ANGLE",
    [3461] = "ICS_ABS_MIN_ELEV_LOW_SPEED",
    [3462] = "ICS_ABS_MAX_ELEV_LOW_SPEED",
    [3463] = "DATA_LOG_DP2_DATA_RESOLUTION_1",
    [3464] = "DATA_LOG_DP2_DATA_OBJECT_2",
    [3465] = "DATA_LOG_DP2_DATA_RESOLUTION_2",
    [3466] = "FWD_STABILITY_COMPENSATION_RATIO",
    [3467] = "DATA_LOG_DP2_DATA_RESOLUTION_3",
    [3468] = "TURN_TRACTION",
    [3469] = "DATA_LOG_DP2_DATA_RESOLUTION_4",
    [3470] = "DISABLE_INHIBIT_3_IN_DRIVE",
    [3471] = "DATA_LOG_DP2_DATA_RESOLUTION_5",
    [3472] = "SERVO_HOME_ACCELERATION",
    [3473] = "DATA_LOG_DP2_DATA_RESOLUTION_6",
    [3474] = "SCX_INH_VIRTUAL_INH_ASSIGN",
    [3475] = "DATA_LOG_DP2_DATA_RESOLUTION_7",
    [3477] = "DATA_LOG_DP2_DATA_RESOLUTION_8",
    [3479] = "DATA_LOG_DP2_DATA_RESOLUTION_9",
    [3481] = "DATA_LOG_DP2_DATA_RESOLUTION_10",
    [3483] = "DATA_LOG_DP2_DATA_RESOLUTION_11",
    [3485] = "DATA_LOG_DP2_DATA_RESOLUTION_12",
    [3487] = "DATA_LOG_DP2_DATA_RESOLUTION_13",
    [3489] = "DATA_LOG_DP2_DATA_RESOLUTION_14",
    [3491] = "DATA_LOG_DP2_DATA_RESOLUTION_15",
    [3493] = "DATA_LOG_DP2_DATA_RESOLUTION_16",
    [3498] = "SCX_INH_LIFT_UP_INHIBIT_IN_BANDS",
    [3499] = "SCX_INH_LIFT_UP_ALARM",
    [3511] = "CXSM_END_STOP_AUTO_DETECT",
    [3513] = "CXSM_INH_C1_UP_ASSIGN",
    [3514] = "CXSM_INH_C2_UP_ASSIGN",
    [3515] = "CXSM_INH_C3_UP_ASSIGN",
    [3516] = "CXSM_INH_C4_UP_ASSIGN",
    [3517] = "CXSM_INH_C5_UP_ASSIGN",
    [3518] = "TRACK_PROGRAMMING_CHANGES",
    [3519] = "PREVENT_PROGRAMMING_MEMORY_FULL",
    [3520] = "ALERT_1_NAME",
    [3521] = "ALERT_1_SYSTEM_PROPERTY",
    [3522] = "ALERT_1_THRESHOLD",
    [3523] = "ALERT_1_ORIENTATION",
    [3524] = "ALERT_1_PRIORITY",
    [3525] = "CXSM_INH_C1_UP_ALARM",
    [3526] = "CXSM_INH_C2_UP_ALARM",
    [3527] = "CXSM_INH_C3_UP_ALARM",
    [3528] = "CXSM_INH_C4_UP_ALARM",
    [3529] = "CXSM_INH_C5_UP_ALARM",
    [3530] = "CXSM_INH_C6_UP_ALARM",
    [3531] = "ALERT_2_NAME",
    [3532] = "ALERT_2_SYSTEM_PROPERTY",
    [3533] = "ALERT_2_THRESHOLD",
    [3534] = "ALERT_2_ORIENTATION",
    [3535] = "ALERT_2_PRIORITY",
    [3536] = "ALERT_3_NAME",
    [3537] = "ALERT_3_SYSTEM_PROPERTY",
    [3538] = "ALERT_3_THRESHOLD",
    [3539] = "ALERT_3_ORIENTATION",
    [3540] = "ALERT_3_PRIORITY",
    [3541] = "ALERT_4_NAME",
    [3542] = "ALERT_4_SYSTEM_PROPERTY",
    [3543] = "ALERT_4_THRESHOLD",
    [3544] = "ALERT_4_ORIENTATION",
    [3545] = "ALERT_4_PRIORITY",
    [3546] = "ALERT_5_NAME",
    [3547] = "ALERT_5_SYSTEM_PROPERTY",
    [3548] = "ALERT_5_THRESHOLD",
    [3549] = "ALERT_5_ORIENTATION",
    [3550] = "ALERT_5_PRIORITY",
    [3551] = "ALERT_6_NAME",
    [3552] = "ALERT_6_SYSTEM_PROPERTY",
    [3553] = "ALERT_6_THRESHOLD",
    [3554] = "ALERT_6_ORIENTATION",
    [4302] = "SCX_AB_MOD2_ASS_BTN3_DOWN_WP",
    [4303] = "SCX_AB_MOD2_ASS_BTN4_UP_WP",
    [4304] = "SCX_AB_MOD2_ASS_BTN4_DOWN_WP",
    [4305] = "SCX_AB_MOD2_ASS_BTN5_UP_WP",
    [4306] = "SCX_AB_MOD2_ASS_BTN5_DOWN_WP",
    [4307] = "FN_ICON_21",
    [4308] = "ALERT_6_PRIORITY",
    [4312] = "ALM_INH_C1_UP_ASSIGN",
    [4314] = "ALM_INH_C1_DN_ALARM",
    [4318] = "ALM_INH_C1_DN_ASSIGN",
    [4319] = "ALM_INH_C2_UP_ASSIGN",
    [4320] = "ALERT_9_SYSTEM_PROPERTY",
    [4322] = "ALERT_9_ORIENTATION",
    [4324] = "ALM_INH_C2_UP_ALARM",
    [4327] = "ACT_ADJUST_WHILE_DRIVING",
    [4328] = "TOGGLE_SW_MODE_AND_PROFILE",
    [4332] = "PROFILE_BUTTON",
    [4342] = "ALM_INH_C2_DN_ASSIGN",
    [4347] = "ALM_INH_C2_DN_ALARM",
    [4348] = "ALM_INH_C3_UP_ASSIGN",
    [4353] = "ALM_INH_C3_UP_ALARM",
    [4354] = "ALM_INH_C3_DN_ASSIGN",
    [4359] = "ALM_INH_C3_DN_ALARM",
    [4360] = "ALM_INH_C4_UP_ASSIGN",
    [4365] = "ALM_INH_C4_UP_ALARM",
    [4366] = "ALM_INH_C4_DN_ASSIGN",
    [4371] = "ALM_INH_C4_DN_ALARM",
    [4372] = "ALM_INH_C5_UP_ASSIGN",
    [4373] = "DISABLE_INHIBIT_2_IN_DRIVE_PROTO",
    [4374] = "IDV2_SHORT_FORWARD_ACTION",
    [4375] = "IDV2_SHORT_REVERSE_ACTION",
    [4376] = "IDV2_SHORT_LEFT_ACTION",
    [4377] = "ALM_INH_C5_UP_ALARM",
    [4378] = "ALM_INH_C5_DN_ASSIGN",
    [4379] = "IDV2_SHORT_EXT_2_ACTION",
    [4380] = "IDV2_MID_FORWARD_ACTION",
    [4381] = "IDV2_MID_REVERSE_ACTION",
    [4382] = "IDV2_MID_LEFT_ACTION",
    [4383] = "ALM_INH_C5_DN_ALARM",
    [4384] = "ALM_INH_C6_UP_ASSIGN",
    [4385] = "IDV2_MID_EXT_2_ACTION",
    [4386] = "IDV2_LONG_FORWARD_ACTION",
    [4387] = "IDV2_LONG_REVERSE_ACTION",
    [4388] = "IDV2_LONG_LEFT_ACTION",
    [4389] = "ALM_INH_C6_UP_ALARM",
    [4390] = "ALM_INH_C6_DN_ASSIGN",
    [4391] = "IDV2_LONG_EXT_2_ACTION",
    [4394] = "IDV2_SPEED_UP_ACTION",
    [4395] = "ALM_INH_C6_DN_ALARM",
    [4396] = "INDICATOR_FAULT_CURRENT_1",
    [4431] = "MOMENTARY_SCREENS_ENABLED",
    [4432] = "SPEED_SWITCH_ON_RIGHT",
    [4433] = "INVERT_PROFILE_SWITCH",
    [4434] = "INVERT_SPEED_SWITCH",
    [4435] = "PROFILE_SWITCH_WRAP",
    [4436] = "SPEED_SWITCH_WRAP",
    [4437] = "PROFILE_SWITCH_FINE_TUNE",
    [4438] = "SPEED_SWITCH_FINE_TUNE",
    [4439] = "PROFILE_SWITCH_SWIPE_TIME",
    [4440] = "SPEED_SWITCH_SWIPE_TIME",
    [4441] = "PROFILE_SWITCH_END_GAP",
    [4442] = "SPEED_SWITCH_END_GAP",
    [4444] = "ALM_INH_C1_UP_BANDS",
    [4445] = "ALM_INH_C1_DN_BANDS",
    [4446] = "ALM_INH_C2_UP_BANDS",
    [4447] = "ALM_INH_C2_DN_BANDS",
    [4448] = "ALM_INH_C3_UP_BANDS",
    [4449] = "ALM_INH_C3_DN_BANDS",
    [4450] = "ALM_INH_C4_UP_BANDS",
    [4451] = "ALM_INH_C4_DN_BANDS",
    [4452] = "ALM_INH_C5_UP_BANDS",
    [4453] = "ALM_INH_C5_DN_BANDS",
    [4454] = "ALM_INH_C6_UP_BANDS",
    [4455] = "ALM_INH_C6_DN_BANDS",
    [4456] = "AIM_RED_CONN_IP1_TYPE",
    [4457] = "AIM_RED_CONN_IP1_FUNCTION",
    [4458] = "AIM_RED_CONN_IP2_TYPE",
    [4460] = "SPIN_END_ACCEL",
    [4463] = "SPIN_END_RATE_ACCEL",
    [4465] = "SCX_SOUND_MUTE_INHIBIT_ASSIGN",
    [4466] = "SCX_CHAN_MIN_SPEED",
    [4468] = "SCX_STANDER_LIFT_DOWN_MIN",
    [4586] = "EXT_ASSIGNABLE_BUTTON_USER",
    [4590] = "EXT_SHORTCUT_KEY_2_TIMED_FUNCTION",
    [4591] = "EXT_SHORTCUT_KEY_3_FUNCTION",
    [4592] = "EXT_SHORTCUT_KEY_3_TIMED_FUNCTION",
    [4593] = "EXT_SHORTCUT_KEY_4_FUNCTION",
    [4594] = "EXT_SHORTCUT_KEY_4_TIMED_FUNCTION",
    [4599] = "BACKLASH_THRESHOLD",
    [4602] = "DATA_LOG_DP1_DATA_RESOLUTION_1",
    [4612] = "INPUT_TYPE",
    [4613] = "OUTPUT_SWITCHING",
    [4614] = "HORN_OPERATION",
    [4619] = "OMNI_PORT",
    [4621] = "FWD_REV_AUTO_TOGGLE",
    [4622] = "9_WAY_DETECT",
    [4623] = "USER_CONTROL",
    [4624] = "ACTUATOR_SELECTION",
    [4626] = "USER_SWITCH",
    [4627] = "SWITCH_DETECT",
    [4628] = "SWITCH_DEBOUNCE",
    [4629] = "SWITCH_LONG",
    [4630] = "DOUBLE_CLICK",
    [4640] = "POSITION_1",
    [4642] = "POSITION_2",
    [4643] = "HMC_CJA_OUTPUTS_GROUP_2_DRIVE_AXIS",
    [4644] = "POSITION_3",
    [4645] = "HMC_CJA_OUTPUTS_GROUP_4_DRIVE_AXIS",
    [4646] = "POSITION_4",
    [4647] = "POSITION_5",
    [4648] = "POSITION_6",
    [4649] = "POSITION_7",
    [4650] = "POSITION_8",
    [4651] = "POSITION_9",
    [4652] = "POSITION_10",
    [4653] = "POSITION_11",
    [4654] = "POSITION_12",
    [4655] = "POSITION_13",
    [4656] = "POSITION_14",
    [4657] = "POSITION_15",
    [4658] = "ALM_INH_C3_HOME_ASSIGN",
    [4659] = "POSITION_16",
    [4660] = "RETURN_TO",
    [4661] = "TIMEOUT_TO_MENU",
    [4662] = "AUTO_REPEAT",
    [4663] = "POSITION_1_BEEP",
    [4664] = "POSITION_2_BEEP",
    [4665] = "POSITION_3_BEEP",
    [4666] = "POSITION_4_BEEP",
    [4667] = "POSITION_5_BEEP",
    [4668] = "POSITION_6_BEEP",
    [4669] = "POSITION_7_BEEP",
    [4670] = "SM_AXIS_HOME_ASSIGN",
    [4671] = "POSITION_8_BEEP",
    [4672] = "POSITION_9_BEEP",
    [4673] = "POSITION_10_BEEP",
    [4674] = "POSITION_11_BEEP",
    [4675] = "POSITION_12_BEEP",
    [4676] = "POSITION_13_BEEP",
    [4677] = "POSITION_14_BEEP",
    [4678] = "POSITION_15_BEEP",
    [4679] = "POSITION_16_BEEP",
    [4691] = "ALM_INH_C5_AWAY_BANDS",
    [4692] = "APP_MANUFACTURER_1",
    [4693] = "POSITION_1_TYPE",
    [4694] = "POSITION_2_TYPE",
    [4695] = "POSITION_3_TYPE",
    [4696] = "POSITION_4_TYPE",
    [4697] = "POSITION_5_TYPE",
    [4698] = "POSITION_6_TYPE",
    [4699] = "POSITION_7_TYPE",
    [4700] = "POSITION_8_TYPE",
    [4701] = "POSITION_9_TYPE",
    [4702] = "POSITION_10_TYPE",
    [4703] = "POSITION_11_TYPE",
    [4704] = "POSITION_12_TYPE",
    [4705] = "POSITION_13_TYPE",
    [4706] = "POSITION_14_TYPE",
    [4707] = "POSITION_15_TYPE",
    [4708] = "POSITION_16_TYPE",
    [4709] = "AXIS_NAME",
    [4710] = "PG_ID_ONLY2",
    [4711] = "APP_MANUFACTURER_2",
    [4712] = "APP_MANUFACTURER_3",
    [4713] = "APP_MANUFACTURER_4",
    [4714] = "APP_MANUFACTURER_5",
    [4715] = "APP_MANUFACTURER_6",
    [4716] = "APP_MANUFACTURER_7",
    [4717] = "APP_MANUFACTURER_8",
    [4721] = "ACTUATOR_AXES",
    [4722] = "SCREEN_NAVIGATION",
    [4723] = "DISPLAY_SPEED",
    [4726] = "FORWARD_INHIBIT",
    [4727] = "REVERSE_INHIBIT",
    [4728] = "RIGHT_INHIBIT",
    [4729] = "LEFT_INHIBIT",
    [4731] = "SRV_PM_FOLDBACK_SP_LIMIT",
    [4732] = "SWITCH_MEDIUM",
    [4734] = "FWD_REV_AUTO_TOGGLE_TIME",
    [4737] = "PUFF_THRESHOLD",
    [4739] = "SIP_THRESHOLD",
    [4740] = "SIP_PUFF_DEADBAND",
    [4741] = "PUFF_RAMP_UP",
    [4742] = "PUFF_RAMP_DOWN",
    [4743] = "SIP_RAMP_UP",
    [4744] = "SIP_RAMP_DOWN",
    [4745] = "SIP_PUFF_DOUBLE_CLICK_TIME",
    [4746] = "SIP_PUFF_DOUBLE_CLICK",
    [4747] = "MENU_SCAN_RATE",
    [4748] = "MODES_MENU_SCROLL",
    [4750] = "SIP_FSD",
    [4751] = "OMNI_BACKGROUND",
    [4769] = "FN_ICON_23",
    [4770] = "ESP_MAX_FWD_SPEED",
    [4771] = "ESP_MIN_FWD_SPEED",
    [4781] = "ESP_MAX_REV_ACC",
    [4782] = "ESP_MIN_REV_ACC",
    [4783] = "ESP_MAX_REV_DEC",
    [4784] = "ESP_MIN_REV_DEC",
    [4785] = "ESP_MAX_TURN_ACC",
    [4786] = "ESP_MIN_TURN_ACC",
    [4787] = "ESP_MAX_TURN_DEC",
    [4788] = "ESP_MIN_TURN_DEC",
    [4789] = "ESP_FAST_BRAKE_RATE",
    [4790] = "ESP_MAX_PRP_FACTOR",
    [4791] = "ESP_MIN_PRP_FACTOR",
    [4792] = "ESP_MAX_DIF_FACTOR",
    [4793] = "ESP_MIN_DIF_FACTOR",
    [4794] = "ESP_MAX_INT_FACTOR",
    [4795] = "ESP_MIN_INT_FACTOR",
    [4796] = "FN_ICON_88",
    [4797] = "ESP_FRONT_WHEEL_DRIVE",
    [4798] = "ESP_INH_ASSIGN",
    [4799] = "ESP_INH_BAND0",
    [4800] = "ESP_INH_BAND1",
    [4801] = "ESP_INH_BAND2",
    [4802] = "ESP_INH_BAND3",
    [4803] = "ESP_LATCHED_DRIVE_EN",
    [4804] = "FN_ICON_108",
    [4805] = "FN_ICON_41",
    [4806] = "FN_ICON_89",
    [4807] = "FN_ICON_45",
    [4809] = "FN_ICON_46",
    [4812] = "SM_AXIS_ENABLED",
    [4815] = "SM_AXIS_UP_ASSIGN",
    [4816] = "SM_AXIS_DN_ASSIGN",
    [4818] = "SM_AXIS_DN_INHIBIT_IN_BANDS",
    [4819] = "ESP_SWITCHED_INPUT",
    [4820] = "SM_AXIS_DISPLAY",
    [4821] = "SCAN_SPEED",
    [4822] = "FN_ICON_111",
    [4823] = "FN_ICON_50",
    [4824] = "FN_ICON_95",
    [4825] = "FN_ICON_54",
    [4826] = "FN_ICON_98",
    [4827] = "FN_ICON_55",
    [4828] = "FN_ICON_112",
    [4829] = "FN_ICON_53",
    [4830] = "FN_ICON_97",
    [4831] = "FN_ICON_57",
    [4832] = "FN_ICON_100",
    [4833] = "FN_ICON_58",
    [4834] = "FN_ICON_113",
    [4835] = "FN_ICON_56",
    [4836] = "FN_ICON_99",
    [4838] = "LONGITUDINAL_SLIP_COEFFICIENT",
    [4839] = "SURFACE_ADHESION_COEFF_MIN",
    [4840] = "FN_ICON_137",
    [4841] = "FN_ICON_132",
    [4842] = "FN_ICON_135",
    [4843] = "FN_ICON_139",
    [4845] = "FN_ICON_140",
    [4847] = "FN_ICON_138",
    [4849] = "FN_ICON_145",
    [4850] = "FN_ICON_148",
    [4851] = "FN_ICON_146",
    [4852] = "FN_ICON_149",
    [4854] = "FN_ICON_147",
    [4855] = "FN_ICON_151",
    [4857] = "FN_ICON_152",
    [4858] = "FN_ICON_155",
    [4860] = "FN_ICON_153",
    [4861] = "FN_ICON_156",
    [4862] = "FN_ICON_157",
    [4863] = "FN_ICON_62",
    [4864] = "FN_ICON_63",
    [4865] = "FN_ICON_163",
    [4866] = "FN_ICON_164",
    [4867] = "FN_ICON_165",
    [4868] = "FN_ICON_166",
    [4869] = "FN_ICON_167",
    [4872] = "FN_ICON_170",
    [4874] = "FN_ICON_70",
    [4875] = "FN_ICON_71",
    [4876] = "FN_ICON_72",
    [4877] = "FN_ICON_73",
    [4878] = "FN_ICON_74",
    [4879] = "FN_ICON_75",
    [4880] = "FN_ICON_76",
    [4881] = "FN_ICON_60",
    [4882] = "FN_ICON_65",
    [4883] = "FN_ICON_59",
    [4884] = "FN_ICON_13",
    [4885] = "FN_ICON_14",
    [4886] = "FN_ICON_15",
    [4887] = "FN_ICON_16",
    [4888] = "FN_ICON_17",
    [4889] = "FN_ICON_18",
    [4890] = "FN_ICON_19",
    [4891] = "FN_ICON_20",
    [4892] = "FN_ICON_12",
    [4893] = "FN_ICON_11",
    [4894] = "FN_ICON_114",
    [4895] = "FN_ICON_115",
    [4896] = "FN_ICON_116",
    [4897] = "FN_ICON_117",
    [4898] = "FN_ICON_118",
    [4899] = "FN_ICON_119",
    [4900] = "FN_ICON_120",
    [4901] = "FN_ICON_121",
    [4903] = "FN_ICON_123",
    [4906] = "FN_ICON_126",
    [4907] = "FN_ICON_127",
    [4908] = "FN_ICON_101",
    [4909] = "FN_ICON_3",
    [4910] = "FN_ICON_4",
    [4911] = "FN_ICON_5",
    [4912] = "FN_ICON_6",
    [4913] = "FN_ICON_7",
    [4914] = "FN_ICON_8",
    [4915] = "FN_ICON_9",
    [4916] = "FN_ICON_10",
    [4917] = "FN_ICON_1",
    [4918] = "FN_ICON_2",
    [4919] = "FN_ICON_0",
    [4920] = "FN_ICON_61",
    [4921] = "FN_ICON_66",
    [4922] = "FN_ICON_68",
    [4923] = "FN_ICON_67",
    [4924] = "FN_ICON_64",
    [4925] = "FN_ICON_129",
    [4926] = "FN_ICON_131",
    [4927] = "FN_ICON_128",
    [4928] = "FN_ICON_130",
    [4929] = "FN_ICON_22",
    [4932] = "ALERT_7_NAME",
    [4933] = "ALERT_7_SYSTEM_PROPERTY",
    [4934] = "ALERT_7_THRESHOLD",
    [4935] = "ALERT_7_ORIENTATION",
    [4936] = "ALERT_7_PRIORITY",
    [4937] = "ALERT_8_NAME",
    [4938] = "ALERT_8_SYSTEM_PROPERTY",
    [4939] = "ALERT_8_THRESHOLD",
    [4940] = "ALERT_8_ORIENTATION",
    [4941] = "ALERT_8_PRIORITY",
    [4942] = "ALERT_9_NAME",
    [4944] = "ALERT_9_THRESHOLD",
    [4946] = "ALERT_9_PRIORITY",
    [4947] = "ALERT_10_NAME",
    [4948] = "ALERT_10_SYSTEM_PROPERTY",
    [4949] = "ALERT_10_THRESHOLD",
    [4950] = "ALERT_10_ORIENTATION",
    [4952] = "ALERT_10_PRIORITY",
    [4965] = "ARMATURE_RESISTANCE",
    [4971] = "SM_AXIS_DN_HOME_SPEED",
    [4994] = "SCREEN_BUTTON_2_FUNCTION",
    [4996] = "DISABLE_INHIBIT_2_IN_DRIVE_PROTO",
    [5017] = "SCAN_FREEZE",
    [5019] = "INDICATOR_FAULT_CURRENT_1",
    [5040] = "CURRENT_FOLDBACK_1",
    [5042] = "CURRENT_TIME_2",
    [5047] = "INVERT_M1_DIRECTION",
    [5048] = "INVERT_M2_DIRECTION",
    [5049] = "MOTOR_SWAP",
    [5051] = "FREEWHEEL_VOLTAGE",
    [5053] = "LAMP_VOLTAGE",
    [5055] = "INDICATOR_LAMP_FAULT_DETECT",
    [5056] = "INDICATOR_SWAP_SEAT_REVERSAL",
    [5058] = "RESERVED_FEATURE_20",
    [5059] = "RESERVED_FEATURE_21",
    [5073] = "GYRO_FWD_SPEED",
    [5074] = "GYRO_FWD_ACCEL",
    [5076] = "GYRO_REV_SPEED",
    [5077] = "GYRO_REV_ACCEL",
    [5078] = "GYRO_REV_DECEL",
    [5079] = "GYRO_TURN_SPEED",
    [5080] = "GYRO_TURN_ACCEL",
    [5082] = "GYRO_FAST_BRAKE_RATE",
    [5092] = "CXSM_INH_C1_UP_ACTIVE_IN_AXIS",
    [5093] = "CXSM_INH_C2_UP_ACTIVE_IN_AXIS",
    [5094] = "CXSM_INH_C3_UP_ACTIVE_IN_AXIS",
    [5095] = "CXSM_INH_C4_UP_ACTIVE_IN_AXIS",
    [5097] = "CXSM_INH_C6_UP_ACTIVE_IN_AXIS",
    [5098] = "CXSM_INH_C7_UP_ACTIVE_IN_AXIS",
    [5099] = "CXSM_INH_C8_UP_ACTIVE_IN_AXIS",
    [5100] = "RESERVED_FEATURE_62",
    [5101] = "RESERVED_FEATURE_63",
    [5103] = "RESERVED_FEATURE_65",
    [5104] = "RESERVED_FEATURE_66",
    [5105] = "RESERVED_FEATURE_67",
    [5106] = "RESERVED_FEATURE_68",
    [5107] = "RESERVED_FEATURE_69",
    [5108] = "CXSM_INH_C1_DOWN_ACTIVE_IN_AXIS",
    [5110] = "CXSM_INH_C3_DOWN_ACTIVE_IN_AXIS",
    [5111] = "CXSM_INH_C4_DOWN_ACTIVE_IN_AXIS",
    [5112] = "CXSM_INH_C5_DOWN_ACTIVE_IN_AXIS",
    [5113] = "CXSM_INH_C6_DOWN_ACTIVE_IN_AXIS",
    [5114] = "CXSM_INH_C7_DOWN_ACTIVE_IN_AXIS",
    [5115] = "CXSM_INH_C8_DOWN_ACTIVE_IN_AXIS",
    [5117] = "EXTERNAL_PROFILE_JACK_FUNCTION_MEYRA",
    [5124] = "RESERVED_FEATURE_86",
    [5127] = "ACCELEROMETER_MIN_ACCEL_THRESHOLD",
    [5130] = "ACCELEROMETER_ANTI_SPIN",
    [5136] = "ACCELEROMETER_ORIENTATION",
    [5137] = "ACCELEROMETER_NULL_CALIBRATION",
    [5142] = "RESERVED_FEATURE_104",
    [5143] = "RESERVED_FEATURE_105",
    [5144] = "RESERVED_FEATURE_106",
    [5145] = "RESERVED_FEATURE_107",
    [5146] = "RESERVED_FEATURE_108",
    [5147] = "RESERVED_FEATURE_109",
    [5148] = "RESERVED_FEATURE_110",
    [5149] = "RESERVED_FEATURE_111",
    [5180] = "RESERVED_FEATURE_142",
    [5185] = "RESERVED_FEATURE_147",
    [5186] = "STALL_TIME",
    [5187] = "STALL_BEEP",
    [5188] = "STALL_ZERO_SPEED_THRESHOLD",
    [5189] = "BATTERY_DVDT_THRESHOLD",
    [5190] = "BATTERY_DVDT_DEBOUNCE",
    [5197] = "RESERVED_FEATURE_159",
    [5198] = "HMC_RBN_CONTROL_AXIS_WHILE_DRIVING",
    [5199] = "HMC_RBN_INPUT1_ASSIGN",
    [5200] = "HMC_RBN_INPUT1_MODE",
    [5203] = "HMC_RBN_INPUT2_ASSIGN",
    [5204] = "HMC_RBN_INPUT2_MODE",
    [5205] = "HMC_RBN_INPUT3_ASSIGN",
    [5206] = "HMC_RBN_INPUT3_MODE",
    [5207] = "HMC_RBN_INPUT4_ASSIGN",
    [5208] = "HMC_RBN_INPUT4_MODE",
    [5209] = "EMERGENCY_STOP_SW",
    [5210] = "HMC_RBN_INPUT5_MODE",
    [5212] = "HMC_RBN_INPUT6_MODE",
    [5222] = "BACKLASH_THRESHOLD",
    [5225] = "SECOND_FUNCTION_TIME",
    [5229] = "ASSIGNABLE_BUTTON_JACK_2",
    [5230] = "ASSIGNABLE_BUTTON_SPEED_DOWN",
    [5231] = "ASSIGNABLE_BUTTON_SPEED_UP",
    [5232] = "ASSIGNABLE_BUTTON_HORN",
    [5233] = "ASSIGNABLE_BUTTON_LIGHTS",
    [5234] = "ASSIGNABLE_BUTTON_LEFT_INDICATOR",
    [5235] = "ASSIGNABLE_BUTTON_RIGHT_INDICATOR",
    [5236] = "ASSIGNABLE_BUTTON_HAZARDS",
    [5237] = "SECOND_FUNCTION_TIME_2",
    [5238] = "ASSIGNABLE_BUTTON_FORWARD",
    [5239] = "ASSIGNABLE_BUTTON_REVERSE",
    [5240] = "ASSIGNABLE_BUTTON_LEFT",
    [5241] = "ASSIGNABLE_BUTTON_RIGHT",
    [5242] = "ASSIGNABLE_BUTTON_FIFTH",
    [5257] = "HMC_CJA_OUTPUTS_GROUP_1",
    [5258] = "HMC_CJA_OUTPUTS_GROUP_2",
    [5418] = "ICS_MAX_ELEV_TRAVEL",
    [5456] = "ICS_ABS_MIN_LEG_LOW_SPD_ANGLE",
    [5457] = "ICS_ABS_MAX_LEG_LOW_SPD_ANGLE",
    [5458] = "ICS_ABS_MIN_LEG_DRV_INHIBIT_ANGLE",
    [5459] = "ICS_ABS_MAX_LEG_DRV_INHIBIT_ANGLE",
    [5460] = "ICS_ABS_MIN_ELEV_LOW_SPEED",
    [5461] = "ICS_ABS_MAX_ELEV_LOW_SPEED",
    [5462] = "ICS_ABS_MIN_ELEV_DRV_INHIBIT_HEIGHT",
    [5463] = "ICS_ABS_MAX_ELEV_DRV_INHIBIT_HEIGHT",
    [5464] = "FWD_STABILITY",
    [5465] = "FWD_STABILITY_COMPENSATION_RATIO",
    [5466] = "FWD_STABILITY_START_VOLTAGE",
    [5467] = "TURN_TRACTION",
    [5468] = "DISABLE_INHIBIT_2_IN_DRIVE",
    [5469] = "DISABLE_INHIBIT_3_IN_DRIVE",
    [5470] = "SERVO_AWAY_ACCELERATION",
    [5471] = "SERVO_HOME_ACCELERATION",
    [5473] = "SCX_INH_VIRTUAL_INH_ASSIGN",
    [5478] = "END_STOP_AUTO_DETECT",
    [5497] = "SCX_INH_LIFT_UP_INHIBIT_IN_BANDS",
    [5498] = "SCX_INH_LIFT_UP_ALARM",
    [5512] = "CXSM_INH_C1_UP_ASSIGN",
    [5513] = "CXSM_INH_C2_UP_ASSIGN",
    [5514] = "CXSM_INH_C3_UP_ASSIGN",
    [5515] = "CXSM_INH_C4_UP_ASSIGN",
    [5516] = "CXSM_INH_C5_UP_ASSIGN",
    [5517] = "CXSM_INH_C6_UP_ASSIGN",
    [5518] = "CXSM_INH_C1_UP_BANDS",
    [5519] = "CXSM_INH_C2_UP_BANDS",
    [5520] = "CXSM_INH_C3_UP_BANDS",
    [5521] = "CXSM_INH_C4_UP_BANDS",
    [5522] = "CXSM_INH_C5_UP_BANDS",
    [5523] = "CXSM_INH_C6_UP_BANDS",
    [5538] = "CXSM_INH_C3_DN_BANDS",
    [5540] = "CXSM_INH_C5_DN_BANDS",
    [5543] = "CXSM_INH_C2_DN_ALARM",
    [5544] = "CXSM_INH_C3_DN_ALARM",
    [5576] = "ALM_INH_C1_UP_ALARM",
    [5578] = "STABILITY_LIMITING",
}

-- ODI class decode from IRConfigurator.exe ODI_CLASS enum (ilspycmd).
-- The 24-bit ODI in POP data[1..3] decomposes as
-- `class_base[CLASS] + size_offset[SIZE]` plus a separately-added address.
-- Class enum names recovered from IRConfigurator.Device.ODI_CLASS via
-- ilspycmd decompile of IRConfigurator.exe v6.1.2.
local function decode_odi_class(odi)
    -- Special case: class 5 SLOT
    if odi == 0x85 then return "ODI_CLASS_SLOT", 0, "size=0" end
    if odi == 0x8C then return "ODI_CLASS_SLOT", 0, "size=1-4" end
    -- Special case: class 6 EVENT
    if odi >= 0x200 and odi <= 0x203 then
        return "ODI_CLASS_EVENT", odi - 0x200, string.format("size=%d", odi - 0x200)
    end
    -- General case: classes 0-4 with size offset 0..4
    local bases = {
        [0] = {0x100, "ODI_CLASS_E2"},   -- EEPROM (non-volatile config)
        [1] = {0x110, "ODI_CLASS_PORT"}, -- I/O ports
        [2] = {0x120, "ODI_CLASS_RAM"},  -- working RAM
        [3] = {0x130, "ODI_CLASS_ROM"},  -- code flash / read-only
        [4] = {0x140, "ODI_CLASS_ADC"},  -- analog channels
    }
    for cls = 0, 4 do
        local base = bases[cls][1]
        local name = bases[cls][2]
        if odi >= base and odi <= base + 4 then
            return name, odi - base, string.format("size=%d", odi - base)
        end
    end
    return nil, nil, nil
end

-- DIME serial-number decode from DeviceDriver.GetSN() (IRConfigurator.exe).
-- 64-bit DIME → human-readable "LLYYMMNNNN" string (2-letter manufacturer
-- prefix + 2-digit year + 2-digit month + 4-digit per-month sequence).
local function decode_dime(b0, b1, b2, b3)
    -- Per GetSN @ DeviceDriver.cs:
    --   letter2 = ((b1 & 0xC0) >> 6) | ((b2 & 0x07) << 2)
    --   letter1 = (b2 & 0xFC) >> 3
    --   year    = b3 / 12 + 4
    --   month   = b3 % 12 + 1
    --   seq     = b0 + ((b1 & 0x3F) << 8)
    local letter2 = bit.bor(bit.rshift(bit.band(b1, 0xC0), 6),
                            bit.lshift(bit.band(b2, 0x07), 2))
    local letter1 = bit.rshift(bit.band(b2, 0xFC), 3)
    -- Defensive: letter indexes 1..26 map to A..Z; anything outside is invalid.
    if letter1 < 1 or letter1 > 26 or letter2 < 1 or letter2 > 26 then
        return nil
    end
    local year  = math.floor(b3 / 12) + 4
    local month = (b3 % 12) + 1
    local seq   = b0 + bit.lshift(bit.band(b1, 0x3F), 8)
    if month < 1 or month > 12 then return nil end
    return string.format("%c%c%02d%02d%04d",
        string.byte("A") + letter1 - 1,
        string.byte("A") + letter2 - 1,
        year % 100, month, seq)
end

local function bytes_to_hex(tvb, off, len)
    if len <= 0 then return "" end
    local s = {}
    for i = 0, len-1 do s[#s+1] = string.format("%02X", tvb(off+i,1):uint()) end
    return table.concat(s)
end

-- Per-class decoders ---------------------------------------------------------

local function decode_joystick(tvb, t, cid)
    local slot = bit.band(bit.rshift(cid, 8), 0xF)
    t:add(pf.class, "Joystick position")
    t:add(pf.slot, slot)
    if tvb:len() >= 2 then
        local x = tvb(0,1):le_int()
        local y = tvb(1,1):le_int()
        t:add(pf.joy_x, tvb(0,1))
        t:add(pf.joy_y, tvb(1,1))
        -- Add a directional cue so users can scan motion at a glance.
        local dir = ""
        if x == 0 and y == 0 then
            dir = "  (idle)"
        else
            local arrow = ""
            if y < -10 then arrow = arrow .. "↑"
            elseif y > 10 then arrow = arrow .. "↓" end
            if x > 10 then arrow = arrow .. "→"
            elseif x < -10 then arrow = arrow .. "←" end
            if arrow ~= "" then dir = "  " .. arrow end
        end
        t:add(pf.summary, string.format("Joystick X=%+4d Y=%+4d%s", x, y, dir))
    end
    add_evidence(t, "Code", "rnet_utils.py:330")
    return "Joy"
end

local function decode_speed(tvb, t, cid)
    local slot = bit.band(bit.rshift(cid, 8), 0xF)
    t:add(pf.class, "Speed setting")
    t:add(pf.slot, slot)
    if tvb:len() >= 1 then
        local pct = tvb(0,1):uint()
        t:add(pf.speed_pct, tvb(0,1))
        t:add(pf.summary, string.format("Speed range %3d%%", pct))
    end
    add_evidence(t, "Documented", "janschu99 RNETdictionary.txt:27 + diary:16")
    return "Speed"
end

local function decode_battery(tvb, t, cid)
    local slot = bit.band(bit.rshift(cid, 8), 0xF)
    t:add(pf.class, "Battery level")
    t:add(pf.slot, slot)
    if tvb:len() >= 1 then
        local pct = tvb(0,1):uint()
        t:add(pf.batt_pct, tvb(0,1))
        -- Add a bar visualization so users can scan battery state.
        local bars = math.floor(pct / 10)
        local bar = string.rep("█", bars) .. string.rep("░", 10-bars)
        t:add(pf.summary, string.format("Battery %3d%% %s", pct, bar))
    end
    add_evidence(t, "Code", "rnet_utils.py:352")
    return "Batt"
end

local function decode_motor_current(tvb, t, cid)
    -- Per janschu99 categorized dictionary line 83:
    -- "14300X00#LlHh :PMtx drive motor current. Little-endian 16-bit.
    --  Instantaneous. Periodic: 200ms. Units of measurement(?) 2e8 = 1.6"
    -- DLC=2 across all 9,647 frames in corpus (rnet_utils.py:359's DLC>=4
    -- requirement never fires — see CRC_VERIFICATION_FINDINGS for the bug).
    local slot = bit.band(bit.rshift(cid, 8), 0xF)
    t:add(pf.class, "Motor current")
    t:add(pf.slot, slot)
    if tvb:len() >= 2 then
        local v = tvb(0,2):le_uint()
        t:add_le(pf.motor_left, tvb(0,2))
        if v == 0 then
            t:add(pf.summary, string.format("Motor current slot=%X: idle", slot))
        else
            t:add(pf.summary, string.format("Motor current slot=%X = %d (LE u16; unit unknown)", slot, v))
        end
    end
    add_evidence(t, "Documented", "janschu99 categorized dictionary line 83 §14300X00")
    return "MotI"
end

local function decode_distance(tvb, t, cid)
    local slot = bit.band(bit.rshift(cid, 8), 0xF)
    t:add(pf.class, "Distance counter")
    t:add(pf.slot, slot)
    if tvb:len() >= 8 then
        t:add_le(pf.dist_left,  tvb(0,4))
        t:add_le(pf.dist_right, tvb(4,4))
    end
    add_evidence(t, "Code", "rnet_utils.py:415")
    return "Dist"
end

local function decode_motor_enable(tvb, t, cid)
    local slot = bit.band(bit.rshift(cid, 8), 0xF)
    t:add(pf.class, "Motor enable")
    t:add(pf.slot, slot)
    if tvb:len() >= 2 then
        t:add(pf.motor_en_l, tvb(0,1))
        t:add(pf.motor_en_r, tvb(1,1))
    end
    add_evidence(t, "Code", "rnet_utils.py:430")
    return "MotEn"
end

local function decode_horn(tvb, t, cid)
    local slot = bit.band(bit.rshift(cid, 8), 0xF)
    local state = (bit.band(cid, 0xF) == 0) and "start" or "stop"
    t:add(pf.class, "Horn")
    t:add(pf.slot, slot)
    t:add(pf.horn_state, state)
    t:add(pf.summary, string.format("Horn %s slot=%X", state, slot))
    add_evidence(t, "Code", "rnet_utils.py:346")
    return "Horn"
end

local function decode_lights(tvb, t)
    -- Per janschu99 RNETdictionary.txt:40: byte 0 = mask (commanded
    -- indicators), byte 1 = bitmap (current indicator state). Bit map:
    -- 0x01=Left, 0x04=Right, 0x10=Hazard, 0x80=Flood. Bits 1, 3, 5, 6
    -- not enumerated in the dictionary; bit 6 is observed during the
    -- "lamp test - all on" payload `D5 D5` (see diary entry) so is a real
    -- 5th-or-later indicator with identity TBD.
    local function light_names(b)
        local on = {}
        if bit.band(b,0x01)~=0 then on[#on+1] = "Left" end
        if bit.band(b,0x04)~=0 then on[#on+1] = "Right" end
        if bit.band(b,0x10)~=0 then on[#on+1] = "Hazard" end
        if bit.band(b,0x40)~=0 then on[#on+1] = "bit6?" end
        if bit.band(b,0x80)~=0 then on[#on+1] = "Flood" end
        return #on > 0 and table.concat(on, "+") or "off"
    end
    t:add(pf.class, "Lighting control")
    if tvb:len() >= 1 then
        local mask = tvb(0,1):uint()
        t:add(pf.light_left,  tvb(0,1))
        t:add(pf.light_bit1,  tvb(0,1))
        t:add(pf.light_right, tvb(0,1))
        t:add(pf.light_bit3,  tvb(0,1))
        t:add(pf.light_haz,   tvb(0,1))
        t:add(pf.light_bit5,  tvb(0,1))
        t:add(pf.light_bit6,  tvb(0,1))
        t:add(pf.light_flood, tvb(0,1))
        if tvb:len() >= 2 then
            local bitmap = tvb(1,1):uint()
            t:add(pf.light_b1, tvb(1,1))
            t:add(pf.summary, string.format(
                "Lights mask=%s bitmap=%s%s",
                light_names(mask), light_names(bitmap),
                (mask == bitmap) and "" or "  (transitioning)"))
        else
            t:add(pf.summary, "Lights mask=" .. light_names(mask) .. " (DLC=1)")
        end
    end
    add_evidence(t, "Documented", "janschu99 RNETdictionary.txt:40")
    return "Lights"
end

local function decode_serial_heartbeat(tvb, t)
    t:add(pf.class, "JSM serial heartbeat")
    if tvb:len() >= 4 then
        t:add(pf.serial_bytes, tvb(0, math.min(8, tvb:len())))
        local sn = bytes_to_hex(tvb, 0, math.min(4, tvb:len()))
        -- Identify the network if the serial matches a known one
        local net_tag = ""
        if     sn == "08901C8A" then net_tag = " [Table A: Standalone JSM]"
        elseif sn == "50C01C8F" then net_tag = " [Table B: M300]"
        elseif sn == "B68021AE" then net_tag = " [Table D: Hackathon]"
        end
        t:add(pf.summary, string.format("JSM serial=%s%s", sn, net_tag))
    end
    add_evidence(t, "Code", "rnet_utils.py:275 + XOR-table identification")
    return "SerHB"
end

local function decode_auth(tvb, t, cid, is_rtr)
    -- 0x1F [SEQ][SLOT] [KEY][VALUE]   (parse_auth_frame_id, line 128)
    local seq   = bit.band(bit.rshift(cid, 20), 0xF)
    local slot  = bit.band(bit.rshift(cid, 16), 0xF)
    local key   = bit.band(bit.rshift(cid,  8), 0xFF)
    local value = bit.band(cid, 0xFF)
    t:add(pf.class, is_rtr and "Serial auth — RTR challenge" or "Serial auth — response")
    t:add(pf.auth_seq, seq)
    t:add(pf.auth_slot, slot)
    t:add(pf.auth_key, key)
    t:add(pf.auth_value, value)

    -- XOR validation: identify the network by key match at seq 0-3 (where
    -- keys are discriminating). All devices on a network share the same
    -- xor_table → same derived key for a given seq regardless of slot.
    -- The value byte is the responding device's serial byte (different per
    -- slot). seq 4-7 keys can coincidentally collide between networks
    -- (both Table A and D have 0x45 at seq=7), so we don't use seq>3 for
    -- network identification.
    local matched_net = nil
    if not is_rtr and seq <= 3 then
        for _, net in ipairs(known_xor_tables) do
            if net.keys[seq] == key then
                matched_net = net
                t:add(pf.auth_valid, true):set_generated()
                t:add(pf.auth_net, net.name):set_generated()
                if net.serial and net.serial[seq] == value then
                    -- JSM-slot match — value also confirms
                    t:add(pf.summary, string.format(
                        "Auth response seq=%d slot=%X key=0x%02X val=0x%02X ✓ %s [JSM serial]",
                        seq, slot, key, value, net.name:match("^([^:]+)")))
                    add_evidence(t, "Code", "XOR-table cross-check (full JSM serial match)")
                    return "Auth"
                end
                break
            end
        end
    end

    -- Short network tag like "Table B" extracted from full name.
    local net_tag = ""
    if matched_net then
        net_tag = " ✓ " .. matched_net.name:match("^([^:]+)")
    end
    if is_rtr then
        t:add(pf.summary, string.format("Auth challenge seq=%d slot=%X key=0x%02X val=0x%02X [RTR]",
            seq, slot, key, value))
    else
        t:add(pf.summary, string.format("Auth response seq=%d slot=%X key=0x%02X val=0x%02X%s",
            seq, slot, key, value, net_tag))
    end
    add_evidence(t, "Code", "rnet_utils.py:315 + parse_auth_frame_id:128")
    return "Auth"
end

-- Standard-ID POP frame: (CAN ID & 0x7E0) == 0x780.
-- Byte 0 is a packed (TransferCode, Quick, bit4, OtherNode) tuple; bytes 1-3
-- hold the 24-bit ODI; bytes 4-6 hold a 24-bit Size; byte 7 is the Block
-- counter. Per docs/DONGLE_INTERFACE_DLL_TYPES.md "Standard (11-bit) CAN ID
-- POP message" (CPOPMsg decompile).
local function decode_pop_std(tvb, t, cid)
    local this_node = bit.band(cid, 0xF)
    local dir       = bit.band(bit.rshift(cid, 4), 1)
    t:add(pf.class, "POP (standard-ID)")
    t:add(pf.pop_this, this_node)
    t:add(pf.pop_this_str, slot_name(this_node)):set_generated()
    t:add(pf.pop_dir, dir)

    if tvb:len() >= 1 then
        local b0 = tvb(0,1):uint()
        local tc       = bit.band(bit.rshift(b0, 6), 0x3)
        local other    = bit.band(b0, 0xF)

        t:add(pf.pop_tc, tc):append_text(string.format("  (bits 7-6 of data[0]=0x%02X)", b0))
        t:add(pf.pop_tc_str, tc_name(tc, false)):set_generated()
        t:add(pf.pop_quick, tvb(0,1))
        t:add(pf.pop_crc,   tvb(0,1))
        t:add(pf.pop_other, other)
        t:add(pf.pop_other_str, slot_name(other)):set_generated()

        local is_abort = (tc == 3)
        t:add(pf.pop_is_abort, is_abort):set_generated()

        local legacy = legacy_label(b0)
        if legacy then t:add(pf.pop_label, legacy):set_generated() end

        local reg_name = nil
        if tvb:len() >= 8 then
            -- ODI = data[1..3] little-endian 24-bit; Size = data[4..6] LE 24-bit;
            -- Block = data[7]. EXCEPTION: when byte 0 = 0x8F (COMPLETE
            -- response), bytes 4-5 carry the embedded CRC-16/CCITT-FALSE
            -- of the just-completed transfer's data, per CPOPMsg::SetCRC @
            -- 0x10002610 (external RE notes R4 reply). Empirically verified
            -- against programmer_write capture: 13-byte TEXT data block
            -- produces CRC 0x6F36 matching frame 270's d[4..5] LE.
            local odi = tvb(1,1):uint() + tvb(2,1):uint()*256 + tvb(3,1):uint()*65536
            local sz  = tvb(4,1):uint() + tvb(5,1):uint()*256 + tvb(6,1):uint()*65536
            t:add(pf.pop_odi,  tvb(1,3), odi)
            if b0 == 0x8F then
                -- COMPLETE: bytes 4-5 are the embedded CRC.
                t:add_le(pf.pop_crc_value, tvb(4,2))
            else
                -- For Quick-style frames on documented registers, bytes 4-7
                -- carry the value/pointer/data being exchanged. The "Size"
                -- label is correct only for segmented-transfer setup frames
                -- (TC=1 with CRCFlag=1) — others use this region as data.
                local reg = tvb(1,1):uint()
                local is_setup = (tc == 1) and (bit.band(b0, 0x10) ~= 0)
                if is_setup then
                    t:add(pf.pop_size, tvb(4,3), sz)
                else
                    t:add_le(pf.pop_value16, tvb(4,2))
                    t:add_le(pf.pop_value32, tvb(4,4))
                    if reg == 0x81 then
                        -- POINTER register: byte 4 = pointer-index,
                        -- byte 6 = sub-index. Per janschu99 dictionary
                        -- line 14: "78M#2P810000Xx00Vv00 : check if
                        -- pointer Xx sub Vv exists."
                        local p_idx = tvb(4,1):uint()
                        local p_sub = tvb(6,1):uint()
                        t:add(pf.pop_ptr_idx, tvb(4,1)):set_generated()
                        t:add(pf.pop_ptr_sub, tvb(6,1)):set_generated()
                        t:add_le(pf.pop_pointer, tvb(4,2)):set_generated()
                        -- Parameter cross-reference: empirical wire POINTER
                        -- (idx, sub) tuples in programmer-attached captures
                        -- map to permobil-pwc-param-id via
                        -- param_id = (sub << 8) | idx. E.g. (6,1) =
                        -- 262 = "BackUp", (14,1) = 270 = "TiltToggle".
                        --
                        -- ONLY emit the name when p_sub >= 1, because low
                        -- param_ids (sub=0, idx<50) have many ambiguous
                        -- registry bindings (e.g. param_id=2 binds
                        -- ALPHANUMERIC, BYTE_SEGMENTS, C350...). The
                        -- sub>=1 range is dominated by Permobil PWC
                        -- chair-actuator commands which have unique
                        -- bindings.
                        local param_id = bit.bor(bit.lshift(p_sub, 8), p_idx)
                        t:add(pf.pop_ptr_pid, param_id):set_generated()
                        if p_sub >= 1 then
                            local name = pwc_params[param_id]
                            if name then
                                t:add(pf.pop_ptr_name, name):set_generated()
                            end
                        end
                    end
                end
            end
            t:add(pf.pop_block, tvb(7,1))
            -- Label the register name when low byte of ODI matches a
            -- documented §8.3 register and the upper 16 bits are zero
            -- (i.e. ODI is a "register address" not a memory address).
            local reg = tvb(1,1):uint()
            if tvb(2,1):uint() == 0 and tvb(3,1):uint() == 0 then
                if pop_register_names[reg] then
                    reg_name = pop_register_names[reg]
                    t:add(pf.pop_reg_name, reg_name):set_generated()
                elseif pop_register_undocumented[reg] then
                    reg_name = string.format("0x%02X (undocumented 0x8X register)", reg)
                    t:add(pf.pop_reg_name, reg_name):set_generated()
                end
            end
            -- ODI class decode (IRConfigurator.exe ODI_CLASS enum (ilspycmd)):
            -- the 24-bit ODI can be split into a class + address pair.
            local odi_cls, odi_addr, _ = decode_odi_class(odi)
            if odi_cls then
                t:add(pf.pop_odi_class, odi_cls):set_generated()
                t:add(pf.pop_odi_addr,  odi_addr):set_generated()
                if not reg_name then
                    reg_name = string.format("%s[0x%02X]",
                        odi_cls:gsub("^ODI_CLASS_", ""), odi_addr)
                end
            end
            -- .rnd memory-address fallback: when ODI is NOT a register
            -- opcode (data[1] not 0x80-0x8F with zero upper bytes) and
            -- data[3]=0, treat data[1..2] as a 16-bit memory address and
            -- look it up in the .rnd parameter table. The hit rate is
            -- low (~14%) and ODI_CLASS isn't yet disambiguated, but the
            -- hits that do land are semantically coherent (consecutive
            -- channel/button parameters). Only fires when no reg_name
            -- was already assigned, so it never overrides register-based
            -- labels.
            if reg_name == nil and tvb(3,1):uint() == 0 then
                local cand = tvb(1,1):uint() + tvb(2,1):uint() * 256
                if cand ~= 0 then
                    local addr_name = rnd_address_names[cand]
                    if addr_name then
                        t:add(pf.pop_addr_name, addr_name):set_generated()
                        reg_name = string.format(".rnd[0x%04X]=%s", cand, addr_name)
                    end
                end
            end
        end

        -- For POP frames touching the TEXT register (0x8C), if bytes 4-7
        -- are printable ASCII the payload is a cJSM display string chunk.
        -- Per janschu99 dictionary line 17: "79M#2P8C0000asciitxt :PMtx
        -- text chunk used for cJSM display messages."
        -- Excludes COMPLETE (b0=0x8F) because bytes 4-5 there are the CRC.
        local ascii_text = nil
        if reg_name == "TEXT" and tvb:len() >= 8 and b0 ~= 0x8F then
            local s = ""
            local printable = 0
            for i = 4, 7 do
                local c = tvb(i,1):uint()
                if c >= 0x20 and c < 0x7F then
                    s = s .. string.char(c)
                    printable = printable + 1
                elseif c == 0 then
                    s = s .. "·"  -- null
                else
                    s = s .. "?"
                end
            end
            if printable >= 1 then ascii_text = s end
        end

        -- Compact form: op-name when known, fall back to TC label.
        local op = legacy or tc_name(tc, false)
        local reg_str    = reg_name and (" reg="..reg_name) or ""
        local text_str   = ascii_text and string.format("  text=\"%s\"", ascii_text) or ""
        local extra_str  = ""
        if b0 == 0x8F and tvb:len() >= 6 then
            -- COMPLETE: bytes 4-5 = embedded CRC
            extra_str = string.format("  CRC=0x%04X", tvb(4,2):le_uint())
        elseif tvb:len() >= 8 then
            local reg = tvb(1,1):uint()
            local is_setup = (tc == 1) and (bit.band(b0, 0x10) ~= 0)
            if not is_setup then
                -- Show the value/pointer that's being exchanged.
                local v16 = tvb(4,2):le_uint()
                local v32 = tvb(4,4):le_uint()
                if reg == 0x81 and bit.band(v32, 0xFF00FF00) == 0 and v32 ~= 0 then
                    -- POINTER frame in (idx, 0, sub, 0) layout. Suppress
                    -- the PWC name for sub=0 (low param_ids have ambiguous
                    -- bindings) — only label sub>=1 actuator-command space.
                    local idx = tvb(4,1):uint()
                    local sub = tvb(6,1):uint()
                    local pid = bit.bor(bit.lshift(sub, 8), idx)
                    local pname = (sub >= 1) and pwc_params[pid] or nil
                    if sub ~= 0 then
                        extra_str = string.format("  ptr=%d.%d (param %d%s)",
                            idx, sub, pid,
                            pname and (": " .. pname) or "")
                    else
                        extra_str = string.format("  ptr=%d", idx)
                    end
                elseif reg == 0x81 and v16 ~= 0 then
                    -- POINTER fallback (data layout not matching idx/sub)
                    extra_str = string.format("  ptr=0x%04X", v16)
                elseif reg == 0x8F and not ascii_text then
                    -- Data value
                    if v32 < 0x10000 then
                        extra_str = string.format("  value=0x%04X (%d)", v16, v16)
                    else
                        extra_str = string.format("  value=0x%08X", v32)
                    end
                end
            end
        end
        t:add(pf.summary, string.format(
            "POP %s→%s  %s%s%s%s",
            slot_name(this_node), slot_name(other),
            op, reg_str, text_str, extra_str))
    end
    add_evidence(t, "Code", "DongleInterface.dll CPOPMsg class (Ghidra)")
    return "POPstd"
end

-- Extended-ID POP frame: ((CAN ID >> 18) & 0x7E0) == 0x780.
-- Bits 21-18 = node (4), 17-16 = TC (2), 15-0 = SegmentNumber. All 8 data
-- bytes are segment payload — no command byte. Per same source.
local function decode_pop_xtd(tvb, t, cid)
    local node    = bit.band(bit.rshift(cid, 18), 0xF)
    local tc      = bit.band(bit.rshift(cid, 16), 0x3)
    local seg     = bit.band(cid, 0xFFFF)
    t:add(pf.class, "POP (extended-ID)")
    t:add(pf.pop_this, node)
    t:add(pf.pop_this_str, slot_name(node)):set_generated()
    t:add(pf.pop_tc, tc)
    t:add(pf.pop_tc_str, tc_name(tc, true)):set_generated()
    t:add(pf.pop_segment, seg)
    t:add(pf.pop_is_last, (tc == 3)):set_generated()
    t:add(pf.summary, string.format(
        "POP-ext to %s  %s  seg=%d",
        slot_name(node), tc_name(tc, true), seg))
    add_evidence(t, "Code", "DongleInterface.dll CPOPMsg class (Ghidra)")
    return "POPxtd"
end

-- Mode-configuration frame: XTD ID 0x1ECMMSST where MM = mode index,
-- SS = sub-address, T = data-type nibble (00/40/60/61/62/80/C0/F0). Per
-- CJSM_DISPLAY_PROTOCOL.md
-- "Mode Configuration Frames" + RNET_PROTOCOL_SPECIFICATION.md §11.
local function decode_mode_config(tvb, t, cid)
    -- Mode index is one nibble (bits 19-16). Sub-address (bits 15-8) and
    -- Type (bits 7-0) are each one full byte.
    --
    -- Per-Type payload format from CJSM_DISPLAY_PROTOCOL.md:
    --   Type 0x40 (config header): payload like `01 03 00 00 00 00 00 00`
    --   Type 0x60 (mode parameters): raw mode-parameter block
    --   Type 0x61 (extended mode data) — known sub-fields:
    --     Bytes 0-1: Slot/index prefix
    --     Bytes 2-3: Data type (0x80=button, 0x40=action)
    --     Bytes 4-5: Address/parameter ID
    --     Bytes 6-7: Value
    --   Type 0x62 (mode XOR/serial data): mode-specific serial bytes
    --   Type 0x80 (status): usually all zeros
    --   Type 0xC0, 0xF0 (flags): like `01 00 00 00 00 00 00 00`
    local mode    = bit.band(bit.rshift(cid, 16), 0xF)
    local subaddr = bit.band(bit.rshift(cid,  8), 0xFF)
    local typ     = bit.band(cid, 0xFF)
    t:add(pf.class, "Mode configuration")
    t:add(pf.mode_idx, mode)
    t:add(pf.mode_subaddr, subaddr)
    t:add(pf.mode_type, typ)
    t:add(pf.mode_type_s, mode_type_names[typ] or string.format("Unknown type 0x%02X", typ)):set_generated()

    local detail = ""
    if typ == 0x40 and tvb:len() >= 8 then
        -- Configuration header. CJSM doc gives example payload
        -- `01 03 00 00 00 00 00 00`. Bytes 0-1 look like a header tag.
        detail = string.format("  hdr=%02X%02X reserved=%02X%02X%02X%02X%02X%02X",
            tvb(0,1):uint(), tvb(1,1):uint(),
            tvb(2,1):uint(), tvb(3,1):uint(), tvb(4,1):uint(),
            tvb(5,1):uint(), tvb(6,1):uint(), tvb(7,1):uint())
    elseif typ == 0x60 and tvb:len() >= 8 then
        -- Mode parameters: raw 8-byte block. Show as hex.
        detail = "  params=" .. bytes_to_hex(tvb, 0, 8)
    elseif typ == 0x61 and tvb:len() >= 8 then
        -- Extended mode data per cJSM display-protocol notes. Per
        -- external RE notes R3.5 F6: byte order is MIXED — example payload
        -- 0001028000400200 decodes only if bytes 2-3 are BE and bytes 6-7
        -- are LE (different fields owned by different protocol layers).
        -- Bytes 0-1 layout is ambiguous in the doc; show as raw pair.
        local b0, b1    = tvb(0,1):uint(), tvb(1,1):uint()
        local data_type = tvb(2,1):uint() * 256 + tvb(3,1):uint()  -- BE
        local addr      = tvb(4,1):uint() * 256 + tvb(5,1):uint()  -- BE per doc example
        local value     = tvb(6,1):uint() + tvb(7,1):uint() * 256  -- LE per doc example
        local dt_name = (data_type == 0x0280) and "button" or
                        (data_type == 0x0040) and "action" or
                        string.format("0x%04X", data_type)
        detail = string.format("  pfx=%02X%02X type=%s(BE) addr=0x%04X(BE) value=0x%04X(LE) [mixed-endian]",
                               b0, b1, dt_name, addr, value)
    elseif typ == 0x62 and tvb:len() >= 8 then
        -- Mode XOR / serial data: show as hex (per-mode XOR key fragment).
        detail = "  xor_data=" .. bytes_to_hex(tvb, 0, 8)
    elseif (typ == 0xC0 or typ == 0xF0) and tvb:len() >= 1 then
        -- Flags: typically `01 00 ...` per CJSM doc.
        detail = string.format("  flag=0x%02X", tvb(0,1):uint())
    end

    t:add(pf.summary, string.format("ModeCfg mode=%d subaddr=0x%02X type=0x%02X (%s)%s",
        mode, subaddr, typ, mode_type_names[typ] or "?", detail))
    add_evidence(t, "Code", "cJSM display-protocol notes §Mode Configuration Frames + empirical Type-0x61 decode")
    return "ModeCfg"
end

local function decode_tones(tvb, t)
    t:add(pf.class, "Tones / buzzer")
    if tvb:len() >= 2 then
        local out = {}
        for i = 0, tvb:len()-1, 2 do
            if i+1 < tvb:len() then
                out[#out+1] = string.format("L%d:N%d", tvb(i,1):uint(), tvb(i+1,1):uint())
            end
        end
        local s = table.concat(out, " ")
        t:add(pf.tones, s)
        t:add(pf.summary, "Tones: " .. s)
    end
    add_evidence(t, "Code", "rnet_utils.py:377")
    return "Tone"
end

local function decode_device_enum(tvb, t, cid)
    local slot = bit.band(cid, 0xF)
    t:add(pf.class, "Device enumeration")
    t:add(pf.slot, slot)
    if tvb:len() >= 8 then
        t:add(pf.serial_bytes, tvb(0, 8))
        -- Decode as DIME → human-readable "LLYYMMNNNN" per
        -- DeviceDriver.GetSN() (IRConfigurator.exe decompile).
        local dime = decode_dime(tvb(0,1):uint(), tvb(1,1):uint(),
                                  tvb(2,1):uint(), tvb(3,1):uint())
        if dime then
            t:add(pf.dime_serial, dime):set_generated()
            t:add(pf.summary, string.format("Device slot=%X serial=%s (raw=%s)",
                slot, dime, bytes_to_hex(tvb, 0, 8)))
        else
            t:add(pf.summary, string.format("Device slot=%X serial=%s",
                slot, bytes_to_hex(tvb, 0, 8)))
        end
    end
    add_evidence(t, "Code", "rnet_utils.py:389 + DeviceDriver.GetSN decompile")
    return "DevEnum"
end

-- Standard-frame (11-bit) decoders -------------------------------------------
-- All rules below are from rnet_utils.py:decode_frame() (lines 269-310).

local function decode_std(tvb, t, cid, is_rtr)
    if cid == 0x000 then
        t:add(pf.class, is_rtr and "Sleep all devices" or "Sleep command")
        t:add(pf.summary, is_rtr and "Sleep all (RTR)" or "Sleep cmd")
        add_evidence(t, "Code", "rnet_utils.py:271")
        return "Sleep"
    elseif cid == 0x002 then
        -- [unverified] dictionary §1 (RNET_FRAME_DICTIONARY.md): "PM sleep all
        -- (alternate) / Seen during JSM init". Not in runnable decoder.
        local desc = is_rtr and "PM sleep all (alternate)" or "Seen during JSM init"
        t:add(pf.class, desc .. " [unverified]")
        add_evidence(t, "Inferred", "frame_dict §1 family-analogy")
        return "Sleep2"
    elseif cid == 0x004 then
        -- [unverified] dictionary §1
        local desc = is_rtr and "Sleep/wake sequence" or "JSM sleep commencing"
        t:add(pf.class, desc .. " [unverified]")
        add_evidence(t, "Inferred", "frame_dict §1 family-analogy")
        return "Sleep4"
    elseif cid == 0x00C then
        t:add(pf.class, "Network test")
        add_evidence(t, "Code", "rnet_utils.py:273")
        return "NetTest"
    elseif cid == 0x00E then
        return decode_serial_heartbeat(tvb, t)
    elseif cid == 0x040 then
        t:add(pf.class, "Open parameter page")
        add_evidence(t, "Code", "rnet_utils.py:279")
        return "OpenParam"
    elseif cid == 0x041 then
        t:add(pf.class, "Close parameter page")
        add_evidence(t, "Code", "rnet_utils.py:281")
        return "CloseParam"
    elseif cid == 0x050 then
        -- Per janschu99 dictionary line 10: `050#Ss0M00XX` JSMrx,
        -- "appears to be in same format as 060#Ss0M00XX" — attribute Ss of
        -- mode M as data XX.
        t:add(pf.class, "Mode map (JSMrx)")
        if tvb:len() >= 4 then
            local ss = tvb(0,1):uint()
            local m  = bit.band(tvb(1,1):uint(), 0xF)
            local xx = tvb(3,1):uint()
            t:add(pf.summary, string.format(
                "Mode map: attribute=0x%02X mode=%d data=0x%02X", ss, m, xx))
        end
        add_evidence(t, "Documented", "janschu99 RNETdictionary.txt:10")
        return "ModeMap"
    elseif cid == 0x060 then
        -- 0x060 has two documented uses:
        --   Per janschu99 dictionary line 13: `060#Ss0M00XX` JSMrx return
        --     attribute Ss of mode M as data XX.
        --   Per janschu99 diary lines 10-12: PM-tx joystick-event for
        --     specific profiles (DriveProfile / LiftProfile / chairAngle):
        --       060#90000000 = DriveProfile joystick event stop
        --       060#90010040 = LiftProfile joystick event start
        --       060#90010000 = LiftProfile joystick event stop
        --       060#90010040 = chairAngle motor running (categorized:56-57)
        --       060#90010000 = chairAngle motor stopped
        t:add(pf.class, "Mode attribute / joystick event (0x060)")
        if tvb:len() >= 4 then
            local b0 = tvb(0,1):uint()
            local b1 = tvb(1,1):uint()
            local b3 = tvb(3,1):uint()
            if b0 == 0x90 then
                local profile = (b1 == 0x00) and "Drive" or (b1 == 0x01) and "Lift/chairAngle" or string.format("0x%02X", b1)
                local state = (b3 == 0x40) and "running/start" or (b3 == 0x00) and "stopped/stop" or string.format("0x%02X", b3)
                t:add(pf.summary, string.format("PMtx %s joystick event: %s", profile, state))
            else
                local m = bit.band(b1, 0xF)
                t:add(pf.summary, string.format(
                    "JSMrx mode attribute: Ss=0x%02X mode=%d data=0x%02X", b0, m, b3))
            end
        end
        add_evidence(t, "Documented", "janschu99 RNETdictionary.txt:13 + diary:10-12 + categorized:56-57")
        return "ModeAttr"
    elseif cid == 0x051 then
        -- Per janschu99 dictionary line 9: `051#004M0000` JSMtx select
        -- profile M.
        t:add(pf.class, "JSMtx select profile")
        if tvb:len() >= 2 then
            local m = bit.band(tvb(1,1):uint(), 0xF)
            t:add(pf.summary, string.format("Select profile %d", m))
        end
        add_evidence(t, "Documented", "janschu99 RNETdictionary.txt:9")
        return "SelProf"
    elseif cid == 0x061 then
        -- Per janschu99 dictionary lines 11-12:
        --   061#404M0000 = suspend mode M
        --   061#004M0000 = select mode M (last mode must be suspended first)
        t:add(pf.class, "Mode control")
        if tvb:len() >= 2 then
            local b0 = tvb(0,1):uint()
            local m  = bit.band(tvb(1,1):uint(), 0xF)
            if b0 == 0x40 then
                t:add(pf.summary, string.format("Suspend mode %d", m))
            elseif b0 == 0x00 then
                t:add(pf.summary, string.format("Select mode %d", m))
            else
                t:add(pf.summary, string.format("Mode control byte0=0x%02X mode=%d", b0, m))
            end
        end
        add_evidence(t, "Documented", "janschu99 RNETdictionary.txt:11-12")
        return "ModeCtl"
    elseif bit.band(cid, 0x7E0) == 0x780 then
        -- POP standard-ID frame (any of 0x780..0x79F).
        return decode_pop_std(tvb, t, cid)
    elseif cid == 0x7A0 then
        -- Programmer presence announcement. Sent by the Programmer when it
        -- joins the bus. Per frame-class glossary notes +
        -- open-rnet UPD_HUNT_AND_POP_FINDING.md.
        t:add(pf.class, "Programmer presence")
        t:add(pf.summary, "Programmer presence announcement")
        add_evidence(t, "Documented", "frame-class glossary notes + UPD_HUNT_AND_POP_FINDING.md")
        return "ProgHere"
    elseif cid == 0x7B0 then
        t:add(pf.class, "Config mode 0")
        add_evidence(t, "Code", "rnet_utils.py:303")
        return "Cfg0"
    elseif cid == 0x7B1 then
        t:add(pf.class, "Config mode 1")
        add_evidence(t, "Code", "rnet_utils.py:305")
        return "Cfg1"
    elseif cid == 0x7B3 then
        t:add(pf.class, is_rtr and "Serial exchange request" or "Serial exchange")
        add_evidence(t, "Code", "rnet_utils.py:307")
        return "SerExch"
    elseif cid >= 0x040 and cid <= 0x04F then
        -- Param-page family extension. 0x040/041 documented (open/close).
        -- 042-04F are not documented but cluster tightly with the documented
        -- pair. Round-3 reply suggested by analogy these are intermediate
        -- param-page operations.
        local fn = cid - 0x040
        t:add(pf.class, string.format("Param-page family (fn 0x%X) [unverified]", fn))
        t:add(pf.summary, string.format("Param-page family, function 0x%X", fn))
        add_evidence(t, "Inferred", "family-analogy to documented 0x040/0x041")
        return "ParamX"
    elseif cid >= 0x050 and cid <= 0x05F then
        -- Mode-map family extension. 0x050 documented as "Mode map" per
        -- rnet_utils.py:283; 051-05F are family variants by analogy.
        local fn = cid - 0x050
        t:add(pf.class, string.format("Mode-map family (fn 0x%X) [unverified]", fn))
        t:add(pf.summary, string.format("Mode-map family, function 0x%X", fn))
        add_evidence(t, "Inferred", "family-analogy to documented 0x050 Mode map")
        return "ModeMapX"
    elseif cid >= 0x060 and cid <= 0x06F then
        -- Mode-family extension. 0x060 = Mode request (R3 evidenced);
        -- 0x061 = Mode control (rnet_utils.py:285); 062-06F by analogy.
        local fn = cid - 0x060
        t:add(pf.class, string.format("Mode family (fn 0x%X) [unverified]", fn))
        t:add(pf.summary, string.format("Mode family, function 0x%X", fn))
        add_evidence(t, "Inferred", "family-analogy to documented 0x060/0x061")
        return "ModeFamX"
    elseif cid >= 0x7B0 and cid <= 0x7BF then
        -- Config-mode family extension. 0x7B0/7B1/7B3 documented in
        -- rnet_utils.py. 7B2/7B4-7BF by analogy.
        local fn = cid - 0x7B0
        t:add(pf.class, string.format("Config-mode family (fn 0x%X) [unverified]", fn))
        t:add(pf.summary, string.format("Config-mode family, function 0x%X", fn))
        add_evidence(t, "Inferred", "family-analogy to documented 0x7B0/0x7B1/0x7B3")
        return "CfgFamX"
    else
        t:add(pf.class, string.format("Unknown STD 0x%03X", cid))
        return nil
    end
end

-- Extended-frame (29-bit) decoders -------------------------------------------
-- Rules from rnet_utils.py:decode_frame() lines 313-442.

local function decode_xtd(tvb, t, cid, is_rtr)
    -- Specific 0x1FB000XX device-enum check BEFORE the generic 0x1F auth
    -- rule, since 0x1FB000XX shares the 0x1F top byte but is a different
    -- frame class (8-byte DIME serial payload, not (key, value)).
    if bit.band(cid, 0xFFFFFF00) == 0x1FB00000 then
        return decode_device_enum(tvb, t, cid)
    elseif bit.rshift(cid, 24) == 0x1F then
        return decode_auth(tvb, t, cid, is_rtr)
    elseif bit.band(cid, 0xFFFFF0FF) == 0x02000000 then
        return decode_joystick(tvb, t, cid)
    elseif bit.band(cid, 0xFFFFF0FF) == 0x0A040000 then
        return decode_speed(tvb, t, cid)
    elseif cid == 0x0A400300 or cid == 0x0A400301 then
        -- BTMouse (Bluetooth Mouse module) Control 1/2.
        -- Evidenced: DongleInterface.dll wire-format notes §14.2 (line
        -- 890-891), corroborated in DEVICE_SERIALS.md §BTMouse.
        local n = (cid == 0x0A400300) and 1 or 2
        t:add(pf.class, string.format("BTM Control %d", n))
        t:add(pf.summary, string.format("BTMouse Control %d", n))
        add_evidence(t, "Code", "DongleInterface.dll wire-format notes §14.2")
        return "BTMctl"
    elseif cid == 0x0A400002 or cid == 0x0A400102 then
        -- BTMouse Status 1/2 — same family, §14.2.
        local n = (cid == 0x0A400002) and 1 or 2
        t:add(pf.class, string.format("BTM Status %d", n))
        t:add(pf.summary, string.format("BTMouse Status %d", n))
        add_evidence(t, "Code", "DongleInterface.dll wire-format notes §14.2")
        return "BTMstat"
    elseif bit.band(cid, 0xFFFFF0F0) == 0x0C040000 then
        return decode_horn(tvb, t, cid)
    elseif bit.band(cid, 0xFFFFF0FF) == 0x1C0C0000 then
        return decode_battery(tvb, t, cid)
    elseif bit.band(cid, 0xFFFFF0FF) == 0x14300000 then
        return decode_motor_current(tvb, t, cid)
    elseif cid == 0x03C30F0F then
        -- Payload empirically constant `87 87 87 87 87 87 87 00` across
        -- 500/500 hackathon-dump samples + open-rnet captures. Treat as
        -- "JSM alive signature" with a validation check.
        t:add(pf.class, "JSM heartbeat")
        local valid = false
        if tvb:len() >= 7 then
            valid = true
            for i = 0, 6 do
                if tvb(i,1):uint() ~= 0x87 then valid = false; break end
            end
        end
        t:add(pf.jsm_signature, valid):set_generated()
        t:add(pf.summary, valid and "JSM heartbeat (signature 87×7 OK, 100ms periodic)"
                                or "JSM heartbeat (UNEXPECTED PAYLOAD)")
        add_evidence(t, "Code", "janschu99 RNETdictionary.txt:26 + empirical 500/500 corroboration")
        return "JSMhb"
    elseif bit.band(cid, 0xFFFFF0FF) == 0x0C140000 then
        -- 0x0C14[slot]00 = module-emitted heartbeat. Originally documented
        -- as "PM heartbeat" (janschu99 line 44, slot=0 case) but the family
        -- is per-emitter: slot 0 (PM) is the documented case; slot 4 (ILM
        -- per default map) has its own variant per janschu99 line 45
        -- ("0C140400#82 :(?) Periodic: 1000ms. Lamp controller(?)").
        -- Byte 0 reuses the documented POP byte-0 bit-packing (TC + OtherNode).
        local slot = bit.band(bit.rshift(cid, 8), 0xF)
        local label = (slot == 0) and "PM heartbeat" or
                      string.format("%s heartbeat", slot_name(slot))
        t:add(pf.class, label)
        t:add(pf.slot, slot)
        if tvb:len() >= 1 then
            local b     = tvb(0,1):uint()
            local tc    = bit.band(bit.rshift(b, 6), 0x3)
            local other = bit.band(b, 0xF)
            t:add(pf.pm_status_byte, tvb(0,1))
            t:add(pf.pop_tc,    tc)
            t:add(pf.pop_quick, tvb(0,1))
            t:add(pf.pop_crc,   tvb(0,1))
            t:add(pf.pop_other, other)
            t:add(pf.pop_other_str, slot_name(other)):set_generated()
            -- Documented phase markers (diary 34-35, slot 0 only):
            local phase = ""
            if slot == 0 and b == 0x01 then phase = "  [post-JSM-init / speed-limit induce]"
            elseif slot == 0 and b == 0xC0 then phase = "  [steady-state → PM]"
            end
            t:add(pf.summary, string.format(
                "%s slot=%X byte0=0x%02X (TC=%d → %s)%s",
                label, slot, b, tc, slot_name(other), phase))
        end
        add_evidence(t, "Code", "janschu99 RNETdictionary.txt:44-45 + POP byte-0 reuse cross-check")
        return "Hb"
    elseif cid == 0x181C0D00 or cid == 0x181C0100 then
        -- Both function bytes 0x0D and 0x01 play tones. Per janschu99
        -- RNETcanframe_diary.txt:43: "XTD: 0x181c0100  20 50 20 51 20 52
        -- 20 53  JSM-rx play tones. Fmt: Dd Nn. D=duration 00-7F, N=note
        -- value 00-9C only 12 notes per lower nibble."
        return decode_tones(tvb, t)
    elseif bit.band(cid, 0xFFFFFF00) == 0x1FB00000 then
        return decode_device_enum(tvb, t, cid)
    elseif cid == 0x1E80000F then
        -- Transfer Complete sentinel — end of POP-extended segmented config-
        -- write. Zero-payload (DLC=0); the information IS the ID. Outside
        -- the POP-extended namespace by design (it's a protocol-control
        -- marker, not a POP message).
        -- Evidence: extract_config_data.py:68-69 (literal handler);
        -- RNET_PROTOCOL_SPECIFICATION.md §1059; PROJECT_NOTES.md:479.
        t:add(pf.class, "Transfer Complete sentinel")
        t:add(pf.summary, "End-of-transfer marker (Programmer)")
        add_evidence(t, "Code", "extract_config_data.py:68-69 + DongleInterface.dll wire-format §1059")
        return "XferDone"
    elseif bit.band(bit.rshift(cid, 18), 0x7E0) == 0x780 then
        -- POP extended-ID frame. Rigorous membership test from
        -- DONGLE_INTERFACE_DLL_TYPES.md "Extended (29-bit) CAN ID POP message".
        -- Replaces the old, narrower 0x1E3C..0x1E8F config-transfer rule.
        return decode_pop_xtd(tvb, t, cid)
    elseif bit.band(cid, 0xFFF00000) == 0x1EC00000 then
        return decode_mode_config(tvb, t, cid)
    elseif bit.band(cid, 0xFFFFF0FF) == 0x1C2C0000 then
        -- 0x1C2C family. Function byte (bits 11-8) discriminates:
        --   0x0D = "Time of Day, little-endian" per janschu99 dictionary
        --          (RNETdictionary.txt §1c2c0D00).
        --   0x01-0x04 = per-slot variants [unverified] — structurally similar
        --               (DLC=6) but byte semantics may differ per slot. Parse
        --               R3 hypothesizes a per-module-class telemetry.
        local fb = bit.band(bit.rshift(cid, 8), 0xF)
        if fb == 0x0D then
            t:add(pf.class, "Time of Day")
            if tvb:len() >= 6 then
                -- LE u48 of the 6 payload bytes
                local v = 0
                for i = 5, 0, -1 do v = v * 256 + tvb(i,1):uint() end
                t:add(pf.summary, string.format(
                    "Time of Day = 0x%012X (LE, 6 bytes)", v))
            end
            add_evidence(t, "Documented", "janschu99 RNETdictionary.txt §1c2c0D00")
            return "TOD"
        end
        t:add(pf.class, "0x1C2C telemetry (per-slot variant) [unverified]")
        t:add(pf.slot, fb)
        if tvb:len() >= 1 then t:add(pf.tlm_sample,  tvb(0,1)) end
        if tvb:len() >= 3 then t:add_le(pf.tlm_counter, tvb(1,2)) end
        if tvb:len() >= 6 then t:add(pf.tlm_const,   tvb(3,3)) end
        if tvb:len() >= 6 then
            t:add(pf.summary, string.format(
                "0x1C2C[%X] sample=0x%02X bytes1-2=%d const=%02X%02X%02X",
                fb, tvb(0,1):uint(), tvb(1,2):le_uint(),
                tvb(3,1):uint(), tvb(4,1):uint(), tvb(5,1):uint()))
        end
        add_evidence(t, "Inferred", "hackathon-only observation, slot-variant hypothesis")
        return "Tlm1C2C"
    elseif bit.band(cid, 0xFFFF00FF) == 0x181C0000 then
        -- 0x181C0X00 cJSM/JSM device-class family. Function byte = X.
        --   0x0D = Audio tones (rnet_utils.py:377) — handled above as a
        --          specific case.
        --   0x0F = Periodic announcement [unverified]. Observed in 2026-05-21
        --          hackathon candump as 102 frames with fully constant
        --          payload 01 60 80 00 00 00 00 00.
        --   other = unknown function in this device class.
        local func = bit.band(bit.rshift(cid, 8), 0xFF)
        t:add(pf.class, string.format("cJSM/JSM family (function 0x%02X) [unverified]", func))
        if func == 0x0F and tvb:len() == 8 then
            t:add(pf.summary, "cJSM/JSM periodic announcement (constant payload)")
        else
            t:add(pf.summary, string.format("cJSM/JSM family, function 0x%02X", func))
        end
        add_evidence(t, "Inferred", "hackathon-only observation, 0x181C family-analogy")
        return "cJSMx"
    elseif cid == 0x0C000005 then
        -- "PMtx global motor has stopped (0 MPH)" per janschu99 dictionary
        -- §0C000005. Zero-payload event.
        t:add(pf.class, "Motor stopped")
        t:add(pf.summary, "PMtx global: motor stopped (0 MPH)")
        add_evidence(t, "Documented", "janschu99 RNETdictionary.txt §0C000005")
        return "MotStop"
    elseif cid == 0x0C000006 then
        -- "PMtx global motor is decelerating" per janschu99 dictionary
        -- §0C000006.
        t:add(pf.class, "Motor decelerating")
        t:add(pf.summary, "PMtx global: motor decelerating")
        add_evidence(t, "Documented", "janschu99 RNETdictionary.txt §0C000006")
        return "MotDecel"
    elseif bit.band(cid, 0xFFFF00FF) == 0x0C000000 and tvb:len() == 2 then
        -- 0x0C00MM00 with 2-byte payload = ILM/lamp-controller (mask, bitmap)
        -- per janschu99 dictionary line 40 (E=adn+1 case 0x0C000E00, but the
        -- same 2-byte format is seen for 0x0C000400 = D=adn=4 ILM, and
        -- 0x0C000500 = secondary controller).
        local adn = bit.band(bit.rshift(cid, 8), 0xFF)
        t:add(pf.slot, adn)
        return decode_lights(tvb, t)
    elseif bit.band(cid, 0xFFFFFF00) == 0x0C000400 then
        -- 0x0C0004NN per-indicator action (DLC=0): 01=L turn, 02=R turn,
        -- 03=hazard, 04=flood. Per dictionary lines 36-39.
        local action = bit.band(cid, 0xFF)
        local action_name = ({[0x01]="start L turn signal",
                              [0x02]="start R turn signal",
                              [0x03]="start hazard lamps",
                              [0x04]="start flood lamps"})[action]
                           or string.format("action 0x%02X", action)
        t:add(pf.class, "Lamp action")
        t:add(pf.summary, "JSMtx → ILM: " .. action_name)
        add_evidence(t, "Documented", "janschu99 RNETdictionary.txt §0C0004NN")
        return "Lamp"
    elseif bit.band(cid, 0xFFFF00F0) == 0x0C000000 and bit.band(cid, 0xF) >= 1
           and bit.band(cid, 0xF) <= 6 and bit.band(bit.rshift(cid, 8), 0xFF) >= 0x01 then
        -- 0x0C00MM0{1,2,3,4,5,6} for MM != 0x00 and MM != 0x04 = JSM UI
        -- interaction events for module MM. Per dictionary lines 32-35.
        -- (0x0C0004XX is handled above; 0x0C000005/06 are motor state.)
        local mm = bit.band(bit.rshift(cid, 8), 0xFF)
        local sub = bit.band(cid, 0xF)
        t:add(pf.class, string.format("JSM UI event (module %d, sub %d) [unverified]", mm, sub))
        t:add(pf.summary, string.format(
            "JSMtx UI interaction for module %d (sub 0x%02X)", mm, sub))
        add_evidence(t, "Documented", "janschu99 RNETdictionary.txt §0C000205/0C000301")
        return "UIEvent"
    elseif bit.band(cid, 0xFFFF0000) == 0x0C000000 then
        return decode_lights(tvb, t)
    elseif bit.band(cid, 0xFFFFF0FF) == 0x1C300004 then
        return decode_distance(tvb, t, cid)
    elseif bit.band(cid, 0xFFFFF0F0) == 0x1C240000 then
        local slot = bit.band(bit.rshift(cid, 8), 0xF)
        local state = (bit.band(cid, 0xF) == 0x01) and "ready" or "power down"
        t:add(pf.class, "Device state")
        t:add(pf.slot, slot)
        t:add(pf.summary, string.format("Device slot=%X %s", slot, state))
        add_evidence(t, "Code", "rnet_utils.py:424")
        return "DevState"
    elseif bit.band(cid, 0xFFFFF0F0) == 0x0C180000 then
        return decode_motor_enable(tvb, t, cid)
    elseif bit.band(cid, 0xFFFFF0F0) == 0x140C0000 then
        -- Payload empirically DLC=2: bytes 0-1 are a BE u16 error code.
        -- Cross-referenced against open-rnet/docs/RNET_ERROR_CODES.md
        -- (302 entries from "PGDT R-net Error Code List with Remedies v1").
        local slot = bit.band(bit.rshift(cid, 8), 0xF)
        t:add(pf.class, "Status / error")
        t:add(pf.slot, slot)
        if tvb:len() >= 2 then
            local code = tvb(0,1):uint() * 256 + tvb(1,1):uint()
            t:add(pf.err_code, code):set_generated()
            t:add(pf.err_state, code ~= 0):set_generated()
            local name = error_codes[code]
            if name then
                t:add(pf.err_name, name):set_generated()
                t:add(pf.summary, string.format(
                    "⚠ FAULT slot=%X: %s (0x%04X)", slot, name, code))
            elseif code == 0 then
                t:add(pf.summary, string.format("Status slot=%X (no fault)", slot))
            else
                t:add(pf.summary, string.format(
                    "⚠ Status slot=%X code=0x%04X (undocumented)", slot, code))
            end
        end
        add_evidence(t, "Code", "rnet_utils.py:437 + docs/RNET_ERROR_CODES.md (302 entries)")
        return "Status"
    elseif cid == 0x0C280000 then
        -- "PM connected" sentinel — sent once by PM after the serial-number
        -- exchange completes. Per janschu99 RNETdictionary.txt §0C280000.
        t:add(pf.class, "PM connected")
        if tvb:len() >= 1 then
            t:add(pf.summary, string.format("PM connected (flag=0x%02X)", tvb(0,1):uint()))
        else
            t:add(pf.summary, "PM connected (DLC=0)")
        end
        add_evidence(t, "Documented", "janschu99 RNETdictionary.txt §0C280000")
        return "PMconn"
    elseif bit.band(cid, 0xFFFFF0FF) == 0x0C280000 then
        -- 0x0C280X00 per-slot variants — by analogy to slot-0 "PM connected"
        -- sentinel, likely module-connected sentinels for slots 1+.
        local slot = bit.band(bit.rshift(cid, 8), 0xF)
        t:add(pf.class, string.format("Module connected (slot %X) [unverified]", slot))
        t:add(pf.slot, slot)
        if tvb:len() >= 1 then
            t:add(pf.summary, string.format(
                "Slot %X connected (flag=0x%02X) [unverified]", slot, tvb(0,1):uint()))
        end
        add_evidence(t, "Inferred", "family-analogy to documented 0x0C280000 PM-connected")
        return "ModConn"
    elseif bit.band(cid, 0xFFFFF000) == 0x0A400000 then
        -- BTM (Bluetooth Mouse) family extension. The documented entries
        -- (0x0A400002/0102 Status 1/2, 0x0A400300/01 Control 1/2) are
        -- specific cases of this prefix. Variants like 0x0A4002X1 and
        -- 0x0A400401 appear in captures but aren't documented; treat as
        -- BTM-family with the function/sub bytes surfaced.
        local sub = bit.band(cid, 0xFFFF)
        t:add(pf.class, string.format("BTM family (sub 0x%04X) [unverified]", sub))
        t:add(pf.summary, string.format("BTM family sub=0x%04X", sub))
        add_evidence(t, "Inferred", "family-analogy to documented BTM Control/Status")
        return "BTMx"
    elseif bit.band(cid, 0xFFFFF0FF) == 0x1C200000 then
        -- Per janschu99 categorized dictionary line 52:
        --   "1C200X00#RrSsTtUuVv :JSMrx X=device (don't care). 0x0481000003
        --    triggers jsm error display... but JoyXY continues"
        -- So this is a JSM-rx event frame; specific payload 0x0481000003
        -- triggers an error display (without halting joystick).
        local slot = bit.band(bit.rshift(cid, 8), 0xF)
        t:add(pf.class, "JSM-rx event (0x1C20 family)")
        t:add(pf.slot, slot)
        if tvb:len() >= 5 then
            local hex = bytes_to_hex(tvb, 0, 5)
            if hex == "0481000003" then
                t:add(pf.summary, "JSM-rx 0x1C20: TRIGGER jsm error display (0481000003)")
            else
                t:add(pf.summary, string.format("JSM-rx 0x1C20 slot=%X payload=%s", slot, hex))
            end
        end
        add_evidence(t, "Documented", "janschu99 categorized dictionary line 52 §1C200X00")
        return "JsmRx1C20"
    elseif bit.band(cid, 0xFFFFF0FF) == 0x14300001 then
        -- DLC=1, byte 0 observed at {0, 25, 50, 100} — quartile percentages.
        -- Hypothesis from external RE notes R3 Q4a: motor-family percentage
        -- scale, possibly torque-limit or speed-cap. Single-byte. Slot in low
        -- nibble of bits 11-8 (matching the 0x14300X00 motor-power pattern).
        local slot = bit.band(bit.rshift(cid, 8), 0xF)
        t:add(pf.class, "Motor scale [unverified]")
        t:add(pf.slot, slot)
        if tvb:len() >= 1 then
            local v = tvb(0,1):uint()
            t:add(pf.summary, string.format(
                "Motor scale slot=%X = %d%% [unverified]", slot, v))
        end
        add_evidence(t, "Inferred", "hackathon-only observation")
        return "MotScl"
    elseif cid == 0x15000000 then
        -- 5 occurrences total in hackathon dump, DLC=4, constant payload
        -- 01 00 01 00. Truly undocumented namespace per external RE notes R3
        -- reply. Likely event/announcement broadcast; precise semantics open.
        t:add(pf.class, "Event broadcast (0x15) [unverified]")
        t:add(pf.summary, "Event broadcast — semantics unknown")
        add_evidence(t, "Inferred", "hackathon-only observation, no corpus citation")
        return "Event"
    elseif bit.band(cid, 0xFFF00000) == 0x1E800000 then
        -- 0x1E8X = Programmer protocol-control sentinel namespace.
        -- Outside POP-ext: `(0x1E8X >> 18) & 0x7E0 = 0x7A0 ≠ 0x780`.
        --
        -- Structural hypothesis from POP 0x1E8X sentinel namespace notes
        -- (NOT yet Ghidra-confirmed):
        --   subtype = bits 18-16 (top nibble after the 0x8):
        --     0 → Transfer Complete; low nibble of tail = target slot
        --         (0x1E80000F = slot 15 = Programmer)
        --     4-5 → Transfer state advance (start? checkpoint?)
        --     6-7 → Transfer-with-payload-in-ID; low 16 bits =
        --           opaque value (CRC echo? hash? transfer ID?)
        local subtype = bit.band(bit.rshift(cid, 16), 0xF)
        local tail = bit.band(cid, 0xFFFF)
        local label, summary
        if subtype == 0 then
            -- 0x1E80NNNN — Transfer Complete variants
            label = "Transfer Complete sentinel"
            if tail == 0x000F then
                summary = "Transfer Complete → Programmer (slot 15)"
            else
                summary = string.format("Transfer Complete (tail=0x%04X) [unverified payload]", tail)
            end
        elseif subtype == 4 or subtype == 5 then
            label = string.format("Transfer state advance (N=%d) [unverified]", subtype)
            summary = string.format("Sentinel N=%d tail=0x%04X — start/checkpoint hypothesis", subtype, tail)
        elseif subtype == 6 or subtype == 7 then
            label = string.format("Transfer-with-payload-in-ID (N=%d) [unverified]", subtype)
            summary = string.format(
                "Sentinel N=%d tail=0x%04X — CRC echo / hash / transfer-ID hypothesis",
                subtype, tail)
        else
            label = string.format("0x1E8X sentinel (N=%d) [unverified]", subtype)
            summary = string.format("Sentinel N=%d tail=0x%04X (subtype semantics TBD)", subtype, tail)
        end
        t:add(pf.class, label)
        t:add(pf.summary, summary)
        add_evidence(t, "Inferred", "POP 0x1E8X sentinel namespace structural hypothesis")
        return "Sentinel"
    else
        t:add(pf.class, string.format("Unknown XTD 0x%08X", cid))
        return nil
    end
end

-- Main dissector -------------------------------------------------------------

function rnet.dissector(tvb, pinfo, tree)
    -- Pull CAN metadata from the SocketCAN dissector below us.
    local fi_id  = f_id()
    if fi_id == nil then return 0 end          -- not a CAN frame
    local cid    = fi_id.value
    local fi_xtd = f_xtd();  local is_xtd = fi_xtd and fi_xtd.value or false
    local fi_rtr = f_rtr();  local is_rtr = fi_rtr and fi_rtr.value or false

    local t = tree:add(rnet, tvb(), string.format(
        "R-Net  ID=0x%0" .. (is_xtd and "8" or "3") .. "X  %s%s  len=%d",
        cid, is_xtd and "XTD" or "STD", is_rtr and " RTR" or "", tvb:len()))

    local tag
    if is_xtd then
        tag = decode_xtd(tvb, t, cid, is_rtr)
    else
        tag = decode_std(tvb, t, cid, is_rtr)
    end

    pinfo.cols.protocol = "R-Net"
    -- Echo the decoded summary into the Info column so users see semantics
    -- in the packet list. Fallback to a terse tag+ID when no summary was
    -- generated (e.g. unknown frame classes).
    local sf = f_summary()
    if sf and sf.value and sf.value ~= "" then
        pinfo.cols.info = sf.value
    elseif tag then
        pinfo.cols.info = string.format("[%s] ID=0x%X", tag, cid)
    else
        pinfo.cols.info = string.format("Unknown ID=0x%X len=%d", cid, tvb:len())
    end
    return tvb:len()
end

-- Heuristic registration on the SocketCAN dissector --------------------------
-- Any SocketCAN-encapsulated frame's payload reaches us via this hook. We
-- always claim it (return true) — there's no reliable way to distinguish
-- "this is R-Net" from "this is some other proprietary CAN payload" at the
-- bit level, so the user is expected to load this dissector only against
-- captures known to be R-Net.

rnet:register_heuristic("can", function(tvb, pinfo, tree)
    rnet.dissector(tvb, pinfo, tree)
    return true
end)
