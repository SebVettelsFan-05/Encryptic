#!/usr/bin/env python3
"""
crypto_uart.py — Robust CLI for FPGA SHA-256 + AES-256.
"""

import serial
import sys
import time

DEBUG = False

# --- Timing controls (tune if needed) ---
STARTUP_DELAY       = 0.4
POST_KEY_DELAY      = 0.05
INTER_BLOCK_DELAY   = 0.01
FIRST_BYTE_DELAY    = 0.01
RETRY_LIMIT         = 3


def open_serial(port, baud):
    ser = serial.Serial(port, baud, timeout=5)
    time.sleep(STARTUP_DELAY)
    ser.reset_input_buffer()
    return ser


def read_line(ser):
    line = ser.readline()
    if not line:
        return ""
    decoded = line.decode('ascii', errors='replace').strip()
    if DEBUG:
        print(f"    [RX] '{decoded}'")
    return decoded


def send_bytes_safe(ser, data):
    time.sleep(FIRST_BYTE_DELAY)
    ser.write(data)
    ser.flush()


def cmd_hash_string(ser, message):
    ser.reset_input_buffer()
    payload = b'S' + message.encode('ascii') + b'\r'
    if DEBUG:
        print(f"    [TX] {payload}")
    send_bytes_safe(ser, payload)
    return read_line(ser)


def cmd_aes_setup(ser, mode, passphrase):
    ser.reset_input_buffer()

    # force exit any lingering AES mode
    ser.write(b'Q')
    ser.flush()
    time.sleep(0.02)
    ser.reset_input_buffer()

    cmd = b'E' if mode == 'encrypt' else b'D'
    payload = cmd + passphrase.strip().encode('ascii') + b'\r'

    if DEBUG:
        print(f"    [TX] {payload}")

    send_bytes_safe(ser, payload)

    line = read_line(ser)

    if 'KEY_OK' not in line:
        print(f"  WARNING: expected KEY_OK, got: '{line}'")
        return False

    print(f"  {line}")

    # give FPGA time to finish key expansion
    time.sleep(POST_KEY_DELAY)

    return True


def cmd_aes_hex_block(ser, block_16_bytes):
    hex_str = block_16_bytes.hex()
    payload = hex_str.encode('ascii') + b'\r'

    for attempt in range(RETRY_LIMIT):

        ser.reset_input_buffer()

        if DEBUG:
            print(f"    [TX] {hex_str}\\r (try {attempt+1})")

        send_bytes_safe(ser, payload)

        line = read_line(ser)

        if line:
            try:
                return bytes.fromhex(line.strip())
            except ValueError:
                if DEBUG:
                    print(f"    [ERROR] bad hex: '{line}'")

        if DEBUG:
            print("    [RETRYING BLOCK]")
        time.sleep(0.02)

    if DEBUG:
        print("    [FAILED BLOCK]")
    return None


def pkcs7_pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def encrypt_file(ser, passphrase, inpath, outpath):
    with open(inpath, 'rb') as f:
        plaintext = f.read()

    padded = pkcs7_pad(plaintext)
    num_blocks = len(padded) // 16

    print(f"  File size:    {len(plaintext)} bytes")
    print(f"  Padded size:  {len(padded)} bytes ({num_blocks} blocks)")
    print(f"  Passphrase:   \"{passphrase}\"")
    print()

    if not cmd_aes_setup(ser, 'encrypt', passphrase):
        return

    ciphertext = b''
    t0 = time.time()

    for i in range(num_blocks):
        block = padded[i*16:(i+1)*16]

        ct_block = cmd_aes_hex_block(ser, block)
        if ct_block is None:
            print(f"\n  ABORTED at block {i+1}")
            return

        ciphertext += ct_block

        time.sleep(INTER_BLOCK_DELAY)

        if not DEBUG:
            pct = (i+1)*100//num_blocks
            print(f"\r  Encrypting: {i+1}/{num_blocks} ({pct}%)", end='', flush=True)

    print()

    with open(outpath, 'wb') as f:
        f.write(ciphertext)

    print(f"  Written to: {outpath} ({time.time()-t0:.1f}s)")


def decrypt_file(ser, passphrase, inpath, outpath):
    with open(inpath, 'rb') as f:
        ciphertext = f.read()

    if len(ciphertext) % 16 != 0:
        print("ERROR: Ciphertext is not multiple of 16")
        return

    num_blocks = len(ciphertext) // 16

    print(f"  File size:    {len(ciphertext)} bytes ({num_blocks} blocks)")
    print(f"  Passphrase:   \"{passphrase}\"")
    print()

    if not cmd_aes_setup(ser, 'decrypt', passphrase):
        return

    plaintext_padded = b''
    t0 = time.time()

    for i in range(num_blocks):
        block = ciphertext[i*16:(i+1)*16]

        pt_block = cmd_aes_hex_block(ser, block)
        if pt_block is None:
            print(f"\n  ABORTED at block {i+1}")
            return

        plaintext_padded += pt_block

        time.sleep(INTER_BLOCK_DELAY)

        if not DEBUG:
            pct = (i+1)*100//num_blocks
            print(f"\r  Decrypting: {i+1}/{num_blocks} ({pct}%)", end='', flush=True)

    print()

    try:
        plaintext = pkcs7_unpad(plaintext_padded)
    except ValueError:
        print("  WARNING: Invalid padding — writing raw output.")
        plaintext = plaintext_padded

    with open(outpath, 'wb') as f:
        f.write(plaintext)

    print(f"  Written to: {outpath} ({time.time()-t0:.1f}s)")


def print_usage():
    print('Usage:')
    print('  crypto_uart.py PORT BAUD hash "message"')
    print('  crypto_uart.py PORT BAUD encrypt PASSPHRASE INPUT OUTPUT')
    print('  crypto_uart.py PORT BAUD decrypt PASSPHRASE INPUT OUTPUT')
    print('  Add --debug for verbose output')


if __name__ == "__main__":
    if '--debug' in sys.argv:
        DEBUG = True
        sys.argv.remove('--debug')

    if len(sys.argv) < 4:
        print_usage()
        sys.exit(1)

    port = sys.argv[1]
    baud = int(sys.argv[2])
    cmd  = sys.argv[3].lower()

    ser = open_serial(port, baud)

    if cmd == "hash" and len(sys.argv) >= 5:
        result = cmd_hash_string(ser, sys.argv[4])
        print(result)

    elif cmd == "encrypt" and len(sys.argv) >= 7:
        encrypt_file(ser, sys.argv[4], sys.argv[5], sys.argv[6])

    elif cmd == "decrypt" and len(sys.argv) >= 7:
        decrypt_file(ser, sys.argv[4], sys.argv[5], sys.argv[6])

    else:
        print_usage()

    ser.close()
