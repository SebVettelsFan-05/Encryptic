#!/usr/bin/env python3
"""
crypto_uart.py — CLI for FPGA SHA-256 + AES-256.

Usage:
    python crypto_uart.py PORT BAUD hash "message"
    python crypto_uart.py PORT BAUD encrypt PASSPHRASE input.txt output.enc
    python crypto_uart.py PORT BAUD decrypt PASSPHRASE input.enc output.txt

Add --debug at the end for verbose output.
"""

import serial
import sys
import time

DEBUG = False


def open_serial(port, baud):
    ser = serial.Serial(port, baud, timeout=10)
    time.sleep(0.2)
    ser.reset_input_buffer()
    return ser


def read_line(ser):
    """Read until \\n, return stripped string."""
    line = ser.readline()
    if not line:
        return ""
    decoded = line.decode('ascii', errors='replace').strip()
    if DEBUG:
        print(f"    [RX] '{decoded}'")
    return decoded


def send_and_wait(ser, data):
    """Send data, flush, and give FPGA a moment."""
    ser.write(data)
    ser.flush()


def cmd_hash_string(ser, message):
    ser.reset_input_buffer()
    payload = b'S' + message.encode('ascii') + b'\r'
    if DEBUG:
        print(f"    [TX] {payload}")
    send_and_wait(ser, payload)
    line = read_line(ser)
    if '|' in line:
        return line.split('|')[0]
    return line


def cmd_aes_setup(ser, mode, passphrase):
    ser.reset_input_buffer()
    cmd = b'E' if mode == 'encrypt' else b'D'
    payload = cmd + passphrase.encode('ascii') + b'\r'
    if DEBUG:
        print(f"    [TX] {payload}")
    send_and_wait(ser, payload)
    line = read_line(ser)
    if 'KEY_OK' not in line:
        print(f"  WARNING: expected KEY_OK, got: '{line}'")
        return False
    print(f"  {line}")
    return True


def cmd_aes_quit(ser):
    ser.write(b'Q')
    ser.flush()
    time.sleep(0.1)
    ser.reset_input_buffer()


def cmd_aes_hex_block(ser, block_16_bytes):
    hex_str = block_16_bytes.hex()
    payload = hex_str.encode('ascii') + b'\r'
    if DEBUG:
        print(f"    [TX] {hex_str}\\r")

    # Wait until input buffer is empty (previous response fully read)
    send_and_wait(ser, payload)

    line = read_line(ser)
    clean = line.strip()
    if not clean:
        if DEBUG:
            print(f"    [TIMEOUT]")
        return None
    try:
        return bytes.fromhex(clean)
    except ValueError:
        if DEBUG:
            print(f"    [ERROR] bad hex: '{clean}'")
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
    for i in range(num_blocks):
        block = padded[i*16 : (i+1)*16]
        ct_block = cmd_aes_hex_block(ser, block)
        if ct_block is None:
            print(f"\n  ABORTED at block {i+1}")
            cmd_aes_quit(ser)
            return
        ciphertext += ct_block
        pct = (i + 1) * 100 // num_blocks
        if not DEBUG:
            print(f"\r  Encrypting: block {i+1}/{num_blocks} ({pct}%)", end='', flush=True)

    print()
    cmd_aes_quit(ser)

    with open(outpath, 'wb') as f:
        f.write(ciphertext)
    print(f"  Written to: {outpath}")


def decrypt_file(ser, passphrase, inpath, outpath):
    with open(inpath, 'rb') as f:
        ciphertext = f.read()

    if len(ciphertext) % 16 != 0:
        print("ERROR: Ciphertext is not a multiple of 16 bytes")
        return

    num_blocks = len(ciphertext) // 16

    print(f"  File size:    {len(ciphertext)} bytes ({num_blocks} blocks)")
    print(f"  Passphrase:   \"{passphrase}\"")
    print()

    if not cmd_aes_setup(ser, 'decrypt', passphrase):
        return

    plaintext_padded = b''
    for i in range(num_blocks):
        block = ciphertext[i*16 : (i+1)*16]
        pt_block = cmd_aes_hex_block(ser, block)
        if pt_block is None:
            print(f"\n  ABORTED at block {i+1}")
            cmd_aes_quit(ser)
            return
        plaintext_padded += pt_block
        pct = (i + 1) * 100 // num_blocks
        if not DEBUG:
            print(f"\r  Decrypting: block {i+1}/{num_blocks} ({pct}%)", end='', flush=True)

    print()
    cmd_aes_quit(ser)

    try:
        plaintext = pkcs7_unpad(plaintext_padded)
    except ValueError:
        print("  WARNING: Invalid padding — wrong passphrase? Writing raw output.")
        plaintext = plaintext_padded

    with open(outpath, 'wb') as f:
        f.write(plaintext)
    print(f"  Written to: {outpath}")


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

    # Reset FPGA state
    ser.write(b'Q')
    ser.flush()
    time.sleep(0.1)
    ser.reset_input_buffer()

    if cmd == "hash" and len(sys.argv) >= 5:
        message = sys.argv[4]
        result = cmd_hash_string(ser, message)
        print(f'SHA-256("{message}") = {result}')

    elif cmd == "encrypt" and len(sys.argv) >= 7:
        encrypt_file(ser, sys.argv[4], sys.argv[5], sys.argv[6])

    elif cmd == "decrypt" and len(sys.argv) >= 7:
        decrypt_file(ser, sys.argv[4], sys.argv[5], sys.argv[6])

    else:
        print_usage()

    ser.close()