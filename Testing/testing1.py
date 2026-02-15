#!/usr/bin/env python3
"""
crypto_uart.py — Robust CLI for FPGA SHA-256 + AES-256.
"""

import serial
import sys
import time
import hashlib

DEBUG = False

# --- Timing controls (tune if needed) ---
STARTUP_DELAY       = 0.4
POST_KEY_DELAY      = 0.05
INTER_BLOCK_DELAY   = 0.005
FIRST_BYTE_DELAY    = 0.005
RETRY_LIMIT         = 3
STREAM_RETRY_LIMIT  = 20
ROLLBACK_BLOCKS     = 2
VERIFY_BLOCK_HASH   = True


def open_serial(port, baud):
    ser = serial.Serial(port, baud, timeout=0.5)
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


def block_hash_16(block_bytes):
    return hashlib.sha256(block_bytes).hexdigest()


def replay_window(ser, mode, passphrase, blocks, start_idx, end_idx):
    if not cmd_aes_setup(ser, mode, passphrase):
        return None

    out = []
    for idx in range(start_idx, end_idx + 1):
        block_out = cmd_aes_hex_block(ser, blocks[idx])
        if block_out is None:
            return None
        out.append(block_out)
        time.sleep(INTER_BLOCK_DELAY)

    return out


def process_blocks_with_rollback(ser, mode, passphrase, blocks, progress_label):
    num_blocks = len(blocks)
    results = [None] * num_blocks
    stream_retries = 0
    i = 0

    if not cmd_aes_setup(ser, mode, passphrase):
        return None

    while i < num_blocks:
        failure_reason = None
        block_out = cmd_aes_hex_block(ser, blocks[i])

        if block_out is None:
            failure_reason = "read/parse failure"
        else:
            results[i] = block_out
            time.sleep(INTER_BLOCK_DELAY)

            if VERIFY_BLOCK_HASH:
                verify_start = max(0, i - (ROLLBACK_BLOCKS - 1))
                verify_out = replay_window(ser, mode, passphrase, blocks, verify_start, i)
                if verify_out is None:
                    failure_reason = "verification replay failed"
                else:
                    verify_last = verify_out[-1]
                    for offset, out_block in enumerate(verify_out):
                        results[verify_start + offset] = out_block

                    primary_hash = block_hash_16(block_out)
                    verify_hash = block_hash_16(verify_last)
                    if primary_hash != verify_hash:
                        failure_reason = "hash mismatch"
                        if DEBUG:
                            print(f"    [VERIFY FAIL] idx={i+1} run={primary_hash[:16]} replay={verify_hash[:16]}")

        if failure_reason is None:
            i += 1

            if not DEBUG:
                pct = i * 100 // num_blocks
                print(f"\r  {progress_label}: {i}/{num_blocks} ({pct}%)", end='', flush=True)
            continue

        stream_retries += 1
        if stream_retries > STREAM_RETRY_LIMIT:
            print(f"\n  ABORTED at block {i+1} (stream retry limit reached)")
            return None

        rollback_start = max(0, i - (ROLLBACK_BLOCKS - 1))
        rolled_from = rollback_start + 1
        rolled_to = i + 1
        print(
            f"\n  Block {i+1} failed ({failure_reason}), rolling back blocks {rolled_from}-{rolled_to} "
            f"(retry {stream_retries}/{STREAM_RETRY_LIMIT})"
        )

        for j in range(rollback_start, i + 1):
            results[j] = None

        i = rollback_start

        if not cmd_aes_setup(ser, mode, passphrase):
            return None

    if not DEBUG:
        print()

    return b''.join(results)


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

    t0 = time.time()
    blocks = [padded[i*16:(i+1)*16] for i in range(num_blocks)]
    ciphertext = process_blocks_with_rollback(ser, 'encrypt', passphrase, blocks, "Encrypting")
    if ciphertext is None:
        return

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

    t0 = time.time()
    blocks = [ciphertext[i*16:(i+1)*16] for i in range(num_blocks)]
    plaintext_padded = process_blocks_with_rollback(ser, 'decrypt', passphrase, blocks, "Decrypting")
    if plaintext_padded is None:
        return

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
