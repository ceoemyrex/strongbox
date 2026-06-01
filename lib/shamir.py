#!/usr/bin/env python3
"""
lib/shamir.py — Shamir's Secret Sharing over GF(2^8)

This is the ONLY Python file in StrongBox.
All other platform logic must be in Bash.

Usage:
  shamir.py split <k> <n>    — reads hex secret from stdin, prints n shares
  shamir.py reconstruct      — reads k shares from stdin (one per line), prints hex secret

Share format:  <x>:<hex_y>
  e.g.  1:a3f0c2...
        2:bd91e4...

Shares are passed via stdin/stdout only — NEVER as CLI arguments.
This keeps share values out of /proc/PID/cmdline and shell history.

All intermediate buffers (polynomial coefficients, share byte arrays)
are explicitly zeroed before exit. Python cannot guarantee OS-level
memory zeroing (GC may copy objects), but we zero everything reachable
to minimise the window for heap inspection.
"""

import sys
import os
import secrets as _secrets

# ── GF(2^8) arithmetic ─────────────────────────────────────────────────────
# Irreducible polynomial: x^8 + x^4 + x^3 + x + 1  (0x11b)

_GF_EXP = [0] * 512
_GF_LOG  = [0] * 256

def _gf_init() -> None:
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        x ^= (x << 1) ^ (0x1b if (x >> 7) & 1 else 0)
        x &= 0xFF
    _GF_EXP[255] = _GF_EXP[0]
    for i in range(256, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]

_gf_init()

def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]

def gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF(2^8) division by zero")
    if a == 0:
        return 0
    return _GF_EXP[(_GF_LOG[a] - _GF_LOG[b]) % 255]

# ── polynomial evaluation (Horner's method) ─────────────────────────────────

def _eval_poly(coeffs: list, x: int) -> int:
    result = 0
    for c in reversed(coeffs):
        result = gf_mul(result, x) ^ c
    return result

# ── split ───────────────────────────────────────────────────────────────────

def split(secret_bytes: bytearray, k: int, n: int) -> list:
    """Return n (x, bytearray) shares; any k sufficient to reconstruct."""
    if k < 2 or k > n or n > 255:
        raise ValueError(f"invalid parameters: k={k} n={n}")

    shares = [(i + 1, bytearray(len(secret_bytes))) for i in range(n)]

    for byte_idx, secret_byte in enumerate(secret_bytes):
        # Random degree-(k-1) polynomial with secret_byte as constant term.
        coeffs = [secret_byte] + [_secrets.randbelow(256) for _ in range(k - 1)]
        for share_idx, (x, y_buf) in enumerate(shares):
            y_buf[byte_idx] = _eval_poly(coeffs, x)
        # Zero coefficients immediately.
        for j in range(len(coeffs)):
            coeffs[j] = 0

    return shares

# ── reconstruct ─────────────────────────────────────────────────────────────

def reconstruct(shares: list) -> bytearray:
    """Reconstruct secret from (x, bytearray) share tuples via Lagrange interpolation."""
    if not shares:
        raise ValueError("no shares provided")

    length = len(shares[0][1])
    secret = bytearray(length)

    for byte_idx in range(length):
        xs = [s[0] for s in shares]
        ys = [s[1][byte_idx] for s in shares]

        # Lagrange interpolation at x=0 in GF(2^8).
        value = 0
        for j in range(len(xs)):
            num, den = 1, 1
            for m in range(len(xs)):
                if m == j:
                    continue
                num = gf_mul(num, xs[m])
                den = gf_mul(den, xs[j] ^ xs[m])
            value ^= gf_mul(ys[j], gf_div(num, den))

        secret[byte_idx] = value

        # Zero intermediates.
        for i in range(len(xs)):
            xs[i] = 0
            ys[i] = 0

    return secret

# ── CLI ─────────────────────────────────────────────────────────────────────

def cmd_split() -> None:
    if len(sys.argv) < 4:
        print("usage: shamir.py split <k> <n>", file=sys.stderr)
        sys.exit(1)

    k, n = int(sys.argv[2]), int(sys.argv[3])
    hex_secret = sys.stdin.readline().strip()
    secret_bytes = bytearray.fromhex(hex_secret)

    # Zero the hex string reference (best-effort).
    hex_secret = "0" * len(hex_secret)

    shares = split(secret_bytes, k, n)
    for x, y_buf in shares:
        print(f"{x}:{y_buf.hex()}")

    # Zero all share buffers.
    for _, y_buf in shares:
        for i in range(len(y_buf)):
            y_buf[i] = 0

    # Zero secret.
    for i in range(len(secret_bytes)):
        secret_bytes[i] = 0


def cmd_reconstruct() -> None:
    raw_shares = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        x_str, y_hex = line.split(":", 1)
        raw_shares.append((int(x_str), bytearray.fromhex(y_hex)))

    secret = reconstruct(raw_shares)
    print(secret.hex())

    # Zero all share buffers and the reconstructed secret.
    for _, y_buf in raw_shares:
        for i in range(len(y_buf)):
            y_buf[i] = 0
    for i in range(len(secret)):
        secret[i] = 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "split":
        cmd_split()
    elif cmd == "reconstruct":
        cmd_reconstruct()
    else:
        print("usage: shamir.py split <k> <n> | shamir.py reconstruct", file=sys.stderr)
        sys.exit(1)
