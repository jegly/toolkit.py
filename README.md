#  toolkit.py — Encoder/Decoder CLI

A simple command‑line toolkit for Linux that lets you convert, encode, decode, hash, encrypt, and inspect data in many formats.

---

##  Features
- Conversions: ASCII ↔ Text ↔ Binary ↔ Hex, Unicode / UTF‑8 / UTF‑16
- Base Encoders/Decoders: Base64 / Base32 / Base58 / Base85 / UUencode / Base91
- Crypto: AES‑256 (CBC, CTR, GCM), RSA key generation, encrypt/decrypt, sign/verify
- Hashes & HMAC: MD5, SHA‑1, SHA‑256, HMAC generator
- Ciphers: ROT13 / Caesar, Simple XOR
- Other Encoders: Morse code
- Checksums: CRC32, Adler‑32
- Utilities: Color code converter (RGB ↔ HEX ↔ HSL), Time/date converter, File hex dump viewer

## Notes
AES requires a 32‑byte key and correct IV/nonce for decryption.
RSA prints PEM keys; keep your private key safe.
Use --hex when passing hex input (ciphertext, keys, etc.).
Outputs are human‑readable strings; binary output can be requested with --output binary.


---

##  Usage

Run with Python 3:

```bash
./toolkit.py <command> [options]

# Conversions
./toolkit.py convert "hello"
./toolkit.py convert --number 12345

# Base encoders/decoders
./toolkit.py base encode base64 "hello"
./toolkit.py base decode base58 "2NEpo7"

# Morse
./toolkit.py morse encode "SOS"
./toolkit.py morse decode "... --- ..."

# ROT13 / Caesar
./toolkit.py rot rot13 "attack at dawn"
./toolkit.py rot caesar "attack" --shift 7

# Hashes & HMAC
./toolkit.py hash sha256 "data"
./toolkit.py hmac sha256 "secretkey" "message"

# XOR
./toolkit.py xor "key" "Attack at dawn"
./toolkit.py xor "key" "Attack" --output hex

# AES‑256
./toolkit.py aes encrypt CBC <32-byte-key-hex> "Top secret" --iv <16-byte-iv-hex>
./toolkit.py aes decrypt CBC <32-byte-key-hex> <ciphertext-hex> --iv <16-byte-iv-hex> --hex

# RSA
./toolkit.py rsa gen --bits 2048 > keys.pem
./toolkit.py rsa encrypt pub.pem "hello"
./toolkit.py rsa decrypt priv.pem <ciphertext-hex>
./toolkit.py rsa sign priv.pem "message"
./toolkit.py rsa verify pub.pem "message" <signature-hex>

# Checksums
./toolkit.py checksum crc32 "data"
./toolkit.py checksum adler32 "data"

# Colours
./toolkit.py color hex-to-rgb "#1e90ff"
./toolkit.py color rgb-to-hex 30 144 255

# Time
./toolkit.py time unix-to-human 1732940000
./toolkit.py time human-to-unix "2025-11-30T05:10:00+00:00"

# File Hex Dump
./toolkit.py dump /bin/ls

