#!/usr/bin/env python3
"""
toolkit.py — Encoder/Decoder/Crypto Toolkit
"""
import argparse
import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import re
import struct
import sys
import unicodedata
from datetime import datetime, timezone

# Optional crypto (AES/RSA)
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asympadding
    from cryptography.hazmat.backends import default_backend
except Exception:
    Cipher = None  # crypto not available unless installed

# ---------- Helpers ----------
def to_bytes(data, encoding='utf-8'):
    if isinstance(data, bytes):
        return data
    return str(data).encode(encoding)

def from_hex(s: str) -> bytes:
    s = s.strip().replace(" ", "").replace("0x", "").replace("0X", "")
    return binascii.unhexlify(s)

def to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode('ascii')

def to_binary(b: bytes) -> str:
    return " ".join(format(x, "08b") for x in b)

def ascii_to_bytes(s: str) -> bytes:
    return s.encode('ascii', errors='strict')

def bytes_to_ascii(b: bytes) -> str:
    return b.decode('ascii', errors='strict')

def utf8_to_bytes(s: str) -> bytes:
    return s.encode('utf-8')

def utf16_to_bytes(s: str, be=False) -> bytes:
    # FIX: use explicit 'utf-16-le' to avoid BOM being prepended
    return s.encode('utf-16-be' if be else 'utf-16-le')

def bytes_to_utf8(b: bytes) -> str:
    return b.decode('utf-8')

def bytes_to_utf16(b: bytes, be=False) -> str:
    # FIX: use explicit 'utf-16-le' to match utf16_to_bytes
    return b.decode('utf-16-be' if be else 'utf-16-le')

def chunk(iterable, size):
    for i in range(0, len(iterable), size):
        yield iterable[i:i+size]

# Base58 alphabet
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(b: bytes) -> str:
    n = int.from_bytes(b, 'big')
    res = []
    while n > 0:
        n, rem = divmod(n, 58)
        res.append(B58_ALPHABET[rem])
    # FIX: use '' for empty input (not '1'); leading zero bytes get '1' padding below
    result = ''.join(reversed(res))
    # preserve leading zero bytes
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return '1' * pad + result

def base58_decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n *= 58
        n += B58_ALPHABET.index(ch)
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    # restore leading zero bytes
    pad = 0
    for ch in s:
        if ch == '1':
            pad += 1
        else:
            break
    return b'\x00' * pad + b

# Base85 (ASCII85 via stdlib)
def ascii85_encode(b: bytes) -> str:
    return base64.a85encode(b).decode('ascii')

def ascii85_decode(s: str) -> bytes:
    return base64.a85decode(s.encode('ascii'))

# UUencode
def uu_encode(b: bytes) -> str:
    lines = []
    for block in chunk(b, 45):
        line = chr(32 + len(block))
        padded_block = block + b'\x00' * ((3 - len(block) % 3) % 3)
        for c in chunk(padded_block, 3):
            a, d, e = c
            n = (a << 16) | (d << 8) | e
            for shift in (18, 12, 6, 0):
                line += chr(((n >> shift) & 0x3F) + 32)
        lines.append(line)
    lines.append("`")  # termination line
    return "\n".join(lines) + "\n"

def uu_decode(s: str) -> bytes:
    out = bytearray()
    for line in s.splitlines():
        if not line or line[0] == '`':
            break
        length = max(ord(line[0]) - 32, 0)
        data = line[1:]
        buf = bytearray()
        for i in range(0, len(data), 4):
            quartet = data[i:i+4]
            if len(quartet) < 4:
                break
            n = 0
            for ch in quartet:
                n = (n << 6) | (ord(ch) - 32 & 0x3F)
            buf.extend([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
        out.extend(buf[:length])
    return bytes(out)

# Base91 (minimal implementation)
B91_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "!#$%&()*+,./:;<=>?@[]^_`{|}~\""
)

def base91_encode(data: bytes) -> str:
    v = -1
    b = 0
    n = 0
    out = []
    for c in data:
        b |= (c & 255) << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out.append(B91_ALPHABET[v % 91])
            out.append(B91_ALPHABET[v // 91])
    if n:
        out.append(B91_ALPHABET[b % 91])
        if n > 7 or b > 90:
            out.append(B91_ALPHABET[b // 91])
    return ''.join(out)

def base91_decode(data: str) -> bytes:
    out = bytearray()
    v = -1
    b = 0
    n = 0
    for ch in data:
        if ch not in B91_ALPHABET:
            continue
        c = B91_ALPHABET.index(ch)
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n >= 8:
                out.append(b & 255)
                b >>= 8
                n -= 8
            v = -1
    if v + 1:
        out.append((b | v << n) & 255)
    return bytes(out)

# Morse code
MORSE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    ' ': '/', '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.',
    '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...',
    ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-',
    '_': '..--.-', '"': '.-..-.', '$': '...-..-', '@': '.--.-.'
}
REV_MORSE = {v: k for k, v in MORSE.items()}

def morse_encode(text: str) -> str:
    return ' '.join(MORSE.get(ch.upper(), '?') for ch in text)

def morse_decode(code: str) -> str:
    return ''.join(REV_MORSE.get(tok, '?') for tok in code.split())

# ROT13 and Caesar
def rot13(s: str) -> str:
    return caesar(s, 13)

def caesar(s: str, shift: int) -> str:
    shift = shift % 26
    out = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr((o - 65 + shift) % 26 + 65))
        elif 97 <= o <= 122:
            out.append(chr((o - 97 + shift) % 26 + 97))
        else:
            out.append(ch)
    return ''.join(out)

# Checksums
def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xffffffff

def adler32(data: bytes) -> int:
    return binascii.adler32(data) & 0xffffffff

# Color conversions
def hex_to_rgb(hexcode: str):
    s = hexcode.strip().lstrip('#')
    if len(s) == 3:
        s = ''.join(ch*2 for ch in s)
    r = int(s[0:2], 16)
    g = int(s[2:4], 16)
    b = int(s[4:6], 16)
    return r, g, b

def rgb_to_hex(r: int, g: int, b: int) -> str:
    return f"#{r:02X}{g:02X}{b:02X}"

def rgb_to_hsl(r, g, b):
    r_, g_, b_ = r/255.0, g/255.0, b/255.0
    mx = max(r_, g_, b_)
    mn = min(r_, g_, b_)
    l = (mx + mn) / 2
    if mx == mn:
        h = s = 0.0
    else:
        d = mx - mn
        s = d / (2 - mx - mn) if l > 0.5 else d / (mx + mn)
        if mx == r_:
            h = (g_ - b_) / d + (6 if g_ < b_ else 0)
        elif mx == g_:
            h = (b_ - r_) / d + 2
        else:
            h = (r_ - g_) / d + 4
        h /= 6
    return round(h*360, 2), round(s*100, 2), round(l*100, 2)

def hsl_to_rgb(h, s, l):
    h = (h % 360) / 360.0
    s = s / 100.0
    l = l / 100.0

    def hue2rgb(p, q, t):
        t = t % 1.0
        if t < 1/6: return p + (q - p) * 6 * t
        if t < 1/2: return q
        if t < 2/3: return p + (q - p) * (2/3 - t) * 6
        return p

    if s == 0:
        r = g = b = l
    else:
        # FIX: correct formula for q when l < 0.5
        q = l * (1 + s) if l < 0.5 else l + s - l * s
        p = 2 * l - q
        r = hue2rgb(p, q, h + 1/3)
        g = hue2rgb(p, q, h)
        b = hue2rgb(p, q, h - 1/3)
    return int(round(r*255)), int(round(g*255)), int(round(b*255))

# Time conversions
def unix_to_human(ts: int, tz='UTC') -> str:
    # FIX: always interpret timestamp as UTC; local tz conversion can be added later
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.isoformat()

def human_to_unix(dt_str: str) -> int:
    return int(datetime.fromisoformat(dt_str.replace('Z', '+00:00')).timestamp())

# File hex dump
def hexdump(path: str, width=16) -> str:
    out = []
    with open(path, 'rb') as f:
        offset = 0
        while True:
            block = f.read(width)
            if not block:
                break
            hexs = ' '.join(f"{b:02X}" for b in block)
            ascii_ = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in block)
            out.append(f"{offset:08X}  {hexs:<{width*3}}  |{ascii_}|")
            offset += len(block)
    return '\n'.join(out)

# AES utilities
def aes_encrypt(data: bytes, key: bytes, mode: str, iv_or_nonce: bytes = None, aad: bytes = None) -> bytes:
    if Cipher is None:
        raise RuntimeError("cryptography not installed")
    if len(key) != 32:
        raise ValueError("AES-256 requires 32-byte key")
    backend = default_backend()
    mode = mode.upper()
    if mode == 'CBC':
        if iv_or_nonce is None or len(iv_or_nonce) != 16:
            raise ValueError("CBC needs 16-byte IV")
        padder = PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        # FIX: reuse the same encryptor object for update() and finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv_or_nonce), backend=backend).encryptor()
        return encryptor.update(padded) + encryptor.finalize()
    elif mode == 'CTR':
        if iv_or_nonce is None or len(iv_or_nonce) != 16:
            raise ValueError("CTR needs 16-byte nonce/counter")
        # FIX: reuse the same encryptor object
        encryptor = Cipher(algorithms.AES(key), modes.CTR(iv_or_nonce), backend=backend).encryptor()
        return encryptor.update(data) + encryptor.finalize()
    elif mode == 'GCM':
        if iv_or_nonce is None or len(iv_or_nonce) not in (12, 16):
            raise ValueError("GCM needs 12/16-byte nonce")
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv_or_nonce), backend=backend).encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)
        ct = encryptor.update(data) + encryptor.finalize()
        return ct + encryptor.tag
    else:
        raise ValueError(f"Unsupported AES mode: {mode}")

def aes_decrypt(ct: bytes, key: bytes, mode: str, iv_or_nonce: bytes = None, aad: bytes = None) -> bytes:
    if Cipher is None:
        raise RuntimeError("cryptography not installed")
    if len(key) != 32:
        raise ValueError("AES-256 requires 32-byte key")
    backend = default_backend()
    mode = mode.upper()
    if mode == 'CBC':
        if iv_or_nonce is None or len(iv_or_nonce) != 16:
            raise ValueError("CBC needs 16-byte IV")
        # FIX: reuse the same decryptor object
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv_or_nonce), backend=backend).decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    elif mode == 'CTR':
        if iv_or_nonce is None or len(iv_or_nonce) != 16:
            raise ValueError("CTR needs 16-byte nonce/counter")
        # FIX: reuse the same decryptor object
        decryptor = Cipher(algorithms.AES(key), modes.CTR(iv_or_nonce), backend=backend).decryptor()
        return decryptor.update(ct) + decryptor.finalize()
    elif mode == 'GCM':
        if iv_or_nonce is None or len(iv_or_nonce) not in (12, 16):
            raise ValueError("GCM needs 12/16-byte nonce")
        if len(ct) < 16:
            raise ValueError("ciphertext must include GCM tag (last 16 bytes)")
        tag = ct[-16:]
        body = ct[:-16]
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv_or_nonce, tag), backend=backend).decryptor()
        if aad:
            decryptor.authenticate_additional_data(aad)
        return decryptor.update(body) + decryptor.finalize()
    else:
        raise ValueError(f"Unsupported AES mode: {mode}")

# RSA utilities
def rsa_generate(bits=2048):
    if Cipher is None:
        raise RuntimeError("cryptography not installed")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_serialize_private(pk) -> bytes:
    return pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def rsa_serialize_public(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def rsa_load_private(pem: bytes):
    # FIX: accept raw bytes directly (not wrapped in to_bytes which would double-encode)
    if isinstance(pem, str):
        pem = pem.encode('ascii')
    return serialization.load_pem_private_key(pem, password=None)

def rsa_load_public(pem: bytes):
    if isinstance(pem, str):
        pem = pem.encode('ascii')
    return serialization.load_pem_public_key(pem)

def rsa_encrypt(pub, data: bytes, oaep_hash='SHA256') -> bytes:
    h = hashes.SHA256() if oaep_hash.upper() == 'SHA256' else hashes.SHA1()
    return pub.encrypt(
        data,
        asympadding.OAEP(
            mgf=asympadding.MGF1(algorithm=h),
            algorithm=h,
            label=None
        )
    )

def rsa_decrypt(priv, ct: bytes, oaep_hash='SHA256') -> bytes:
    h = hashes.SHA256() if oaep_hash.upper() == 'SHA256' else hashes.SHA1()
    return priv.decrypt(
        ct,
        asympadding.OAEP(
            mgf=asympadding.MGF1(algorithm=h),
            algorithm=h,
            label=None
        )
    )

def rsa_sign(priv, data: bytes, hash_alg='SHA256') -> bytes:
    h = hashes.SHA256() if hash_alg.upper() == 'SHA256' else hashes.SHA1()
    return priv.sign(
        data,
        asympadding.PSS(
            mgf=asympadding.MGF1(h),
            salt_length=asympadding.PSS.MAX_LENGTH
        ),
        h
    )

def rsa_verify(pub, sig: bytes, data: bytes, hash_alg='SHA256') -> None:
    h = hashes.SHA256() if hash_alg.upper() == 'SHA256' else hashes.SHA1()
    pub.verify(
        sig,
        data,
        asympadding.PSS(
            mgf=asympadding.MGF1(h),
            salt_length=asympadding.PSS.MAX_LENGTH
        ),
        h
    )

# ---------- CLI commands ----------
def cmd_convert(args):
    src = args.input
    encoding = args.encoding
    as_bytes = None

    if args.number:
        src_clean = str(src).strip().lower().replace('_', '')
        if src_clean.startswith('0x'):
            val = int(src_clean, 16)
        elif src_clean.startswith('0b'):
            val = int(src_clean, 2)
        else:
            val = int(src_clean, 10)
        width = (val.bit_length() + 7) // 8 or 1
        as_bytes = val.to_bytes(width, 'big')
    else:
        if encoding == 'ascii':
            as_bytes = ascii_to_bytes(src)
        elif encoding == 'latin1':
            as_bytes = src.encode('latin-1', errors='replace')
        elif encoding == 'utf16-be':
            as_bytes = utf16_to_bytes(src, be=True)
        elif encoding == 'utf16':
            as_bytes = utf16_to_bytes(src, be=False)
        else:
            as_bytes = utf8_to_bytes(src)

    print(f"Input: {src}")
    print(f"Encoding: {encoding} {'(number mode)' if args.number else ''}")
    print()
    print("Representations:")
    print(f"- Decimal: {int.from_bytes(as_bytes, 'big') if as_bytes else 'N/A'}")
    print(f"- Hex: 0x{to_hex(as_bytes)}")
    print(f"- Binary: {to_binary(as_bytes)}")
    print()
    print("Byte breakdown:")
    # FIX: rename loop variable to avoid shadowing the chunk() function
    hex_str = to_hex(as_bytes)
    byte_pairs = list(chunk(hex_str, 2))
    print(f"- Bytes (hex): {' '.join(byte_pairs)}")
    print(f"- Byte count: {len(as_bytes)}")
    print()
    print("Text interpretations:")
    for enc in ('latin-1', 'utf-8', 'utf-16-be'):
        try:
            txt = as_bytes.decode(enc)
        except Exception:
            txt = "(invalid)"
        print(f"- {enc}: {txt}")
    print()
    print("Unicode per character (UTF-8 decode):")
    # FIX: unicodedata import moved to top of file
    try:
        s = as_bytes.decode('utf-8')
        for ch in s:
            cp = f"U+{ord(ch):04X}"
            name = unicodedata.name(ch, 'UNKNOWN')
            print(f"- {ch} — {cp} — {name}")
    except Exception:
        print("- (not decodable as UTF-8)")

def cmd_base(args):
    data = to_bytes(args.input) if not args.hex else from_hex(args.input)
    if args.action == 'encode':
        if args.scheme == 'base64':
            print(base64.b64encode(data).decode('ascii'))
        elif args.scheme == 'base32':
            print(base64.b32encode(data).decode('ascii'))
        elif args.scheme == 'base58':
            print(base58_encode(data))
        elif args.scheme == 'base85':
            print(ascii85_encode(data))
        elif args.scheme == 'uu':
            print(uu_encode(data), end='')
        elif args.scheme == 'base91':
            print(base91_encode(data))
        else:
            raise SystemExit("Unknown base scheme")
    else:
        if args.scheme == 'base64':
            print(base64.b64decode(data).decode('latin-1'))
        elif args.scheme == 'base32':
            print(base64.b32decode(data).decode('latin-1'))
        elif args.scheme == 'base58':
            print(base58_decode(args.input).decode('latin-1'))
        elif args.scheme == 'base85':
            print(ascii85_decode(args.input).decode('latin-1'))
        elif args.scheme == 'uu':
            print(uu_decode(args.input).decode('latin-1'))
        elif args.scheme == 'base91':
            print(base91_decode(args.input).decode('latin-1'))
        else:
            raise SystemExit("Unknown base scheme")

def cmd_morse(args):
    if args.action == 'encode':
        print(morse_encode(args.input))
    else:
        print(morse_decode(args.input))

def cmd_rot(args):
    if args.scheme == 'rot13':
        print(rot13(args.input))
    else:
        print(caesar(args.input, args.shift))

def cmd_hash(args):
    data = to_bytes(args.input)
    algo = args.algo.lower()
    # IMPROVEMENT: support sha224, sha384, sha512 in addition to original three
    supported = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
    }
    if algo not in supported:
        raise SystemExit(f"Unknown hash algorithm: {algo}. Supported: {', '.join(supported)}")
    print(supported[algo](data).hexdigest())

def cmd_hmac(args):
    key = to_bytes(args.key)
    data = to_bytes(args.input)
    algo = args.algo.lower()
    digestmod_map = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
    }
    if algo not in digestmod_map:
        raise SystemExit(f"Unknown HMAC hash: {algo}")
    print(hmac.new(key, data, digestmod_map[algo]).hexdigest())

def cmd_xor(args):
    key = to_bytes(args.key)
    data = to_bytes(args.input) if not args.hex else from_hex(args.input)
    out = bytes(d ^ key[i % len(key)] for i, d in enumerate(data))
    if args.output == 'hex':
        print(to_hex(out))
    elif args.output == 'binary':
        print(to_binary(out))
    else:
        print(out.decode('latin-1'))

def _parse_key_or_hex(value: str) -> bytes:
    """Parse a value as hex if it looks like hex, otherwise as UTF-8 bytes."""
    if value.startswith('0x') or value.startswith('0X') or re.fullmatch(r'[0-9a-fA-F]+', value):
        return from_hex(value)
    return to_bytes(value)

def cmd_aes(args):
    if Cipher is None:
        raise SystemExit("cryptography not installed. pip install cryptography")
    key = _parse_key_or_hex(args.key)
    if len(key) != 32:
        raise SystemExit("AES-256 requires a 32-byte key")
    iv = _parse_key_or_hex(args.iv) if args.iv else None
    data = to_bytes(args.input) if not args.hex else from_hex(args.input)
    mode = args.mode.upper()
    if args.action == 'encrypt':
        ct = aes_encrypt(data, key, mode, iv_or_nonce=iv)
        print(to_hex(ct))
    else:
        pt = aes_decrypt(data, key, mode, iv_or_nonce=iv)
        print(pt.decode('utf-8', errors='replace'))

def cmd_rsa(args):
    if Cipher is None:
        raise SystemExit("cryptography not installed. pip install cryptography")
    if args.sub == 'gen':
        priv, pub = rsa_generate(args.bits)
        print(rsa_serialize_private(priv).decode('ascii'))
        print(rsa_serialize_public(pub).decode('ascii'))
    elif args.sub == 'encrypt':
        # FIX: read file as bytes directly, don't wrap in to_bytes()
        pub = rsa_load_public(open(args.pub, 'rb').read())
        ct = rsa_encrypt(pub, to_bytes(args.input))
        print(to_hex(ct))
    elif args.sub == 'decrypt':
        priv = rsa_load_private(open(args.priv, 'rb').read())
        pt = rsa_decrypt(priv, from_hex(args.input))
        print(pt.decode('utf-8', errors='replace'))
    elif args.sub == 'sign':
        priv = rsa_load_private(open(args.priv, 'rb').read())
        sig = rsa_sign(priv, to_bytes(args.input), args.hash)
        print(to_hex(sig))
    elif args.sub == 'verify':
        pub = rsa_load_public(open(args.pub, 'rb').read())
        try:
            rsa_verify(pub, from_hex(args.sig), to_bytes(args.input), args.hash)
            print("OK")
        except Exception as e:
            print(f"FAIL: {e}")

def cmd_checksum(args):
    data = to_bytes(args.input) if not args.hex else from_hex(args.input)
    if args.algo == 'crc32':
        print(f"{crc32(data):08X}")
    else:
        print(f"{adler32(data):08X}")

def cmd_color(args):
    if args.sub == 'hex-to-rgb':
        r, g, b = hex_to_rgb(args.hex)
        print(json.dumps({"r": r, "g": g, "b": b}))
    elif args.sub == 'rgb-to-hex':
        print(rgb_to_hex(args.r, args.g, args.b))
    elif args.sub == 'rgb-to-hsl':
        h, s, l = rgb_to_hsl(args.r, args.g, args.b)
        print(json.dumps({"h": h, "s": s, "l": l}))
    elif args.sub == 'hsl-to-rgb':
        r, g, b = hsl_to_rgb(args.h, args.s, args.l)
        print(json.dumps({"r": r, "g": g, "b": b}))

def cmd_time(args):
    if args.sub == 'unix-to-human':
        print(unix_to_human(int(args.ts)))
    else:
        print(human_to_unix(args.iso))

def cmd_dump(args):
    if not os.path.isfile(args.path):
        raise SystemExit(f"File not found: {args.path}")
    print(hexdump(args.path, width=args.width))

# ---------- Argument parser ----------
def build_parser():
    p = argparse.ArgumentParser(
        description="Encoder/Decoder/Crypto Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest='cmd', required=True)

    # convert
    c = sub.add_parser('convert', help="Text/number to hex/binary/encodings")
    c.add_argument('input', help="Text or number")
    c.add_argument('--encoding', default='utf-8',
                   choices=['utf-8', 'ascii', 'latin1', 'utf16', 'utf16-be'],
                   help="Input text encoding (ignored for --number)")
    c.add_argument('--number', action='store_true', help="Treat input as number")
    c.set_defaults(func=cmd_convert)

    # base
    b = sub.add_parser('base', help="Base encoders/decoders")
    b.add_argument('action', choices=['encode', 'decode'])
    b.add_argument('scheme', choices=['base64', 'base32', 'base58', 'base85', 'uu', 'base91'])
    b.add_argument('input', help="Input (text or hex)")
    b.add_argument('--hex', action='store_true', help="Interpret input as hex")
    b.set_defaults(func=cmd_base)

    # morse
    m = sub.add_parser('morse', help="Morse encoder/decoder")
    m.add_argument('action', choices=['encode', 'decode'])
    m.add_argument('input')
    m.set_defaults(func=cmd_morse)

    # rot/caesar
    r = sub.add_parser('rot', help="ROT13/Caesar cipher")
    r.add_argument('scheme', choices=['rot13', 'caesar'])
    r.add_argument('input')
    r.add_argument('--shift', type=int, default=13, help="Shift for Caesar (default: 13)")
    r.set_defaults(func=cmd_rot)

    # hash — IMPROVEMENT: added sha224, sha384, sha512
    h = sub.add_parser('hash', help="Hash generator")
    h.add_argument('algo', choices=['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'])
    h.add_argument('input')
    h.set_defaults(func=cmd_hash)

    # hmac — IMPROVEMENT: added sha384, sha512
    hm = sub.add_parser('hmac', help="HMAC generator")
    hm.add_argument('algo', choices=['md5', 'sha1', 'sha256', 'sha384', 'sha512'])
    hm.add_argument('key')
    hm.add_argument('input')
    hm.set_defaults(func=cmd_hmac)

    # xor
    x = sub.add_parser('xor', help="XOR encoder/decoder")
    x.add_argument('key')
    x.add_argument('input')
    x.add_argument('--hex', action='store_true', help="Input as hex")
    x.add_argument('--output', choices=['text', 'hex', 'binary'], default='text')
    x.set_defaults(func=cmd_xor)

    # aes
    ae = sub.add_parser('aes', help="AES-256 encrypt/decrypt")
    ae.add_argument('action', choices=['encrypt', 'decrypt'])
    ae.add_argument('mode', choices=['CBC', 'CTR', 'GCM'])
    ae.add_argument('key', help="32-byte key (hex or text)")
    ae.add_argument('input', help="Plaintext (encrypt) or ciphertext hex (decrypt, use --hex)")
    ae.add_argument('--iv', help="IV/nonce (hex or text)")
    ae.add_argument('--hex', action='store_true', help="Treat input as hex")
    ae.set_defaults(func=cmd_aes)

    # rsa
    rs = sub.add_parser('rsa', help="RSA operations")
    rs_sub = rs.add_subparsers(dest='sub', required=True)
    rs_gen = rs_sub.add_parser('gen', help="Generate RSA keypair")
    rs_gen.add_argument('--bits', type=int, default=2048, help="Key size in bits (default: 2048)")
    rs_gen.set_defaults(func=cmd_rsa)
    rs_enc = rs_sub.add_parser('encrypt', help="Encrypt with public key")
    rs_enc.add_argument('pub', help="Public key PEM file")
    rs_enc.add_argument('input')
    rs_enc.set_defaults(func=cmd_rsa)
    rs_dec = rs_sub.add_parser('decrypt', help="Decrypt with private key")
    rs_dec.add_argument('priv', help="Private key PEM file")
    rs_dec.add_argument('input', help="Ciphertext hex")
    rs_dec.set_defaults(func=cmd_rsa)
    rs_sign = rs_sub.add_parser('sign', help="Sign with private key")
    rs_sign.add_argument('priv')
    rs_sign.add_argument('input')
    rs_sign.add_argument('--hash', default='SHA256', choices=['SHA256', 'SHA1'])
    rs_sign.set_defaults(func=cmd_rsa)
    rs_ver = rs_sub.add_parser('verify', help="Verify signature with public key")
    rs_ver.add_argument('pub')
    rs_ver.add_argument('input')
    rs_ver.add_argument('sig', help="Signature hex")
    rs_ver.add_argument('--hash', default='SHA256', choices=['SHA256', 'SHA1'])
    rs_ver.set_defaults(func=cmd_rsa)

    # checksum
    cs = sub.add_parser('checksum', help="CRC32/Adler-32 checksum")
    cs.add_argument('algo', choices=['crc32', 'adler32'])
    cs.add_argument('input')
    cs.add_argument('--hex', action='store_true', help="Treat input as hex")
    cs.set_defaults(func=cmd_checksum)

    # color
    co = sub.add_parser('color', help="Color code converter")
    cos = co.add_subparsers(dest='sub', required=True)
    c1 = cos.add_parser('hex-to-rgb', help="Hex color to RGB")
    c1.add_argument('hex')
    c1.set_defaults(func=cmd_color)
    c2 = cos.add_parser('rgb-to-hex', help="RGB to hex color")
    c2.add_argument('r', type=int)
    c2.add_argument('g', type=int)
    c2.add_argument('b', type=int)
    c2.set_defaults(func=cmd_color)
    c3 = cos.add_parser('rgb-to-hsl', help="RGB to HSL")
    c3.add_argument('r', type=int)
    c3.add_argument('g', type=int)
    c3.add_argument('b', type=int)
    c3.set_defaults(func=cmd_color)
    c4 = cos.add_parser('hsl-to-rgb', help="HSL to RGB")
    c4.add_argument('h', type=float)
    c4.add_argument('s', type=float)
    c4.add_argument('l', type=float)
    c4.set_defaults(func=cmd_color)

    # time
    ti = sub.add_parser('time', help="Unix timestamp ↔ human-readable ISO 8601")
    tis = ti.add_subparsers(dest='sub', required=True)
    t1 = tis.add_parser('unix-to-human', help="Unix timestamp to ISO 8601")
    t1.add_argument('ts', help="Unix timestamp (seconds)")
    t1.set_defaults(func=cmd_time)
    t2 = tis.add_parser('human-to-unix', help="ISO 8601 to Unix timestamp")
    t2.add_argument('iso', help="ISO 8601 datetime string")
    t2.set_defaults(func=cmd_time)

    # dump
    d = sub.add_parser('dump', help="File hex dump viewer")
    d.add_argument('path', help="Path to file")
    d.add_argument('--width', type=int, default=16, help="Bytes per line (default: 16)")
    d.set_defaults(func=cmd_dump)

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except (ValueError, RuntimeError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
