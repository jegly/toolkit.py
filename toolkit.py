#!/usr/bin/env python3
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
import time
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
    s = s.strip().replace(" ", "").replace("0x", "")
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
    return s.encode('utf-16-be' if be else 'utf-16')

def bytes_to_utf8(b: bytes) -> str:
    return b.decode('utf-8')

def bytes_to_utf16(b: bytes, be=False) -> str:
    return b.decode('utf-16-be' if be else 'utf-16')

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
    res = ''.join(reversed(res)) or '1'
    # preserve leading zeros
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return '1' * pad + res

def base58_decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n *= 58
        n += B58_ALPHABET.index(ch)
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    # restore leading zeros
    pad = 0
    for ch in s:
        if ch == '1':
            pad += 1
        else:
            break
    return b'\x00' * pad + b

# Base85 (ASCII85/Z85 via stdlib: ascii85/base64.a85)
def ascii85_encode(b: bytes) -> str:
    return base64.a85encode(b).decode('ascii')

def ascii85_decode(s: str) -> bytes:
    return base64.a85decode(s.encode('ascii'))

# UUencode (simple)
def uu_encode(b: bytes) -> str:
    lines = []
    for block in chunk(b, 45):
        # encode line length
        lines.append(chr(32 + len(block)))
        # 3-byte chunks -> 4 chars
        for c in chunk(block + b'\x00' * ((3 - len(block) % 3) % 3), 3):
            a, d, e = c
            n = (a << 16) | (d << 8) | e
            for shift in (18, 12, 6, 0):
                lines.append(chr(((n >> shift) & 0x3F) + 32))
        lines.append("\n")
    lines.append("`\n")  # termination
    return ''.join(lines)

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
    return codecs_encode_shift(s, 13)

def caesar(s: str, shift: int) -> str:
    return codecs_encode_shift(s, shift % 26)

def codecs_encode_shift(s: str, shift: int) -> str:
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
        t = (t + 1) % 1.0
        if t < 1/6: return p + (q - p) * 6 * t
        if t < 1/2: return q
        if t < 2/3: return p + (q - p) * (2/3 - t) * 6
        return p
    if s == 0:
        r = g = b = l
    else:
        q = l + s - l*s if l < 0.5 else l + s - l*s
        p = 2*l - q
        r = hue2rgb(p, q, h + 1/3)
        g = hue2rgb(p, q, h)
        b = hue2rgb(p, q, h - 1/3)
    return int(round(r*255)), int(round(g*255)), int(round(b*255))

# Time conversions
def unix_to_human(ts: int, tz='UTC'):
    dt = datetime.fromtimestamp(ts, tz=timezone.utc if tz == 'UTC' else None)
    return dt.isoformat()

def human_to_unix(dt_str: str):
    return int(datetime.fromisoformat(dt_str.replace('Z', '+00:00')).timestamp())

# File hex dump
def hexdump(path: str, width=16):
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
def aes_encrypt(data: bytes, key: bytes, mode: str, iv_or_nonce: bytes = None, aad: bytes = None):
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
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv_or_nonce), backend=backend)
        ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
        return ct
    elif mode == 'CTR':
        if iv_or_nonce is None or len(iv_or_nonce) != 16:
            raise ValueError("CTR needs 16-byte nonce/counter")
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv_or_nonce), backend=backend)
        ct = cipher.encryptor().update(data) + cipher.encryptor().finalize()
        return ct
    elif mode == 'GCM':
        if iv_or_nonce is None or len(iv_or_nonce) not in (12, 16):
            raise ValueError("GCM needs 12/16-byte nonce")
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv_or_nonce), backend=backend).encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)
        ct = encryptor.update(data) + encryptor.finalize()
        return ct + encryptor.tag
    else:
        raise ValueError("Unsupported AES mode")

def aes_decrypt(ct: bytes, key: bytes, mode: str, iv_or_nonce: bytes = None, aad: bytes = None):
    if Cipher is None:
        raise RuntimeError("cryptography not installed")
    if len(key) != 32:
        raise ValueError("AES-256 requires 32-byte key")
    backend = default_backend()
    mode = mode.upper()
    if mode == 'CBC':
        if iv_or_nonce is None or len(iv_or_nonce) != 16:
            raise ValueError("CBC needs 16-byte IV")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv_or_nonce), backend=backend)
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        data = unpadder.update(padded) + unpadder.finalize()
        return data
    elif mode == 'CTR':
        if iv_or_nonce is None or len(iv_or_nonce) != 16:
            raise ValueError("CTR needs 16-byte nonce/counter")
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv_or_nonce), backend=backend)
        data = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
        return data
    elif mode == 'GCM':
        if iv_or_nonce is None or len(iv_or_nonce) not in (12, 16):
            raise ValueError("GCM needs 12/16-byte nonce")
        if len(ct) < 16:
            raise ValueError("ciphertext must include tag (last 16 bytes)")
        tag = ct[-16:]
        body = ct[:-16]
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv_or_nonce, tag), backend=backend).decryptor()
        if aad:
            decryptor.authenticate_additional_data(aad)
        data = decryptor.update(body) + decryptor.finalize()
        return data
    else:
        raise ValueError("Unsupported AES mode")

# RSA utilities
def rsa_generate(bits=2048):
    if Cipher is None:
        raise RuntimeError("cryptography not installed")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_serialize_private(pk):
    return pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def rsa_serialize_public(pub):
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def rsa_load_private(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)

def rsa_load_public(pem: bytes):
    return serialization.load_pem_public_key(pem)

def rsa_encrypt(pub, data: bytes, oaep_hash='SHA256'):
    h = hashes.SHA256() if oaep_hash.upper() == 'SHA256' else hashes.SHA1()
    return pub.encrypt(
        data,
        asympadding.OAEP(
            mgf=asympadding.MGF1(algorithm=h),
            algorithm=h,
            label=None
        )
    )

def rsa_decrypt(priv, ct: bytes, oaep_hash='SHA256'):
    h = hashes.SHA256() if oaep_hash.upper() == 'SHA256' else hashes.SHA1()
    return priv.decrypt(
        ct,
        asympadding.OAEP(
            mgf=asympadding.MGF1(algorithm=h),
            algorithm=h,
            label=None
        )
    )

def rsa_sign(priv, data: bytes, hash_alg='SHA256'):
    h = hashes.SHA256() if hash_alg.upper() == 'SHA256' else hashes.SHA1()
    return priv.sign(
        data,
        asympadding.PSS(
            mgf=asympadding.MGF1(h),
            salt_length=asympadding.PSS.MAX_LENGTH
        ),
        h
    )

def rsa_verify(pub, sig: bytes, data: bytes, hash_alg='SHA256'):
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

    # Auto-detect numeric if --number specified or input looks like hex/binary
    if args.number:
        # parse number (supports 0x..., 0b..., decimal)
        src_clean = str(src).strip().lower().replace('_', '')
        if src_clean.startswith('0x'):
            val = int(src_clean, 16)
        elif src_clean.startswith('0b'):
            val = int(src_clean, 2)
        else:
            val = int(src_clean, 10)
        # 32-bit big-endian representation
        width = (val.bit_length() + 7) // 8 or 1
        as_bytes = val.to_bytes(width, 'big')
        text_repr = str(val)
    else:
        # treat as text with encoding
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
        text_repr = src

    print(f"Input: {src}")
    print(f"Encoding: {encoding} {'(number mode)' if args.number else ''}")
    print()
    print("Representations:")
    print(f"- Decimal: {int.from_bytes(as_bytes, 'big') if as_bytes else 'N/A'}")
    print(f"- Hex: 0x{to_hex(as_bytes)}")
    print(f"- Binary: {to_binary(as_bytes)}")
    print()
    print("Byte breakdown:")
    print(f"- Bytes (hex): {' '.join(chunk for chunk in chunk(to_hex(as_bytes), 2))}")
    print(f"- Byte count: {len(as_bytes)}")
    print()
    print("Text interpretations:")
    # Latin-1, UTF-8, UTF-16 (BE)
    for enc in ('latin-1', 'utf-8', 'utf-16-be'):
        try:
            txt = as_bytes.decode(enc)
        except Exception:
            txt = "(invalid)"
        print(f"- {enc}: {txt}")
    print()
    print("Unicode per character (UTF-8 decode):")
    try:
        s = as_bytes.decode('utf-8')
        for ch in s:
            cp = f"U+{ord(ch):04X}"
            import unicodedata
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
            print(uu_encode(data))
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
    if algo == 'md5':
        print(hashlib.md5(data).hexdigest())
    elif algo == 'sha1':
        print(hashlib.sha1(data).hexdigest())
    elif algo == 'sha256':
        print(hashlib.sha256(data).hexdigest())
    else:
        raise SystemExit("Unknown hash")

def cmd_hmac(args):
    key = to_bytes(args.key)
    data = to_bytes(args.input)
    algo = args.algo.lower()
    if algo == 'md5':
        digestmod = hashlib.md5
    elif algo == 'sha1':
        digestmod = hashlib.sha1
    elif algo == 'sha256':
        digestmod = hashlib.sha256
    else:
        raise SystemExit("Unknown HMAC hash")
    print(hmac.new(key, data, digestmod).hexdigest())

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

def cmd_aes(args):
    if Cipher is None:
        raise SystemExit("cryptography not installed. pip install cryptography")
    key = from_hex(args.key) if args.key.startswith('0x') or re.fullmatch(r'[0-9a-fA-F]+', args.key) else to_bytes(args.key)
    if len(key) != 32:
        raise SystemExit("AES-256 requires 32-byte key")
    iv = None
    if args.iv:
        iv = from_hex(args.iv) if args.iv.startswith('0x') or re.fullmatch(r'[0-9a-fA-F]+', args.iv) else to_bytes(args.iv)
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
        pub = rsa_load_public(to_bytes(open(args.pub, 'rb').read()))
        ct = rsa_encrypt(pub, to_bytes(args.input))
        print(to_hex(ct))
    elif args.sub == 'decrypt':
        priv = rsa_load_private(to_bytes(open(args.priv, 'rb').read()))
        pt = rsa_decrypt(priv, from_hex(args.input))
        print(pt.decode('utf-8', errors='replace'))
    elif args.sub == 'sign':
        priv = rsa_load_private(to_bytes(open(args.priv, 'rb').read()))
        sig = rsa_sign(priv, to_bytes(args.input), args.hash)
        print(to_hex(sig))
    elif args.sub == 'verify':
        pub = rsa_load_public(to_bytes(open(args.pub, 'rb').read()))
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
    print(hexdump(args.path, width=args.width))

# ---------- Argument parser ----------
def build_parser():
    p = argparse.ArgumentParser(description="Encoder/Decoder Toolkit")
    sub = p.add_subparsers(dest='cmd', required=True)

    # convert
    c = sub.add_parser('convert', help="Text/number to hex/binary/encodings")
    c.add_argument('input', help="Text or number")
    c.add_argument('--encoding', default='utf-8', choices=['utf-8','ascii','latin1','utf16','utf16-be'], help="Input text encoding (ignored for --number)")
    c.add_argument('--number', action='store_true', help="Treat input as number")
    c.set_defaults(func=cmd_convert)

    # base
    b = sub.add_parser('base', help="Base encoders/decoders")
    b.add_argument('action', choices=['encode','decode'])
    b.add_argument('scheme', choices=['base64','base32','base58','base85','uu','base91'])
    b.add_argument('input', help="Input (text or hex)")
    b.add_argument('--hex', action='store_true', help="Interpret input as hex")
    b.set_defaults(func=cmd_base)

    # morse
    m = sub.add_parser('morse', help="Morse encoder/decoder")
    m.add_argument('action', choices=['encode','decode'])
    m.add_argument('input')
    m.set_defaults(func=cmd_morse)

    # rot/caesar
    r = sub.add_parser('rot', help="ROT13/Caesar")
    r.add_argument('scheme', choices=['rot13','caesar'])
    r.add_argument('input')
    r.add_argument('--shift', type=int, default=13, help="Shift for Caesar")
    r.set_defaults(func=cmd_rot)

    # hash
    h = sub.add_parser('hash', help="Hash generator")
    h.add_argument('algo', choices=['md5','sha1','sha256'])
    h.add_argument('input')
    h.set_defaults(func=cmd_hash)

    # hmac
    hm = sub.add_parser('hmac', help="HMAC generator")
    hm.add_argument('algo', choices=['md5','sha1','sha256'])
    hm.add_argument('key')
    hm.add_argument('input')
    hm.set_defaults(func=cmd_hmac)

    # xor
    x = sub.add_parser('xor', help="XOR encoder/decoder")
    x.add_argument('key')
    x.add_argument('input')
    x.add_argument('--hex', action='store_true', help="Input as hex")
    x.add_argument('--output', choices=['text','hex','binary'], default='text')
    x.set_defaults(func=cmd_xor)

    # aes
    ae = sub.add_parser('aes', help="AES-256 encrypt/decrypt")
    ae.add_argument('action', choices=['encrypt','decrypt'])
    ae.add_argument('mode', choices=['CBC','CTR','GCM'])
    ae.add_argument('key', help="32-byte key (hex or text)")
    ae.add_argument('input', help="Plaintext (encrypt) or ciphertext (decrypt). Use --hex for ciphertext hex.")
    ae.add_argument('--iv', help="IV/nonce (hex or text)")
    ae.add_argument('--hex', action='store_true', help="Treat input as hex")
    ae.set_defaults(func=cmd_aes)

    # rsa
    rs = sub.add_parser('rsa', help="RSA operations")
    rs_sub = rs.add_subparsers(dest='sub', required=True)
    rs_gen = rs_sub.add_parser('gen', help="Generate RSA keypair")
    rs_gen.add_argument('--bits', type=int, default=2048)
    rs_gen.set_defaults(func=cmd_rsa)
    rs_enc = rs_sub.add_parser('encrypt')
    rs_enc.add_argument('pub', help="Public key PEM file")
    rs_enc.add_argument('input')
    rs_enc.set_defaults(func=cmd_rsa)
    rs_dec = rs_sub.add_parser('decrypt')
    rs_dec.add_argument('priv', help="Private key PEM file")
    rs_dec.add_argument('input', help="Ciphertext hex")
    rs_dec.set_defaults(func=cmd_rsa)
    rs_sign = rs_sub.add_parser('sign')
    rs_sign.add_argument('priv')
    rs_sign.add_argument('input')
    rs_sign.add_argument('--hash', default='SHA256', choices=['SHA256','SHA1'])
    rs_sign.set_defaults(func=cmd_rsa)
    rs_ver = rs_sub.add_parser('verify')
    rs_ver.add_argument('pub')
    rs_ver.add_argument('input')
    rs_ver.add_argument('sig', help="Signature hex")
    rs_ver.add_argument('--hash', default='SHA256', choices=['SHA256','SHA1'])
    rs_ver.set_defaults(func=cmd_rsa)

    # checksum
    cs = sub.add_parser('checksum', help="CRC32/Adler-32")
    cs.add_argument('algo', choices=['crc32','adler32'])
    cs.add_argument('input')
    cs.add_argument('--hex', action='store_true')
    cs.set_defaults(func=cmd_checksum)

    # color
    co = sub.add_parser('color', help="Color code converter")
    cos = co.add_subparsers(dest='sub', required=True)
    c1 = cos.add_parser('hex-to-rgb')
    c1.add_argument('hex')
    c1.set_defaults(func=cmd_color)
    c2 = cos.add_parser('rgb-to-hex')
    c2.add_argument('r', type=int)
    c2.add_argument('g', type=int)
    c2.add_argument('b', type=int)
    c2.set_defaults(func=cmd_color)
    c3 = cos.add_parser('rgb-to-hsl')
    c3.add_argument('r', type=int)
    c3.add_argument('g', type=int)
    c3.add_argument('b', type=int)
    c3.set_defaults(func=cmd_color)
    c4 = cos.add_parser('hsl-to-rgb')
    c4.add_argument('h', type=float)
    c4.add_argument('s', type=float)
    c4.add_argument('l', type=float)
    c4.set_defaults(func=cmd_color)

    # time
    ti = sub.add_parser('time', help="Unix timestamp ↔ human-readable")
    tis = ti.add_subparsers(dest='sub', required=True)
    t1 = tis.add_parser('unix-to-human')
    t1.add_argument('ts')
    t1.set_defaults(func=cmd_time)
    t2 = tis.add_parser('human-to-unix')
    t2.add_argument('iso')
    t2.set_defaults(func=cmd_time)

    # dump
    d = sub.add_parser('dump', help="File to hex dump viewer")
    d.add_argument('path')
    d.add_argument('--width', type=int, default=16)
    d.set_defaults(func=cmd_dump)

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()

