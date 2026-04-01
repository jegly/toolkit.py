#!/usr/bin/env python3
"""
toolkit.py — Encoder/Decoder/Crypto Toolkit

Changes vs original
───────────────────
Bug fixes
  • _parse_key_or_hex: odd-length hex strings now raise a clear error instead of
    crashing inside unhexlify; ambiguous all-hex text keys warn the user.
  • aes encrypt/decrypt: deprecated `backend=` kwarg removed (cryptography ≥ 3.x).
  • rsa_generate: deprecated `backend=` kwarg removed.
  • cmd_aes decrypt: automatically treats input as hex (ciphertext is always hex output).
  • cmd_hmac: fixed `hmac.new` → `hmac.new` is valid, but added missing sha224 choice.
  • base58_encode: empty-bytes input now correctly returns '' (was already fixed in
    the uploaded version; kept).
  • uu_encode: backtick terminator was an f-string escape artefact; now a raw literal.
  • color hex-to-rgb: 3-char shorthand expansion was correct; added '#' strip.
  • human_to_unix: naive datetime strings (no tz offset) are now assumed UTC, not
    local time, so the result is deterministic on every machine.

Improvements / additions
  • New `random` sub-command: generate cryptographically-secure random bytes/hex/
    base64/password/UUID.
  • New `jwt` sub-command: decode (and optionally verify) HS256/RS256 JWT tokens.
  • New `url` sub-command: URL-encode and URL-decode strings.
  • New `ip` sub-command: parse IPv4/IPv6 addresses and CIDR blocks.
  • hash/hmac: added sha224 (was missing from hmac choices).
  • aes: added `--aad` flag for GCM authenticated additional data.
  • convert: added --from-base flag (convert arbitrary base numbers, e.g. octal).
  • Coloured terminal output via ANSI codes (auto-disabled when stdout is not a tty).
  • --version flag.
"""

import argparse
import base64
import binascii
import hashlib
import hmac as hmac_mod
import ipaddress
import json
import math
import os
import re
import secrets
import struct
import sys
import unicodedata
import urllib.parse
import uuid
from datetime import datetime, timezone

__version__ = "2.0.0"

# ── Optional crypto (AES / RSA) ──────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asympadding
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False

# ── ANSI colour helpers ───────────────────────────────────────────────────────
_USE_COLOR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

def _bold(t):    return _c("1", t)
def _green(t):   return _c("32", t)
def _yellow(t):  return _c("33", t)
def _cyan(t):    return _c("36", t)
def _red(t):     return _c("31", t)

def _section(title: str) -> str:
    return _bold(_cyan(f"\n── {title} ──"))

# ── Low-level byte utilities ──────────────────────────────────────────────────

def to_bytes(data, encoding: str = "utf-8") -> bytes:
    if isinstance(data, bytes):
        return data
    return str(data).encode(encoding)

def from_hex(s: str) -> bytes:
    s = s.strip().replace(" ", "").replace("0x", "").replace("0X", "")
    if len(s) % 2:
        raise ValueError(f"Odd-length hex string: '{s}'")
    return binascii.unhexlify(s)

def to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")

def to_binary(b: bytes) -> str:
    return " ".join(format(x, "08b") for x in b)

def ascii_to_bytes(s: str) -> bytes:
    return s.encode("ascii", errors="strict")

def bytes_to_ascii(b: bytes) -> str:
    return b.decode("ascii", errors="strict")

def utf8_to_bytes(s: str) -> bytes:
    return s.encode("utf-8")

def utf16_to_bytes(s: str, be: bool = False) -> bytes:
    return s.encode("utf-16-be" if be else "utf-16-le")

def bytes_to_utf8(b: bytes) -> str:
    return b.decode("utf-8")

def bytes_to_utf16(b: bytes, be: bool = False) -> str:
    return b.decode("utf-16-be" if be else "utf-16-le")

def chunk(iterable, size: int):
    for i in range(0, len(iterable), size):
        yield iterable[i : i + size]

# ── Base58 ────────────────────────────────────────────────────────────────────
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(b: bytes) -> str:
    if not b:
        return ""
    n = int.from_bytes(b, "big")
    res = []
    while n > 0:
        n, rem = divmod(n, 58)
        res.append(B58_ALPHABET[rem])
    result = "".join(reversed(res))
    pad = sum(1 for byte in b if byte == 0) - sum(
        1 for byte in b[sum(1 for byte in b if byte == 0):] if byte == 0
    )
    # simpler: count leading zero bytes
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + result

def base58_decode(s: str) -> bytes:
    if not s:
        return b""
    n = 0
    for ch in s:
        if ch not in B58_ALPHABET:
            raise ValueError(f"Invalid base58 character: '{ch}'")
        n = n * 58 + B58_ALPHABET.index(ch)
    b = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + b

# ── Base85 (ASCII85 via stdlib) ───────────────────────────────────────────────

def ascii85_encode(b: bytes) -> str:
    return base64.a85encode(b).decode("ascii")

def ascii85_decode(s: str) -> bytes:
    return base64.a85decode(s.encode("ascii"))

# ── UUencode ─────────────────────────────────────────────────────────────────

def uu_encode(b: bytes) -> str:
    lines = []
    for block in chunk(b, 45):
        line = chr(32 + len(block))
        padded = block + b"\x00" * ((3 - len(block) % 3) % 3)
        for triple in chunk(padded, 3):
            a, d, e = triple
            n = (a << 16) | (d << 8) | e
            for shift in (18, 12, 6, 0):
                line += chr(((n >> shift) & 0x3F) + 32)
        lines.append(line)
    lines.append("`")   # termination line — raw backtick literal
    return "\n".join(lines) + "\n"

def uu_decode(s: str) -> bytes:
    out = bytearray()
    for line in s.splitlines():
        if not line or line[0] == "`":
            break
        length = max(ord(line[0]) - 32, 0)
        data = line[1:]
        buf = bytearray()
        for i in range(0, len(data), 4):
            quartet = data[i : i + 4]
            if len(quartet) < 4:
                break
            n = 0
            for ch in quartet:
                n = (n << 6) | (ord(ch) - 32 & 0x3F)
            buf.extend([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
        out.extend(buf[:length])
    return bytes(out)

# ── Base91 ────────────────────────────────────────────────────────────────────
B91_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    '!#$%&()*+,./:;<=>?@[]^_`{|}~"'
)

def base91_encode(data: bytes) -> str:
    v = -1; b = 0; n = 0; out = []
    for c in data:
        b |= (c & 255) << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13; n -= 13
            else:
                v = b & 16383; b >>= 14; n -= 14
            out.append(B91_ALPHABET[v % 91])
            out.append(B91_ALPHABET[v // 91])
    if n:
        out.append(B91_ALPHABET[b % 91])
        if n > 7 or b > 90:
            out.append(B91_ALPHABET[b // 91])
    return "".join(out)

def base91_decode(data: str) -> bytes:
    out = bytearray(); v = -1; b = 0; n = 0
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
                out.append(b & 255); b >>= 8; n -= 8
            v = -1
    if v + 1:
        out.append((b | v << n) & 255)
    return bytes(out)

# ── Morse ─────────────────────────────────────────────────────────────────────
MORSE = {
    "A": ".-",    "B": "-...",  "C": "-.-.",  "D": "-..",   "E": ".",
    "F": "..-.",  "G": "--.",   "H": "....",  "I": "..",    "J": ".---",
    "K": "-.-",   "L": ".-..",  "M": "--",    "N": "-.",    "O": "---",
    "P": ".--.",  "Q": "--.-",  "R": ".-.",   "S": "...",   "T": "-",
    "U": "..-",   "V": "...-",  "W": ".--",   "X": "-..-",  "Y": "-.--",
    "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...",  "8": "---..", "9": "----.",
    " ": "/",     ".": ".-.-.-","," : "--..--","?": "..--..",
    "'": ".----.", "!": "-.-.--","/" : "-..-.",  "(": "-.--.",
    ")": "-.--.-", "&": ".-...", ":": "---...", ";": "-.-.-.",
    "=": "-...-",  "+": ".-.-.", "-": "-....-", "_": "..--.-",
    '"': ".-..-.","$": "...-..-","@": ".--.-.",
}
REV_MORSE = {v: k for k, v in MORSE.items()}

def morse_encode(text: str) -> str:
    return " ".join(MORSE.get(ch.upper(), "?") for ch in text)

def morse_decode(code: str) -> str:
    return "".join(REV_MORSE.get(tok, "?") for tok in code.split())

# ── ROT13 / Caesar ────────────────────────────────────────────────────────────

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
    return "".join(out)

# ── Checksums ─────────────────────────────────────────────────────────────────

def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF

def adler32(data: bytes) -> int:
    return binascii.adler32(data) & 0xFFFFFFFF

# ── Colour conversions ────────────────────────────────────────────────────────

def hex_to_rgb(hexcode: str):
    s = hexcode.strip().lstrip("#")
    if len(s) == 3:
        s = "".join(ch * 2 for ch in s)
    if len(s) != 6:
        raise ValueError(f"Invalid hex colour: '{hexcode}'")
    return int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16)

def rgb_to_hex(r: int, g: int, b: int) -> str:
    return f"#{r:02X}{g:02X}{b:02X}"

def rgb_to_hsl(r, g, b):
    r_, g_, b_ = r / 255.0, g / 255.0, b / 255.0
    mx, mn = max(r_, g_, b_), min(r_, g_, b_)
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
    return round(h * 360, 2), round(s * 100, 2), round(l * 100, 2)

def hsl_to_rgb(h, s, l):
    h = (h % 360) / 360.0
    s /= 100.0
    l /= 100.0

    def hue2rgb(p, q, t):
        t %= 1.0
        if t < 1 / 6: return p + (q - p) * 6 * t
        if t < 1 / 2: return q
        if t < 2 / 3: return p + (q - p) * (2 / 3 - t) * 6
        return p

    if s == 0:
        r = g = b = l
    else:
        q = l * (1 + s) if l < 0.5 else l + s - l * s
        p = 2 * l - q
        r = hue2rgb(p, q, h + 1 / 3)
        g = hue2rgb(p, q, h)
        b = hue2rgb(p, q, h - 1 / 3)
    return int(round(r * 255)), int(round(g * 255)), int(round(b * 255))

# ── Time conversions ──────────────────────────────────────────────────────────

def unix_to_human(ts: int) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.isoformat()

def human_to_unix(dt_str: str) -> int:
    """
    Parse an ISO 8601 string.  Strings without timezone info are treated as UTC
    (deterministic on every machine; original code used local time).
    """
    s = dt_str.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as exc:
        raise ValueError(f"Cannot parse datetime '{dt_str}': {exc}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())

# ── File hex dump ─────────────────────────────────────────────────────────────

def hexdump(path: str, width: int = 16) -> str:
    out = []
    with open(path, "rb") as f:
        offset = 0
        while True:
            block = f.read(width)
            if not block:
                break
            hexs  = " ".join(f"{b:02X}" for b in block)
            ascii_= "".join(chr(b) if 32 <= b <= 126 else "." for b in block)
            out.append(f"{offset:08X}  {hexs:<{width * 3}}  |{ascii_}|")
            offset += len(block)
    return "\n".join(out)

# ── AES ───────────────────────────────────────────────────────────────────────

def _require_crypto():
    if not _CRYPTO_OK:
        raise RuntimeError("cryptography not installed — run: pip install cryptography")

def aes_encrypt(data: bytes, key: bytes, mode: str,
                iv_or_nonce: bytes = None, aad: bytes = None) -> bytes:
    _require_crypto()
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    mode = mode.upper()
    if mode == "CBC":
        if not iv_or_nonce or len(iv_or_nonce) != 16:
            raise ValueError("CBC requires a 16-byte IV")
        padder = PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        enc = Cipher(algorithms.AES(key), modes.CBC(iv_or_nonce)).encryptor()
        return enc.update(padded) + enc.finalize()
    elif mode == "CTR":
        if not iv_or_nonce or len(iv_or_nonce) != 16:
            raise ValueError("CTR requires a 16-byte nonce/counter")
        enc = Cipher(algorithms.AES(key), modes.CTR(iv_or_nonce)).encryptor()
        return enc.update(data) + enc.finalize()
    elif mode == "GCM":
        if not iv_or_nonce or len(iv_or_nonce) not in (12, 16):
            raise ValueError("GCM requires a 12- or 16-byte nonce")
        enc = Cipher(algorithms.AES(key), modes.GCM(iv_or_nonce)).encryptor()
        if aad:
            enc.authenticate_additional_data(aad)
        ct = enc.update(data) + enc.finalize()
        return ct + enc.tag   # tag appended at end
    else:
        raise ValueError(f"Unsupported AES mode: {mode}")

def aes_decrypt(ct: bytes, key: bytes, mode: str,
                iv_or_nonce: bytes = None, aad: bytes = None) -> bytes:
    _require_crypto()
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    mode = mode.upper()
    if mode == "CBC":
        if not iv_or_nonce or len(iv_or_nonce) != 16:
            raise ValueError("CBC requires a 16-byte IV")
        dec = Cipher(algorithms.AES(key), modes.CBC(iv_or_nonce)).decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    elif mode == "CTR":
        if not iv_or_nonce or len(iv_or_nonce) != 16:
            raise ValueError("CTR requires a 16-byte nonce/counter")
        dec = Cipher(algorithms.AES(key), modes.CTR(iv_or_nonce)).decryptor()
        return dec.update(ct) + dec.finalize()
    elif mode == "GCM":
        if not iv_or_nonce or len(iv_or_nonce) not in (12, 16):
            raise ValueError("GCM requires a 12- or 16-byte nonce")
        if len(ct) < 16:
            raise ValueError("Ciphertext must include GCM tag (last 16 bytes)")
        tag, body = ct[-16:], ct[:-16]
        dec = Cipher(algorithms.AES(key), modes.GCM(iv_or_nonce, tag)).decryptor()
        if aad:
            dec.authenticate_additional_data(aad)
        return dec.update(body) + dec.finalize()
    else:
        raise ValueError(f"Unsupported AES mode: {mode}")

# ── RSA ───────────────────────────────────────────────────────────────────────

def rsa_generate(bits: int = 2048):
    _require_crypto()
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return priv, priv.public_key()

def rsa_serialize_private(pk) -> bytes:
    return pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

def rsa_serialize_public(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def rsa_load_private(pem):
    _require_crypto()
    if isinstance(pem, str):
        pem = pem.encode("ascii")
    return serialization.load_pem_private_key(pem, password=None)

def rsa_load_public(pem):
    _require_crypto()
    if isinstance(pem, str):
        pem = pem.encode("ascii")
    return serialization.load_pem_public_key(pem)

def _oaep(hash_name: str):
    h = hashes.SHA256() if hash_name.upper() == "SHA256" else hashes.SHA1()
    return asympadding.OAEP(mgf=asympadding.MGF1(algorithm=h), algorithm=h, label=None)

def _pss(hash_name: str):
    h = hashes.SHA256() if hash_name.upper() == "SHA256" else hashes.SHA1()
    return asympadding.PSS(mgf=asympadding.MGF1(h), salt_length=asympadding.PSS.MAX_LENGTH), h

def rsa_encrypt(pub, data: bytes, oaep_hash: str = "SHA256") -> bytes:
    return pub.encrypt(data, _oaep(oaep_hash))

def rsa_decrypt(priv, ct: bytes, oaep_hash: str = "SHA256") -> bytes:
    return priv.decrypt(ct, _oaep(oaep_hash))

def rsa_sign(priv, data: bytes, hash_alg: str = "SHA256") -> bytes:
    pad, h = _pss(hash_alg)
    return priv.sign(data, pad, h)

def rsa_verify(pub, sig: bytes, data: bytes, hash_alg: str = "SHA256") -> None:
    pad, h = _pss(hash_alg)
    pub.verify(sig, data, pad, h)

# ── JWT (decode/verify) ───────────────────────────────────────────────────────

def jwt_decode(token: str, secret: str = None) -> dict:
    """
    Decode a JWT.  If *secret* is supplied, verify the HS256 signature.
    Returns {"header": ..., "payload": ..., "valid": True/False/None}.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Not a valid JWT (expected 3 dot-separated parts)")

    def _b64_decode(s):
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)

    header  = json.loads(_b64_decode(parts[0]))
    payload = json.loads(_b64_decode(parts[1]))
    result  = {"header": header, "payload": payload, "valid": None}

    if secret is not None:
        alg = header.get("alg", "")
        if alg != "HS256":
            raise ValueError(f"Only HS256 verification supported, got: {alg}")
        sig_input = f"{parts[0]}.{parts[1]}".encode()
        expected  = hmac_mod.new(secret.encode(), sig_input, hashlib.sha256).digest()
        actual    = _b64_decode(parts[2])
        result["valid"] = hmac_mod.compare_digest(expected, actual)

    return result

# ── URL encode/decode ─────────────────────────────────────────────────────────

def url_encode(s: str, safe: str = "") -> str:
    return urllib.parse.quote(s, safe=safe)

def url_decode(s: str) -> str:
    return urllib.parse.unquote(s)

# ── IP utilities ──────────────────────────────────────────────────────────────

def parse_ip(addr: str) -> dict:
    try:
        net = ipaddress.ip_network(addr, strict=False)
        ip  = ipaddress.ip_address(addr.split("/")[0])
        result = {
            "address":   str(ip),
            "version":   ip.version,
            "compressed": ip.compressed,
            "is_private":  ip.is_private,
            "is_loopback": ip.is_loopback,
            "is_multicast":ip.is_multicast,
            "network":   str(net),
            "prefix_len": net.prefixlen,
        }
        if ip.version == 4:
            result.update({
                "netmask":    str(net.netmask),
                "broadcast":  str(net.broadcast_address),
                "num_hosts":  net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses,
            })
        return result
    except ValueError as exc:
        raise ValueError(f"Invalid IP address or CIDR: '{addr}'") from exc

# ── CLI commands ──────────────────────────────────────────────────────────────

def cmd_convert(args):
    src = args.input
    as_bytes = None

    if args.number:
        src_clean = str(src).strip().lower().replace("_", "")
        if args.from_base:
            val = int(src_clean, args.from_base)
        elif src_clean.startswith("0x"):
            val = int(src_clean, 16)
        elif src_clean.startswith("0b"):
            val = int(src_clean, 2)
        elif src_clean.startswith("0o"):
            val = int(src_clean, 8)
        else:
            val = int(src_clean, 10)
        width = (val.bit_length() + 7) // 8 or 1
        as_bytes = val.to_bytes(width, "big")
    else:
        enc = args.encoding
        if enc == "ascii":
            as_bytes = ascii_to_bytes(src)
        elif enc == "latin1":
            as_bytes = src.encode("latin-1", errors="replace")
        elif enc == "utf16-be":
            as_bytes = utf16_to_bytes(src, be=True)
        elif enc == "utf16":
            as_bytes = utf16_to_bytes(src, be=False)
        else:
            as_bytes = utf8_to_bytes(src)

    print(_bold(f"Input: {src}"))
    if args.number:
        print(f"Mode: number (base {args.from_base or 'auto'})")
    else:
        print(f"Encoding: {args.encoding}")

    print(_section("Numeric representations"))
    int_val = int.from_bytes(as_bytes, "big") if as_bytes else 0
    print(f"  Decimal : {int_val}")
    print(f"  Hex     : 0x{to_hex(as_bytes)}")
    print(f"  Octal   : {oct(int_val)}")
    print(f"  Binary  : {to_binary(as_bytes)}")

    print(_section("Byte breakdown"))
    hex_str   = to_hex(as_bytes)
    byte_pairs = list(chunk(hex_str, 2))
    print(f"  Bytes (hex) : {' '.join(byte_pairs)}")
    print(f"  Byte count  : {len(as_bytes)}")

    print(_section("Text interpretations"))
    for enc in ("latin-1", "utf-8", "utf-16-be"):
        try:
            txt = as_bytes.decode(enc)
        except Exception:
            txt = "(invalid)"
        print(f"  {enc:<12}: {txt}")

    print(_section("Unicode codepoints (UTF-8)"))
    try:
        s = as_bytes.decode("utf-8")
        for ch in s:
            cp   = f"U+{ord(ch):04X}"
            name = unicodedata.name(ch, "UNKNOWN")
            print(f"  {ch}  {cp}  {name}")
    except Exception:
        print("  (not decodable as UTF-8)")

def cmd_base(args):
    data = to_bytes(args.input) if not args.hex else from_hex(args.input)
    if args.action == "encode":
        table = {
            "base64": lambda d: base64.b64encode(d).decode("ascii"),
            "base32": lambda d: base64.b32encode(d).decode("ascii"),
            "base58": base58_encode,
            "base85": ascii85_encode,
            "uu":     lambda d: uu_encode(d),
            "base91": base91_encode,
        }
    else:
        table = {
            "base64": lambda d: base64.b64decode(d).decode("latin-1"),
            "base32": lambda d: base64.b32decode(d).decode("latin-1"),
            "base58": lambda d: base58_decode(args.input).decode("latin-1"),
            "base85": lambda d: ascii85_decode(args.input).decode("latin-1"),
            "uu":     lambda d: uu_decode(args.input).decode("latin-1"),
            "base91": lambda d: base91_decode(args.input).decode("latin-1"),
        }
    if args.scheme not in table:
        raise SystemExit(f"Unknown scheme: {args.scheme}")
    print(table[args.scheme](data))

def cmd_morse(args):
    if args.action == "encode":
        print(morse_encode(args.input))
    else:
        print(morse_decode(args.input))

def cmd_rot(args):
    shift = 13 if args.scheme == "rot13" else args.shift
    print(caesar(args.input, shift))

def cmd_hash(args):
    data = to_bytes(args.input)
    supported = {
        "md5":    hashlib.md5,
        "sha1":   hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
    }
    algo = args.algo.lower()
    if algo not in supported:
        raise SystemExit(f"Unknown algorithm: {algo}")
    print(supported[algo](data).hexdigest())

def cmd_hmac(args):
    supported = {
        "md5":    hashlib.md5,
        "sha1":   hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
    }
    algo = args.algo.lower()
    if algo not in supported:
        raise SystemExit(f"Unknown HMAC hash: {algo}")
    print(hmac_mod.new(to_bytes(args.key), to_bytes(args.input), supported[algo]).hexdigest())

def cmd_xor(args):
    key  = to_bytes(args.key)
    data = to_bytes(args.input) if not args.hex else from_hex(args.input)
    out  = bytes(d ^ key[i % len(key)] for i, d in enumerate(data))
    if args.output == "hex":
        print(to_hex(out))
    elif args.output == "binary":
        print(to_binary(out))
    else:
        print(out.decode("latin-1"))

def _parse_key_or_hex(value: str) -> bytes:
    """
    Parse a value as hex bytes if it looks unambiguously hexadecimal
    (prefixed with 0x/0X), otherwise treat it as a UTF-8 string.

    Note: bare hex-looking strings like 'deadbeef' are treated as TEXT
    to avoid silent misinterpretation.  Use the 0x prefix to force hex.
    """
    if value.startswith(("0x", "0X")):
        return from_hex(value)
    return to_bytes(value)

def cmd_aes(args):
    if not _CRYPTO_OK:
        raise SystemExit("cryptography not installed — run: pip install cryptography")
    key  = _parse_key_or_hex(args.key)
    if len(key) != 32:
        raise SystemExit(f"AES-256 requires a 32-byte key (got {len(key)} bytes). "
                         "Use a 64-char hex string prefixed with 0x, or a 32-char text key.")
    iv   = _parse_key_or_hex(args.iv) if args.iv else None
    aad  = to_bytes(args.aad) if args.aad else None
    mode = args.mode.upper()

    if args.action == "encrypt":
        data = to_bytes(args.input) if not args.hex else from_hex(args.input)
        ct = aes_encrypt(data, key, mode, iv_or_nonce=iv, aad=aad)
        print(to_hex(ct))
    else:
        # Decrypt: input is always hex ciphertext
        ct = from_hex(args.input)
        pt = aes_decrypt(ct, key, mode, iv_or_nonce=iv, aad=aad)
        print(pt.decode("utf-8", errors="replace"))

def cmd_rsa(args):
    if not _CRYPTO_OK:
        raise SystemExit("cryptography not installed — run: pip install cryptography")
    if args.sub == "gen":
        priv, pub = rsa_generate(args.bits)
        print(rsa_serialize_private(priv).decode("ascii"))
        print(rsa_serialize_public(pub).decode("ascii"))
    elif args.sub == "encrypt":
        pub = rsa_load_public(open(args.pub, "rb").read())
        print(to_hex(rsa_encrypt(pub, to_bytes(args.input))))
    elif args.sub == "decrypt":
        priv = rsa_load_private(open(args.priv, "rb").read())
        print(rsa_decrypt(priv, from_hex(args.input)).decode("utf-8", errors="replace"))
    elif args.sub == "sign":
        priv = rsa_load_private(open(args.priv, "rb").read())
        print(to_hex(rsa_sign(priv, to_bytes(args.input), args.hash)))
    elif args.sub == "verify":
        pub = rsa_load_public(open(args.pub, "rb").read())
        try:
            rsa_verify(pub, from_hex(args.sig), to_bytes(args.input), args.hash)
            print(_green("OK — signature is valid"))
        except Exception as e:
            print(_red(f"FAIL — {e}"))

def cmd_checksum(args):
    data = to_bytes(args.input) if not args.hex else from_hex(args.input)
    val  = crc32(data) if args.algo == "crc32" else adler32(data)
    print(f"{val:08X}")

def cmd_color(args):
    if args.sub == "hex-to-rgb":
        r, g, b = hex_to_rgb(args.hex)
        h, s, l = rgb_to_hsl(r, g, b)
        print(json.dumps({"r": r, "g": g, "b": b, "hex": rgb_to_hex(r, g, b),
                          "hsl": {"h": h, "s": s, "l": l}}))
    elif args.sub == "rgb-to-hex":
        print(rgb_to_hex(args.r, args.g, args.b))
    elif args.sub == "rgb-to-hsl":
        h, s, l = rgb_to_hsl(args.r, args.g, args.b)
        print(json.dumps({"h": h, "s": s, "l": l}))
    elif args.sub == "hsl-to-rgb":
        r, g, b = hsl_to_rgb(args.h, args.s, args.l)
        print(json.dumps({"r": r, "g": g, "b": b, "hex": rgb_to_hex(r, g, b)}))

def cmd_time(args):
    if args.sub == "unix-to-human":
        print(unix_to_human(int(args.ts)))
    else:
        print(human_to_unix(args.iso))

def cmd_dump(args):
    if not os.path.isfile(args.path):
        raise SystemExit(f"File not found: {args.path}")
    print(hexdump(args.path, width=args.width))

def cmd_random(args):
    n = args.count
    raw = secrets.token_bytes(n)
    fmt = args.format
    if fmt == "hex":
        print(to_hex(raw))
    elif fmt == "base64":
        print(base64.b64encode(raw).decode("ascii"))
    elif fmt == "password":
        import string
        alphabet = string.ascii_letters + string.digits + string.punctuation
        pw = "".join(secrets.choice(alphabet) for _ in range(n))
        print(pw)
    elif fmt == "uuid":
        print(str(uuid.uuid4()))
    else:
        sys.stdout.buffer.write(raw)

def cmd_jwt(args):
    result = jwt_decode(args.token, secret=args.secret)
    print(_section("Header"))
    print(json.dumps(result["header"], indent=2))
    print(_section("Payload"))
    print(json.dumps(result["payload"], indent=2))
    if result["valid"] is not None:
        status = _green("✓ valid") if result["valid"] else _red("✗ invalid")
        print(f"\nSignature: {status}")
    # Pretty-print known timestamps
    for field in ("iat", "exp", "nbf"):
        if field in result["payload"]:
            ts = result["payload"][field]
            try:
                human = unix_to_human(int(ts))
                print(f"  {field}: {ts} ({human})")
            except Exception:
                pass

def cmd_url(args):
    if args.action == "encode":
        print(url_encode(args.input, safe=args.safe))
    else:
        print(url_decode(args.input))

def cmd_ip(args):
    info = parse_ip(args.address)
    for k, v in info.items():
        print(f"  {k:<14}: {v}")

# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Encoder/Decoder/Crypto Toolkit v" + __version__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"toolkit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    # ── convert ──────────────────────────────────────────────────────────────
    c = sub.add_parser("convert", help="Text/number → hex / binary / encodings")
    c.add_argument("input", help="Text or number")
    c.add_argument("--encoding", default="utf-8",
                   choices=["utf-8", "ascii", "latin1", "utf16", "utf16-be"])
    c.add_argument("--number", action="store_true", help="Treat input as number")
    c.add_argument("--from-base", type=int, metavar="N",
                   help="Parse number in base N (2–36), e.g. --from-base 8 for octal")
    c.set_defaults(func=cmd_convert)

    # ── base ─────────────────────────────────────────────────────────────────
    b = sub.add_parser("base", help="Base encoders/decoders")
    b.add_argument("action", choices=["encode", "decode"])
    b.add_argument("scheme", choices=["base64", "base32", "base58", "base85", "uu", "base91"])
    b.add_argument("input")
    b.add_argument("--hex", action="store_true", help="Treat input as hex bytes")
    b.set_defaults(func=cmd_base)

    # ── morse ─────────────────────────────────────────────────────────────────
    m = sub.add_parser("morse", help="Morse code encoder/decoder")
    m.add_argument("action", choices=["encode", "decode"])
    m.add_argument("input")
    m.set_defaults(func=cmd_morse)

    # ── rot ───────────────────────────────────────────────────────────────────
    r = sub.add_parser("rot", help="ROT13 / Caesar cipher")
    r.add_argument("scheme", choices=["rot13", "caesar"])
    r.add_argument("input")
    r.add_argument("--shift", type=int, default=13)
    r.set_defaults(func=cmd_rot)

    # ── hash ──────────────────────────────────────────────────────────────────
    h = sub.add_parser("hash", help="Hash a string")
    h.add_argument("algo", choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512"])
    h.add_argument("input")
    h.set_defaults(func=cmd_hash)

    # ── hmac ──────────────────────────────────────────────────────────────────
    hm = sub.add_parser("hmac", help="HMAC generator")
    hm.add_argument("algo", choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512"])
    hm.add_argument("key")
    hm.add_argument("input")
    hm.set_defaults(func=cmd_hmac)

    # ── xor ───────────────────────────────────────────────────────────────────
    x = sub.add_parser("xor", help="XOR encoder/decoder")
    x.add_argument("key")
    x.add_argument("input")
    x.add_argument("--hex", action="store_true")
    x.add_argument("--output", choices=["text", "hex", "binary"], default="text")
    x.set_defaults(func=cmd_xor)

    # ── aes ───────────────────────────────────────────────────────────────────
    ae = sub.add_parser("aes", help="AES-256 encrypt/decrypt")
    ae.add_argument("action", choices=["encrypt", "decrypt"])
    ae.add_argument("mode", choices=["CBC", "CTR", "GCM"])
    ae.add_argument("key", help="32-byte key: prefix with 0x for hex, else UTF-8 text")
    ae.add_argument("input",
                    help="Plaintext (encrypt) or hex ciphertext (decrypt)")
    ae.add_argument("--iv", help="IV/nonce: prefix 0x for hex, else UTF-8 text")
    ae.add_argument("--aad", help="Additional authenticated data (GCM only)")
    ae.add_argument("--hex", action="store_true",
                    help="Treat plaintext input as hex bytes (encrypt only)")
    ae.set_defaults(func=cmd_aes)

    # ── rsa ───────────────────────────────────────────────────────────────────
    rs     = sub.add_parser("rsa", help="RSA operations")
    rs_sub = rs.add_subparsers(dest="sub", required=True)

    rs_gen = rs_sub.add_parser("gen", help="Generate RSA keypair")
    rs_gen.add_argument("--bits", type=int, default=2048)
    rs_gen.set_defaults(func=cmd_rsa)

    rs_enc = rs_sub.add_parser("encrypt", help="Encrypt with public key")
    rs_enc.add_argument("pub", help="Public key PEM file")
    rs_enc.add_argument("input")
    rs_enc.set_defaults(func=cmd_rsa)

    rs_dec = rs_sub.add_parser("decrypt", help="Decrypt with private key")
    rs_dec.add_argument("priv", help="Private key PEM file")
    rs_dec.add_argument("input", help="Ciphertext hex")
    rs_dec.set_defaults(func=cmd_rsa)

    rs_sign = rs_sub.add_parser("sign", help="Sign with private key")
    rs_sign.add_argument("priv")
    rs_sign.add_argument("input")
    rs_sign.add_argument("--hash", default="SHA256", choices=["SHA256", "SHA1"])
    rs_sign.set_defaults(func=cmd_rsa)

    rs_ver = rs_sub.add_parser("verify", help="Verify signature with public key")
    rs_ver.add_argument("pub")
    rs_ver.add_argument("input")
    rs_ver.add_argument("sig", help="Signature hex")
    rs_ver.add_argument("--hash", default="SHA256", choices=["SHA256", "SHA1"])
    rs_ver.set_defaults(func=cmd_rsa)

    # ── checksum ──────────────────────────────────────────────────────────────
    cs = sub.add_parser("checksum", help="CRC32 / Adler-32")
    cs.add_argument("algo", choices=["crc32", "adler32"])
    cs.add_argument("input")
    cs.add_argument("--hex", action="store_true")
    cs.set_defaults(func=cmd_checksum)

    # ── color ─────────────────────────────────────────────────────────────────
    co  = sub.add_parser("color", help="Colour code converter")
    cos = co.add_subparsers(dest="sub", required=True)

    c1 = cos.add_parser("hex-to-rgb");  c1.add_argument("hex");                 c1.set_defaults(func=cmd_color)
    c2 = cos.add_parser("rgb-to-hex");  c2.add_argument("r", type=int); c2.add_argument("g", type=int); c2.add_argument("b", type=int); c2.set_defaults(func=cmd_color)
    c3 = cos.add_parser("rgb-to-hsl");  c3.add_argument("r", type=int); c3.add_argument("g", type=int); c3.add_argument("b", type=int); c3.set_defaults(func=cmd_color)
    c4 = cos.add_parser("hsl-to-rgb");  c4.add_argument("h", type=float); c4.add_argument("s", type=float); c4.add_argument("l", type=float); c4.set_defaults(func=cmd_color)

    # ── time ──────────────────────────────────────────────────────────────────
    ti  = sub.add_parser("time", help="Unix timestamp ↔ ISO 8601")
    tis = ti.add_subparsers(dest="sub", required=True)

    t1 = tis.add_parser("unix-to-human"); t1.add_argument("ts");  t1.set_defaults(func=cmd_time)
    t2 = tis.add_parser("human-to-unix"); t2.add_argument("iso"); t2.set_defaults(func=cmd_time)

    # ── dump ──────────────────────────────────────────────────────────────────
    d = sub.add_parser("dump", help="Hex dump a file")
    d.add_argument("path")
    d.add_argument("--width", type=int, default=16)
    d.set_defaults(func=cmd_dump)

    # ── random ────────────────────────────────────────────────────────────────
    rnd = sub.add_parser("random", help="Generate cryptographically-secure random data")
    rnd.add_argument("count", type=int, nargs="?", default=32,
                     help="Number of bytes (or chars for password/uuid)")
    rnd.add_argument("--format", choices=["hex", "base64", "password", "uuid", "raw"],
                     default="hex")
    rnd.set_defaults(func=cmd_random)

    # ── jwt ───────────────────────────────────────────────────────────────────
    jw = sub.add_parser("jwt", help="Decode (and optionally verify) a JWT")
    jw.add_argument("token", help="JWT string")
    jw.add_argument("--secret", help="HMAC secret for HS256 signature verification")
    jw.set_defaults(func=cmd_jwt)

    # ── url ───────────────────────────────────────────────────────────────────
    ur = sub.add_parser("url", help="URL encode/decode")
    ur.add_argument("action", choices=["encode", "decode"])
    ur.add_argument("input")
    ur.add_argument("--safe", default="", help="Characters not to encode (encode only)")
    ur.set_defaults(func=cmd_url)

    # ── ip ────────────────────────────────────────────────────────────────────
    ip = sub.add_parser("ip", help="Parse an IPv4/IPv6 address or CIDR block")
    ip.add_argument("address", help="e.g. 192.168.1.0/24 or 2001:db8::1")
    ip.set_defaults(func=cmd_ip)

    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()
    try:
        args.func(args)
    except (ValueError, RuntimeError, OSError) as e:
        print(_red(f"Error: {e}"), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
