"""Readium LCP key derivation and decryption helpers.

Profile transform implementations adapted from lcpdf_exporter by Chaiavi:
https://github.com/Chaiavi/lcpdf_exporter (MIT License)
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac as _hmac
import struct
import zlib

from Crypto.Cipher import AES

_PROFILE_MASTER_KEY = (
    "b3a07c4d42880e69398e05392405050efeea0664c0b638b7c986556fa9b58d77"
    "b31a40eb6a4fdba1e4537229d9f779daad1cc41ee968153cb71f27dc9696d40f"
)

_B3_IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]
_B3_MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
_B3_BLOCK_LEN = 64
_B3_CHUNK_LEN = 1024
_B3_CHUNK_START, _B3_CHUNK_END, _B3_PARENT, _B3_ROOT = 1, 2, 4, 8


def _b3_mask32(x):
    return x & 0xFFFFFFFF


def _b3_add32(x, y):
    return _b3_mask32(x + y)


def _b3_rotr32(x, n):
    return _b3_mask32(x << (32 - n)) | (x >> n)


def _b3_g(s, a, b, c, d, mx, my):
    s[a] = _b3_add32(s[a], _b3_add32(s[b], mx))
    s[d] = _b3_rotr32(s[d] ^ s[a], 16)
    s[c] = _b3_add32(s[c], s[d])
    s[b] = _b3_rotr32(s[b] ^ s[c], 12)
    s[a] = _b3_add32(s[a], _b3_add32(s[b], my))
    s[d] = _b3_rotr32(s[d] ^ s[a], 8)
    s[c] = _b3_add32(s[c], s[d])
    s[b] = _b3_rotr32(s[b] ^ s[c], 7)


def _b3_round(s, m):
    _b3_g(s, 0, 4, 8, 12, m[0], m[1])
    _b3_g(s, 1, 5, 9, 13, m[2], m[3])
    _b3_g(s, 2, 6, 10, 14, m[4], m[5])
    _b3_g(s, 3, 7, 11, 15, m[6], m[7])
    _b3_g(s, 0, 5, 10, 15, m[8], m[9])
    _b3_g(s, 1, 6, 11, 12, m[10], m[11])
    _b3_g(s, 2, 7, 8, 13, m[12], m[13])
    _b3_g(s, 3, 4, 9, 14, m[14], m[15])


def _b3_permute(m):
    orig = list(m)
    for i in range(16):
        m[i] = orig[_B3_MSG_PERM[i]]


def _b3_compress(cv, bw, counter, bl, flags):
    s = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        _B3_IV[0], _B3_IV[1], _B3_IV[2], _B3_IV[3],
        _b3_mask32(counter), _b3_mask32(counter >> 32), bl, flags,
    ]
    block = list(bw)
    for _ in range(7):
        _b3_round(s, block)
        _b3_permute(block)
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def _b3_words(b):
    return [int.from_bytes(b[i : i + 4], "little") for i in range(0, len(b), 4)]


class _B3Output:
    def __init__(self, icv, bw, ctr, bl, fl):
        self.icv, self.bw, self.ctr, self.bl, self.fl = icv, bw, ctr, bl, fl

    def cv(self):
        return _b3_compress(self.icv, self.bw, self.ctr, self.bl, self.fl)[:8]

    def root_bytes(self, length):
        out = bytearray()
        i = 0
        while i < length:
            words = _b3_compress(
                self.icv, self.bw, i // 64, self.bl, self.fl | _B3_ROOT
            )
            for w in words:
                wb = w.to_bytes(4, "little")
                take = min(len(wb), length - i)
                out.extend(wb[:take])
                i += take
        return bytes(out)


class _B3Chunk:
    def __init__(self, kw, cc, fl):
        self.cv, self.cc, self.block = list(kw), cc, bytearray(_B3_BLOCK_LEN)
        self.blen, self.bcomp, self.fl = 0, 0, fl

    def total(self):
        return _B3_BLOCK_LEN * self.bcomp + self.blen

    def sflag(self):
        return _B3_CHUNK_START if self.bcomp == 0 else 0

    def update(self, data):
        while data:
            if self.blen == _B3_BLOCK_LEN:
                self.cv = _b3_compress(
                    self.cv,
                    _b3_words(self.block),
                    self.cc,
                    _B3_BLOCK_LEN,
                    self.fl | self.sflag(),
                )[:8]
                self.bcomp += 1
                self.block = bytearray(_B3_BLOCK_LEN)
                self.blen = 0
            take = min(_B3_BLOCK_LEN - self.blen, len(data))
            self.block[self.blen : self.blen + take] = data[:take]
            self.blen += take
            data = data[take:]

    def output(self):
        return _B3Output(
            self.cv,
            _b3_words(self.block),
            self.cc,
            self.blen,
            self.fl | self.sflag() | _B3_CHUNK_END,
        )


def _blake3(data, length=32):
    kw = list(_B3_IV)
    stack = []
    cs = _B3Chunk(kw, 0, 0)
    pos = 0
    while pos < len(data):
        if cs.total() == _B3_CHUNK_LEN:
            ccv = cs.output().cv()
            tc = cs.cc + 1
            while tc & 1 == 0:
                ccv = _b3_compress(stack.pop(), ccv + [0] * 8, 0, _B3_BLOCK_LEN, _B3_PARENT)[:8]
                tc >>= 1
            stack.append(ccv)
            cs = _B3Chunk(kw, tc, 0)
        take = min(_B3_CHUNK_LEN - cs.total(), len(data) - pos)
        cs.update(data[pos : pos + take])
        pos += take
    out = cs.output()
    for i in range(len(stack) - 1, -1, -1):
        parent_bw = stack[i] + out.cv()
        out = _B3Output(kw, parent_bw, 0, _B3_BLOCK_LEN, _B3_PARENT)
    return out.root_bytes(length)


def _crc32bts(data):
    return struct.pack(">I", zlib.crc32(data) & 0xFFFFFFFF)


def _adler32bts(data):
    return struct.pack(">I", zlib.adler32(data) & 0xFFFFFFFF)


def _hmac256(key, msg):
    return _hmac.new(key, msg, hashlib.sha256).digest()


def _hmacmd5(key, msg):
    return _hmac.new(key, msg, hashlib.md5).digest()


def _pbkdf2_sha256(msg, salt, iters):
    return hashlib.pbkdf2_hmac("sha256", msg, salt, iters, dklen=32)


def _pbkdf2_md5(msg, salt, iters):
    return hashlib.pbkdf2_hmac("md5", msg, salt, iters, dklen=16)


def _pbkdf2_sha1(msg, salt, iters):
    return hashlib.pbkdf2_hmac("sha1", msg, salt, iters, dklen=20)


def _md5(data):
    return hashlib.md5(data).digest()


def _fnv11_interleaved(data):
    p, b = 0x01000193, 0x811C9DC5
    h, hi = b, b
    for byte in data:
        hi = ((hi * p) & 0xFFFFFFFF) ^ byte
        h = ((h ^ byte) * p) & 0xFFFFFFFF
    return bytes(
        [
            (h >> 24) & 0xFF,
            (hi >> 24) & 0xFF,
            (h >> 16) & 0xFF,
            (hi >> 16) & 0xFF,
            (h >> 8) & 0xFF,
            (hi >> 8) & 0xFF,
            h & 0xFF,
            hi & 0xFF,
        ]
    )


def _xorstrs(s1, s2):
    return bytes(s1[i % len(s1)] ^ s2[i] for i in range(len(s2)))


def _getindex(bts, md):
    offs = bts[0] % len(bts)
    if offs == 0:
        return 1
    ret = bts[offs - 1] % md
    return ret if ret != 0 else 1


def _sha256hex(data):
    return binascii.hexlify(hashlib.sha256(data).digest()).decode("latin-1")


def _identity_transform(input_hash):
    return input_hash


def _transform_profile10(input_hash):
    masterkey = bytearray.fromhex(_PROFILE_MASTER_KEY)
    try:
        current_hash = bytearray.fromhex(input_hash)
    except (ValueError, TypeError):
        return None
    for byte in masterkey:
        current_hash.append(byte)
        current_hash = bytearray(hashlib.sha256(current_hash).digest())
    return binascii.hexlify(current_hash).decode("latin-1")


def _transform_profile20(input_hash):
    try:
        mk = bytearray.fromhex(input_hash)
    except ValueError:
        return None
    blk = _blake3(mk, 64)
    crc = _crc32bts(blk)
    adlr = _adler32bts(blk)
    h = _hmac256(adlr, blk + crc + adlr)
    return _sha256hex(h)


def _transform_profile21(input_hash):
    try:
        mk = bytearray.fromhex(input_hash)
    except ValueError:
        return None
    blk = _blake3(mk, 32)
    crc = _crc32bts(blk)
    adlr = _adler32bts(blk)
    iters = _getindex(mk, 9)
    h = _pbkdf2_sha256(crc + adlr + blk + crc + adlr, crc, iters)
    return _sha256hex(h)


def _transform_profile22(input_hash):
    try:
        mk = bytearray.fromhex(input_hash)
    except ValueError:
        return None
    hsh = hashlib.sha256(mk).digest()
    crc = _crc32bts(hsh)
    adlr = _adler32bts(hsh)
    iters = _getindex(mk, 9)
    h = _pbkdf2_md5(crc + adlr + hsh + crc + adlr, adlr, iters)
    return _sha256hex(h)


def _transform_profile23(input_hash):
    try:
        mk = bytearray.fromhex(input_hash)
    except ValueError:
        return None
    blk1 = _blake3(mk, 64)
    blk2 = _blake3(blk1, 32)
    adlr = _adler32bts(mk)
    iters = _getindex(adlr, 10)
    h = _pbkdf2_sha1(blk1 + blk2, adlr, iters)
    return _sha256hex(h)


def _transform_profile24(input_hash):
    try:
        mk = bytearray.fromhex(input_hash)
    except ValueError:
        return None
    ostr = bytes.fromhex("496e76616c696420626c6f636b2073697a65213f")
    st1 = _xorstrs(mk, ostr)
    st2 = hashlib.sha256(mk).digest()
    h = _hmac256(st1, st2)
    blk = _blake3(h, 32)
    adlr = _adler32bts(mk)
    iters = _getindex(mk, 9)
    h = _pbkdf2_sha1(blk, adlr, iters)
    return _sha256hex(h)


def _transform_profile25(input_hash):
    try:
        mk = bytearray.fromhex(input_hash)
    except ValueError:
        return None
    fnv = _fnv11_interleaved(mk)
    st1 = _xorstrs(fnv, mk)
    st2 = hashlib.sha256(mk).digest()
    h = _hmac256(st1, st2)
    blk = _blake3(h + fnv + h + st1, 32)
    adlr = _adler32bts(mk)
    iters = _getindex(mk, 9)
    h = _pbkdf2_md5(blk, adlr, iters)
    return _sha256hex(h)


def _transform_profile26(input_hash):
    try:
        mk = bytearray.fromhex(input_hash)
    except ValueError:
        return None
    fnv = _fnv11_interleaved(mk)
    st1 = _xorstrs(fnv, mk)
    blk1 = _blake3(mk, 64)
    h = _hmac256(st1 + st1, blk1)
    blk = _blake3(h, 32)
    return _sha256hex(blk)


def _transform_profile27(input_hash):
    try:
        mk = bytearray.fromhex(input_hash)
    except ValueError:
        return None
    fnv = _fnv11_interleaved(mk)
    st1 = _xorstrs(fnv, mk)
    adl5 = _adler32bts(st1)
    crc6 = _crc32bts(st1)
    blk1 = _blake3(st1 + st1 + fnv + st1 + fnv + crc6 + adl5, 32)
    h = _hmacmd5(st1 + st1, blk1) + b"\x00\x00\x00\x00"
    blk2 = _blake3(h, 64)
    return _sha256hex(blk2)


def _transform_profile28(input_hash):
    try:
        mk = bytearray.fromhex(input_hash)
    except ValueError:
        return None
    _1 = _fnv11_interleaved(mk)
    _2 = _xorstrs(_1, mk)
    _4 = _adler32bts(_2)
    _5 = _crc32bts(_2)
    _6 = _pbkdf2_sha1(_2 + _2, _1 + _5 + _4, 3)
    _7 = _hmac256(_2, _6)
    _8 = _blake3(_7, 32)
    _9 = _adler32bts(mk)
    it = _getindex(_9, 9)
    _11 = _pbkdf2_sha1(_8, _9, it)
    return _sha256hex(_11)


def _transform_profile29(input_hash):
    try:
        mk = bytearray.fromhex(input_hash)
    except ValueError:
        return None
    _1 = _blake3(mk, 32)
    _2 = _md5(mk)
    _3 = _fnv11_interleaved(_1)
    _5 = _adler32bts(_2)
    _6 = _crc32bts(_2)
    _7 = _3 + _3 + _1 + _3 + _3
    it = _getindex(mk, 9)
    _9 = _pbkdf2_sha256(_7, _5 + _6, it)
    return _sha256hex(_9)


KNOWN_PROFILES = {
    "http://readium.org/lcp/basic-profile": _identity_transform,
    "http://readium.org/lcp/profile-1.0": _transform_profile10,
    "http://readium.org/lcp/profile-2.0": _transform_profile20,
    "http://readium.org/lcp/profile-2.1": _transform_profile21,
    "http://readium.org/lcp/profile-2.2": _transform_profile22,
    "http://readium.org/lcp/profile-2.3": _transform_profile23,
    "http://readium.org/lcp/profile-2.4": _transform_profile24,
    "http://readium.org/lcp/profile-2.5": _transform_profile25,
    "http://readium.org/lcp/profile-2.6": _transform_profile26,
    "http://readium.org/lcp/profile-2.7": _transform_profile27,
    "http://readium.org/lcp/profile-2.8": _transform_profile28,
    "http://readium.org/lcp/profile-2.9": _transform_profile29,
}


def userpass_to_hash(passphrase_bytes, algorithm):
    if algorithm == "http://www.w3.org/2001/04/xmlenc#sha256":
        return hashlib.sha256(passphrase_bytes).hexdigest()
    return None


def decrypt_lcp_data(b64data, hex_key):
    raw = base64.b64decode(b64data.encode("ascii"))
    iv, cipher = raw[:16], raw[16:]
    temp = AES.new(binascii.unhexlify(hex_key), AES.MODE_CBC, iv).decrypt(cipher)
    pad = temp[-1] if isinstance(temp[-1], int) else ord(temp[-1])
    return temp[:-pad]


def find_user_key(license_data, passphrase):
    profile = license_data["encryption"]["profile"]
    key_check = license_data["encryption"]["user_key"]["key_check"]
    book_id = license_data["id"]
    algo = license_data["encryption"]["user_key"].get(
        "algorithm", "http://www.w3.org/2001/04/xmlenc#sha256"
    )

    password_hashes = []
    user_key_section = license_data["encryption"]["user_key"]
    if "value" in user_key_section:
        try:
            password_hashes.append(
                binascii.hexlify(base64.b64decode(user_key_section["value"])).decode("ascii")
            )
        except Exception:
            pass

    hashed = userpass_to_hash(passphrase.encode("utf-8"), algo)
    if hashed:
        password_hashes.append(hashed)

    transforms = [("basic", _identity_transform)]
    if profile in KNOWN_PROFILES:
        transforms.insert(0, (profile, KNOWN_PROFILES[profile]))
    else:
        for url, fn in KNOWN_PROFILES.items():
            transforms.append((url.split("/")[-1], fn))

    for pw_hash in password_hashes:
        for _, transform_fn in transforms:
            for candidate in (pw_hash, transform_fn(pw_hash)):
                if not candidate:
                    continue
                try:
                    decrypted = decrypt_lcp_data(key_check, candidate)
                    if decrypted.decode("ascii", errors="ignore") == book_id:
                        return candidate
                except Exception:
                    pass

    raise ValueError("Passphrase did not unlock this book")


def maybe_inflate(data):
    try:
        return zlib.decompress(data, -15)
    except Exception:
        return data
