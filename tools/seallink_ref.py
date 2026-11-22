#!/usr/bin/env python3
"""
SealLink v1.0 Zero-Dependency Reference Primitives (Python 3.9+ stdlib).

Implements normative primitives from SPEC-01, SPEC-02, SPEC-04, SPEC-05, SPEC-06:
  - Restricted RFC 8785 JCS serializer & strict validator (SL-WIRE-001..008)
  - BIP-340 tagged hashes, object_id, signing_digest, content_addr, clause_commit
  - Pure-Python secp256k1 BIP-340 Schnorr signing & verification
  - Pure-Python RIPEMD-160 / HASH160 fallback (OpenSSL 3 safe)
  - Namecoin ScriptPolicy compiler & NAME_NEW / NAME_FIRSTUPDATE / NAME_UPDATE parser
  - SLNK OP_RETURN framing & 0x02 Merkle batch tree (sorted, tagged, odd-promotion)
  - 7-predicate Constraint Algebra, capability attenuation, R8.5 & R8.6 checks
  - Hash-chained journal commitments
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from typing import Any

# ============================================================================
# 1. Pure-Python RIPEMD-160 (OpenSSL 3 safe) & HASH160
# ============================================================================

_R1 = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]
_R2 = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]
_S1 = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]
_S2 = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]


def _rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _f(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def ripemd160(data: bytes) -> bytes:
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    bit_len = len(data) * 8
    padded = data + b"\x80"
    padded += b"\x00" * ((56 - len(padded) % 64) % 64)
    padded += struct.pack("<Q", bit_len)

    k1 = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    k2 = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]

    for off in range(0, len(padded), 64):
        x = struct.unpack("<16I", padded[off : off + 64])
        al, bl, cl, dl, el = h0, h1, h2, h3, h4
        ar, br, cr, dr, er = h0, h1, h2, h3, h4
        for j in range(80):
            r = j // 16
            t = (_rol32((al + _f(j, bl, cl, dl) + x[_R1[j]] + k1[r]) & 0xFFFFFFFF, _S1[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, _rol32(cl, 10), bl, t
            t = (_rol32((ar + _f(79 - j, br, cr, dr) + x[_R2[j]] + k2[r]) & 0xFFFFFFFF, _S2[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, _rol32(cr, 10), br, t
        t = (h1 + cl + dr) & 0xFFFFFFFF
        h1 = (h2 + dl + er) & 0xFFFFFFFF
        h2 = (h3 + el + ar) & 0xFFFFFFFF
        h3 = (h4 + al + br) & 0xFFFFFFFF
        h4 = (h0 + bl + cr) & 0xFFFFFFFF
        h0 = t
    return struct.pack("<5I", h0, h1, h2, h3, h4)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))


# ============================================================================
# 2. BIP-340 Tagged Hashes & SealLink Three Hashes (SPEC-01 §3, §5, SPEC-06 §6)
# ============================================================================

def tagged_hash(tag: str, msg: bytes) -> bytes:
    t = sha256(tag.encode("ascii"))
    return sha256(t + t + msg)


def object_id(payload_obj: dict[str, Any]) -> str:
    return sha256(jcs_encode(payload_obj)).hex()


def signing_digest(payload_obj: dict[str, Any]) -> bytes:
    obj_type = payload_obj["type"]
    return tagged_hash(obj_type, jcs_encode(payload_obj))


def content_addr(full_obj: dict[str, Any]) -> str:
    return sha256(jcs_encode(full_obj)).hex()


def clause_commit(salt_hex: str, clause_obj: dict[str, Any]) -> str:
    salt_bytes = bytes.fromhex(salt_hex)
    if len(salt_bytes) != 32:
        raise ValueError("salt must be 32 bytes")
    return tagged_hash("seallink-clause/1", salt_bytes + jcs_encode(clause_obj)).hex()


def journal_commit_init(journal_id_hex: str) -> str:
    jid = bytes.fromhex(journal_id_hex)
    if len(jid) != 32:
        raise ValueError("journal_id must be 32 bytes")
    return tagged_hash("seallink-journal/1", jid).hex()


def journal_commit_step(prev_commit_hex: str, entry_obj: dict[str, Any]) -> str:
    prev_b = bytes.fromhex(prev_commit_hex)
    return tagged_hash("seallink-journal/1", prev_b + jcs_encode(entry_obj)).hex()


# ============================================================================
# 3. Restricted RFC 8785 JCS (SPEC-01 §1-2)
# ============================================================================

MULTILINE_FIELDS = frozenset({"terms_text", "text", "reason", "role"})
MAX_UINT53 = 9007199254740991
MAX_UINT64 = 18446744073709551615
UINT64_STR_RE = re.compile(r"^(0|[1-9][0-9]{0,19})$")


def _utf16_sort_key(s: str) -> bytes:
    return s.encode("utf-16-be")


def _validate_string(s: str, allow_lf: bool) -> bool:
    for ch in s:
        cp = ord(ch)
        if cp < 0x20:
            if allow_lf and cp == 0x0A:
                continue
            return False
        if 0x7F <= cp <= 0x9F:
            return False
        if 0xD800 <= cp <= 0xDFFF:
            return False
    return True


def _encode_jcs_str(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_serialize(val: Any, field_name: str | None = None, depth: int = 1) -> str:
    if depth > 16:
        raise ValueError("WIRE_SIZE")
    if val is None:
        raise ValueError("WIRE_VALUE")
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        if val < 0 or val > MAX_UINT53:
            raise ValueError("WIRE_NUMBER")
        return str(val)
    if isinstance(val, float):
        raise ValueError("WIRE_NUMBER")
    if isinstance(val, str):
        allow_lf = field_name in MULTILINE_FIELDS
        if not _validate_string(val, allow_lf):
            raise ValueError("WIRE_STRING")
        return _encode_jcs_str(val)
    if isinstance(val, list):
        return "[" + ",".join(_jcs_serialize(x, None, depth + 1) for x in val) + "]"
    if isinstance(val, dict):
        items = sorted(val.items(), key=lambda kv: _utf16_sort_key(kv[0]))
        parts = []
        for k, v in items:
            if not isinstance(k, str) or not _validate_string(k, False):
                raise ValueError("WIRE_STRING")
            parts.append(f"{_encode_jcs_str(k)}:{_jcs_serialize(v, k, depth + 1)}")
        return "{" + ",".join(parts) + "}"
    raise ValueError("WIRE_VALUE")


def jcs_encode(obj: dict[str, Any]) -> bytes:
    if not isinstance(obj, dict):
        raise ValueError("WIRE_JSON")
    return _jcs_serialize(obj, None, 1).encode("utf-8")


def _check_depth_and_values(val: Any, field_name: str | None, depth: int) -> str | None:
    if depth > 16:
        return "WIRE_SIZE"
    if val is None:
        return "WIRE_VALUE"
    if isinstance(val, bool):
        return None
    if isinstance(val, float):
        return "WIRE_NUMBER"
    if isinstance(val, int):
        if val < 0 or val > MAX_UINT53:
            return "WIRE_NUMBER"
        return None
    if isinstance(val, str):
        if not _validate_string(val, field_name in MULTILINE_FIELDS):
            return "WIRE_STRING"
        return None
    if isinstance(val, list):
        for item in val:
            err = _check_depth_and_values(item, None, depth + 1)
            if err:
                return err
        return None
    if isinstance(val, dict):
        for k, v in val.items():
            if not _validate_string(k, False):
                return "WIRE_STRING"
            err = _check_depth_and_values(v, k, depth + 1)
            if err:
                return err
        return None
    return "WIRE_VALUE"


def jcs_validate(raw: bytes, max_bytes: int = 1048576) -> tuple[bool, Any]:
    """Validate raw bytes against SPEC-01 §1-2 pipeline steps 1..6. Returns (True, obj) or (False, refusal_code)."""
    if len(raw) > max_bytes:
        return False, "WIRE_SIZE"
    if raw.startswith(b"\xef\xbb\xbf"):
        return False, "WIRE_JSON"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False, "WIRE_JSON"

    dup_found = False
    bad_num = False

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal dup_found
        d: dict[str, Any] = {}
        for k, v in pairs:
            if k in d:
                dup_found = True
            d[k] = v
        return d

    def parse_float(_s: str) -> float:
        nonlocal bad_num
        bad_num = True
        return 0.0

    def parse_int(s: str) -> int:
        nonlocal bad_num
        if s.startswith("-") or (len(s) > 1 and s.startswith("0")):
            bad_num = True
            return 0
        v = int(s)
        if v > MAX_UINT53:
            bad_num = True
            return 0
        return v

    try:
        obj = json.loads(
            text,
            object_pairs_hook=pairs_hook,
            parse_float=parse_float,
            parse_int=parse_int,
        )
    except Exception:
        return False, "WIRE_JSON"

    if not isinstance(obj, dict):
        return False, "WIRE_JSON"

    # Depth check (SL-WIRE-001) runs before duplicate/value checks per §7 step 1
    def max_depth(v: Any, cur: int = 1) -> int:
        if isinstance(v, dict):
            return max([cur] + [max_depth(x, cur + 1) for x in v.values()])
        if isinstance(v, list):
            return max([cur] + [max_depth(x, cur + 1) for x in v])
        return cur

    if max_depth(obj) > 16:
        return False, "WIRE_SIZE"
    if dup_found:
        return False, "WIRE_DUPLICATE"
    err = _check_depth_and_values(obj, None, 1)
    if err == "WIRE_VALUE":
        return False, "WIRE_VALUE"
    if bad_num or err == "WIRE_NUMBER":
        return False, "WIRE_NUMBER"
    if err is not None:
        return False, err

    try:
        reencoded = jcs_encode(obj)
    except ValueError as exc:
        return False, str(exc)

    if reencoded != raw:
        return False, "WIRE_NOT_CANONICAL"
    return True, obj


# ============================================================================
# 4. Pure-Python secp256k1 & BIP-340 Schnorr
# ============================================================================

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _jac_double(pt: tuple[int, int, int]) -> tuple[int, int, int]:
    x1, y1, z1 = pt
    if y1 == 0 or z1 == 0:
        return (0, 1, 0)
    xx = (x1 * x1) % _P
    yy = (y1 * y1) % _P
    yyyy = (yy * yy) % _P
    s = (4 * x1 * yy) % _P
    m = (3 * xx) % _P
    x3 = (m * m - 2 * s) % _P
    y3 = (m * (s - x3) - 8 * yyyy) % _P
    z3 = (2 * y1 * z1) % _P
    return (x3, y3, z3)


def _jac_add(p1: tuple[int, int, int], p2: tuple[int, int, int]) -> tuple[int, int, int]:
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1
    z1z1 = (z1 * z1) % _P
    z2z2 = (z2 * z2) % _P
    u1 = (x1 * z2z2) % _P
    u2 = (x2 * z1z1) % _P
    s1 = (y1 * z2 * z2z2) % _P
    s2 = (y2 * z1 * z1z1) % _P
    if u1 == u2:
        if s1 != s2:
            return (0, 1, 0)
        return _jac_double(p1)
    h = (u2 - u1) % _P
    hh = (h * h) % _P
    hhh = (h * hh) % _P
    r = (s2 - s1) % _P
    v = (u1 * hh) % _P
    x3 = (r * r - hhh - 2 * v) % _P
    y3 = (r * (v - x3) - s1 * hhh) % _P
    z3 = (h * z1 * z2) % _P
    return (x3, y3, z3)


def _point_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        lam = (3 * x1 * x1 * pow(2 * y1, _P - 2, _P)) % _P
    else:
        lam = ((y2 - y1) * pow(x2 - x1, _P - 2, _P)) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _point_mul(p: tuple[int, int] | None, n: int) -> tuple[int, int] | None:
    if p is None:
        return None
    k = n % _N
    if k == 0:
        return None
    r = (0, 1, 0)
    addend = (p[0], p[1], 1)
    while k:
        if k & 1:
            r = _jac_add(r, addend)
        addend = _jac_double(addend)
        k >>= 1
    rx, ry, rz = r
    if rz == 0:
        return None
    z_inv = pow(rz, _P - 2, _P)
    z_inv2 = (z_inv * z_inv) % _P
    return ((rx * z_inv2) % _P, (ry * z_inv2 * z_inv) % _P)


def _lift_x(x: int) -> tuple[int, int] | None:
    if x >= _P:
        return None
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if (y * y) % _P != y_sq:
        return None
    return (x, y if y % 2 == 0 else _P - y)


def deterministic_privkey(label: str) -> bytes:
    """Derive a reproducible non-zero secp256k1 test secret key from an ASCII label (test vectors ONLY)."""
    h = sha256(b"seallink-test-vector-key:" + label.encode("utf-8"))
    d = int.from_bytes(h, "big") % (_N - 1) + 1
    return d.to_bytes(32, "big")


def xonly_pubkey(privkey: bytes) -> str:
    d0 = int.from_bytes(privkey, "big")
    pt = _point_mul(_G, d0)
    assert pt is not None
    return pt[0].to_bytes(32, "big").hex()


def compressed_pubkey(privkey: bytes) -> str:
    d0 = int.from_bytes(privkey, "big")
    pt = _point_mul(_G, d0)
    assert pt is not None
    prefix = b"\x02" if pt[1] % 2 == 0 else b"\x03"
    return (prefix + pt[0].to_bytes(32, "big")).hex()


def is_valid_xonly_pubkey(hex_pk: str) -> bool:
    if len(hex_pk) != 64 or hex_pk != hex_pk.lower():
        return False
    try:
        x = int(hex_pk, 16)
    except ValueError:
        return False
    return _lift_x(x) is not None


def is_valid_compressed_pubkey(hex_pk: str) -> bool:
    if len(hex_pk) != 66 or hex_pk != hex_pk.lower() or hex_pk[:2] not in ("02", "03"):
        return False
    try:
        x = int(hex_pk[2:], 16)
    except ValueError:
        return False
    return _lift_x(x) is not None


def schnorr_sign(msg32: bytes, privkey: bytes, aux_rand: bytes = b"\x00" * 32) -> str:
    if len(msg32) != 32 or len(privkey) != 32 or len(aux_rand) != 32:
        raise ValueError("BIP-340 requires 32-byte inputs")
    d0 = int.from_bytes(privkey, "big")
    if not (1 <= d0 <= _N - 1):
        raise ValueError("Invalid secret key")
    pt = _point_mul(_G, d0)
    assert pt is not None
    d = d0 if pt[1] % 2 == 0 else _N - d0
    px = pt[0].to_bytes(32, "big")
    t = bytes(a ^ b for a, b in zip(d.to_bytes(32, "big"), tagged_hash("BIP0340/aux", aux_rand)))
    k0 = int.from_bytes(tagged_hash("BIP0340/nonce", t + px + msg32), "big") % _N
    if k0 == 0:
        raise ValueError("Zero nonce")
    r_pt = _point_mul(_G, k0)
    assert r_pt is not None
    k = k0 if r_pt[1] % 2 == 0 else _N - k0
    rx = r_pt[0].to_bytes(32, "big")
    e = int.from_bytes(tagged_hash("BIP0340/challenge", rx + px + msg32), "big") % _N
    s = (k + e * d) % _N
    sig = rx + s.to_bytes(32, "big")
    assert schnorr_verify(msg32, px.hex(), sig.hex())
    return sig.hex()


def schnorr_verify(msg32: bytes, pubkey_hex: str, sig_hex: str) -> bool:
    if len(msg32) != 32 or len(pubkey_hex) != 64 or len(sig_hex) != 128:
        return False
    if pubkey_hex != pubkey_hex.lower() or sig_hex != sig_hex.lower():
        return False
    try:
        px_bytes = bytes.fromhex(pubkey_hex)
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    pt = _lift_x(int.from_bytes(px_bytes, "big"))
    if pt is None:
        return False
    r = int.from_bytes(sig_bytes[:32], "big")
    s = int.from_bytes(sig_bytes[32:], "big")
    if r >= _P or s >= _N:
        return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge", sig_bytes[:32] + px_bytes + msg32), "big") % _N
    r_pt = _point_add(_point_mul(_G, s), _point_mul(pt, (_N - e) % _N))
    return r_pt is not None and r_pt[1] % 2 == 0 and r_pt[0] == r


def sign_envelope(
    payload: dict[str, Any],
    signers: list[bytes],
    policy_pks: list[str] | None = None,
    m: int | None = None,
) -> dict[str, Any]:
    """Build a canonical signed SealLink envelope with pure BIP-340 SignatureSet."""
    digest = signing_digest(payload)
    derived_pks = [xonly_pubkey(sk) for sk in signers]
    pks = sorted(set(policy_pks if policy_pks is not None else derived_pks))
    threshold = m if m is not None else len(signers)
    sigs = []
    for sk in sorted(signers, key=xonly_pubkey):
        pk = xonly_pubkey(sk)
        sigs.append({"pk": pk, "sig": schnorr_sign(digest, sk)})
    return {"payload": payload, "signatures": {"policy": {"m": threshold, "pks": pks}, "sigs": sigs}}


def sign_guardian_envelope(
    payload: dict[str, Any],
    approvals: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a canonical ward guardian-quorum envelope with independent per-slot SignatureSets.

    Each item in `approvals` has keys:
      slot (int), revision (int), guardian_name (str), signers (list[bytes]),
      optional policy_pks (list[str]), optional m (int).
    """
    digest = signing_digest(payload)
    out_approvals: list[dict[str, Any]] = []
    for item in sorted(approvals, key=lambda a: a["slot"]):
        signers = item["signers"]
        derived_pks = [xonly_pubkey(sk) for sk in signers]
        pks = sorted(set(item.get("policy_pks") or derived_pks))
        threshold = item.get("m") if item.get("m") is not None else len(signers)
        sigs = [{"pk": xonly_pubkey(sk), "sig": schnorr_sign(digest, sk)} for sk in sorted(signers, key=xonly_pubkey)]
        out_approvals.append({
            "guardian_name": item["guardian_name"],
            "revision": item["revision"],
            "signatures": {"policy": {"m": threshold, "pks": pks}, "sigs": sigs},
            "slot": item["slot"],
        })
    return {"guardian_approvals": out_approvals, "payload": payload}


def verify_signature_set(
    digest: bytes,
    sigset: dict[str, Any],
    expected_policy: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """Verify a BIP-340 SignatureSet over `digest`, optionally requiring exact policy equality (SL-WIRE-013)."""
    if not isinstance(sigset, dict) or "policy" not in sigset or "sigs" not in sigset:
        return False, "WIRE_SIGNATURE"
    policy = sigset["policy"]
    alg = policy.get("alg", "bip340")
    if alg != "bip340":
        return False, "WIRE_SIGNATURE"
    pks = policy.get("pks", [])
    m = policy.get("m", 0)
    if not isinstance(pks, list) or not isinstance(m, int) or isinstance(m, bool):
        return False, "WIRE_SIGNATURE"
    if not (1 <= m <= len(pks) <= 32):
        return False, "WIRE_SIGNATURE"
    if pks != sorted(set(pks)):
        return False, "WIRE_SIGNATURE"
    for pk in pks:
        if not isinstance(pk, str) or not is_valid_xonly_pubkey(pk):
            return False, "WIRE_KEY"
    if expected_policy is not None:
        exp_alg = expected_policy.get("alg", "bip340")
        if exp_alg != alg or expected_policy.get("m") != m or expected_policy.get("pks") != pks:
            return False, "WIRE_SIGNATURE"
    seen: set[str] = set()
    valid = 0
    for entry in sigset["sigs"]:
        if not isinstance(entry, dict) or set(entry.keys()) != {"pk", "sig"}:
            return False, "WIRE_SIGNATURE"
        pk = entry["pk"]
        if pk not in pks or pk in seen:
            return False, "WIRE_SIGNATURE"
        seen.add(pk)
        if not schnorr_verify(digest, pk, entry["sig"]):
            return False, "WIRE_SIGNATURE"
        valid += 1
    if valid < m:
        return False, "WIRE_SIGNATURE"
    return True, "OK"


def verify_envelope_signatures(
    env: dict[str, Any],
    expected_policy: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """Verify either an ordinary `signatures` envelope or a ward `guardian_approvals` envelope."""
    payload = env.get("payload")
    if not isinstance(payload, dict) or "type" not in payload:
        return False, "WIRE_MEMBER"
    digest = signing_digest(payload)
    if "signatures" in env and "guardian_approvals" not in env:
        return verify_signature_set(digest, env["signatures"], expected_policy=expected_policy)
    if "guardian_approvals" in env and "signatures" not in env:
        approvals = env["guardian_approvals"]
        if not isinstance(approvals, list) or not (1 <= len(approvals) <= 32):
            return False, "WIRE_SIGNATURE"
        prev_slot = 0
        for item in approvals:
            slot = item.get("slot")
            if not isinstance(slot, int) or isinstance(slot, bool) or not (1 <= slot <= 32) or slot <= prev_slot:
                return False, "WIRE_SIGNATURE"
            prev_slot = slot
            ok, code = verify_signature_set(digest, item.get("signatures", {}))
            if not ok:
                return False, code
        return True, "OK"
    return False, "WIRE_MEMBER"


# ============================================================================
# 5. ScriptPolicy Compiler & Namecoin Prefix Parser (SPEC-02 §3)
# ============================================================================

OP_0 = 0x00
OP_1 = 0x51
OP_NAME_NEW = 0x51
OP_NAME_FIRSTUPDATE = 0x52
OP_NAME_UPDATE = 0x53
OP_IF = 0x63
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_2DROP = 0x6D
OP_DROP = 0x75
OP_CHECKSIG = 0xAC
OP_CHECKMULTISIG = 0xAE
OP_CHECKSEQUENCEVERIFY = 0xB2

P2A_SCRIPTPUBKEY = bytes.fromhex("51024e73")


def _push_data(data: bytes) -> bytes:
    n = len(data)
    if n < 0x4C:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([0x4C, n]) + data
    if n <= 0xFFFF:
        return bytes([0x4D]) + struct.pack("<H", n) + data
    raise ValueError("push too large")


def _encode_script_num(n: int) -> bytes:
    if n == 0:
        return bytes([OP_0])
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    neg = n < 0
    abs_n = abs(n)
    res = bytearray()
    while abs_n:
        res.append(abs_n & 0xFF)
        abs_n >>= 8
    if res[-1] & 0x80:
        res.append(0x80 if neg else 0x00)
    elif neg:
        res[-1] |= 0x80
    return _push_data(bytes(res))


def compile_script_policy(policy: dict[str, Any]) -> tuple[bytes, bytes | None]:
    """Compile ScriptPolicy -> (scriptPubKey, witnessScript_or_None)."""
    kind = policy["kind"]
    if kind == "key":
        pk = bytes.fromhex(policy["pk"])
        if len(pk) != 33 or not is_valid_compressed_pubkey(policy["pk"]):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        spk = bytes([OP_0, 20]) + hash160(pk)
        return spk, None

    if kind == "multisig":
        m = policy["m"]
        pks = policy["pks"]
        if not (1 <= m <= len(pks) <= 15) or pks != sorted(set(pks)):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        ws = bytearray([0x50 + m])
        for pk_hex in pks:
            if not is_valid_compressed_pubkey(pk_hex):
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            ws.extend(_push_data(bytes.fromhex(pk_hex)))
        ws.append(0x50 + len(pks))
        ws.append(OP_CHECKMULTISIG)
        ws_b = bytes(ws)
        return bytes([OP_0, 32]) + sha256(ws_b), ws_b

    if kind == "branch":
        tpl = policy["template"]
        keys = policy["keys"]
        if tpl in ("either_of_2", "both_of_2"):
            a, b = sorted([keys["a"], keys["b"]])
            op_m = 0x51 if tpl == "either_of_2" else 0x52
            ws_b = bytes([op_m]) + _push_data(bytes.fromhex(a)) + _push_data(bytes.fromhex(b)) + bytes([0x52, OP_CHECKMULTISIG])
            return bytes([OP_0, 32]) + sha256(ws_b), ws_b
        if tpl == "arbiter_or_both":
            a, b = sorted([keys["a"], keys["b"]])
            arb = keys["arbiter"]
            ws_b = (
                bytes([OP_IF, 0x52])
                + _push_data(bytes.fromhex(a))
                + _push_data(bytes.fromhex(b))
                + bytes([0x52, OP_CHECKMULTISIG, OP_ELSE])
                + _push_data(bytes.fromhex(arb))
                + bytes([OP_CHECKSIG, OP_ENDIF])
            )
            return bytes([OP_0, 32]) + sha256(ws_b), ws_b
        if tpl == "single_use_1_of_2":
            ws_b = (
                bytes([OP_IF])
                + _push_data(bytes.fromhex(keys["issuer"]))
                + bytes([OP_CHECKSIG, OP_ELSE])
                + _push_data(bytes.fromhex(keys["grantee"]))
                + bytes([OP_CHECKSIG, OP_ENDIF])
            )
            return bytes([OP_0, 32]) + sha256(ws_b), ws_b
        if tpl == "guardian_slot_pending":
            delay = policy["delay_blocks"]
            if not (1 <= delay <= 52560):
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            ws_b = (
                bytes([OP_IF])
                + _push_data(bytes.fromhex(keys["disposer"]))
                + bytes([OP_CHECKSIG, OP_ELSE, OP_IF])
                + _push_data(bytes.fromhex(keys["challenger"]))
                + bytes([OP_CHECKSIG, OP_ELSE])
                + _encode_script_num(delay)
                + bytes([OP_CHECKSEQUENCEVERIFY, OP_DROP])
                + _push_data(bytes.fromhex(keys["guardian"]))
                + bytes([OP_CHECKSIG, OP_ENDIF, OP_ENDIF])
            )
            return bytes([OP_0, 32]) + sha256(ws_b), ws_b
    raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")


def encode_name_output(op: str, trailing_spk: bytes, **kwargs: bytes) -> bytes:
    """Encode exact Namecoin Core nc28.0 output script for NAME_NEW, NAME_FIRSTUPDATE, or NAME_UPDATE."""
    if op == "NAME_NEW":
        h20 = kwargs["hash20"]
        assert len(h20) == 20
        return bytes([OP_NAME_NEW]) + _push_data(h20) + bytes([OP_2DROP]) + trailing_spk
    if op == "NAME_FIRSTUPDATE":
        return (
            bytes([OP_NAME_FIRSTUPDATE])
            + _push_data(kwargs["name"])
            + _push_data(kwargs["rand"])
            + _push_data(kwargs["value"])
            + bytes([OP_2DROP, OP_2DROP])
            + trailing_spk
        )
    if op == "NAME_UPDATE":
        return (
            bytes([OP_NAME_UPDATE])
            + _push_data(kwargs["name"])
            + _push_data(kwargs["value"])
            + bytes([OP_2DROP, OP_DROP])
            + trailing_spk
        )
    raise ValueError(f"Unknown op {op}")


def _read_push(script: bytes, pos: int) -> tuple[bytes, int]:
    if pos >= len(script):
        raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
    op = script[pos]
    pos += 1
    if 1 <= op < 0x4C:
        end = pos + op
        if end > len(script):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        return script[pos:end], end
    if op == 0x4C:
        if pos >= len(script):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        n = script[pos]
        if n < 0x4C:
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")  # non-minimal
        pos += 1
        end = pos + n
        if end > len(script):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        return script[pos:end], end
    if op == 0x4D:
        if pos + 2 > len(script):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        n = struct.unpack("<H", script[pos : pos + 2])[0]
        if n <= 0xFF:
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")  # non-minimal
        pos += 2
        end = pos + n
        if end > len(script):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        return script[pos:end], end
    raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")


def parse_name_output(script: bytes) -> dict[str, Any]:
    """Parse Namecoin output script per SPEC-02 SL-LDGR-005."""
    if not script:
        raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
    op = script[0]
    pos = 1
    if op == OP_NAME_NEW:
        h20, pos = _read_push(script, pos)
        if len(h20) != 20 or script[pos : pos + 1] != bytes([OP_2DROP]):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        tail = script[pos + 1 :]
        result: dict[str, Any] = {"op": "NAME_NEW", "hash20": h20.hex()}
    elif op == OP_NAME_FIRSTUPDATE:
        name, pos = _read_push(script, pos)
        rand, pos = _read_push(script, pos)
        val, pos = _read_push(script, pos)
        if script[pos : pos + 2] != bytes([OP_2DROP, OP_2DROP]):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        tail = script[pos + 2 :]
        result = {"op": "NAME_FIRSTUPDATE", "name": name.decode("utf-8"), "rand": rand.hex(), "value": val.decode("utf-8")}
    elif op == OP_NAME_UPDATE:
        name, pos = _read_push(script, pos)
        val, pos = _read_push(script, pos)
        if script[pos : pos + 2] != bytes([OP_2DROP, OP_DROP]):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        tail = script[pos + 2 :]
        result = {"op": "NAME_UPDATE", "name": name.decode("utf-8"), "value": val.decode("utf-8")}
    else:
        raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")

    # Trailing scriptPubKey MUST be native SegWit v0 P2WPKH (22B) or P2WSH (34B)
    if not ((len(tail) == 22 and tail[:2] == b"\x00\x14") or (len(tail) == 34 and tail[:2] == b"\x00\x20")):
        raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
    result["trailing_script_pubkey"] = tail.hex()
    return result


# ============================================================================
# 6. SLNK OP_RETURN Framing & Merkle Batch 0x02 (SPEC-02 §5.2-5.3)
# ============================================================================

SLNK_MAGIC = b"SLNK"


def encode_opreturn(
    action: int,
    commitment_hex: str,
    loc_type: int = 0x00,
    pointer_hex: str | None = None,
    h_c: int | None = None,
) -> bytes:
    if action == 0x06 or not (0x01 <= action <= 0x12):
        raise ValueError("CHAIN_FRAME_INVALID")
    comm = bytes.fromhex(commitment_hex)
    if len(comm) != 32:
        raise ValueError("CHAIN_FRAME_INVALID")
    if action == 0x0B:
        if h_c is None or loc_type != 0x00 or pointer_hex is not None:
            raise ValueError("CHAIN_FRAME_INVALID")
        payload = bytes([0x01]) + comm + struct.pack("<Q", h_c) + bytes([0x00])
    else:
        if loc_type == 0x00:
            if pointer_hex is not None:
                raise ValueError("CHAIN_FRAME_INVALID")
            payload = bytes([0x01]) + comm + bytes([0x00])
        elif loc_type in (0x01, 0x02, 0x05):
            if pointer_hex is None:
                raise ValueError("CHAIN_FRAME_INVALID")
            ptr = bytes.fromhex(pointer_hex)
            if len(ptr) != 32:
                raise ValueError("CHAIN_FRAME_INVALID")
            payload = bytes([0x01]) + comm + bytes([loc_type]) + ptr
        else:
            raise ValueError("CHAIN_FRAME_INVALID")
    script = bytes([0x6A, 0x05]) + SLNK_MAGIC + bytes([action]) + _push_data(payload)
    if len(script) > 83:
        raise ValueError("CHAIN_FRAME_INVALID")
    return script


def decode_opreturn(script: bytes) -> dict[str, Any]:
    if len(script) < 8 or len(script) > 83 or script[0] != 0x6A or script[1] != 0x05 or script[2:6] != SLNK_MAGIC:
        raise ValueError("CHAIN_FRAME_INVALID")
    action = script[6]
    if action == 0x06 or not (0x01 <= action <= 0x12):
        raise ValueError("CHAIN_FRAME_INVALID")
    payload, end = _read_push(script, 7)
    if end != len(script) or len(payload) < 34 or payload[0] != 0x01:
        raise ValueError("CHAIN_FRAME_INVALID")
    comm = payload[1:33].hex()
    if action == 0x0B:
        if len(payload) != 42 or payload[41] != 0x00:
            raise ValueError("CHAIN_FRAME_INVALID")
        h_c = struct.unpack("<Q", payload[33:41])[0]
        return {"action": f"0x{action:02x}", "version": 1, "commitment": comm, "h_c": h_c, "loc_type": "0x00"}
    loc = payload[33]
    if loc == 0x00 and len(payload) == 34:
        return {"action": f"0x{action:02x}", "version": 1, "commitment": comm, "loc_type": "0x00"}
    if loc in (0x01, 0x02, 0x05) and len(payload) == 66:
        return {
            "action": f"0x{action:02x}",
            "version": 1,
            "commitment": comm,
            "loc_type": f"0x{loc:02x}",
            "pointer": payload[34:66].hex(),
        }
    raise ValueError("CHAIN_FRAME_INVALID")


def merkle_leaf(item_digest_hex: str) -> bytes:
    b = bytes.fromhex(item_digest_hex)
    if len(b) != 32:
        raise ValueError("leaf digest must be 32 bytes")
    return tagged_hash("seallink-merkle-leaf/1", b)


def merkle_node(left: bytes, right: bytes) -> bytes:
    return tagged_hash("seallink-merkle-node/1", left + right)


def build_merkle_tree(item_digests: list[str]) -> tuple[str, dict[str, dict[str, Any]]]:
    """Build SPEC-02 §5.3 Merkle tree (sorted unique digests, tagged leaves/nodes, odd-node promotion)."""
    ordered = sorted(set(item_digests), key=bytes.fromhex)
    if not (1 <= len(ordered) <= 65536):
        raise ValueError("invalid batch size")
    levels: list[list[bytes]] = [[merkle_leaf(d) for d in ordered]]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt: list[bytes] = []
        i = 0
        while i < len(cur):
            if i + 1 < len(cur):
                nxt.append(merkle_node(cur[i], cur[i + 1]))
            else:
                nxt.append(cur[i])  # odd-node promotion without duplication
            i += 2
        levels.append(nxt)
    root_hex = levels[-1][0].hex()

    proofs: dict[str, dict[str, Any]] = {}
    for idx, d in enumerate(ordered):
        steps = []
        pos = idx
        for lvl in levels[:-1]:
            if pos % 2 == 0:
                if pos + 1 < len(lvl):
                    steps.append({"side": "R", "hash": lvl[pos + 1].hex()})
            else:
                steps.append({"side": "L", "hash": lvl[pos - 1].hex()})
            pos //= 2
        proofs[d] = {"root": root_hex, "leaf_digest": d, "steps": steps}
    return root_hex, proofs


def verify_merkle_proof(proof: dict[str, Any]) -> bool:
    cur = merkle_leaf(proof["leaf_digest"])
    for step in proof["steps"]:
        sib = bytes.fromhex(step["hash"])
        if step["side"] == "L":
            cur = merkle_node(sib, cur)
        elif step["side"] == "R":
            cur = merkle_node(cur, sib)
        else:
            return False
    return cur.hex() == proof["root"]


# ============================================================================
# 7. Constraint Algebra & R8.5 / R8.6 Checks (SPEC-01 §6, SPEC-06 §3)
# ============================================================================

def validate_predicate(pred: dict[str, Any]) -> bool:
    if len(pred) != 1:
        return False
    op, val = next(iter(pred.items()))
    if op == "eq":
        return isinstance(val, (str, bool))
    if op in ("in", "not_in"):
        if not isinstance(val, list) or not (1 <= len(val) <= 256):
            return False
        if not all(isinstance(x, str) for x in val):
            return False
        return val == sorted(set(val), key=_utf16_sort_key)
    if op in ("prefix", "suffix"):
        return isinstance(val, str) and 1 <= len(val) <= 512
    if op == "range":
        if not (isinstance(val, list) and len(val) == 2):
            return False
        if not all(isinstance(x, str) and UINT64_STR_RE.match(x) for x in val):
            return False
        lo, hi = int(val[0]), int(val[1])
        return 0 <= lo <= hi <= MAX_UINT64
    if op == "hash_eq":
        return isinstance(val, str) and bool(re.match(r"^[0-9a-f]{64}$", val))
    return False


def match_predicate(pred: dict[str, Any], arg: Any) -> bool:
    op, val = next(iter(pred.items()))
    if op == "eq":
        return type(arg) is type(val) and arg == val
    if op == "in":
        return isinstance(arg, str) and arg in val
    if op == "not_in":
        return isinstance(arg, str) and arg not in val
    if op == "prefix":
        return isinstance(arg, str) and arg.startswith(val)
    if op == "suffix":
        return isinstance(arg, str) and arg.endswith(val)
    if op == "range":
        if not (isinstance(arg, str) and UINT64_STR_RE.match(arg)):
            return False
        v = int(arg)
        return int(val[0]) <= v <= int(val[1])
    if op == "hash_eq":
        if not isinstance(arg, str):
            return False
        return arg == val or sha256(arg.encode("utf-8")).hex() == val
    return False


def narrows_predicate(child: dict[str, Any], parent: dict[str, Any]) -> bool:
    if not (validate_predicate(child) and validate_predicate(parent)):
        return False
    cop, cval = next(iter(child.items()))
    pop, pval = next(iter(parent.items()))
    if pop == "eq":
        return cop == "eq" and type(cval) is type(pval) and cval == pval
    if pop == "in":
        pset = set(pval)
        if cop == "in":
            return set(cval).issubset(pset)
        if cop == "eq":
            return isinstance(cval, str) and cval in pset
        return False
    if pop == "not_in":
        pset = set(pval)
        if cop == "not_in":
            return pset.issubset(set(cval))
        if cop == "in":
            return set(cval).isdisjoint(pset)
        if cop == "eq":
            return isinstance(cval, str) and cval not in pset
        return False
    if pop == "prefix":
        if cop == "prefix":
            return cval.startswith(pval)
        if cop == "eq":
            return isinstance(cval, str) and cval.startswith(pval)
        if cop == "in":
            return all(v.startswith(pval) for v in cval)
        return False
    if pop == "suffix":
        if cop == "suffix":
            return cval.endswith(pval)
        if cop == "eq":
            return isinstance(cval, str) and cval.endswith(pval)
        if cop == "in":
            return all(v.endswith(pval) for v in cval)
        return False
    if pop == "range":
        plo, phi = int(pval[0]), int(pval[1])
        if cop == "range":
            clo, chi = int(cval[0]), int(cval[1])
            return plo <= clo <= chi <= phi
        if cop == "eq":
            return isinstance(cval, str) and bool(UINT64_STR_RE.match(cval)) and plo <= int(cval) <= phi
        if cop == "in":
            return all(bool(UINT64_STR_RE.match(v)) and plo <= int(v) <= phi for v in cval)
        return False
    if pop == "hash_eq":
        return cop == "hash_eq" and cval == pval
    return False


def check_whole_parent_budget_r85(delegate: dict[str, Any]) -> tuple[bool, dict[str, int]]:
    """Verify R8.5 aggregate budget across all groups: sum_g(rows(g) * cap(g, q)) <= pool_max(q)."""
    pools = {
        (q["kind"], q["resource"], q["unit"], q["window"]): int(q["max"])
        for q in delegate.get("pools", [])
    }
    totals: dict[tuple[str, str, str, str], int] = {}
    for g in delegate["groups"]:
        rows = sum(r["count"] for r in g["ranges"])
        group_caps: dict[tuple[str, str, str, str], int] = {}
        for cap in g["template"]["capabilities"]:
            for q in cap.get("quotas", []):
                key = (q["kind"], q["resource"], q["unit"], q["window"])
                group_caps[key] = group_caps.get(key, 0) + int(q["max"])
        for key, gcap in group_caps.items():
            totals[key] = totals.get(key, 0) + rows * gcap
            if totals[key] > MAX_UINT64:
                return False, {}
    for key, needed in totals.items():
        if key not in pools or needed > pools[key]:
            return False, {"|".join(k): v for k, v in totals.items()}
    return True, {"|".join(k): v for k, v in totals.items()}


def check_disjoint_ranges_r86(parent_payload: dict[str, Any]) -> bool:
    """Verify R8.6 pairwise disjointness of all row coins, stop coins, parent seal, and linkage output."""
    seen: set[tuple[str, int]] = set()
    rev = parent_payload.get("revocation", {})
    if rev.get("mode") == "seal":
        seal = rev["seal"]
        seen.add((seal["txid"], seal["vout"]))
        seen.add((seal["txid"], seal["vout"] + 1))  # linkage output
    for g in parent_payload["delegate"]["groups"]:
        for r in g["ranges"]:
            for v in range(r["first"], r["first"] + r["count"]):
                op = (r["txid"], v)
                if op in seen:
                    return False
                seen.add(op)
            if "stop_txid" in r:
                for v in range(r["stop_first"], r["stop_first"] + r["count"]):
                    op = (r["stop_txid"], v)
                    if op in seen:
                        return False
                    seen.add(op)
    return True


# ============================================================================
# 8. Guardianship Consistency (SL-ORIG-016) & Event Class Derivation (SPEC-04)
# ============================================================================

EVENT_CLASS_ORDER = {
    "routine_read": 0,
    "effect_grant": 1,
    "contract_assent": 2,
    "custody_change": 3,
}
EVENT_CLASS_BY_RANK = {v: k for k, v in EVENT_CLASS_ORDER.items()}

# Actions with external_mutation=True or forced effect_grant class
MUTATING_OR_EFFECT_ACTIONS = frozenset({
    "mail/send",
    "agent/tool",
    "agent/session",
    "agent/guardian-message",
})


def required_guardian_slots(quorum: dict[str, int], revision_size: int) -> int:
    """Exact integer ceiling quorum formula SL-ORIG-005: max(min, ceil(num * revision_size / den))."""
    num, den, mn = quorum["num"], quorum["den"], quorum["min"]
    ceil_val = (num * revision_size + den - 1) // den
    return max(mn, ceil_val)


def check_guardian_policy_consistency(policy: dict[str, Any]) -> tuple[bool, str]:
    """Validate SL-ORIG-016 mechanical consistency on origin.guardian_policy or GuardianRoster.payload."""
    rev_size = policy.get("revision_size", 0)
    if not isinstance(rev_size, int) or not (1 <= rev_size <= 32):
        return False, "WIRE_INTEGER"
    quorums = policy.get("quorums", {})
    if set(quorums.keys()) != set(EVENT_CLASS_ORDER.keys()):
        return False, "WIRE_MEMBER"
    for q in quorums.values():
        num, den, mn = q.get("num", 0), q.get("den", 0), q.get("min", 0)
        if not (1 <= num <= den <= 32) or not (1 <= mn <= rev_size):
            return False, "WIRE_INTEGER"
    slots = policy.get("slots", [])
    if len(slots) != rev_size:
        return False, "WIRE_INTEGER"
    slot_nums = [s.get("slot") for s in slots]
    if len(set(slot_nums)) != rev_size or set(slot_nums) != set(range(1, rev_size + 1)):
        return False, "WIRE_INTEGER"
    disp = policy.get("disposer_pk")
    arb = policy.get("arbiter_pk")
    chal = policy.get("challenger_pk")
    if not (disp and arb and chal):
        return False, "WIRE_MEMBER"
    if not (is_valid_compressed_pubkey(disp) and is_valid_compressed_pubkey(arb) and is_valid_compressed_pubkey(chal)):
        return False, "WIRE_KEY"
    if disp == arb:
        return False, "ORIGIN_UNVERIFIED"
    if "roster_seal" in policy:
        expected_roster = {"kind": "branch", "template": "both_of_2", "keys": {"a": disp, "b": arb}}
        try:
            got_spk, _ = compile_script_policy(policy["roster_seal"]["script_policy"])
            exp_spk, _ = compile_script_policy(expected_roster)
        except ValueError:
            return False, "CHAIN_SCRIPT_UNSUPPORTED"
        if got_spk != exp_spk:
            return False, "CHAIN_SCRIPT_UNSUPPORTED"
    return True, "OK"


def derive_guardian_event_class(payload: dict[str, Any]) -> str:
    """Deterministically derive the required GuardianEventClass (SPEC-04 §3.1)."""
    obj_type = payload.get("type")
    if obj_type == "seallink-assent/1":
        target_type = payload.get("target_type")
        if target_type == "seallink-migration/1":
            return "custody_change"
        return "contract_assent"
    if obj_type == "seallink-grant/1":
        if "delegate" in payload:
            return "custody_change"
        if "contract_id" in payload:
            return "contract_assent"
        rank = 0
        rev = payload.get("revocation", {})
        if rev.get("mode") == "seal" and rev.get("kind") == "single_use":
            rank = max(rank, 1)
        for cap in payload.get("capabilities", []):
            if cap.get("quotas") or cap.get("action") in MUTATING_OR_EFFECT_ACTIONS:
                rank = max(rank, 1)
        return EVENT_CLASS_BY_RANK[rank]
    raise ValueError(f"Unsupported guardian_context carrier: {obj_type}")


def self_test() -> None:
    """Verify pure-Python BIP-340 against official BIP-340 Vector 0 and clause_commit Vector."""
    # Official BIP-340 Test Vector 0
    sk0 = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")
    pk0_exp = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    msg0 = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    aux0 = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    sig0_exp = (
        "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215"
        "25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
    )
    assert xonly_pubkey(sk0) == pk0_exp, "BIP-340 pubkey mismatch"
    sig0 = schnorr_sign(msg0, sk0, aux0)
    assert sig0 == sig0_exp, f"BIP-340 sig mismatch: {sig0}"
    assert schnorr_verify(msg0, pk0_exp, sig0), "BIP-340 verify failed"

    # Official RIPEMD-160 test vector for "abc"
    assert ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", "RIPEMD-160 mismatch"

    # Clause commitment vector (SPEC-01 §5)
    salt = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    c_hash = clause_commit(salt, {"text": "Room inspection"})
    assert c_hash.startswith("b030a8a82ef79e9d"), f"clause_commit mismatch: {c_hash}"
    print(f"seallink_ref self_test PASS | clause_commit={c_hash}")


if __name__ == "__main__":
    self_test()
