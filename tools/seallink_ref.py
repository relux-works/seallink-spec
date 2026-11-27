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

import functools
import hashlib
import hmac
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
    return tagged_hash("seallink-clause/1", salt_bytes + jcs_encode(clause_obj, allow_lf_paths=CLAUSE_LF_PATHS)).hex()


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

# Exact schema paths annotated with "x-seallink-allow-lf": true (SPEC-01 §1 SL-WIRE-005)
ALLOW_LF_BY_TYPE: dict[str, frozenset[tuple[str, ...]]] = {
    "seallink-grant/1": frozenset({("payload", "terms_text"), ("terms_text",)}),
    "seallink-termination/1": frozenset({("reason",), ("payload", "reason")}),
    "seallink-card/1": frozenset({("role",)}),
}
CLAUSE_LF_PATHS: frozenset[tuple[str, ...]] = frozenset({("text",)})
MAX_UINT53 = 9007199254740991
MAX_UINT53_STR = "9007199254740991"
MAX_UINT64 = 18446744073709551615
UINT64_STR_RE = re.compile(r"\A(0|[1-9][0-9]{0,19})\Z")
HEX64_RE = re.compile(r"\A[0-9a-f]{64}\Z")


def _extract_root_type(obj: Any) -> str | None:
    if not isinstance(obj, dict):
        return None
    t = obj.get("type")
    if isinstance(t, str):
        return t
    p = obj.get("payload")
    if isinstance(p, dict) and isinstance(p.get("type"), str):
        return p["type"]
    return None


def _path_allows_lf(
    root_type: str | None,
    path: tuple[str, ...],
    extra_allow_lf: frozenset[tuple[str, ...]] | None = None,
) -> bool:
    if extra_allow_lf is not None and path in extra_allow_lf:
        return True
    if root_type is None:
        return False
    allowed = ALLOW_LF_BY_TYPE.get(root_type)
    return bool(allowed and path in allowed)


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


def _jcs_serialize(
    val: Any,
    root_type: str | None = None,
    path: tuple[str, ...] = (),
    depth: int = 0,
    allow_lf_paths: frozenset[tuple[str, ...]] | None = None,
) -> str:
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
        allow_lf = _path_allows_lf(root_type, path, allow_lf_paths)
        if not _validate_string(val, allow_lf):
            raise ValueError("WIRE_STRING")
        return _encode_jcs_str(val)
    if isinstance(val, list):
        next_depth = depth + 1
        if next_depth > 16:
            raise ValueError("WIRE_SIZE")
        return "[" + ",".join(_jcs_serialize(x, root_type, path + ("[]",), next_depth, allow_lf_paths) for x in val) + "]"
    if isinstance(val, dict):
        next_depth = depth + 1
        if next_depth > 16:
            raise ValueError("WIRE_SIZE")
        items = sorted(val.items(), key=lambda kv: _utf16_sort_key(kv[0]))
        parts = []
        for k, v in items:
            if not isinstance(k, str) or not _validate_string(k, False):
                raise ValueError("WIRE_STRING")
            parts.append(f"{_encode_jcs_str(k)}:{_jcs_serialize(v, root_type, path + (k,), next_depth, allow_lf_paths)}")
        return "{" + ",".join(parts) + "}"
    raise ValueError("WIRE_VALUE")


def jcs_encode(obj: dict[str, Any], *, allow_lf_paths: frozenset[tuple[str, ...]] | None = None) -> bytes:
    if not isinstance(obj, dict):
        raise ValueError("WIRE_JSON")
    return _jcs_serialize(obj, _extract_root_type(obj), (), 0, allow_lf_paths).encode("utf-8")


def _collect_depth_and_value_errors(
    val: Any,
    root_type: str | None,
    path: tuple[str, ...],
    depth: int,
    errs: set[str],
    allow_lf_paths: frozenset[tuple[str, ...]] | None = None,
) -> None:
    if val is None:
        errs.add("WIRE_VALUE")
        return
    if isinstance(val, bool):
        return
    if isinstance(val, float):
        errs.add("WIRE_NUMBER")
        return
    if isinstance(val, int):
        if val < 0 or val > MAX_UINT53:
            errs.add("WIRE_NUMBER")
        return
    if isinstance(val, str):
        if not _validate_string(val, _path_allows_lf(root_type, path, allow_lf_paths)):
            errs.add("WIRE_STRING")
        return
    if isinstance(val, list):
        next_depth = depth + 1
        if next_depth > 16:
            errs.add("WIRE_SIZE")
            return
        for item in val:
            _collect_depth_and_value_errors(item, root_type, path + ("[]",), next_depth, errs, allow_lf_paths)
        return
    if isinstance(val, dict):
        next_depth = depth + 1
        if next_depth > 16:
            errs.add("WIRE_SIZE")
            return
        for k, v in val.items():
            if not _validate_string(k, False):
                errs.add("WIRE_STRING")
            _collect_depth_and_value_errors(v, root_type, path + (k,), next_depth, errs, allow_lf_paths)
        return
    errs.add("WIRE_VALUE")


def _scan_container_depth(text: str) -> tuple[int, bool]:
    """Iterative O(n) string-aware lexical container depth scan (guards json.loads against RecursionError)."""
    cur = 0
    best = 0
    in_str = False
    esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            cur += 1
            if cur > best:
                best = cur
        elif ch in "}]":
            cur -= 1
            if cur < 0:
                return best, False
    return best, (not in_str and cur == 0)


_ASCII_DIGITS = frozenset("0123456789")
_VALUE_DELIMS = frozenset(("", ":", ",", "[", "{", " ", "\t", "\r", "\n"))
_END_DELIMS = frozenset((",", "}", "]", " ", "\t", "\r", "\n"))


class _JsonConstantError(ValueError):
    """Raised on non-RFC-8259 Python JSON extensions (NaN, Infinity, -Infinity) so they always map to WIRE_JSON."""


def _reject_json_constant(_tok: str) -> Any:
    raise _JsonConstantError("non-RFC8259 JSON constant")


def _is_malformed_number_error(text: str, pos: int) -> bool:
    """Detect malformed ASCII numeric tokens (`01`, `-01`, `+1`, `.5`, `-.5`, `1.`, `1e`) so they map deterministically to WIRE_NUMBER (SPEC-01 §7, M-2)."""
    if pos < 0 or pos >= len(text):
        return False
    prev = text[pos - 1] if pos >= 1 else ""
    prev2 = text[pos - 2] if pos >= 2 else ""
    ch = text[pos]
    nxt = text[pos + 1] if pos + 1 < len(text) else ""
    nxt2 = text[pos + 2] if pos + 2 < len(text) else ""
    # Leading zero like 01, 00, -01 (strictly ASCII digits)
    if prev == "0" and ch in _ASCII_DIGITS and (prev2 in _VALUE_DELIMS or prev2 == "-"):
        return True
    # Explicit plus sign like +1
    if ch == "+" and nxt in _ASCII_DIGITS and prev in _VALUE_DELIMS:
        return True
    # Leading decimal point like .5 or -.5
    if ch == "." and nxt in _ASCII_DIGITS and (prev in _VALUE_DELIMS or prev == "-"):
        return True
    if ch == "-" and nxt == "." and nxt2 in _ASCII_DIGITS and prev in _VALUE_DELIMS:
        return True
    # Trailing decimal point like 1. (JSONDecodeError may point at '.' OR at the delimiter after '.')
    if ch == "." and prev in _ASCII_DIGITS and (nxt == "" or nxt in _END_DELIMS):
        return True
    if prev == "." and prev2 in _ASCII_DIGITS and ch in _END_DELIMS:
        return True
    # Incomplete exponent like 1e, 1E, 1e+, 1e-
    if ch in ("e", "E") and prev in _ASCII_DIGITS and (nxt == "" or nxt in _END_DELIMS or (nxt in ("+", "-") and (nxt2 == "" or nxt2 in _END_DELIMS))):
        return True
    if prev in ("e", "E") and prev2 in _ASCII_DIGITS and ch in _END_DELIMS:
        return True
    return False


def jcs_validate(
    raw: bytes,
    max_bytes: int = 1048576,
    *,
    allow_lf_paths: frozenset[tuple[str, ...]] | None = None,
) -> tuple[bool, Any]:
    """Validate raw bytes against SPEC-01 §1-2 pipeline steps 1..6 (whole-tree precedence: WIRE_SIZE -> WIRE_JSON -> WIRE_DUPLICATE -> WIRE_VALUE -> WIRE_NUMBER -> WIRE_STRING -> WIRE_NOT_CANONICAL)."""
    if len(raw) > max_bytes:
        return False, "WIRE_SIZE"
    if raw.startswith(b"\xef\xbb\xbf"):
        return False, "WIRE_JSON"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False, "WIRE_JSON"

    # SL-WIRE-002: single RFC 8259 JSON object with no leading or trailing bytes (including whitespace)
    if not text or text[0] in " \t\r\n" or text[-1] in " \t\r\n":
        return False, "WIRE_JSON"

    # Iterative depth guard enforcing SPEC-01 §7 Step 2 (lexical depth > 16 -> immediate WIRE_SIZE; H-20, F-19)
    lex_depth, _lex_balanced = _scan_container_depth(text)
    if lex_depth > 16:
        return False, "WIRE_SIZE"

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
        # Bounds check BEFORE int(s) so huge integers (>4300 digits on CPython >=3.11) deterministically return WIRE_NUMBER (M03 / R12-M6)!
        if len(s) > 16 or not all(c in _ASCII_DIGITS for c in s) or (len(s) == 16 and s > MAX_UINT53_STR):
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
            parse_constant=_reject_json_constant,
        )
    except _JsonConstantError:
        return False, "WIRE_JSON"
    except json.JSONDecodeError as exc:
        if _is_malformed_number_error(text, exc.pos):
            return False, "WIRE_NUMBER"
        return False, "WIRE_JSON"
    except RecursionError:
        return False, "WIRE_SIZE"
    except Exception:
        return False, "WIRE_JSON"

    if not isinstance(obj, dict):
        return False, "WIRE_JSON"

    # Container-only depth check (SL-WIRE-001): root object = 1, only dict/list increment depth
    def max_container_depth(v: Any, cur: int = 1) -> int:
        if isinstance(v, dict):
            sub = [max_container_depth(x, cur + 1) for x in v.values() if isinstance(x, (dict, list))]
            return max([cur] + sub)
        if isinstance(v, list):
            sub = [max_container_depth(x, cur + 1) for x in v if isinstance(x, (dict, list))]
            return max([cur] + sub)
        return cur

    if max_container_depth(obj) > 16:
        return False, "WIRE_SIZE"
    if dup_found:
        return False, "WIRE_DUPLICATE"
    root_type = _extract_root_type(obj)
    val_errs: set[str] = set()
    _collect_depth_and_value_errors(obj, root_type, (), 0, val_errs, allow_lf_paths)
    if bad_num:
        val_errs.add("WIRE_NUMBER")
    # Strict whole-tree precedence (SPEC-01 §7, R3 Blocker #5): WIRE_VALUE before WIRE_NUMBER before WIRE_STRING!
    for code in ("WIRE_SIZE", "WIRE_VALUE", "WIRE_NUMBER", "WIRE_STRING"):
        if code in val_errs:
            return False, code

    try:
        reencoded = jcs_encode(obj, allow_lf_paths=allow_lf_paths)
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


@functools.lru_cache(maxsize=16384)
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


@functools.lru_cache(maxsize=16384)
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


# ============================================================================
# 4b. Pure-Python RFC 8032 Ed25519 & SEC 1 NIST P-256 ECDSA (Strict Low-S)
# ============================================================================

DEVICE_ALG_ALLOWED_TYPES = frozenset({
    "seallink-owner-command/1",
    "seallink-statement/1",
})

# --- RFC 8032 Ed25519 (Twisted Edwards: -x^2 + y^2 = 1 + d*x^2*y^2 mod p) ---
_ED_P = (1 << 255) - 19
_ED_L = (1 << 252) + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_recover_x(y: int, sign: int) -> int | None:
    if y >= _ED_P:
        return None
    x2 = ((y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P)) % _ED_P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = (x * _ED_I) % _ED_P
    if (x * x - x2) % _ED_P != 0:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x


_ED_BY = (4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P
_ED_BX = _ed_recover_x(_ED_BY, 0)
assert _ED_BX is not None
_ED_B = (_ED_BX, _ED_BY, 1, (_ED_BX * _ED_BY) % _ED_P)
_ED_ID = (0, 1, 1, 0)


def _ed_add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _ED_P
    b = ((y1 + x1) * (y2 + x2)) % _ED_P
    c = (2 * _ED_D * t1 * t2) % _ED_P
    d = (2 * z1 * z2) % _ED_P
    e = (b - a) % _ED_P
    f = (d - c) % _ED_P
    g = (d + c) % _ED_P
    h = (b + a) % _ED_P
    return ((e * f) % _ED_P, (g * h) % _ED_P, (f * g) % _ED_P, (e * h) % _ED_P)


def _ed_mul(pt: tuple[int, int, int, int], s: int) -> tuple[int, int, int, int]:
    r = _ED_ID
    addend = pt
    k = s
    while k > 0:
        if k & 1:
            r = _ed_add(r, addend)
        addend = _ed_add(addend, addend)
        k >>= 1
    return r


def _ed_encode_point(pt: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, _ED_P - 2, _ED_P)
    ax = (x * zi) % _ED_P
    ay = (y * zi) % _ED_P
    b = bytearray(ay.to_bytes(32, "little"))
    b[31] |= (ax & 1) << 7
    return bytes(b)


def _ed_is_identity(pt: tuple[int, int, int, int]) -> bool:
    x, y, z, _ = pt
    return x % _ED_P == 0 and (y - z) % _ED_P == 0


def _ed_is_small_order(pt: tuple[int, int, int, int]) -> bool:
    """Return True iff pt is one of the 8 Ed25519 small-order points (order dividing cofactor 8)."""
    p2 = _ed_add(pt, pt)
    p4 = _ed_add(p2, p2)
    p8 = _ed_add(p4, p4)
    return _ed_is_identity(p8)


def _ed_decode_point(b: bytes) -> tuple[int, int, int, int] | None:
    if len(b) != 32:
        return None
    sign = (b[31] >> 7) & 1
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    x = _ed_recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _ED_P)


def deterministic_ed25519_seed(label: str) -> bytes:
    """Derive a reproducible 32-byte Ed25519 seed for test vectors ONLY."""
    return sha256(b"seallink-test-vector-ed25519:" + label.encode("utf-8"))


def ed25519_pubkey(seed32: bytes) -> str:
    if len(seed32) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed32).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _ed_encode_point(_ed_mul(_ED_B, a)).hex()


def is_valid_ed25519_pubkey(hex_pk: str) -> bool:
    """Strict canonical non-small-order Ed25519 public key check (SPEC-01 §4.1)."""
    if len(hex_pk) != 64 or hex_pk != hex_pk.lower():
        return False
    try:
        raw = bytes.fromhex(hex_pk)
    except ValueError:
        return False
    pt = _ed_decode_point(raw)
    return pt is not None and not _ed_is_small_order(pt)


def ed25519_sign(msg: bytes, seed32: bytes) -> str:
    if len(seed32) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed32).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    pub_b = _ed_encode_point(_ed_mul(_ED_B, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _ED_L
    r_b = _ed_encode_point(_ed_mul(_ED_B, r))
    k = int.from_bytes(hashlib.sha512(r_b + pub_b + msg).digest(), "little") % _ED_L
    s = (r + k * a) % _ED_L
    sig = r_b + s.to_bytes(32, "little")
    assert ed25519_verify(msg, pub_b.hex(), sig.hex())
    return sig.hex()


@functools.lru_cache(maxsize=4096)
def ed25519_verify(msg: bytes, pubkey_hex: str, sig_hex: str) -> bool:
    """Strict canonical non-small-order cofactorless Ed25519 verification (SPEC-01 §4.1)."""
    if len(pubkey_hex) != 64 or len(sig_hex) != 128:
        return False
    if pubkey_hex != pubkey_hex.lower() or sig_hex != sig_hex.lower():
        return False
    try:
        pub_b = bytes.fromhex(pubkey_hex)
        sig_b = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    a_pt = _ed_decode_point(pub_b)
    r_pt = _ed_decode_point(sig_b[:32])
    if a_pt is None or r_pt is None or _ed_is_small_order(a_pt) or _ed_is_small_order(r_pt):
        return False
    s = int.from_bytes(sig_b[32:], "little")
    if s >= _ED_L:
        return False
    k = int.from_bytes(hashlib.sha512(sig_b[:32] + pub_b + msg).digest(), "little") % _ED_L
    lhs = _ed_mul(_ED_B, s)
    rhs = _ed_add(r_pt, _ed_mul(a_pt, k))
    # Strict un-cofactored comparison in projective coordinates: X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1
    return (lhs[0] * rhs[2] - rhs[0] * lhs[2]) % _ED_P == 0 and (lhs[1] * rhs[2] - rhs[1] * lhs[2]) % _ED_P == 0


# --- SEC 1 NIST P-256 (secp256r1) ECDSA with Strict Low-S (s <= n/2) ---
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_HALF_N = _P256_N // 2
_P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def _p256_jac_double(pt: tuple[int, int, int]) -> tuple[int, int, int]:
    x1, y1, z1 = pt
    if y1 == 0 or z1 == 0:
        return (0, 1, 0)
    z1z1 = (z1 * z1) % _P256_P
    # Shortcut for a = -3 mod p: 3*(x1 - z1^2)*(x1 + z1^2)
    m = (3 * (x1 - z1z1) * (x1 + z1z1)) % _P256_P
    yy = (y1 * y1) % _P256_P
    yyyy = (yy * yy) % _P256_P
    s = (4 * x1 * yy) % _P256_P
    x3 = (m * m - 2 * s) % _P256_P
    y3 = (m * (s - x3) - 8 * yyyy) % _P256_P
    z3 = (2 * y1 * z1) % _P256_P
    return (x3, y3, z3)


def _p256_jac_add(p1: tuple[int, int, int], p2: tuple[int, int, int]) -> tuple[int, int, int]:
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1
    z1z1 = (z1 * z1) % _P256_P
    z2z2 = (z2 * z2) % _P256_P
    u1 = (x1 * z2z2) % _P256_P
    u2 = (x2 * z1z1) % _P256_P
    s1 = (y1 * z2 * z2z2) % _P256_P
    s2 = (y2 * z1 * z1z1) % _P256_P
    if u1 == u2:
        if s1 != s2:
            return (0, 1, 0)
        return _p256_jac_double(p1)
    h = (u2 - u1) % _P256_P
    hh = (h * h) % _P256_P
    hhh = (h * hh) % _P256_P
    r = (s2 - s1) % _P256_P
    v = (u1 * hh) % _P256_P
    x3 = (r * r - hhh - 2 * v) % _P256_P
    y3 = (r * (v - x3) - s1 * hhh) % _P256_P
    z3 = (h * z1 * z2) % _P256_P
    return (x3, y3, z3)


def _p256_point_mul(p: tuple[int, int] | None, n: int) -> tuple[int, int] | None:
    if p is None:
        return None
    k = n % _P256_N
    if k == 0:
        return None
    r = (0, 1, 0)
    addend = (p[0], p[1], 1)
    while k:
        if k & 1:
            r = _p256_jac_add(r, addend)
        addend = _p256_jac_double(addend)
        k >>= 1
    rx, ry, rz = r
    if rz == 0:
        return None
    z_inv = pow(rz, _P256_P - 2, _P256_P)
    z_inv2 = (z_inv * z_inv) % _P256_P
    return ((rx * z_inv2) % _P256_P, (ry * z_inv2 * z_inv) % _P256_P)


def _p256_point_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    rx, ry, rz = _p256_jac_add((p1[0], p1[1], 1), (p2[0], p2[1], 1))
    if rz == 0:
        return None
    z_inv = pow(rz, _P256_P - 2, _P256_P)
    z_inv2 = (z_inv * z_inv) % _P256_P
    return ((rx * z_inv2) % _P256_P, (ry * z_inv2 * z_inv) % _P256_P)


def _p256_decompress(hex_pk: str) -> tuple[int, int] | None:
    if len(hex_pk) != 66 or hex_pk != hex_pk.lower() or hex_pk[:2] not in ("02", "03"):
        return None
    try:
        x = int(hex_pk[2:], 16)
    except ValueError:
        return None
    if x >= _P256_P:
        return None
    y_sq = (pow(x, 3, _P256_P) + _P256_A * x + _P256_B) % _P256_P
    # _P256_P % 4 == 3
    y = pow(y_sq, (_P256_P + 1) // 4, _P256_P)
    if (y * y) % _P256_P != y_sq:
        return None
    want_odd = hex_pk[:2] == "03"
    if (y & 1) != (1 if want_odd else 0):
        y = _P256_P - y
    return (x, y)


def deterministic_p256_privkey(label: str) -> bytes:
    """Derive a reproducible non-zero NIST P-256 test secret key from an ASCII label (test vectors ONLY)."""
    h = sha256(b"seallink-test-vector-p256:" + label.encode("utf-8"))
    d = int.from_bytes(h, "big") % (_P256_N - 1) + 1
    return d.to_bytes(32, "big")


def p256_compressed_pubkey(privkey: bytes) -> str:
    d = int.from_bytes(privkey, "big")
    if not (1 <= d < _P256_N):
        raise ValueError("Invalid P-256 secret key")
    pt = _p256_point_mul(_P256_G, d)
    assert pt is not None
    prefix = b"\x02" if pt[1] % 2 == 0 else b"\x03"
    return (prefix + pt[0].to_bytes(32, "big")).hex()


def is_valid_p256_compressed_pubkey(hex_pk: str) -> bool:
    return _p256_decompress(hex_pk) is not None


def _rfc6979_k_p256(priv32: bytes, digest32: bytes) -> int:
    """RFC 6979 deterministic nonce generation for NIST P-256 with SHA-256."""
    h1_int = int.from_bytes(digest32, "big") % _P256_N
    h1_octets = h1_int.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + priv32 + h1_octets, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + priv32 + h1_octets, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < _P256_N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def p256_sign_low_s(msg32: bytes, privkey: bytes) -> str:
    """Sign 32-byte digest with NIST P-256 ECDSA returning 64-byte raw low-S r||s hex (SPEC-01 §4.1)."""
    if len(msg32) != 32 or len(privkey) != 32:
        raise ValueError("P-256 requires 32-byte digest and secret key")
    d = int.from_bytes(privkey, "big")
    if not (1 <= d < _P256_N):
        raise ValueError("Invalid P-256 secret key")
    e = int.from_bytes(msg32, "big")
    k = _rfc6979_k_p256(privkey, msg32)
    r_pt = _p256_point_mul(_P256_G, k)
    assert r_pt is not None
    r = r_pt[0] % _P256_N
    if r == 0:
        raise ValueError("Zero r")
    s = (pow(k, _P256_N - 2, _P256_N) * (e + r * d)) % _P256_N
    if s == 0:
        raise ValueError("Zero s")
    if s > _P256_HALF_N:
        s = _P256_N - s
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    pub_hex = p256_compressed_pubkey(privkey)
    assert p256_verify_low_s(msg32, pub_hex, sig.hex())
    return sig.hex()


def p256_verify_low_s(msg32: bytes, pubkey_hex: str, sig_hex: str) -> bool:
    """Verify 64-byte raw low-S NIST P-256 ECDSA signature over 32-byte pre-hashed digest."""
    if len(msg32) != 32 or len(pubkey_hex) != 66 or len(sig_hex) != 128:
        return False
    if pubkey_hex != pubkey_hex.lower() or sig_hex != sig_hex.lower():
        return False
    q_pt = _p256_decompress(pubkey_hex)
    if q_pt is None:
        return False
    try:
        sig_b = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    r = int.from_bytes(sig_b[:32], "big")
    s = int.from_bytes(sig_b[32:], "big")
    # Strict low-S enforcement: 1 <= r < n and 1 <= s <= n/2
    if not (1 <= r < _P256_N) or not (1 <= s <= _P256_HALF_N):
        return False
    e = int.from_bytes(msg32, "big")
    w = pow(s, _P256_N - 2, _P256_N)
    u1 = (e * w) % _P256_N
    u2 = (r * w) % _P256_N
    pt = _p256_point_add(_p256_point_mul(_P256_G, u1), _p256_point_mul(q_pt, u2))
    return pt is not None and (pt[0] % _P256_N) == r


def sign_envelope(
    payload: dict[str, Any],
    signers: list[bytes],
    policy_pks: list[str] | None = None,
    m: int | None = None,
    alg: str = "bip340",
) -> dict[str, Any]:
    """Build a canonical signed SealLink envelope supporting bip340, ed25519, and low-S p256."""
    digest = signing_digest(payload)
    if alg == "bip340":
        pub_fn = xonly_pubkey
        sig_fn = schnorr_sign
    elif alg == "ed25519":
        pub_fn = ed25519_pubkey
        sig_fn = ed25519_sign
    elif alg == "p256":
        pub_fn = p256_compressed_pubkey
        sig_fn = p256_sign_low_s
    else:
        raise ValueError(f"Unsupported alg: {alg}")
    derived_pks = [pub_fn(sk) for sk in signers]
    pks = sorted(set(policy_pks if policy_pks is not None else derived_pks))
    threshold = m if m is not None else len(signers)
    sigs = []
    for sk in sorted(signers, key=pub_fn):
        pk = pub_fn(sk)
        sigs.append({"pk": pk, "sig": sig_fn(digest, sk)})
    policy: dict[str, Any] = {"m": threshold, "pks": pks}
    if alg != "bip340":
        policy["alg"] = alg
    return {"payload": payload, "signatures": {"policy": policy, "sigs": sigs}}


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
    obj_type: str | None = None,
) -> tuple[bool, str]:
    """Verify a SignatureSet (bip340, ed25519, or low-S p256) over `digest`, enforcing SL-WIRE-013."""
    if not isinstance(sigset, dict) or set(sigset.keys()) != {"policy", "sigs"}:
        return False, "WIRE_SIGNATURE"
    policy = sigset["policy"]
    if not isinstance(policy, dict):
        return False, "WIRE_SIGNATURE"
    if not set(policy.keys()).issubset({"m", "pks", "alg"}):
        return False, "WIRE_MEMBER"
    # Canonical single encoding: "alg": "bip340" MUST be omitted (S-1 / SPEC-01 §4.2)
    if "alg" in policy and policy["alg"] == "bip340":
        return False, "WIRE_MEMBER"
    alg = policy.get("alg", "bip340")
    if alg not in ("bip340", "ed25519", "p256"):
        return False, "WIRE_SIGNATURE"
    if alg != "bip340" and obj_type is not None and obj_type not in DEVICE_ALG_ALLOWED_TYPES:
        return False, "WIRE_MEMBER"
    pks = policy.get("pks", [])
    m = policy.get("m", 0)
    if not isinstance(pks, list) or not isinstance(m, int) or isinstance(m, bool):
        return False, "WIRE_SIGNATURE"
    if not (1 <= m <= len(pks) <= 32):
        return False, "WIRE_SIGNATURE"
    if pks != sorted(set(pks)):
        return False, "WIRE_SIGNATURE"
    if alg == "bip340":
        pk_ok_fn = is_valid_xonly_pubkey
        ver_fn = schnorr_verify
    elif alg == "ed25519":
        pk_ok_fn = is_valid_ed25519_pubkey
        ver_fn = ed25519_verify
    else:
        pk_ok_fn = is_valid_p256_compressed_pubkey
        ver_fn = p256_verify_low_s
    for pk in pks:
        if not isinstance(pk, str) or not pk_ok_fn(pk):
            return False, "WIRE_KEY"
    if expected_policy is not None:
        exp_alg = expected_policy.get("alg", "bip340")
        if exp_alg != alg or expected_policy.get("m") != m or expected_policy.get("pks") != pks:
            return False, "WIRE_SIGNATURE"
    sigs = sigset["sigs"]
    if not isinstance(sigs, list):
        return False, "WIRE_SIGNATURE"
    seen: set[str] = set()
    prev_pk: str = ""
    valid = 0
    for entry in sigs:
        if not isinstance(entry, dict) or set(entry.keys()) != {"pk", "sig"}:
            return False, "WIRE_SIGNATURE"
        pk = entry["pk"]
        if not isinstance(pk, str) or pk not in pks or pk in seen or pk <= prev_pk:
            return False, "WIRE_SIGNATURE"
        prev_pk = pk
        seen.add(pk)
        if not isinstance(entry["sig"], str) or not ver_fn(digest, pk, entry["sig"]):
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
    if not isinstance(payload, dict) or "type" not in payload or not isinstance(payload["type"], str):
        return False, "WIRE_MEMBER"
    obj_type = payload["type"]
    digest = signing_digest(payload)
    if "signatures" in env and "guardian_approvals" not in env:
        return verify_signature_set(digest, env["signatures"], expected_policy=expected_policy, obj_type=obj_type)
    if "guardian_approvals" in env and "signatures" not in env:
        if obj_type not in ("seallink-grant/1", "seallink-assent/1", "seallink-termination/1"):
            return False, "WIRE_MEMBER"
        approvals = env["guardian_approvals"]
        if not isinstance(approvals, list) or not (1 <= len(approvals) <= 32):
            return False, "WIRE_SIGNATURE"
        prev_slot = 0
        for item in approvals:
            if not isinstance(item, dict):
                return False, "WIRE_SIGNATURE"
            slot = item.get("slot")
            if not isinstance(slot, int) or isinstance(slot, bool) or not (1 <= slot <= 32) or slot <= prev_slot:
                return False, "WIRE_SIGNATURE"
            prev_slot = slot
            # guardian_approvals MUST strictly use bip340 (SL-WIRE-013 item 2)
            ok, code = verify_signature_set(digest, item.get("signatures", {}), obj_type="__guardian_approval__")
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
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE
OP_CHECKMULTISIGVERIFY = 0xAF
OP_CHECKSEQUENCEVERIFY = 0xB2

P2A_SCRIPTPUBKEY = bytes.fromhex("51024e73")


def cast_to_bool(elem: bytes) -> bool:
    """Exact Bitcoin Script CastToBool (SPEC-02 §3.1, L-12)."""
    if not elem:
        return False
    for i, b in enumerate(elem):
        if b != 0:
            # Negative zero (0x80 in final byte with all preceding bytes 0) is FALSE
            if i == len(elem) - 1 and b == 0x80:
                return False
            return True
    return False


def _distinct_xcoords(pks: list[str]) -> bool:
    return len({pk[2:] for pk in pks}) == len(pks)


def is_valid_branch_key_spec(spec: Any) -> bool:
    """Validate BranchKeySpec: single CompressedPubkey66 OR compact m-of-n (2 <= n <= 5, 1 <= m <= n)."""
    if isinstance(spec, str):
        return is_valid_compressed_pubkey(spec)
    if isinstance(spec, dict) and set(spec.keys()) == {"m", "pks"}:
        m = spec["m"]
        pks = spec["pks"]
        if not isinstance(m, int) or isinstance(m, bool) or not isinstance(pks, list):
            return False
        if not (2 <= len(pks) <= 5 and 1 <= m <= len(pks)):
            return False
        if not all(isinstance(pk, str) and is_valid_compressed_pubkey(pk) for pk in pks):
            return False
        return pks == sorted(set(pks)) and _distinct_xcoords(pks)
    return False


def branch_key_spec_pks(spec: Any) -> list[str]:
    if isinstance(spec, str):
        return [spec]
    if isinstance(spec, dict) and isinstance(spec.get("pks"), list):
        return list(spec["pks"])
    return []


def branch_key_spec_xcoords(spec: Any) -> set[str]:
    return {pk[2:] for pk in branch_key_spec_pks(spec) if isinstance(pk, str) and len(pk) == 66}


def _branch_spec_sort_key(spec: Any) -> bytes:
    return _jcs_serialize(spec, None, (), 0).encode("utf-8")


def canonical_branch_pair(spec_a: Any, spec_b: Any) -> dict[str, Any]:
    """Return canonical sorted `{"a": lo, "b": hi}` pair for unordered ScriptPolicy pairs (SPEC-02 §3.1, Decision 4)."""
    lo, hi = sorted([spec_a, spec_b], key=_branch_spec_sort_key)
    return {"a": lo, "b": hi}


def _compile_branch_clause(spec: Any, verify: bool = False) -> bytes:
    if isinstance(spec, str):
        return _push_data(bytes.fromhex(spec)) + bytes([OP_CHECKSIGVERIFY if verify else OP_CHECKSIG])
    m = spec["m"]
    pks = spec["pks"]
    out = bytearray([0x50 + m])
    for pk_hex in pks:
        out.extend(_push_data(bytes.fromhex(pk_hex)))
    out.append(0x50 + len(pks))
    out.append(OP_CHECKMULTISIGVERIFY if verify else OP_CHECKMULTISIG)
    return bytes(out)


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


def is_witness_program_script(spk: bytes) -> bool:
    """Recognize BIP-141/BIP-341/P2A standard witness programs (v0..v16, incl. P2A 51024e73) so 0x51..0x60 is never misclassified as a Namecoin name op (H-4 / F-06)."""
    if len(spk) < 4 or len(spk) > 42:
        return False
    op0 = spk[0]
    if op0 != 0x00 and not (0x51 <= op0 <= 0x60):
        return False
    plen = spk[1]
    return 2 <= plen <= 40 and len(spk) == 2 + plen


def parse_p2wsh_multisig_script(ws: bytes) -> dict[str, Any] | None:
    """Decode canonical SealLink P2WSH m-of-n OP_CHECKMULTISIG witnessScript (1 <= m <= n <= 15, sorted unique compressed pubkeys) -> ScriptPolicy or None (BLK-8 / M-6)."""
    if len(ws) < 37 or ws[-1] != 0xAE:  # OP_CHECKMULTISIG
        return None
    m_op = ws[0]
    n_op = ws[-2]
    if not (0x51 <= m_op <= 0x5F) or not (0x51 <= n_op <= 0x5F):
        return None
    m = m_op - 0x50
    n = n_op - 0x50
    if not (1 <= m <= n <= 15):
        return None
    if len(ws) != 1 + n * 34 + 2:
        return None
    pks: list[str] = []
    pos = 1
    for _ in range(n):
        if ws[pos] != 33:
            return None
        pk_hex = ws[pos + 1 : pos + 34].hex()
        if not is_valid_compressed_pubkey(pk_hex):
            return None
        pks.append(pk_hex)
        pos += 34
    if pks != sorted(set(pks)):
        return None
    pol = {"kind": "multisig", "m": m, "pks": pks}
    try:
        _, check_ws = compile_script_policy(pol)
        if check_ws != ws:
            return None
    except ValueError:
        return None
    return pol


def compile_script_policy(policy: dict[str, Any]) -> tuple[bytes, bytes | None]:
    """Compile ScriptPolicy (incl. BranchKeySpec m-of-n) -> (scriptPubKey, witnessScript_or_None)."""
    if not isinstance(policy, dict):
        raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
    kind = policy.get("kind")
    if kind == "key":
        pk_hex = policy.get("pk")
        if not isinstance(pk_hex, str) or not is_valid_compressed_pubkey(pk_hex):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        pk = bytes.fromhex(pk_hex)
        spk = bytes([OP_0, 20]) + hash160(pk)
        return spk, None

    if kind == "multisig":
        m = policy.get("m")
        pks = policy.get("pks")
        if not isinstance(m, int) or isinstance(m, bool) or not isinstance(pks, list):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        if not (1 <= m <= len(pks) <= 15) or pks != sorted(set(pks)):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        if not all(isinstance(pk_hex, str) and is_valid_compressed_pubkey(pk_hex) for pk_hex in pks):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        if not _distinct_xcoords(pks):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        ws = bytearray([0x50 + m])
        for pk_hex in pks:
            ws.extend(_push_data(bytes.fromhex(pk_hex)))
        ws.append(0x50 + len(pks))
        ws.append(OP_CHECKMULTISIG)
        ws_b = bytes(ws)
        return bytes([OP_0, 32]) + sha256(ws_b), ws_b

    if kind == "branch":
        tpl = policy.get("template")
        keys = policy.get("keys")
        if not isinstance(keys, dict):
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
        if tpl in ("either_of_2", "both_of_2"):
            a_spec, b_spec = keys.get("a"), keys.get("b")
            if not (is_valid_branch_key_spec(a_spec) and is_valid_branch_key_spec(b_spec)):
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            if not branch_key_spec_xcoords(a_spec).isdisjoint(branch_key_spec_xcoords(b_spec)):
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            # Decision 4 / R3 Blocker #4: strict canonical input order a < b eliminates dual JCS encodings!
            if _branch_spec_sort_key(a_spec) >= _branch_spec_sort_key(b_spec):
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            if isinstance(a_spec, str) and isinstance(b_spec, str):
                op_m = 0x51 if tpl == "either_of_2" else 0x52
                ws_b = bytes([op_m]) + _push_data(bytes.fromhex(a_spec)) + _push_data(bytes.fromhex(b_spec)) + bytes([0x52, OP_CHECKMULTISIG])
            else:
                if tpl == "either_of_2":
                    ws_b = (
                        bytes([OP_IF])
                        + _compile_branch_clause(a_spec, verify=False)
                        + bytes([OP_ELSE])
                        + _compile_branch_clause(b_spec, verify=False)
                        + bytes([OP_ENDIF])
                    )
                else:
                    ws_b = _compile_branch_clause(a_spec, verify=True) + _compile_branch_clause(b_spec, verify=False)
            return bytes([OP_0, 32]) + sha256(ws_b), ws_b
        if tpl == "arbiter_or_both":
            a_pk, b_pk, arb = keys.get("a"), keys.get("b"), keys.get("arbiter")
            if not (isinstance(a_pk, str) and is_valid_compressed_pubkey(a_pk)
                    and isinstance(b_pk, str) and is_valid_compressed_pubkey(b_pk)
                    and is_valid_branch_key_spec(arb)):
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            if a_pk >= b_pk or a_pk[2:] == b_pk[2:]:
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            arb_xs = branch_key_spec_xcoords(arb)
            if a_pk[2:] in arb_xs or b_pk[2:] in arb_xs:
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            ws_b = (
                bytes([OP_IF, 0x52])
                + _push_data(bytes.fromhex(a_pk))
                + _push_data(bytes.fromhex(b_pk))
                + bytes([0x52, OP_CHECKMULTISIG, OP_ELSE])
                + _compile_branch_clause(arb, verify=False)
                + bytes([OP_ENDIF])
            )
            return bytes([OP_0, 32]) + sha256(ws_b), ws_b
        if tpl == "single_use_1_of_2":
            iss_pk, gr_pk = keys.get("issuer"), keys.get("grantee")
            if not (isinstance(iss_pk, str) and is_valid_compressed_pubkey(iss_pk)
                    and isinstance(gr_pk, str) and is_valid_compressed_pubkey(gr_pk)):
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            if iss_pk[2:] == gr_pk[2:]:
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            ws_b = (
                bytes([OP_IF])
                + _push_data(bytes.fromhex(iss_pk))
                + bytes([OP_CHECKSIG, OP_ELSE])
                + _push_data(bytes.fromhex(gr_pk))
                + bytes([OP_CHECKSIG, OP_ENDIF])
            )
            return bytes([OP_0, 32]) + sha256(ws_b), ws_b
        if tpl == "guardian_slot_pending":
            delay = policy.get("delay_blocks")
            disp, chal, guard = keys.get("disposer"), keys.get("challenger"), keys.get("guardian")
            if not isinstance(delay, int) or isinstance(delay, bool) or not (1 <= delay <= 52560):
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            if not (is_valid_branch_key_spec(disp) and is_valid_branch_key_spec(chal)
                    and isinstance(guard, str) and is_valid_compressed_pubkey(guard)):
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            disp_xs = branch_key_spec_xcoords(disp)
            chal_xs = branch_key_spec_xcoords(chal)
            if not disp_xs.isdisjoint(chal_xs) or guard[2:] in disp_xs or guard[2:] in chal_xs:
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            ws_b = (
                bytes([OP_IF])
                + _compile_branch_clause(disp, verify=False)
                + bytes([OP_ELSE, OP_IF])
                + _compile_branch_clause(chal, verify=False)
                + bytes([OP_ELSE])
                + _encode_script_num(delay)
                + bytes([OP_CHECKSEQUENCEVERIFY, OP_DROP])
                + _push_data(bytes.fromhex(guard))
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


def _read_push(script: bytes, pos: int, allow_empty: bool = False) -> tuple[bytes, int]:
    if pos >= len(script):
        raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
    op = script[pos]
    pos += 1
    if op == 0x00 and allow_empty:
        return b"", pos
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
    """Parse Namecoin output script per SPEC-02 SL-LDGR-005 (supports OP_0 empty values & 01 xx data pushes)."""
    if not script:
        raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
    op = script[0]
    pos = 1
    try:
        if op == OP_NAME_NEW:
            h20, pos = _read_push(script, pos)
            if len(h20) != 20 or script[pos : pos + 1] != bytes([OP_2DROP]):
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            tail = script[pos + 1 :]
            result: dict[str, Any] = {"op": "NAME_NEW", "hash20": h20.hex()}
        elif op == OP_NAME_FIRSTUPDATE:
            name, pos = _read_push(script, pos)
            rand, pos = _read_push(script, pos, allow_empty=True)
            val, pos = _read_push(script, pos, allow_empty=True)
            if script[pos : pos + 2] != bytes([OP_2DROP, OP_2DROP]):
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            tail = script[pos + 2 :]
            result = {"op": "NAME_FIRSTUPDATE", "name": name.decode("utf-8"), "rand": rand.hex(), "value": val.decode("utf-8")}
        elif op == OP_NAME_UPDATE:
            name, pos = _read_push(script, pos)
            val, pos = _read_push(script, pos, allow_empty=True)
            if script[pos : pos + 2] != bytes([OP_2DROP, OP_DROP]):
                raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
            tail = script[pos + 2 :]
            result = {"op": "NAME_UPDATE", "name": name.decode("utf-8"), "value": val.decode("utf-8")}
        else:
            raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
    except UnicodeDecodeError as exc:
        raise ValueError("CHAIN_SCRIPT_UNSUPPORTED") from exc

    # Trailing scriptPubKey MUST be native SegWit v0 P2WPKH (22B) or P2WSH (34B)
    if not ((len(tail) == 22 and tail[:2] == b"\x00\x14") or (len(tail) == 34 and tail[:2] == b"\x00\x20")):
        raise ValueError("CHAIN_SCRIPT_UNSUPPORTED")
    result["trailing_script_pubkey"] = tail.hex()
    return result


# ============================================================================
# 6. SLNK OP_RETURN Framing & Merkle Batch 0x02 (SPEC-02 §5.2-5.3)
# ============================================================================

SLNK_MAGIC = b"SLNK"

# Exact per-action allowed locators matching registry/opreturn-actions.json (H-23, R3 M2)
ACTION_ALLOWED_LOCATORS: dict[int, frozenset[int]] = {
    0x01: frozenset({0x00, 0x01, 0x05}),
    0x02: frozenset({0x00, 0x01, 0x02, 0x05}),
    0x03: frozenset({0x00, 0x01, 0x05}),
    0x04: frozenset({0x00, 0x01, 0x05}),
    0x05: frozenset({0x00, 0x01, 0x05}),
    0x07: frozenset({0x00, 0x01, 0x05}),
    0x08: frozenset({0x00, 0x01, 0x05}),
    0x09: frozenset({0x00, 0x01, 0x05}),
    0x0A: frozenset({0x00, 0x01, 0x05}),
    0x0B: frozenset({0x00}),
    0x0C: frozenset({0x00, 0x01, 0x05}),
    0x0D: frozenset({0x00, 0x01, 0x05}),
    0x0E: frozenset({0x00}),
    0x0F: frozenset({0x00, 0x01, 0x05}),
    0x10: frozenset({0x00}),
    0x11: frozenset({0x00}),
    0x12: frozenset({0x00, 0x01, 0x05}),
    0x13: frozenset({0x00, 0x01, 0x05}),
    0x14: frozenset({0x00, 0x01, 0x05}),
}


def encode_opreturn(
    action: int,
    commitment_hex: str,
    loc_type: int = 0x00,
    pointer_hex: str | None = None,
    h_c: int | None = None,
) -> bytes:
    allowed = ACTION_ALLOWED_LOCATORS.get(action)
    if allowed is None or loc_type not in allowed:
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
    allowed = ACTION_ALLOWED_LOCATORS.get(action)
    if allowed is None:
        raise ValueError("CHAIN_FRAME_INVALID")
    try:
        payload, end = _read_push(script, 7)
    except ValueError as exc:
        raise ValueError("CHAIN_FRAME_INVALID") from exc
    if end != len(script) or len(payload) < 34 or payload[0] != 0x01:
        raise ValueError("CHAIN_FRAME_INVALID")
    comm = payload[1:33].hex()
    if action == 0x0B:
        if len(payload) != 42 or payload[41] != 0x00:
            raise ValueError("CHAIN_FRAME_INVALID")
        h_c = struct.unpack("<Q", payload[33:41])[0]
        return {"action": f"0x{action:02x}", "version": 1, "commitment": comm, "h_c": h_c, "loc_type": "0x00"}
    loc = payload[33]
    if loc not in allowed:
        raise ValueError("CHAIN_FRAME_INVALID")
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


def is_slnk_opreturn(script: bytes) -> bool:
    """Return True if script starts with OP_RETURN + PUSH5 + 'SLNK' magic."""
    return len(script) >= 6 and script[0] == 0x6A and script[1] == 0x05 and script[2:6] == SLNK_MAGIC


def decode_opreturn_with_criticality(script: bytes) -> dict[str, Any]:
    """Decode an SLNK OP_RETURN frame in name history with outer-before-semantic criticality rules (SPEC-02 §5.2).

    1. Outer envelope checked FIRST on every SLNK output: 8 <= len <= 83, `6a 05 SLNK <action>`,
       valid minimal Bitcoin Script data push reaching end-of-script with non-empty payload -> else CHAIN_FRAME_INVALID.
    2. Known v1.0 actions (0x01..0x05, 0x07..0x14): strict `decode_opreturn` (malformed -> CHAIN_FRAME_INVALID).
    3. Critical forward-only reserved range (0x15..0x1a): returns {'action': ..., 'critical_scope': 'forward_only'}.
    4. Critical retroactive reserved range (0x1b..0x1f): returns {'action': ..., 'critical_scope': 'retroactive'}.
    5. Advisory ignorable range (0x20..0x2f): validates standard 42B/74B v1 framing (malformed -> CHAIN_FRAME_INVALID)
       and returns {'advisory': True, ...} so v1.0 readers safely ignore non-critical future extensions.
    6. Reserved 0x06 or any other unknown action byte: raises ValueError('CHAIN_FRAME_INVALID').
    """
    if len(script) < 8 or len(script) > 83 or script[0] != 0x6A or script[1] != 0x05 or script[2:6] != SLNK_MAGIC:
        raise ValueError("CHAIN_FRAME_INVALID")
    action = script[6]
    try:
        payload, end = _read_push(script, 7)
    except ValueError as exc:
        raise ValueError("CHAIN_FRAME_INVALID") from exc
    if end != len(script) or not payload:
        raise ValueError("CHAIN_FRAME_INVALID")
    if action in ACTION_ALLOWED_LOCATORS:
        return decode_opreturn(script)
    if 0x15 <= action <= 0x1A:
        return {"action": f"0x{action:02x}", "critical_scope": "forward_only"}
    if 0x1B <= action <= 0x1F:
        return {"action": f"0x{action:02x}", "critical_scope": "retroactive"}
    if 0x20 <= action <= 0x2F:
        if len(payload) < 34 or payload[0] != 0x01:
            raise ValueError("CHAIN_FRAME_INVALID")
        comm = payload[1:33].hex()
        loc = payload[33]
        if loc == 0x00 and len(payload) == 34:
            return {"action": f"0x{action:02x}", "advisory": True, "version": 1, "commitment": comm, "loc_type": "0x00"}
        if loc in (0x01, 0x02, 0x05) and len(payload) == 66:
            return {
                "action": f"0x{action:02x}",
                "advisory": True,
                "version": 1,
                "commitment": comm,
                "loc_type": f"0x{loc:02x}",
                "pointer": payload[34:66].hex(),
            }
        raise ValueError("CHAIN_FRAME_INVALID")
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
    if not isinstance(proof, dict):
        return False
    steps = proof.get("steps")
    leaf = proof.get("leaf_digest")
    root = proof.get("root")
    if not isinstance(steps, list) or len(steps) > 16 or not isinstance(leaf, str) or not isinstance(root, str):
        return False
    try:
        cur = merkle_leaf(leaf)
        for step in steps:
            if not isinstance(step, dict) or not isinstance(step.get("hash"), str):
                return False
            sib = bytes.fromhex(step["hash"])
            if len(sib) != 32:
                return False
            if step.get("side") == "L":
                cur = merkle_node(sib, cur)
            elif step.get("side") == "R":
                cur = merkle_node(cur, sib)
            else:
                return False
    except ValueError:
        return False
    return cur.hex() == root


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
        return isinstance(val, str) and bool(HEX64_RE.match(val))
    return False


def match_predicate(pred: dict[str, Any], arg: Any) -> bool:
    if not validate_predicate(pred):
        return False
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
        if isinstance(arg, int) and not isinstance(arg, bool):
            v = arg
        elif isinstance(arg, str) and UINT64_STR_RE.match(arg):
            v = int(arg)
        else:
            return False
        if v < 0 or v > MAX_UINT64:
            return False
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
            return isinstance(cval, str) and bool(UINT64_STR_RE.match(cval)) and 0 <= int(cval) <= MAX_UINT64 and plo <= int(cval) <= phi
        if cop == "in":
            return all(bool(UINT64_STR_RE.match(v)) and 0 <= int(v) <= MAX_UINT64 and plo <= int(v) <= phi for v in cval)
        return False
    if pop == "hash_eq":
        return cop == "hash_eq" and cval == pval
    return False


def check_whole_parent_budget_r85(
    delegate: dict[str, Any],
    parent_capabilities: list[dict[str, Any]] | None = None,
) -> tuple[bool, dict[str, int]]:
    """Verify R8.5 aggregate budget across all groups: sum_g(rows(g) * cap(g, q)) <= pool_max(q) (and <= root cap if present)."""
    pools = {
        (q["kind"], q["resource"], q["unit"], q["window"]): int(q["max"])
        for q in delegate.get("pools", [])
    }
    if parent_capabilities is not None:
        root_caps: dict[tuple[str, str, str, str], int] = {}
        for cap in parent_capabilities:
            for q in cap.get("quotas", []):
                key = (q["kind"], q["resource"], q["unit"], q["window"])
                root_caps[key] = max(root_caps.get(key, 0), int(q["max"]))
        for key, pmax in pools.items():
            if key in root_caps and pmax > root_caps[key]:
                return False, {}
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
    """Verify R8.6 pairwise disjointness & bounds of all row coins, stop coins, parent seal, and linkage output."""
    seen: set[tuple[str, int]] = set()
    rev = parent_payload.get("revocation", {})
    if rev.get("mode") == "seal":
        seal = rev["seal"]
        seen.add((seal["txid"], seal["vout"]))
        seen.add((seal["txid"], seal["vout"] + 1))  # linkage output
    for g in parent_payload["delegate"]["groups"]:
        for r in g["ranges"]:
            cnt = r["count"]
            if not isinstance(cnt, int) or isinstance(cnt, bool) or not (1 <= cnt <= 2048):
                return False
            if r["first"] < 0 or r["first"] + cnt > 0x100000000:
                return False
            for v in range(r["first"], r["first"] + cnt):
                op = (r["txid"], v)
                if op in seen:
                    return False
                seen.add(op)
            if "stop_txid" in r:
                if r["stop_first"] < 0 or r["stop_first"] + cnt > 0x100000000:
                    return False
                for v in range(r["stop_first"], r["stop_first"] + cnt):
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

_ACTION_EVENT_CLASSES_CACHE: dict[str, str] | None = None


def _action_event_classes() -> dict[str, str]:
    global _ACTION_EVENT_CLASSES_CACHE
    if _ACTION_EVENT_CLASSES_CACHE is None:
        from pathlib import Path
        reg_path = Path(__file__).resolve().parent.parent / "registry" / "actions.json"
        raw = json.loads(reg_path.read_text(encoding="utf-8"))
        _ACTION_EVENT_CLASSES_CACHE = {
            e["action"]: e["guardian_event_class"]
            for e in raw.get("actions", [])
            if isinstance(e, dict) and "action" in e and "guardian_event_class" in e
        }
    return _ACTION_EVENT_CLASSES_CACHE


def required_guardian_slots(quorum: dict[str, int], revision_size: int) -> int:
    """Exact integer ceiling quorum formula SL-ORIG-005: max(min, ceil(num * revision_size / den))."""
    num, den, mn = quorum["num"], quorum["den"], quorum["min"]
    ceil_val = (num * revision_size + den - 1) // den
    return max(mn, ceil_val)


def check_guardian_policy_consistency(
    policy: dict[str, Any],
    prev_roster: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """Validate SL-ORIG-015 / SL-ORIG-016 mechanical consistency on origin.guardian_policy or GuardianRoster.payload."""
    rev_size = policy.get("revision_size", 0)
    if not isinstance(rev_size, int) or isinstance(rev_size, bool) or not (1 <= rev_size <= 32):
        return False, "WIRE_INTEGER"
    quorums = policy.get("quorums", {})
    if not isinstance(quorums, dict) or set(quorums.keys()) != set(EVENT_CLASS_ORDER.keys()):
        return False, "WIRE_MEMBER"
    for q in quorums.values():
        if not isinstance(q, dict):
            return False, "WIRE_MEMBER"
        num, den, mn = q.get("num", 0), q.get("den", 0), q.get("min", 0)
        if not (1 <= num <= den <= 32) or not (1 <= mn <= rev_size):
            return False, "WIRE_INTEGER"
    # SL-ORIG-016 monotonic QuorumMap (H-7): required(routine_read) <= effect_grant <= contract_assent <= custody_change
    req_order = [
        required_guardian_slots(quorums[cname], rev_size)
        for cname in ("routine_read", "effect_grant", "contract_assent", "custody_change")
    ]
    if req_order != sorted(req_order):
        return False, "WIRE_INTEGER"
    slots = policy.get("slots", [])
    if not isinstance(slots, list) or len(slots) != rev_size:
        return False, "WIRE_INTEGER"
    slot_nums = [s.get("slot") for s in slots if isinstance(s, dict)]
    if len(slot_nums) != rev_size or len(set(slot_nums)) != rev_size or set(slot_nums) != set(range(1, rev_size + 1)):
        return False, "WIRE_INTEGER"
    disp = policy.get("disposer_pk")
    arb = policy.get("arbiter_pk")
    chal = policy.get("challenger_pk")
    if not (disp and arb and chal):
        return False, "WIRE_MEMBER"
    if not (is_valid_branch_key_spec(disp) and is_valid_branch_key_spec(arb) and is_valid_branch_key_spec(chal)):
        return False, "WIRE_KEY"
    if disp == arb or not branch_key_spec_xcoords(disp).isdisjoint(branch_key_spec_xcoords(arb)):
        return False, "ORIGIN_UNVERIFIED"
    if not branch_key_spec_xcoords(disp).isdisjoint(branch_key_spec_xcoords(chal)):
        return False, "ORIGIN_UNVERIFIED"
    expected_both = {"kind": "branch", "template": "both_of_2", "keys": canonical_branch_pair(disp, arb)}
    exp_both_spk, _ = compile_script_policy(expected_both)
    seen_outpoints: set[tuple[str, int]] = set()
    if "roster_seal" in policy:
        try:
            rs = policy["roster_seal"]
            got_spk, _ = compile_script_policy(rs["script_policy"])
            seen_outpoints.add((rs["txid"], rs["vout"]))
        except (ValueError, KeyError, TypeError):
            return False, "CHAIN_SCRIPT_UNSUPPORTED"
        if got_spk != exp_both_spk:
            return False, "CHAIN_SCRIPT_UNSUPPORTED"
    if "next_roster_policy" in policy:
        try:
            got_spk, _ = compile_script_policy(policy["next_roster_policy"])
        except (ValueError, KeyError, TypeError):
            return False, "CHAIN_SCRIPT_UNSUPPORTED"
        if got_spk != exp_both_spk:
            return False, "CHAIN_SCRIPT_UNSUPPORTED"
    keys_rotated = (
        prev_roster is not None
        and (disp != prev_roster.get("disposer_pk") or arb != prev_roster.get("arbiter_pk"))
    )
    for s in slots:
        act = s.get("action")
        if act in ("retain_active", "retain_vacant") and keys_rotated:
            return False, "CHAIN_SCRIPT_UNSUPPORTED"
        if act == "new_vacant":
            try:
                got_vac_spk, _ = compile_script_policy(s["new_vacant_policy"])
            except (ValueError, KeyError, TypeError):
                return False, "CHAIN_SCRIPT_UNSUPPORTED"
            if got_vac_spk != exp_both_spk:
                return False, "CHAIN_SCRIPT_UNSUPPORTED"
        if "vacant_utxo" in s:
            vu = s["vacant_utxo"]
            if not isinstance(vu, dict) or "txid" not in vu or "vout" not in vu:
                return False, "WIRE_MEMBER"
            op_key = (vu["txid"], vu["vout"])
            if op_key in seen_outpoints:
                return False, "ORIGIN_UNVERIFIED"
            seen_outpoints.add(op_key)
            if "script_policy" in vu:
                try:
                    got_vu_spk, _ = compile_script_policy(vu["script_policy"])
                except (ValueError, KeyError, TypeError):
                    return False, "CHAIN_SCRIPT_UNSUPPORTED"
                if got_vu_spk != exp_both_spk:
                    return False, "CHAIN_SCRIPT_UNSUPPORTED"
    return True, "OK"


def derive_guardian_event_class(payload: dict[str, Any]) -> str:
    """Deterministically derive the required GuardianEventClass from registry/actions.json SSOT (SPEC-04 §3.1, G-2, R2G-11)."""
    obj_type = payload.get("type")
    if obj_type == "seallink-assent/1":
        target_type = payload.get("target_type")
        if target_type in ("seallink-migration/1", "seallink-guardian/1"):
            return "custody_change"
        return "contract_assent"
    if obj_type == "seallink-termination/1":
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
        act_classes = _action_event_classes()
        for cap in payload.get("capabilities", []):
            act = cap.get("action")
            # Fail closed on unknown/unregistered action -> contract_assent (rank 2), never routine_read (G-2)!
            act_cls = act_classes.get(act, "contract_assent")
            rank = max(rank, EVENT_CLASS_ORDER.get(act_cls, 2))
            if cap.get("quotas"):
                rank = max(rank, 1)
        return EVENT_CLASS_BY_RANK[rank]
    raise ValueError(f"Unsupported guardian_context carrier: {obj_type}")


# ============================================================================
# 9. v1.0.0-draft.11 Primitives: Artifact ID, Transparency Logs (0x14),
#    Acyclic RFC 9162 checkpoints_root, Canonical Fixed-Depth-256 SMT,
#    Consensus-Exact SegWitNameUpdateProof & Namecoin AuxPoW / Retarget
# ============================================================================

EMPTY_BATCH_ROOT = tagged_hash("seallink-batch-empty/1", b"").hex()
EMPTY_CHECKPOINTS_ROOT = tagged_hash("seallink-log-ckpt-empty/1", b"").hex()
NAMECOIN_POW_LIMIT_MAIN = 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
NAMECOIN_POW_LIMIT_TESTNET = 0x0000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
NAMECOIN_POW_LIMIT_REGTEST = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
NAMECOIN_AUXPOW_START_MAIN = 19200
NAMECOIN_LEGACY_BEFORE_MAIN = 19200
NAMECOIN_LEGACY_BEFORE_TESTNET = -1
NAMECOIN_LEGACY_BEFORE_REGTEST = 0
NAMECOIN_BIP34_MAIN = 250000
NAMECOIN_BIP66_MAIN = 250000
NAMECOIN_BIP65_MAIN = 335000
NAMECOIN_TARGET_TIMESPAN = 1209600  # 14 days
NAMECOIN_MIN_TIMESPAN = 302400      # 1209600 // 4
NAMECOIN_MAX_TIMESPAN = 4838400     # 1209600 * 4
NAMECOIN_AUX_CHAIN_ID = 0x0001


def _popcount(n: int) -> int:
    """Python 3.9+ compatible popcount (avoids int.bit_count() added in 3.10)."""
    return bin(n).count("1")


def dsha256(data: bytes) -> bytes:
    return sha256(sha256(data))


def fsverity_sha256_digest(data: bytes) -> str:
    """Exact Linux kernel FS_IOC_MEASURE_VERITY (fsverity-sha256, 4096B blocks, salt_size=0)."""
    block_size = 4096
    if not data:
        root_hash = b"\x00" * 32
    else:
        chunks = [data[i : i + block_size].ljust(block_size, b"\x00") for i in range(0, len(data), block_size)]
        level = b"".join(sha256(c) for c in chunks)
        while len(level) > 32:
            p_chunks = [level[i : i + block_size].ljust(block_size, b"\x00") for i in range(0, len(level), block_size)]
            level = b"".join(sha256(c) for c in p_chunks)
        root_hash = level
    # struct fsverity_descriptor (256B LE): version=1, hash_algorithm=1 (SHA-256), log_blocksize=12 (4096),
    # salt_size=0, __reserved_0x04=0 (4B), data_size (8B LE), root_hash[64] (32B + 32B zero), salt[32], reserved[144]
    descriptor = struct.pack("<BBBBIQ", 1, 1, 12, 0, 0, len(data)) + root_hash + (b"\x00" * 208)
    assert len(descriptor) == 256
    return sha256(descriptor).hex()


def artifact_target_id(artifact_identity: dict[str, Any]) -> str:
    """Canonical artifact target_id = target_sha256 strictly over {'digest', 'scheme'} (EXCLUDING params, F1/P0-C)."""
    return tagged_hash(
        "seallink-artifact-id/1",
        jcs_encode({"digest": artifact_identity["digest"], "scheme": artifact_identity["scheme"]}),
    ).hex()


def compute_log_id(
    network: str,
    genesis: str,
    role: str,
    issuer_name: str,
    issuer_registration: dict[str, Any],
    genesis_seal_outpoint: dict[str, Any],
    predecessor_log_id: str | None = None,
) -> str:
    """Immutable log_id bound to (name, registration, genesis_seal_outpoint[, predecessor_log_id]) WITHOUT owner_policy (survives cold rotation, M-b, BLK-5)."""
    obj: dict[str, Any] = {
        "genesis": genesis,
        "genesis_seal_outpoint": {"txid": genesis_seal_outpoint["txid"], "vout": genesis_seal_outpoint["vout"]},
        "issuer_name": issuer_name,
        "issuer_registration": {"txid": issuer_registration["txid"], "vout": issuer_registration["vout"]},
        "network": network,
        "role": role,
    }
    if predecessor_log_id is not None:
        obj["predecessor_log_id"] = predecessor_log_id
    return tagged_hash("seallink-log-id/1", jcs_encode(obj)).hex()


def log_entry_digest(kind_byte: int, content_addr_hex: str) -> str:
    """Tagged log batch leaf digest: 0x01=issue, 0x02=revocation, 0x03=reinstatement."""
    if kind_byte not in (0x01, 0x02, 0x03):
        raise ValueError("invalid log entry kind_byte")
    b = bytes.fromhex(content_addr_hex)
    if len(b) != 32:
        raise ValueError("content_addr must be 32 bytes")
    return tagged_hash("seallink-log-entry/1", bytes([kind_byte]) + b).hex()


def build_log_batch_root(entry_digests: list[str]) -> tuple[str, dict[str, dict[str, Any]]]:
    """Build SPEC-02 §5.3 batch root for a log checkpoint (EMPTY_BATCH_ROOT when empty)."""
    if not entry_digests:
        return EMPTY_BATCH_ROOT, {}
    return build_merkle_tree(entry_digests)


# --- Acyclic RFC 9162 §2.1.1 / §2.1.3 checkpoints_root (P0-CORE-1 & P0-CORE-2) ---

def ckpt_leaf(seq: int, checkpoint_caddr_hex: str) -> bytes:
    if seq < 1:
        raise ValueError("checkpoint seq must be >= 1")
    b = bytes.fromhex(checkpoint_caddr_hex)
    if len(b) != 32:
        raise ValueError("checkpoint content_addr must be 32 bytes")
    return tagged_hash("seallink-log-ckpt-leaf/1", struct.pack(">Q", seq) + b)


def ckpt_node(left: bytes, right: bytes) -> bytes:
    return tagged_hash("seallink-log-ckpt-node/1", left + right)


def _largest_pow2_lt(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


def rfc9162_mth(leaves: list[bytes]) -> bytes:
    """RFC 9162 §2.1.1 Merkle Tree Hash over predecessor checkpoints 1..(k-1)."""
    n = len(leaves)
    if n == 0:
        return bytes.fromhex(EMPTY_CHECKPOINTS_ROOT)
    if n == 1:
        return leaves[0]
    p = _largest_pow2_lt(n)
    return ckpt_node(rfc9162_mth(leaves[:p]), rfc9162_mth(leaves[p:]))


def rfc9162_inclusion_proof(leaves: list[bytes], leaf_index: int) -> dict[str, Any]:
    """Build RFC 9162 §2.1.3 audit path proving leaf_index in MTH(leaves)."""
    n = len(leaves)
    if not (0 <= leaf_index < n):
        raise ValueError("leaf_index out of bounds")

    def _path(m: int, sub: list[bytes]) -> list[str]:
        sz = len(sub)
        if sz == 1:
            return []
        p = _largest_pow2_lt(sz)
        if m < p:
            return _path(m, sub[:p]) + [rfc9162_mth(sub[p:]).hex()]
        return _path(m - p, sub[p:]) + [rfc9162_mth(sub[:p]).hex()]

    return {
        "hashes": _path(leaf_index, leaves),
        "leaf_index": leaf_index,
        "tree_size": n,
    }


def rfc9162_verify_inclusion(
    leaf_hash: bytes,
    leaf_index: int,
    tree_size: int,
    hashes: list[str],
    expected_root_hex: str,
) -> bool:
    """Verify RFC 9162 §2.1.3.2 audit path of leaf_hash at leaf_index in tree of size tree_size."""
    if tree_size < 1 or not (0 <= leaf_index < tree_size) or len(hashes) > 64:
        return False
    fn = leaf_index
    sn = tree_size - 1
    r = leaf_hash
    for h_hex in hashes:
        if sn == 0 or not isinstance(h_hex, str) or len(h_hex) != 64:
            return False
        try:
            p = bytes.fromhex(h_hex)
        except ValueError:
            return False
        if (fn & 1) == 1 or fn == sn:
            r = ckpt_node(p, r)
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = ckpt_node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r.hex() == expected_root_hex


def rfc9162_peaks(leaves: list[bytes]) -> list[str]:
    """Decompose leaves[0..n] into exactly popcount(n) full-binary subtree peaks (left-to-right)."""
    n = len(leaves)
    peaks: list[str] = []
    pos = 0
    rem = n
    while rem > 0:
        sz = 1 << (rem.bit_length() - 1)
        peaks.append(rfc9162_mth(leaves[pos : pos + sz]).hex())
        pos += sz
        rem -= sz
    return peaks


def rfc9162_root_from_peaks(peaks: list[str], tree_size: int) -> str | None:
    """Fold popcount(tree_size) peaks right-to-left into exact RFC 9162 MTH."""
    if tree_size < 0 or len(peaks) != _popcount(tree_size):
        return None
    if tree_size == 0:
        return EMPTY_CHECKPOINTS_ROOT
    try:
        pbytes = [bytes.fromhex(p) for p in peaks]
    except ValueError:
        return None
    if any(len(b) != 32 for b in pbytes):
        return None
    acc = pbytes[-1]
    for b in reversed(pbytes[:-1]):
        acc = ckpt_node(b, acc)
    return acc.hex()


def rfc9162_append_leaf_to_peaks(peaks: list[str], prev_tree_size: int, new_leaf: bytes) -> str | None:
    """Compute MTH(prev_tree_size + 1) by appending new_leaf onto popcount(prev_tree_size) peaks."""
    if prev_tree_size < 0 or len(peaks) != _popcount(prev_tree_size):
        return None
    try:
        rem = [bytes.fromhex(p) for p in peaks]
    except ValueError:
        return None
    if any(len(b) != 32 for b in rem):
        return None
    cur = new_leaf
    bit = 0
    while (prev_tree_size >> bit) & 1:
        cur = ckpt_node(rem.pop(), cur)
        bit += 1
    rem.append(cur)
    acc = rem[-1]
    for b in reversed(rem[:-1]):
        acc = ckpt_node(b, acc)
    return acc.hex()


# --- Canonical Fixed-Depth-256 Logical Binary SMT (P0-B, P1) ---

def _build_smt_defaults() -> list[bytes]:
    d: list[bytes] = [tagged_hash("seallink-smt-empty/1", b"")]
    for _ in range(256):
        prev = d[-1]
        d.append(tagged_hash("seallink-smt-node/1", prev + prev))
    return d


SMT_DEFAULTS: list[bytes] = _build_smt_defaults()
SMT_EMPTY_ROOT: str = SMT_DEFAULTS[256].hex()


def smt_get_bit(buf32: bytes, depth: int) -> int:
    """MSB-first bit at depth d in [0..255] (d=0 is top bit near root, d=255 is leaf)."""
    return (buf32[depth >> 3] >> (7 - (depth & 7))) & 1


def smt_leaf_hash(key_hash32: bytes, value_hex: str) -> bytes:
    vb = bytes.fromhex(value_hex)
    if len(vb) != 32:
        raise ValueError("SMT value must be 32-byte hex")
    return tagged_hash("seallink-smt-leaf/1", key_hash32 + vb)


def smt_node_hash(left: bytes, right: bytes) -> bytes:
    return tagged_hash("seallink-smt-node/1", left + right)


def _smt_subtree_hash(items: list[tuple[bytes, bytes]], depth: int) -> bytes:
    if not items:
        return SMT_DEFAULTS[256 - depth]
    if depth == 256:
        return items[0][1]
    left = [it for it in items if smt_get_bit(it[0], depth) == 0]
    right = [it for it in items if smt_get_bit(it[0], depth) == 1]
    return smt_node_hash(_smt_subtree_hash(left, depth + 1), _smt_subtree_hash(right, depth + 1))


def smt_root(kv_map: dict[str, str]) -> str:
    """Compute canonical Fixed-Depth-256 Logical Binary SMT root from {denial_key: content_addr_hex}."""
    items = [(sha256(k.encode("utf-8")), smt_leaf_hash(sha256(k.encode("utf-8")), v)) for k, v in kv_map.items()]
    return _smt_subtree_hash(items, 0).hex()


def smt_prove(kv_map: dict[str, str], key_str: str) -> dict[str, Any]:
    """Generate canonical Fixed-Depth-256 SmtProof (inclusion or absence) with MSB-first bitmap_hex & bottom-up siblings."""
    items = [(sha256(k.encode("utf-8")), smt_leaf_hash(sha256(k.encode("utf-8")), v)) for k, v in kv_map.items()]
    root_hex = _smt_subtree_hash(items, 0).hex()
    target_k = sha256(key_str.encode("utf-8"))
    sib_by_depth: list[bytes] = []
    cur_items = items
    for d in range(256):
        bit = smt_get_bit(target_k, d)
        left = [it for it in cur_items if smt_get_bit(it[0], d) == 0]
        right = [it for it in cur_items if smt_get_bit(it[0], d) == 1]
        if bit == 0:
            sib_by_depth.append(_smt_subtree_hash(right, d + 1))
            cur_items = left
        else:
            sib_by_depth.append(_smt_subtree_hash(left, d + 1))
            cur_items = right
    bitmap = bytearray(32)
    siblings: list[str] = []
    for h in range(1, 257):
        d = 256 - h
        sib = sib_by_depth[d]
        if sib != SMT_DEFAULTS[h - 1]:
            bitmap[d >> 3] |= 1 << (7 - (d & 7))
            siblings.append(sib.hex())
    out: dict[str, Any] = {
        "bitmap_hex": bytes(bitmap).hex(),
        "key_str": key_str,
        "root": root_hex,
        "siblings": siblings,
        "state": "included" if key_str in kv_map else "absent",
    }
    if key_str in kv_map:
        out["value"] = kv_map[key_str]
    return out


def smt_verify_proof(proof: dict[str, Any]) -> bool:
    """Verify canonical Fixed-Depth-256 Logical Binary SMT proof (enforces canonical sib != D[h-1], P0-B & P1)."""
    if not isinstance(proof, dict):
        return False
    root = proof.get("root")
    key_str = proof.get("key_str")
    state = proof.get("state")
    bitmap_hex = proof.get("bitmap_hex")
    siblings = proof.get("siblings")
    if (
        not isinstance(root, str) or len(root) != 64
        or not isinstance(key_str, str)
        or state not in ("included", "absent")
        or not isinstance(bitmap_hex, str) or len(bitmap_hex) != 64
        or not isinstance(siblings, list)
    ):
        return False
    try:
        bitmap = bytes.fromhex(bitmap_hex)
    except ValueError:
        return False
    popcnt = sum(_popcount(b) for b in bitmap)
    if len(siblings) != popcnt:
        return False
    k = sha256(key_str.encode("utf-8"))
    if state == "included":
        val = proof.get("value")
        if not isinstance(val, str) or len(val) != 64:
            return False
        try:
            cur = smt_leaf_hash(k, val)
        except ValueError:
            return False
    else:
        if "value" in proof:
            return False
        cur = SMT_DEFAULTS[0]
    sib_idx = 0
    for h in range(1, 257):
        d = 256 - h
        if smt_get_bit(bitmap, d) == 1:
            s_hex = siblings[sib_idx]
            sib_idx += 1
            if not isinstance(s_hex, str) or len(s_hex) != 64:
                return False
            try:
                sib = bytes.fromhex(s_hex)
            except ValueError:
                return False
            # P1 canonical check: a 1-bit in bitmap MUST NOT supply the empty subtree constant D[h-1]!
            if sib == SMT_DEFAULTS[h - 1]:
                return False
        else:
            sib = SMT_DEFAULTS[h - 1]
        cur = smt_node_hash(sib, cur) if smt_get_bit(k, d) == 1 else smt_node_hash(cur, sib)
    return sib_idx == len(siblings) and cur.hex() == root


# --- Strict BIP-66 DER ECDSA (accepting consensus-valid high-S, P0-CONS-1) ---

def parse_bip66_der_sig(sig_with_hashtype: bytes) -> tuple[int, int, int] | None:
    """Strict BIP-66 DER signature + sighash byte parser WITHOUT low-S rejection (Namecoin/Bitcoin consensus)."""
    n = len(sig_with_hashtype)
    if n < 9 or n > 73:
        return None
    if sig_with_hashtype[0] != 0x30 or sig_with_hashtype[1] != n - 3:
        return None
    if sig_with_hashtype[2] != 0x02:
        return None
    len_r = sig_with_hashtype[3]
    if len_r == 0 or 5 + len_r >= n:
        return None
    r_bytes = sig_with_hashtype[4 : 4 + len_r]
    if r_bytes[0] & 0x80:
        return None
    if len_r > 1 and r_bytes[0] == 0x00 and not (r_bytes[1] & 0x80):
        return None
    pos_s = 4 + len_r
    if sig_with_hashtype[pos_s] != 0x02:
        return None
    len_s = sig_with_hashtype[pos_s + 1]
    if len_s == 0 or pos_s + 2 + len_s != n - 1:
        return None
    s_bytes = sig_with_hashtype[pos_s + 2 : pos_s + 2 + len_s]
    if s_bytes[0] & 0x80:
        return None
    if len_s > 1 and s_bytes[0] == 0x00 and not (s_bytes[1] & 0x80):
        return None
    r = int.from_bytes(r_bytes, "big")
    s = int.from_bytes(s_bytes, "big")
    if not (1 <= r < _N and 1 <= s < _N):
        return None
    return r, s, sig_with_hashtype[-1]


def _decode_secp256k1_compressed(comp_pk_hex: str) -> tuple[int, int] | None:
    if not is_valid_compressed_pubkey(comp_pk_hex):
        return None
    x = int(comp_pk_hex[2:], 16)
    pt = _lift_x(x)
    if pt is None:
        return None
    want_odd = comp_pk_hex[:2] == "03"
    y = pt[1] if (pt[1] % 2 == (1 if want_odd else 0)) else (_P - pt[1])
    return (x, y)


@functools.lru_cache(maxsize=4096)
def secp256k1_ecdsa_verify_bip66(msg32: bytes, comp_pk_hex: str, sig_with_hashtype: bytes) -> tuple[bool, int]:
    """Verify strict BIP-66 DER ECDSA signature (consensus-exact: accepts high-S!) over msg32."""
    if len(msg32) != 32:
        return False, -1
    parsed = parse_bip66_der_sig(sig_with_hashtype)
    if parsed is None:
        return False, -1
    r, s, sht = parsed
    q_pt = _decode_secp256k1_compressed(comp_pk_hex)
    if q_pt is None:
        return False, sht
    z = int.from_bytes(msg32, "big")
    w = pow(s, _N - 2, _N)
    u1 = (z * w) % _N
    u2 = (r * w) % _N
    p1 = _point_mul(_G, u1)
    p2 = _point_mul(q_pt, u2)
    pt = _point_add(p1, p2)
    if pt is None:
        return False, sht
    return (pt[0] % _N) == r, sht


# --- Consensus-Exact Raw SegWit TX, BIP-143, SegWitNameUpdateProof & Namecoin AuxPoW (P0-CONS-1) ---

def _read_varint(buf: bytes, off: int) -> tuple[int, int]:
    if off >= len(buf):
        raise ValueError("truncated varint")
    b0 = buf[off]
    if b0 < 0xFD:
        return b0, off + 1
    if b0 == 0xFD:
        if off + 3 > len(buf):
            raise ValueError("truncated varint 0xfd")
        val = struct.unpack("<H", buf[off + 1 : off + 3])[0]
        if val < 0xFD:
            raise ValueError("non-minimal varint")
        return val, off + 3
    if b0 == 0xFE:
        if off + 5 > len(buf):
            raise ValueError("truncated varint 0xfe")
        val = struct.unpack("<I", buf[off + 1 : off + 5])[0]
        if val <= 0xFFFF:
            raise ValueError("non-minimal varint")
        return val, off + 5
    if off + 9 > len(buf):
        raise ValueError("truncated varint 0xff")
    val = struct.unpack("<Q", buf[off + 1 : off + 9])[0]
    if val <= 0xFFFFFFFF:
        raise ValueError("non-minimal varint")
    return val, off + 9


def _encode_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def parse_raw_tx(raw: bytes, *, allow_empty_vout: bool = False) -> dict[str, Any]:
    """Strict BIP-141 raw Bitcoin/Namecoin transaction parser (enforces 00 01 marker/flag)."""
    if len(raw) < 10:
        raise ValueError("tx too short")
    version = struct.unpack("<I", raw[0:4])[0]
    off = 4
    has_witness = False
    if raw[off] == 0x00:
        if off + 2 > len(raw) or raw[off + 1] != 0x01:
            raise ValueError("invalid segwit marker/flag")
        has_witness = True
        off += 2
    vin_start = off
    vin_cnt, off = _read_varint(raw, off)
    if vin_cnt == 0:
        raise ValueError("zero inputs")
    vins: list[dict[str, Any]] = []
    for _ in range(vin_cnt):
        if off + 36 > len(raw):
            raise ValueError("truncated vin")
        prev_txid_le = raw[off : off + 32]
        prev_vout = struct.unpack("<I", raw[off + 32 : off + 36])[0]
        off += 36
        ss_len, off = _read_varint(raw, off)
        if off + ss_len + 4 > len(raw):
            raise ValueError("truncated scriptSig")
        script_sig = raw[off : off + ss_len]
        off += ss_len
        seq = struct.unpack("<I", raw[off : off + 4])[0]
        off += 4
        vins.append({
            "prev_txid": prev_txid_le[::-1].hex(),
            "prev_txid_le": prev_txid_le,
            "prev_vout": prev_vout,
            "script_sig": script_sig,
            "sequence": seq,
            "witness": [],
        })
    vout_cnt, off = _read_varint(raw, off)
    if vout_cnt == 0 and not allow_empty_vout:
        raise ValueError("zero outputs")
    vouts: list[dict[str, Any]] = []
    for n_idx in range(vout_cnt):
        if off + 8 > len(raw):
            raise ValueError("truncated vout value")
        val_sat = struct.unpack("<Q", raw[off : off + 8])[0]
        off += 8
        spk_len, off = _read_varint(raw, off)
        if off + spk_len > len(raw):
            raise ValueError("truncated scriptPubKey")
        spk = raw[off : off + spk_len]
        off += spk_len
        vouts.append({"n": n_idx, "value_sat": val_sat, "script_pubkey": spk})
    body_end = off
    if has_witness:
        any_wit = False
        for vin in vins:
            w_cnt, off = _read_varint(raw, off)
            stack: list[bytes] = []
            for _ in range(w_cnt):
                item_len, off = _read_varint(raw, off)
                if off + item_len > len(raw):
                    raise ValueError("truncated witness item")
                stack.append(raw[off : off + item_len])
                off += item_len
            if stack:
                any_wit = True
            vin["witness"] = stack
        if not any_wit:
            raise ValueError("empty segwit witness")
    if off + 4 != len(raw):
        raise ValueError("trailing or truncated locktime")
    locktime = struct.unpack("<I", raw[off : off + 4])[0]
    non_witness_bytes = raw[0:4] + raw[vin_start:body_end] + raw[off : off + 4]
    txid_le = dsha256(non_witness_bytes)
    wtxid_le = dsha256(raw) if has_witness else txid_le
    return {
        "version": version,
        "has_witness": has_witness,
        "vin": vins,
        "vout": vouts,
        "locktime": locktime,
        "non_witness_bytes": non_witness_bytes,
        "full_bytes": raw,
        "txid_le": txid_le,
        "txid": txid_le[::-1].hex(),
        "wtxid_le": wtxid_le,
        "wtxid": wtxid_le[::-1].hex(),
    }


def verify_btc_merkle_branch(leaf_le: bytes, index: int, branch_be: list[str], expected_root_le: bytes) -> bool:
    """Verify Bitcoin/Namecoin Merkle branch (32B LE hashes internally, BE hex on wire) with CVE-2012-2459 guard."""
    if len(leaf_le) != 32 or len(expected_root_le) != 32 or index < 0:
        return False
    cur = leaf_le
    idx = index
    for h_be in branch_be:
        if not isinstance(h_be, str) or len(h_be) != 64:
            return False
        try:
            sib_le = bytes.fromhex(h_be)[::-1]
        except ValueError:
            return False
        if (idx & 1) == 1:
            if sib_le == cur:
                return False  # CVE-2012-2459 odd-position duplicate rejection
            cur = dsha256(sib_le + cur)
        else:
            cur = dsha256(cur + sib_le)
        idx >>= 1
    return idx == 0 and cur == expected_root_le


def compute_bip143_sighash(tx: dict[str, Any], in_idx: int, script_code: bytes, value_sat: int, sighash_type: int = 0x01) -> bytes:
    """Compute BIP-143 SegWit v0 sighash with CompactSize varint prefix on scriptCode."""
    prevouts = b"".join(v["prev_txid_le"] + struct.pack("<I", v["prev_vout"]) for v in tx["vin"])
    seqs = b"".join(struct.pack("<I", v["sequence"]) for v in tx["vin"])
    outs = b"".join(struct.pack("<Q", o["value_sat"]) + _encode_varint(len(o["script_pubkey"])) + o["script_pubkey"] for o in tx["vout"])
    inp = tx["vin"][in_idx]
    preimage = (
        struct.pack("<I", tx["version"])
        + dsha256(prevouts)
        + dsha256(seqs)
        + inp["prev_txid_le"]
        + struct.pack("<I", inp["prev_vout"])
        + _encode_varint(len(script_code))
        + script_code
        + struct.pack("<Q", value_sat)
        + struct.pack("<I", inp["sequence"])
        + dsha256(outs)
        + struct.pack("<I", tx["locktime"])
        + struct.pack("<I", sighash_type)
    )
    return dsha256(preimage)


def verify_segwit_name_update_proof(
    proof: dict[str, Any],
    expected_owner_policy: dict[str, Any],
    expected_name: str,
) -> tuple[bool, dict[str, Any] | str]:
    """Verify all 7 consensus-exact P0-CONS-1 checks on a Tier-2 SegWitNameUpdateProof (OP_NAME_FIRSTUPDATE & OP_NAME_UPDATE, key/multisig)."""
    if not isinstance(expected_owner_policy, dict):
        return False, "TICKET_PROOF_INVALID"
    kind = expected_owner_policy.get("kind")
    if kind == "branch":
        return False, "CHAIN_SCRIPT_UNSUPPORTED"
    if kind not in ("key", "multisig"):
        return False, "TICKET_PROOF_INVALID"
    try:
        exp_spk, exp_ws = compile_script_policy(expected_owner_policy)
    except (ValueError, KeyError, TypeError):
        return False, "TICKET_PROOF_INVALID"

    try:
        hdr = bytes.fromhex(proof["block_header_hex"])
        if len(hdr) != 80:
            return False, "TICKET_PROOF_INVALID"
        if dsha256(hdr)[::-1].hex() != proof["block_hash"]:
            return False, "TICKET_PROOF_INVALID"
        merkle_root_le = hdr[36:68]
        tx = parse_raw_tx(bytes.fromhex(proof["tx_hex"]))
        prev_tx = parse_raw_tx(bytes.fromhex(proof["prevout_tx_hex"]))
        cb_tx = parse_raw_tx(bytes.fromhex(proof["coinbase_tx_hex"]))
    except (ValueError, KeyError, TypeError):
        return False, "TICKET_PROOF_INVALID"

    # Step 1: Reject 64-byte leaf forgery variants + require nVersion == 0x7100 + SegWit witness
    if (
        len(cb_tx["non_witness_bytes"]) == 64
        or len(tx["non_witness_bytes"]) == 64
        or len(tx["full_bytes"]) == 64
        or len(prev_tx["non_witness_bytes"]) == 64
        or tx["version"] != 0x7100
        or not tx["has_witness"]
    ):
        return False, "TICKET_PROOF_INVALID"

    # Step 2: Coinbase structural check (len(vin) == 1, null prevout) + index==0 Merkle branch -> exact D_tree
    if len(cb_tx["vin"]) != 1 or cb_tx["vin"][0]["prev_txid_le"] != (b"\x00" * 32) or cb_tx["vin"][0]["prev_vout"] != 0xFFFFFFFF:
        return False, "TICKET_PROOF_INVALID"
    cb_branch = proof.get("coinbase_merkle_branch", [])
    if not cb_branch or not verify_btc_merkle_branch(cb_tx["txid_le"], 0, cb_branch, merkle_root_le):
        return False, "TICKET_PROOF_INVALID"
    d_tree = len(cb_branch)

    # Step 3: Exact depth D_tree on txid_branch, wtxid_branch, wtxid_coinbase_branch + tx_index >= 1
    tx_index = proof.get("tx_index", 0)
    txid_branch = proof.get("txid_branch", [])
    wtxid_branch = proof.get("wtxid_branch", [])
    wtxid_cb_branch = proof.get("wtxid_coinbase_branch", [])
    if (
        not isinstance(tx_index, int) or isinstance(tx_index, bool) or tx_index < 1
        or len(txid_branch) != d_tree
        or len(wtxid_branch) != d_tree
        or len(wtxid_cb_branch) != d_tree
    ):
        return False, "TICKET_PROOF_INVALID"
    if not verify_btc_merkle_branch(tx["txid_le"], tx_index, txid_branch, merkle_root_le):
        return False, "TICKET_PROOF_INVALID"

    # Step 4: BIP-141 LAST coinbase output starting with 6a24aa21a9ed + 32B witness_reserved_value
    witness_commitment: bytes | None = None
    for vo in cb_tx["vout"]:
        spk = vo["script_pubkey"]
        if len(spk) >= 38 and spk[:6] == b"\x6a\x24\xaa\x21\xa9\xed":
            witness_commitment = spk[6:38]
    cb_wit = cb_tx["vin"][0]["witness"]
    if witness_commitment is None or len(cb_wit) != 1 or len(cb_wit[0]) != 32:
        return False, "TICKET_PROOF_INVALID"
    witness_reserved_value = cb_wit[0]

    # Step 5: wtxid tree binding (same tx_index, coinbase wtxid[0] == 00*32, SHA256d(wtxid_root || reserved) == commitment)
    cur_w = tx["wtxid_le"]
    idx_w = tx_index
    for h_be in wtxid_branch:
        if not isinstance(h_be, str) or len(h_be) != 64:
            return False, "TICKET_PROOF_INVALID"
        try:
            sib_le = bytes.fromhex(h_be)[::-1]
        except ValueError:
            return False, "TICKET_PROOF_INVALID"
        if (idx_w & 1) == 1:
            if sib_le == cur_w:
                return False, "TICKET_PROOF_INVALID"
            cur_w = dsha256(sib_le + cur_w)
        else:
            cur_w = dsha256(cur_w + sib_le)
        idx_w >>= 1
    if idx_w != 0:
        return False, "TICKET_PROOF_INVALID"
    wtxid_root_le = cur_w
    if not verify_btc_merkle_branch(b"\x00" * 32, 0, wtxid_cb_branch, wtxid_root_le):
        return False, "TICKET_PROOF_INVALID"
    if dsha256(wtxid_root_le + witness_reserved_value) != witness_commitment:
        return False, "TICKET_PROOF_INVALID"

    # Step 6: Locate unique name output in tx (OP_NAME_FIRSTUPDATE or OP_NAME_UPDATE), locate matching name input
    # spending prev_tx with empty scriptSig, strip Namecoin prefix, verify expected_owner_policy & compute BIP-143 sighash
    parsed_new: dict[str, Any] | None = None
    new_vout: int = -1
    opreturns: list[dict[str, Any]] = []
    name_out_count = 0
    for vo in tx["vout"]:
        spk = vo["script_pubkey"]
        if spk[:1] == b"\x6a":
            opreturns.append({"script_pubkey_hex": spk.hex(), "value_sat": vo["value_sat"]})
            continue
        if is_witness_program_script(spk):
            continue
        if spk[:1] in (bytes([OP_NAME_NEW]), bytes([OP_NAME_FIRSTUPDATE]), bytes([OP_NAME_UPDATE])):
            name_out_count += 1
            try:
                pn = parse_name_output(spk)
            except ValueError:
                return False, "TICKET_PROOF_INVALID"
            if pn.get("name") == expected_name and pn.get("op") in ("NAME_FIRSTUPDATE", "NAME_UPDATE"):
                parsed_new = pn
                new_vout = int(vo["n"])
    if parsed_new is None or name_out_count != 1:
        return False, "TICKET_PROOF_INVALID"

    name_in_idx: int | None = None
    prev_out: dict[str, Any] | None = None
    prev_parsed: dict[str, Any] | None = None
    for i, vin in enumerate(tx["vin"]):
        if vin["prev_txid"] == prev_tx["txid"] and vin["prev_vout"] < len(prev_tx["vout"]):
            cand_out = prev_tx["vout"][vin["prev_vout"]]
            try:
                p_prev = parse_name_output(cand_out["script_pubkey"])
            except ValueError:
                continue
            if parsed_new["op"] == "NAME_FIRSTUPDATE":
                if p_prev.get("op") != "NAME_NEW":
                    continue
                if hash160(bytes.fromhex(parsed_new["rand"]) + expected_name.encode("utf-8")).hex() != p_prev.get("hash20"):
                    return False, "TICKET_PROOF_INVALID"
                if vin["script_sig"] != b"" or parsed_new["trailing_script_pubkey"] != exp_spk.hex():
                    return False, "TICKET_PROOF_INVALID"
            else:
                if p_prev.get("name") != expected_name or p_prev.get("op") not in ("NAME_FIRSTUPDATE", "NAME_UPDATE"):
                    continue
                if vin["script_sig"] != b"" or p_prev["trailing_script_pubkey"] != exp_spk.hex():
                    return False, "TICKET_PROOF_INVALID"
            name_in_idx = i
            prev_out = cand_out
            prev_parsed = p_prev
            break
    if name_in_idx is None or prev_out is None or prev_parsed is None:
        return False, "TICKET_PROOF_INVALID"

    # Step 7: Strict consensus BIP-66 DER + SIGHASH_ALL (0x01), WITHOUT rejecting consensus-valid high-S!
    # For registrar-funded OP_NAME_FIRSTUPDATE (NAME_NEW trailing script != expected_owner_policy), verify the native
    # SegWit NAME_NEW witness directly and mark owner_authored=False (SL-LDGR-007 rule 3 requires a subsequent OP_NAME_UPDATE).
    wit = tx["vin"][name_in_idx]["witness"]
    owner_authored = True
    if parsed_new["op"] == "NAME_FIRSTUPDATE" and prev_parsed["trailing_script_pubkey"] != exp_spk.hex():
        owner_authored = False
        reg_spk = prev_parsed["trailing_script_pubkey"]
        if len(reg_spk) == 44 and reg_spk.startswith("0014"):
            if len(wit) != 2 or not is_valid_compressed_pubkey(wit[1].hex()) or hash160(wit[1]).hex() != reg_spk[4:]:
                return False, "TICKET_PROOF_INVALID"
            script_code = b"\x76\xa9\x14" + hash160(wit[1]) + b"\x88\xac"
            sighash = compute_bip143_sighash(tx, name_in_idx, script_code, prev_out["value_sat"], 0x01)
            ok_sig, sht = secp256k1_ecdsa_verify_bip66(sighash, wit[1].hex(), wit[0])
            if not ok_sig or sht != 0x01:
                return False, "TICKET_PROOF_INVALID"
        elif len(reg_spk) == 68 and reg_spk.startswith("0020"):
            if len(wit) < 2 or sha256(wit[-1]).hex() != reg_spk[4:]:
                return False, "TICKET_PROOF_INVALID"
        else:
            return False, "TICKET_PROOF_INVALID"
    elif kind == "key":
        if len(wit) != 2 or wit[1].hex() != expected_owner_policy["pk"]:
            return False, "TICKET_PROOF_INVALID"
        script_code = b"\x76\xa9\x14" + hash160(wit[1]) + b"\x88\xac"
        sighash = compute_bip143_sighash(tx, name_in_idx, script_code, prev_out["value_sat"], 0x01)
        ok_sig, sht = secp256k1_ecdsa_verify_bip66(sighash, expected_owner_policy["pk"], wit[0])
        if not ok_sig or sht != 0x01:
            return False, "TICKET_PROOF_INVALID"
    else:  # multisig
        assert exp_ws is not None
        m = int(expected_owner_policy["m"])
        pks = list(expected_owner_policy["pks"])
        if len(wit) != m + 2 or wit[0] != b"" or wit[-1] != exp_ws:
            return False, "TICKET_PROOF_INVALID"
        sighash = compute_bip143_sighash(tx, name_in_idx, exp_ws, prev_out["value_sat"], 0x01)
        sigs = wit[1:-1]
        pk_pos = 0
        for sb in sigs:
            matched = False
            while pk_pos < len(pks):
                ok_s, sht = secp256k1_ecdsa_verify_bip66(sighash, pks[pk_pos], sb)
                pk_pos += 1
                if ok_s and sht == 0x01:
                    matched = True
                    break
            if not matched:
                return False, "TICKET_PROOF_INVALID"

    # For OP_NAME_UPDATE ownership transfer (new_trailing_script_pubkey != exp_spk), the departing previous owner
    # signed the spend — NOT the new owner — so owner_authored MUST be False (SL-LDGR-007, H-1a / H05).
    if parsed_new["op"] == "NAME_UPDATE" and parsed_new["trailing_script_pubkey"] != exp_spk.hex():
        owner_authored = False

    return True, {
        "txid": tx["txid"],
        "name_vout": new_vout,
        "spent_prev_txid": tx["vin"][name_in_idx]["prev_txid"],
        "spent_prev_vout": tx["vin"][name_in_idx]["prev_vout"],
        "new_trailing_script_pubkey": parsed_new["trailing_script_pubkey"],
        "opreturns": opreturns,
        "owner_authored": owner_authored,
        "parsed_update": parsed_new,
    }


# --- Namecoin Difficulty Retarget & CAuxPow::check (P0-CONS-1, nc28.0 exact) ---

def _namecoin_pow_limit(network: str) -> int:
    if network == "regtest":
        return NAMECOIN_POW_LIMIT_REGTEST
    if network == "testnet":
        return NAMECOIN_POW_LIMIT_TESTNET
    return NAMECOIN_POW_LIMIT_MAIN


def namecoin_retarget_ancestor_height(height: int, *, network: str = "main") -> int:
    """Exact Namecoin Core nc28.0 src/pow.cpp:47-55 retarget ancestor height (H - 2017 post-AuxPoW!)."""
    auxpow_start = NAMECOIN_AUXPOW_START_MAIN if network == "main" else 0
    n_blocks_back = 2016 if ((height - 1) >= auxpow_start and height > 2016) else 2015
    return (height - 1) - n_blocks_back


def bits_to_target(nbits: int) -> int:
    exp = (nbits >> 24) & 0xFF
    mant = nbits & 0x007FFFFF
    if nbits & 0x00800000:
        return 0
    if exp <= 3:
        return mant >> (8 * (3 - exp))
    return mant << (8 * (exp - 3))


def target_to_bits(target: int) -> int:
    if target <= 0:
        return 0
    b = target.to_bytes((target.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    exp = len(b)
    if exp >= 3:
        mant = int.from_bytes(b[:3], "big")
    else:
        mant = int.from_bytes(b, "big") << (8 * (3 - exp))
    return (exp << 24) | (mant & 0x007FFFFF)


def compute_namecoin_next_bits(
    prev_bits: int,
    epoch_start_time: int,
    prev_block_time: int,
    *,
    network: str = "main",
) -> int:
    """Exact Namecoin Core nc28.0 retarget (actual_timespan = block[H-1].nTime - block[nHeightFirst].nTime clamped to [302400, 4838400], fPowNoRetargeting on regtest)."""
    if network == "regtest":
        return prev_bits
    actual = prev_block_time - epoch_start_time
    if actual < NAMECOIN_MIN_TIMESPAN:
        actual = NAMECOIN_MIN_TIMESPAN
    elif actual > NAMECOIN_MAX_TIMESPAN:
        actual = NAMECOIN_MAX_TIMESPAN
    old_t = bits_to_target(prev_bits)
    new_t = (old_t * actual) // NAMECOIN_TARGET_TIMESPAN
    pow_limit = _namecoin_pow_limit(network)
    if new_t > pow_limit:
        new_t = pow_limit
    return target_to_bits(new_t)


def auxpow_expected_index(nonce: int, chain_id: int, merkle_size: int) -> int:
    """Exact Namecoin Core CAuxPow::getExpectedIndex."""
    rand = nonce & 0xFFFFFFFF
    rand = (rand * 1103515245 + 12345) & 0xFFFFFFFF
    rand = (rand + chain_id) & 0xFFFFFFFF
    rand = (rand * 1103515245 + 12345) & 0xFFFFFFFF
    return rand % merkle_size


def _check_namecoin_version_rules(n_ver: int, *, network: str, height: int | None, is_auxpow: bool) -> bool:
    """Exact Namecoin Core nc28.0 pureheader + ContextualCheckBlockHeader version & chain_id rules (R12-H2, M04, F-09d, D12-L1)."""
    if is_auxpow:
        if (n_ver & 0x00000100) == 0:
            return False
    else:
        if (n_ver & 0x00000100) != 0:
            return False
    # Genesis block (height == 0) always has nVersion == 1 across main, testnet, and regtest
    if height == 0:
        return (not is_auxpow) and n_ver == 1

    # IsLegacy() == (nVersion == 1), allowed below nLegacyBlocksBefore (-1 on testnet means legacy allowed at all heights)
    legacy_before = (
        NAMECOIN_LEGACY_BEFORE_MAIN
        if network == "main"
        else (NAMECOIN_LEGACY_BEFORE_TESTNET if network == "testnet" else NAMECOIN_LEGACY_BEFORE_REGTEST)
    )
    is_legacy = (n_ver == 1)
    if is_legacy:
        if is_auxpow:
            return False
        if legacy_before != -1 and (height is None or height >= legacy_before):
            return False
    else:
        # fStrictChainId is True on main & regtest, False on testnet (unless AuxPoW which always binds chain_id=1)
        strict_chain_id = (network != "testnet") or is_auxpow
        if strict_chain_id and (n_ver >> 16) != NAMECOIN_AUX_CHAIN_ID:
            return False

    # Base version activation thresholds (nc28.0 src/validation.cpp ContextualCheckBlockHeader)
    # Namecoin pureheader: bits 0..7 are base version (bit 8 = AuxPoW, bits 16..31 = chain_id).
    base_ver = n_ver & 0xFF
    if height is not None:
        if network == "main":
            if height >= NAMECOIN_BIP65_MAIN and base_ver < 4:
                return False
            if height >= NAMECOIN_BIP66_MAIN and base_ver < 3:
                return False
            if height >= NAMECOIN_BIP34_MAIN and base_ver < 2:
                return False
        elif network == "regtest":
            if height >= 1 and base_ver < 4:
                return False
        elif network == "testnet":
            if height >= 1 and not is_legacy and base_ver < 1:
                return False
    return True


def verify_namecoin_header_pow(header_hex: str, *, network: str = "main", height: int | None = None) -> bool:
    """Verify non-AuxPoW Namecoin block header PoW & exact nc28.0 version/chain_id rules."""
    try:
        hdr = bytes.fromhex(header_hex)
        if len(hdr) != 80:
            return False
        n_ver = struct.unpack("<I", hdr[0:4])[0]
        if not _check_namecoin_version_rules(n_ver, network=network, height=height, is_auxpow=False):
            return False
        nbits = struct.unpack("<I", hdr[72:76])[0]
        pow_limit = _namecoin_pow_limit(network)
        target = bits_to_target(nbits)
        if target <= 0 or target > pow_limit:
            return False
        return int.from_bytes(dsha256(hdr), "little") <= target
    except Exception:
        return False


def verify_namecoin_auxpow(header_hex: str, auxpow: dict[str, Any], *, network: str = "main", height: int | None = None) -> bool:
    """Verify Namecoin Core nc28.0 CAuxPow::check (AuxPoW start height, chain_id=1, !parent.IsAuxpow(), fStrictChainId, len(chain_branch)<=30, parent PoW, !parent_coinbase.vin.empty(), coinbase branch, fabe6d6d, GetExpectedIndex)."""
    try:
        hdr = bytes.fromhex(header_hex)
        if len(hdr) != 80:
            return False
        auxpow_start = NAMECOIN_AUXPOW_START_MAIN if network == "main" else 0
        if height is not None and height < auxpow_start:
            return False
        n_ver = struct.unpack("<I", hdr[0:4])[0]
        n_bits = struct.unpack("<I", hdr[72:76])[0]
        if not _check_namecoin_version_rules(n_ver, network=network, height=height, is_auxpow=True):
            return False
        pow_limit = _namecoin_pow_limit(network)
        target = bits_to_target(n_bits)
        if target <= 0 or target > pow_limit:
            return False
        parent_hdr = bytes.fromhex(auxpow["parent_header_hex"])
        if len(parent_hdr) != 80:
            return False
        parent_ver = struct.unpack("<I", parent_hdr[0:4])[0]
        if (parent_ver & 0x00000100) != 0:
            return False  # !parentBlock.IsAuxpow()
        if network != "testnet" and (parent_ver >> 16) == NAMECOIN_AUX_CHAIN_ID:
            return False  # fStrictChainId: parent block cannot have Namecoin's own chain_id
        parent_hash_int = int.from_bytes(dsha256(parent_hdr), "little")
        if parent_hash_int > target:
            return False
        parent_merkle_le = parent_hdr[36:68]
        cb_tx = parse_raw_tx(bytes.fromhex(auxpow["parent_coinbase_hex"]), allow_empty_vout=True)
        # Exact nc28.0 src/auxpow.cpp CAuxPow::check: only requires !coinbaseTx->vin.empty() (R12-L4, M04)
        if not cb_tx["vin"]:
            return False
        if not verify_btc_merkle_branch(cb_tx["txid_le"], 0, auxpow["coinbase_branch"], parent_merkle_le):
            return False
        merkle_size = int(auxpow["chain_merkle_size"])
        merkle_nonce = int(auxpow["chain_merkle_nonce"])
        chain_branch = auxpow["chain_branch"]
        if not isinstance(chain_branch, list) or len(chain_branch) > 30 or merkle_size != (1 << len(chain_branch)):
            return False
        exp_idx = auxpow_expected_index(merkle_nonce, NAMECOIN_AUX_CHAIN_ID, merkle_size)
        aux_block_hash_le = dsha256(hdr)
        cur = aux_block_hash_le
        idx = exp_idx
        for h_be in chain_branch:
            if not isinstance(h_be, str) or len(h_be) != 64:
                return False
            sib_le = bytes.fromhex(h_be)[::-1]
            cur = dsha256(sib_le + cur) if (idx & 1) else dsha256(cur + sib_le)
            idx >>= 1
        aux_root_be = cur[::-1]
        ss = cb_tx["vin"][0]["script_sig"]
        magic = b"\xfa\xbe\x6d\x6d"
        pc = ss.find(aux_root_be)
        if pc < 0:
            return False
        mpos = ss.find(magic)
        if mpos >= 0:
            # Namecoin Core CAuxPow::check: at most one fabe6d6d magic, immediately preceding aux_root_be
            if ss.find(magic, mpos + 4) != -1 or mpos + 4 != pc:
                return False
        elif pc > 20:
            # Namecoin Core CAuxPow::check: when fabe6d6d is omitted, aux_root_be MUST start within first 20 bytes
            return False
        # Followed immediately by 4B LE chain_merkle_size + 4B LE chain_merkle_nonce
        if len(ss) < pc + 40:
            return False
        got_sz, got_nonce = struct.unpack("<II", ss[pc + 32 : pc + 40])
        return got_sz == merkle_size and got_nonce == merkle_nonce
    except (ValueError, KeyError, TypeError):
        return False


def self_test() -> None:
    """Verify pure-Python BIP-340, RIPEMD-160, RFC 8032 Ed25519, and low-S NIST P-256 against official vectors."""
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

    # Official RFC 8032 §7.1 Ed25519 Test Vector 1 (empty message)
    ed_sk1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    ed_pk1_exp = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    ed_sig1_exp = (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert ed25519_pubkey(ed_sk1) == ed_pk1_exp, "RFC 8032 Ed25519 TV1 pubkey mismatch"
    assert ed25519_sign(b"", ed_sk1) == ed_sig1_exp, "RFC 8032 Ed25519 TV1 sig mismatch"
    assert ed25519_verify(b"", ed_pk1_exp, ed_sig1_exp), "RFC 8032 Ed25519 TV1 verify failed"

    # Official RFC 8032 §7.1 Ed25519 Test Vector 2 (message = 0x72)
    ed_sk2 = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    ed_pk2_exp = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    ed_sig2_exp = (
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )
    assert ed25519_pubkey(ed_sk2) == ed_pk2_exp, "RFC 8032 Ed25519 TV2 pubkey mismatch"
    assert ed25519_sign(b"\x72", ed_sk2) == ed_sig2_exp, "RFC 8032 Ed25519 TV2 sig mismatch"
    assert ed25519_verify(b"\x72", ed_pk2_exp, ed_sig2_exp), "RFC 8032 Ed25519 TV2 verify failed"

    # Strict Ed25519 negative checks (R3 B6 / W-11): all 8 small-order points & non-canonical encodings MUST reject
    small_order_hexes = [
        "0100000000000000000000000000000000000000000000000000000000000000",  # order 1 (identity)
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # order 2
        "0000000000000000000000000000000000000000000000000000000000000000",  # order 4
        "0000000000000000000000000000000000000000000000000000000000000080",  # order 4
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  # order 8
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",  # order 8
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  # order 8
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",  # order 8
    ]
    for spk in small_order_hexes:
        assert not is_valid_ed25519_pubkey(spk), f"Small-order Ed25519 key MUST reject: {spk}"
        # Classic forged signature with small-order A, small-order R, S = 0
        assert not ed25519_verify(b"test", spk, spk + "00" * 32), f"Small-order Ed25519 sig MUST reject: {spk}"
    # Non-canonical y >= p (y = p = 2^255 - 19 -> edff..7f)
    assert not is_valid_ed25519_pubkey("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")

    # BranchKeySpec m-of-n compilation self-test (Decision 6A-A2)
    p1 = compressed_pubkey(deterministic_privkey("bks-1"))
    p2 = compressed_pubkey(deterministic_privkey("bks-2"))
    p3 = compressed_pubkey(deterministic_privkey("bks-3"))
    p4 = compressed_pubkey(deterministic_privkey("bks-4"))
    p5 = compressed_pubkey(deterministic_privkey("bks-5"))
    bks_disp = {"m": 2, "pks": sorted([p1, p2, p3])}
    bks_arb = {"m": 2, "pks": sorted([p4, p5])}
    spk_e2, ws_e2 = compile_script_policy({"kind": "branch", "template": "either_of_2", "keys": canonical_branch_pair(bks_disp, p4)})
    assert len(spk_e2) == 34 and ws_e2 is not None and len(ws_e2) < 400
    spk_b2, ws_b2 = compile_script_policy({"kind": "branch", "template": "both_of_2", "keys": canonical_branch_pair(bks_disp, bks_arb)})
    assert len(spk_b2) == 34 and ws_b2 is not None and len(ws_b2) < 400
    # Unsorted pair MUST reject CHAIN_SCRIPT_UNSUPPORTED (Decision 4 / R3 Blocker #4)
    p_lo, p_hi = sorted([p1, p4])
    try:
        compile_script_policy({"kind": "branch", "template": "both_of_2", "keys": {"a": p_hi, "b": p_lo}})
        raise AssertionError("Unsorted both_of_2 MUST reject")
    except ValueError as exc:
        assert str(exc) == "CHAIN_SCRIPT_UNSUPPORTED"
    # Whole-tree WIRE_VALUE before WIRE_STRING (R3 Blocker #5)
    ok_vs, err_vs = jcs_validate(b'{"a":"\\t","b":null}')
    assert not ok_vs and err_vs == "WIRE_VALUE", f"Expected WIRE_VALUE before WIRE_STRING, got {err_vs}"
    spk_gp, ws_gp = compile_script_policy({
        "kind": "branch", "template": "guardian_slot_pending",
        "keys": {"disposer": bks_disp, "challenger": bks_arb, "guardian": compressed_pubkey(deterministic_privkey("bks-6"))},
        "delay_blocks": 16,
    })
    assert len(spk_gp) == 34 and ws_gp is not None and len(ws_gp) < 400
    # 1000-deep JSON MUST return WIRE_SIZE without RecursionError
    ok_d, err_d = jcs_validate((b'{"a":' * 1000) + b'1' + (b'}' * 1000))
    assert not ok_d and err_d == "WIRE_SIZE", f"Expected WIRE_SIZE on 1000-deep JSON, got {(ok_d, err_d)}"
    # Exact container depth 16 MUST pass; depth 17 MUST fail WIRE_SIZE
    ok_16, _ = jcs_validate((b'{"a":' * 16) + b'1' + (b'}' * 16))
    assert ok_16, "Container depth 16 MUST pass"
    ok_17, err_17 = jcs_validate((b'{"a":' * 17) + b'1' + (b'}' * 17))
    assert not ok_17 and err_17 == "WIRE_SIZE", f"Container depth 17 MUST fail WIRE_SIZE, got {(ok_17, err_17)}"
    # Leading-zero number MUST return WIRE_NUMBER; trailing whitespace MUST return WIRE_JSON
    ok_lz, err_lz = jcs_validate(b'{"a":01}')
    assert not ok_lz and err_lz == "WIRE_NUMBER", f"Leading zero expected WIRE_NUMBER, got {err_lz}"
    ok_tw, err_tw = jcs_validate(b'{"a":1}\n')
    assert not ok_tw and err_tw == "WIRE_JSON", f"Trailing newline expected WIRE_JSON, got {err_tw}"

    # Official RFC 6979 Appendix A.2.5 NIST P-256 SHA-256 test vector (low-S normalized + high-S rejected)
    rfc_p256_sk = bytes.fromhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
    rfc_p256_pk_exp = "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
    assert p256_compressed_pubkey(rfc_p256_sk) == rfc_p256_pk_exp, "RFC 6979 P-256 pubkey mismatch"
    rfc_h = sha256(b"sample")
    rfc_r = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
    rfc_high_s = "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
    rfc_low_s = f"{(_P256_N - int(rfc_high_s, 16)):064x}"
    assert p256_sign_low_s(rfc_h, rfc_p256_sk) == rfc_r + rfc_low_s, "RFC 6979 P-256 low-S sig mismatch"
    assert p256_verify_low_s(rfc_h, rfc_p256_pk_exp, rfc_r + rfc_low_s), "RFC 6979 P-256 low-S verify failed"
    assert not p256_verify_low_s(rfc_h, rfc_p256_pk_exp, rfc_r + rfc_high_s), "P-256 high-S signature MUST be rejected"

    # Official RIPEMD-160 test vector for "abc"
    assert ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", "RIPEMD-160 mismatch"

    # Clause commitment vector (SPEC-01 §5)
    salt = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    c_hash = clause_commit(salt, {"text": "Room inspection"})
    assert c_hash.startswith("b030a8a82ef79e9d"), f"clause_commit mismatch: {c_hash}"

    # v1.0.0-draft.11 primitives self-tests: target_id (excluding params), RFC 9162 checkpoints_root & peaks,
    # canonical Fixed-Depth-256 SMT (incl. sib != D[h-1]), consensus BIP-66 high-S ECDSA, and Namecoin retarget/AuxPoW
    tid1 = artifact_target_id({"scheme": "sha256", "digest": "11" * 32, "params": {"filename": "a.bin"}})
    tid2 = artifact_target_id({"scheme": "sha256", "digest": "11" * 32, "params": {"filename": "b.bin"}})
    assert tid1 == tid2, "target_id MUST ignore params"
    c_leaves = [ckpt_leaf(i + 1, sha256(f"cp-{i+1}".encode()).hex()) for i in range(7)]
    for sz in range(1, 8):
        sub = c_leaves[:sz]
        r_mth = rfc9162_mth(sub).hex()
        pks = rfc9162_peaks(sub)
        assert len(pks) == _popcount(sz) and rfc9162_root_from_peaks(pks, sz) == r_mth
        if sz < 7:
            assert rfc9162_append_leaf_to_peaks(pks, sz, c_leaves[sz]) == rfc9162_mth(c_leaves[: sz + 1]).hex()
        for m_i in range(sz):
            ip = rfc9162_inclusion_proof(sub, m_i)
            assert rfc9162_verify_inclusion(sub[m_i], m_i, sz, ip["hashes"], r_mth)
    kv_smt = {"act:" + ("aa" * 32) + "|*": "bb" * 32, "target:" + ("cc" * 32) + "|*": "dd" * 32}
    p_inc = smt_prove(kv_smt, "act:" + ("aa" * 32) + "|*")
    p_abs = smt_prove(kv_smt, "rel:" + ("ee" * 32) + "|*")
    assert smt_verify_proof(p_inc) and smt_verify_proof(p_abs)
    # Non-canonical SMT proof supplying D[h-1] for a 1-bit MUST reject (P1)!
    bad_bm = bytearray(bytes.fromhex(p_abs["bitmap_hex"]))
    for h_i in range(1, 257):
        d_i = 256 - h_i
        if smt_get_bit(bytes(bad_bm), d_i) == 0:
            bad_bm[d_i >> 3] |= 1 << (7 - (d_i & 7))
            # insert D[h_i - 1] at exact bottom-up position
            ins_at = sum(smt_get_bit(bytes(bad_bm), 256 - hh) for hh in range(1, h_i))
            bad_sibs = list(p_abs["siblings"])
            bad_sibs.insert(ins_at, SMT_DEFAULTS[h_i - 1].hex())
            assert not smt_verify_proof({**p_abs, "bitmap_hex": bytes(bad_bm).hex(), "siblings": bad_sibs})
            break
    # Consensus BIP-66 DER ECDSA MUST accept high-S (P0-CONS-1)
    sk_e = deterministic_privkey("bip66-high-s-test")
    pk_e = compressed_pubkey(sk_e)
    z_e = sha256(b"consensus-high-s")
    d_int = int.from_bytes(sk_e, "big")
    k_int = int.from_bytes(sha256(b"k-high-s"), "big") % (_N - 1) + 1
    pt_k = _point_mul(_G, k_int)
    assert pt_k is not None
    r_e = pt_k[0] % _N
    s_e = (pow(k_int, _N - 2, _N) * (int.from_bytes(z_e, "big") + r_e * d_int)) % _N
    if s_e <= _N // 2:
        s_e = _N - s_e  # force high-S
    def _der_u(v: int) -> bytes:
        b = v.to_bytes((v.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    der_body = _der_u(r_e) + _der_u(s_e)
    sig_high_s = b"\x30" + bytes([len(der_body)]) + der_body + b"\x01"
    ok_hs, sht_hs = secp256k1_ecdsa_verify_bip66(z_e, pk_e, sig_high_s)
    assert ok_hs and sht_hs == 0x01, "Consensus BIP-66 verifier MUST accept valid high-S ECDSA signature"
    assert compute_namecoin_next_bits(0x1D00FFFF, 1000, 1000 + 100, network="main") == target_to_bits(bits_to_target(0x1D00FFFF) // 4)
    assert compute_namecoin_next_bits(0x207FFFFF, 1000, 1000 + 100, network="regtest") == 0x207FFFFF
    # Real Namecoin Core nc28.0 mainnet archival retarget tuples (verified on synced mainnet node at height 853,134)
    assert namecoin_retarget_ancestor_height(18144, network="main") == 16128
    assert namecoin_retarget_ancestor_height(20160, network="main") == 18143
    assert namecoin_retarget_ancestor_height(733824, network="main") == 731807
    assert compute_namecoin_next_bits(0x1B00B269, 1318761208, 1319487998, network="main") == 0x1A6B32B1  # height 24192
    assert compute_namecoin_next_bits(0x1A385BFC, 1321247518, 1322148153, network="main") == 0x1A29F6AE  # height 30240
    assert compute_namecoin_next_bits(0x1705D999, 1723460218, 1724608760, network="main") == 0x17058E00  # height 733824
    # Linux FS_IOC_MEASURE_VERITY fsverity-sha256 exact empty-file digest
    assert fsverity_sha256_digest(b"") == "3d248ca542a24fc62d1c43b916eae5016878e2533c88238480b26128a1f1af95"
    # CAuxPow::check regtest parity: omitted fabe6d6d allowed iff root_offset <= 20, empty vout allowed in parent coinbase,
    # parent MUST NOT set IsAuxpow() and MUST NOT have chain_id == 1 under fStrictChainId
    _aux_hdr = struct.pack("<I", 0x00010104) + (b"\x00" * 32) + (b"\x11" * 32) + struct.pack("<III", 1700000000, 0x207FFFFF, 0)
    _aux_root_be = dsha256(_aux_hdr)[::-1]
    def _mk_cb_empty_vout(ss_b: bytes) -> bytes:
        return struct.pack("<I", 1) + b"\x01" + (b"\x00" * 32) + struct.pack("<I", 0xFFFFFFFF) + _encode_varint(len(ss_b)) + ss_b + struct.pack("<I", 0xFFFFFFFF) + b"\x00" + struct.pack("<I", 0)
    _cb_ok = _mk_cb_empty_vout(b"\x28" + _aux_root_be + struct.pack("<II", 1, 0))
    _cb_far = _mk_cb_empty_vout((b"\x00" * 21) + _aux_root_be + struct.pack("<II", 1, 0))
    def _mine_hdr(ver: int, mr_le: bytes) -> bytes:
        h = struct.pack("<I", ver) + (b"\x00" * 32) + mr_le + struct.pack("<III", 0, 0, 0)
        while int.from_bytes(dsha256(h), "little") > bits_to_target(0x207FFFFF):
            h = h[:-4] + struct.pack("<I", struct.unpack("<I", h[-4:])[0] + 1)
        return h
    _ph_ok = _mine_hdr(1, dsha256(_cb_ok))
    _ph_far = _mine_hdr(1, dsha256(_cb_far))
    _ph_aux = _mine_hdr(0x00000101, dsha256(_cb_ok))
    _ph_same_cid = _mine_hdr(0x00010002, dsha256(_cb_ok))
    assert verify_namecoin_auxpow(_aux_hdr.hex(), {"chain_branch": [], "chain_merkle_nonce": 0, "chain_merkle_size": 1, "coinbase_branch": [], "parent_coinbase_hex": _cb_ok.hex(), "parent_header_hex": _ph_ok.hex()}, network="regtest")
    assert not verify_namecoin_auxpow(_aux_hdr.hex(), {"chain_branch": [], "chain_merkle_nonce": 0, "chain_merkle_size": 1, "coinbase_branch": [], "parent_coinbase_hex": _cb_far.hex(), "parent_header_hex": _ph_far.hex()}, network="regtest")
    assert not verify_namecoin_auxpow(_aux_hdr.hex(), {"chain_branch": [], "chain_merkle_nonce": 0, "chain_merkle_size": 1, "coinbase_branch": [], "parent_coinbase_hex": _cb_ok.hex(), "parent_header_hex": _ph_aux.hex()}, network="regtest")
    assert not verify_namecoin_auxpow(_aux_hdr.hex(), {"chain_branch": [], "chain_merkle_nonce": 0, "chain_merkle_size": 1, "coinbase_branch": [], "parent_coinbase_hex": _cb_ok.hex(), "parent_header_hex": _ph_same_cid.hex()}, network="regtest")
    assert not verify_namecoin_header_pow(_ph_ok.hex(), network="regtest", height=10)  # missing chain_id=1 on non-legacy
    _hdr_badv2 = struct.pack("<I", 0x00010002) + (b"\x00" * 32) + dsha256(_cb_ok) + struct.pack("<III", 1700000000, 0x207FFFFF, 0)
    while int.from_bytes(dsha256(_hdr_badv2), "little") > bits_to_target(0x207FFFFF):
        _hdr_badv2 = _hdr_badv2[:-4] + struct.pack("<I", struct.unpack("<I", _hdr_badv2[-4:])[0] + 1)
    assert not verify_namecoin_header_pow(_hdr_badv2.hex(), network="regtest", height=10), "nc28.0 regtest rejects base version 2 (bad-version)"
    _hdr_nonaux = struct.pack("<I", 0x00010004) + (b"\x00" * 32) + dsha256(_cb_ok) + struct.pack("<III", 1700000000, 0x207FFFFF, 0)
    while int.from_bytes(dsha256(_hdr_nonaux), "little") > bits_to_target(0x207FFFFF):
        _hdr_nonaux = _hdr_nonaux[:-4] + struct.pack("<I", struct.unpack("<I", _hdr_nonaux[-4:])[0] + 1)
    assert verify_namecoin_header_pow(_hdr_nonaux.hex(), network="regtest", height=10)
    # Genesis block (height=0, nVersion=1) MUST be accepted
    _hdr_gen = struct.pack("<I", 1) + (b"\x00" * 32) + dsha256(_cb_ok) + struct.pack("<III", 1296688602, 0x207FFFFF, 0)
    while int.from_bytes(dsha256(_hdr_gen), "little") > bits_to_target(0x207FFFFF):
        _hdr_gen = _hdr_gen[:-4] + struct.pack("<I", struct.unpack("<I", _hdr_gen[-4:])[0] + 1)
    assert verify_namecoin_header_pow(_hdr_gen.hex(), network="regtest", height=0)
    # P2A & witness v1 recognition + P2WSH multisig decoder + JCS edge cases
    assert is_witness_program_script(bytes.fromhex("51024e73"))
    assert is_witness_program_script(bytes.fromhex("5120" + "11" * 32))
    _ms_pol = {"kind": "multisig", "m": 2, "pks": sorted([p1, p2, p3])}
    _, _ms_ws = compile_script_policy(_ms_pol)
    assert _ms_ws is not None and parse_p2wsh_multisig_script(_ms_ws) == _ms_pol
    assert jcs_validate(b'{"a":1.}') == (False, "WIRE_NUMBER")
    assert jcs_validate(b'{"a":.5}') == (False, "WIRE_NUMBER")
    assert jcs_validate(b'{"a":-.5}') == (False, "WIRE_NUMBER")
    assert jcs_validate(b'{"a":NaN}') == (False, "WIRE_JSON")
    assert jcs_validate(b'{"a":Infinity}') == (False, "WIRE_JSON")
    assert jcs_validate(('{"a":0\u0661}').encode("utf-8")) == (False, "WIRE_JSON")
    assert jcs_validate(('{"a":' + "9" * 5000 + '}').encode("utf-8")) == (False, "WIRE_NUMBER")
    assert jcs_validate(b'{"text":"line1\\nline2"}') == (False, "WIRE_STRING")
    assert jcs_validate(b'{"text":"line1\\nline2"}', allow_lf_paths=CLAUSE_LF_PATHS)[0] is True

    print(f"seallink_ref self_test PASS (BIP-340 + RFC8032 Ed25519 + low-S P-256 + RIPEMD-160 + RFC9162 + SMT256 + BIP66 + CAuxPow + fsverity) | clause_commit={c_hash}")


if __name__ == "__main__":
    self_test()
