#!/usr/bin/env python3
"""
Live Two-Node Namecoin Core nc28.0 Regtest Conformance Harness for SealLink v1.0.0-draft.4.

Executes all four end-to-end SealLink protocol traces on two fresh loopback-only
Namecoin Core 28 regtest nodes under strict standard policy (`-acceptnonstdtxn=0`,
`-txindex=1`), extracting live ChainViews strictly from the independent read-only
peer node B's RPC responses and verifying every step with `tools/seallink_verifier.py`
(`Tier1Verifier(pinned_network="regtest", require_jsonschema=True)`).

Exercises on real nc28.0 regtest:
  - Trace 01: Live `name_new` -> `name_firstupdate` -> `name_update` (JCS <= 520B),
              P2WPKH seal + `0x01` issuance, live ADMIT, real mempool revocation
              observed on peer B BEFORE mining -> SEAL_SPENT -> GRANT_CLOSED.
  - Trace 02: Live `0x09` origin anchor + `0x0c` name binding; real `P2WSH` 2-of-3
              multisig ward name ownership updated via `createpsbt` + `namepsbt` +
              BIP-143 P2WSH multisig witness; `0x12` initial activation (`both_of_2`),
              active `either_of_2` halt spend, `0x0d` `guardian_slot_pending` CSV
              branch proving BOTH premature `non-BIP68-final` rejection AND post-CSV
              `0x0e` activation, `0x0f` roster transition, `0x10` RECOVERY_CANCEL,
              and live `Tier1Verifier.verify_assent` verdicts.
  - Trace 03: Live delegation with `single_use_1_of_2` P2WSH (`0x11` branch-0 grantee
              consumption vs branch-1 issuer revoke) AND TRUC v3 zero-fee `P2A`
              (`0x51024e73`) CPFP revocation package propagated via `submitpackage`
              from node A to peer node B before mining, verified live by Tier1Verifier.
  - Trace 04: Live anchored ward origin with 2-of-2 active `either_of_2` guardians
              and `agent/guardian-message` (`strict_drop`, `effect_grant`) ADMIT plus
              1-of-2 downgrade refusal (`GUARDIAN_QUORUM_UNMET`).

Zero external cryptographic dependencies beyond Python stdlib + `jsonschema` +
repository `tools/seallink_ref.py` and `tools/seallink_verifier.py`.
"""

from __future__ import annotations

import argparse
from decimal import Decimal
import hashlib
import hmac
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import seallink_ref as sl  # noqa: E402
import seallink_verifier as sv  # noqa: E402

NAMECOIN_TX_VERSION = 0x7100
MIN_NAME_SAT = 1_000_000  # 0.01 NMC (Namecoin Core MinNameCoinAmount)
SEAL_SAT = 500_000        # 0.005 NMC (covers single-input revocation fee + change)
FEE_SAT = 200_000         # 0.002 NMC (well above Namecoin Core 0.001 NMC/kB minrelaytxfee)


# ============================================================================
# 1. Pure-Python RFC 6979 Low-S DER secp256k1 ECDSA & BIP-143 SegWit v0 Builder
# ============================================================================

def dsha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _rfc6979_k_secp256k1(sk_bytes: bytes, msg32: bytes) -> int:
    """Deterministic RFC 6979 nonce for secp256k1 ECDSA (HMAC-SHA256)."""
    n = sl._N
    z_int = int.from_bytes(msg32, "big") % n
    bx = sk_bytes + z_int.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + bx, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + bx, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < n:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def _der_int(val: int) -> bytes:
    b = val.to_bytes((val.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def ecdsa_sign_der_low_s(msg32: bytes, sk_bytes: bytes, sighash_type: int = 0x01) -> bytes:
    """Strict BIP-62 low-S, BIP-66 DER secp256k1 ECDSA signature + sighash byte."""
    n = sl._N
    d = int.from_bytes(sk_bytes, "big")
    z = int.from_bytes(msg32, "big")
    k = _rfc6979_k_secp256k1(sk_bytes, msg32)
    pt = sl._point_mul(sl._G, k)
    assert pt is not None
    r = pt[0] % n
    s = (pow(k, n - 2, n) * (z + r * d)) % n
    if s > n // 2:
        s = n - s
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body + bytes([sighash_type])


def kp(label: str) -> dict[str, Any]:
    sk = sl.deterministic_privkey(f"regtest-nc28-{label}")
    comp_hex = sl.compressed_pubkey(sk)
    return {
        "label": label,
        "sk": sk,
        "comp": comp_hex,
        "comp_bytes": bytes.fromhex(comp_hex),
        "xonly": sl.xonly_pubkey(sk),
        "p2wpkh_spk": b"\x00\x14" + sl.hash160(bytes.fromhex(comp_hex)),
    }


def _bip143_sighash(
    version: int,
    inputs: list[dict[str, Any]],
    outputs: list[tuple[int, bytes]],
    locktime: int,
    in_idx: int,
    script_code: bytes,
    value_sat: int,
    sighash_type: int = 0x01,
) -> bytes:
    prevouts = b"".join(bytes.fromhex(i["txid"])[::-1] + struct.pack("<I", i["vout"]) for i in inputs)
    seqs = b"".join(struct.pack("<I", i.get("sequence", 0xFFFFFFFD)) for i in inputs)
    outs = b"".join(struct.pack("<Q", val) + varint(len(spk)) + spk for val, spk in outputs)
    inp = inputs[in_idx]
    preimage = (
        struct.pack("<I", version)
        + dsha256(prevouts)
        + dsha256(seqs)
        + bytes.fromhex(inp["txid"])[::-1]
        + struct.pack("<I", inp["vout"])
        + varint(len(script_code))
        + script_code
        + struct.pack("<Q", value_sat)
        + struct.pack("<I", inp.get("sequence", 0xFFFFFFFD))
        + dsha256(outs)
        + struct.pack("<I", locktime)
        + struct.pack("<I", sighash_type)
    )
    return dsha256(preimage)


def build_signed_tx(
    inputs: list[dict[str, Any]],
    outputs: list[tuple[int, bytes]],
    *,
    version: int = 2,
    locktime: int = 0,
) -> tuple[str, str]:
    """Build and sign a SegWit v0 / P2A Bitcoin or Namecoin transaction.

    Each input dict has:
      txid (str), vout (int), value_sat (int), sequence (optional int, default 0xfffffffd),
      kind:
        - "p2wpkh": signer=kp
        - "p2wsh_multisig": witness_script=bytes, signers=[kp1, kp2, ...] (in sorted pk order)
        - "p2wsh_single_key_branch": witness_script=bytes, signer=kp, selectors=[bytes, ...]
        - "p2a": (empty witness stack)
    Returns (txid_hex, raw_tx_hex).
    """
    witnesses: list[list[bytes]] = []
    for idx, inp in enumerate(inputs):
        kind = inp["kind"]
        if kind == "p2wpkh":
            k = inp["signer"]
            sc = b"\x76\xa9\x14" + sl.hash160(k["comp_bytes"]) + b"\x88\xac"
            sh = _bip143_sighash(version, inputs, outputs, locktime, idx, sc, inp["value_sat"])
            sig = ecdsa_sign_der_low_s(sh, k["sk"])
            witnesses.append([sig, k["comp_bytes"]])
        elif kind == "p2wsh_multisig":
            ws = inp["witness_script"]
            sh = _bip143_sighash(version, inputs, outputs, locktime, idx, ws, inp["value_sat"])
            # Sort signers by compressed pubkey to match canonical sorted multisig witnessScript!
            ordered = sorted(inp["signers"], key=lambda x: x["comp"])
            sigs = [ecdsa_sign_der_low_s(sh, k["sk"]) for k in ordered]
            witnesses.append([b""] + sigs + [ws])
        elif kind == "p2wsh_single_key_branch":
            ws = inp["witness_script"]
            sh = _bip143_sighash(version, inputs, outputs, locktime, idx, ws, inp["value_sat"])
            sig = ecdsa_sign_der_low_s(sh, inp["signer"]["sk"])
            witnesses.append([sig] + list(inp.get("selectors", [])) + [ws])
        elif kind == "p2a":
            witnesses.append([])
        else:
            raise ValueError(f"Unsupported input kind: {kind}")

    vin_b = varint(len(inputs)) + b"".join(
        bytes.fromhex(i["txid"])[::-1]
        + struct.pack("<I", i["vout"])
        + b"\x00"
        + struct.pack("<I", i.get("sequence", 0xFFFFFFFD))
        for i in inputs
    )
    vout_b = varint(len(outputs)) + b"".join(
        struct.pack("<Q", val) + varint(len(spk)) + spk for val, spk in outputs
    )
    base_tx = struct.pack("<I", version) + vin_b + vout_b + struct.pack("<I", locktime)
    txid = dsha256(base_tx)[::-1].hex()
    has_wit = any(len(w) > 0 for w in witnesses)
    if has_wit:
        wit_b = b"".join(
            varint(len(stack)) + b"".join(varint(len(item)) + item for item in stack)
            for stack in witnesses
        )
        full_tx = struct.pack("<I", version) + b"\x00\x01" + vin_b + vout_b + wit_b + struct.pack("<I", locktime)
    else:
        full_tx = base_tx
    return txid, full_tx.hex()


def op_return_spk(action_byte: int, digest_hex: str) -> bytes:
    """Build exact OP_RETURN <40-byte SLNK frame> scriptPubKey (sl.encode_opreturn includes 0x6a + push)."""
    return sl.encode_opreturn(action_byte, digest_hex)


# ============================================================================
# 2. Two-Node Loopback-Only Namecoin Core nc28.0 Harness + Live RPC ChainView
# ============================================================================

class RegtestCluster:
    """Manages two fresh loopback-only Namecoin Core 28 regtest nodes."""

    def __init__(self, bin_dir: Path, work_dir: Path) -> None:
        self.bin_dir = bin_dir.resolve(strict=True)
        self.work_dir = work_dir.resolve()
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.dirs = [
            Path(tempfile.mkdtemp(prefix=f"nc28-node{i}-", dir=self.work_dir)).resolve()
            for i in range(2)
        ]
        socks = [socket.socket() for _ in range(4)]
        for s in socks:
            s.bind(("127.0.0.1", 0))
        self.ports = [s.getsockname()[1] for s in socks]
        for s in socks:
            s.close()
        self.procs: list[subprocess.Popen[Any]] = []
        self.fund_key = kp("cluster-funder")
        self.fund_addr = ""
        self.genesis_hash = ""
        self.coinbase_pool: list[dict[str, Any]] = []
        # Track known ScriptPolicies for live names so ChainView includes the pinned owner_policy
        # alongside the actual on-chain output_script_hex verified by Tier1Verifier!
        self.name_owner_policies: dict[tuple[str, str, int], dict[str, Any]] = {}
        self.name_history_entries: dict[str, list[dict[str, Any]]] = {}

    def rpc(self, node: int, method: str, *args: Any, wait: bool = False) -> Any:
        cmd = [
            str(self.bin_dir / "namecoin-cli"),
            "-regtest",
            f"-datadir={self.dirs[node]}",
            f"-rpcport={self.ports[node]}",
            "-rpcconnect=127.0.0.1",
            "-stdin",
        ]
        if wait:
            cmd.extend(["-rpcwait", "-rpcwaittimeout=25"])
        cmd.append(method)
        vals = [v if isinstance(v, str) else json.dumps(v, separators=(",", ":")) for v in args]
        p = subprocess.run(
            cmd,
            input="\n".join(vals) + ("\n" if vals else ""),
            text=True,
            capture_output=True,
            timeout=30,
        )
        if p.returncode != 0:
            raise RuntimeError(f"node[{node}] {method} failed: {p.stderr.strip()[:400]}")
        out = p.stdout.strip()
        if not out:
            return None
        try:
            return json.loads(out)
        except ValueError:
            return out

    @staticmethod
    def until(pred: Any, limit: float = 30.0) -> bool:
        t0 = time.monotonic()
        while time.monotonic() - t0 < limit:
            if pred():
                return True
            time.sleep(0.15)
        return False

    def start(self) -> dict[str, Any]:
        common_flags = [
            "-regtest",
            "-server=1",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            "-listen=1",
            "-listenonion=0",
            "-onion=0",
            "-onlynet=ipv4",
            "-connect=0",
            "-dnsseed=0",
            "-fixedseeds=0",
            "-discover=0",
            "-txindex=1",
            "-acceptnonstdtxn=0",
            "-printtoconsole=0",
            "-par=2",
        ]
        for i in range(2):
            extra = ["-disablewallet=1"] if i == 1 else []
            cmd = [
                str(self.bin_dir / "namecoind"),
                f"-datadir={self.dirs[i]}",
                f"-rpcport={self.ports[i]}",
                f"-port={self.ports[2 + i]}",
                f"-bind=127.0.0.1:{self.ports[2 + i]}",
                *common_flags,
                *extra,
            ]
            self.procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        for i in range(2):
            info = self.rpc(i, "getblockchaininfo", wait=True)
            assert info["chain"] == "regtest"
        self.rpc(1, "addnode", f"127.0.0.1:{self.ports[2]}", "onetry")
        assert self.until(
            lambda: all(len(self.rpc(i, "getpeerinfo")) == 1 and self.rpc(i, "getpeerinfo")[0]["version"] > 0 for i in range(2)),
            limit=20.0,
        ), "node A and node B failed to establish loopback peer connection"

        self.genesis_hash = self.rpc(0, "getblockhash", 0)
        assert self.rpc(1, "getblockhash", 0) == self.genesis_hash
        net_info = self.rpc(0, "getnetworkinfo")

        # Derive bech32 address for cluster funder key and mine 140 blocks -> 40 mature coinbase UTXOs
        desc = self.rpc(0, "getdescriptorinfo", f"wpkh({self.fund_key['comp']})")["descriptor"]
        self.fund_addr = self.rpc(0, "deriveaddresses", desc)[0]
        blocks = self.rpc(0, "generatetoaddress", 140, self.fund_addr)
        assert self.until(lambda: self.rpc(1, "getbestblockhash") == blocks[-1], limit=30.0)
        for bh in blocks[:40]:
            cb = self.rpc(0, "getblock", bh, 2)["tx"][0]
            out = next(x for x in cb["vout"] if x["scriptPubKey"].get("address") == self.fund_addr)
            self.coinbase_pool.append({
                "txid": cb["txid"],
                "vout": out["n"],
                "value_sat": int(Decimal(str(out["value"])) * 100_000_000),
                "kind": "p2wpkh",
                "signer": self.fund_key,
            })
        return {
            "subversion": net_info["subversion"],
            "version": net_info["version"],
            "regtest_genesis_hash": self.genesis_hash,
            "initial_tip_height": self.rpc(1, "getblockcount"),
        }

    def stop(self) -> bool:
        for i, p in enumerate(self.procs):
            if p.poll() is None:
                try:
                    self.rpc(i, "stop")
                except Exception:
                    p.terminate()
        for p in self.procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.terminate()
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
        stopped = all(p.poll() is not None for p in self.procs)
        for d in self.dirs:
            if d.exists():
                shutil.rmtree(d)
        return stopped

    def next_funding_utxo(self) -> dict[str, Any]:
        return self.coinbase_pool.pop(0)

    def mine(self, n: int = 1) -> list[str]:
        blocks = self.rpc(0, "generatetoaddress", n, self.fund_addr)
        assert self.until(lambda: self.rpc(1, "getbestblockhash") == blocks[-1], limit=25.0), "peer B did not sync mined block"
        return blocks

    def broadcast_and_wait_peer(self, raw_hex: str) -> str:
        txid = self.rpc(0, "sendrawtransaction", raw_hex)
        assert self.until(lambda: txid in self.rpc(1, "getrawmempool"), limit=20.0), f"tx {txid} not observed in peer B mempool"
        return txid

    def split_funding(self, count: int, each_sat: int = 50_000_000) -> list[dict[str, Any]]:
        """Split one mature coinbase UTXO into `count` equal P2WPKH UTXOs for self.fund_key."""
        src = self.next_funding_utxo()
        outs = [(each_sat, self.fund_key["p2wpkh_spk"]) for _ in range(count)]
        rem = src["value_sat"] - count * each_sat - FEE_SAT
        if rem > 10_000:
            outs.append((rem, self.fund_key["p2wpkh_spk"]))
        txid, raw_hex = build_signed_tx([src], outs)
        self.broadcast_and_wait_peer(raw_hex)
        self.mine(1)
        return [
            {"txid": txid, "vout": idx, "value_sat": each_sat, "kind": "p2wpkh", "signer": self.fund_key}
            for idx in range(count)
        ]

    def register_names_batch(self, specs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """Register a batch of Namecoin names on live nc28.0 regtest:
        NAME_NEW -> mine 13 blocks (maturity >= 12) -> NAME_FIRSTUPDATE -> mine 1 block.

        Each spec: {"name": str, "owner_policy": ScriptPolicy, "value_obj": dict, "rand_label": str}
        Returns {name: {"registration": {txid, vout}, "first_txid": str, "first_raw": str,
                        "new_txid": str, "new_raw": str, "value_sat": int, "owner_policy": dict,
                        "height": int}}.
        """
        funds = self.split_funding(len(specs) * 3, each_sat=3_000_000)
        new_recs: list[dict[str, Any]] = []
        nn_txids: set[str] = set()
        for idx, sp in enumerate(specs):
            name_b = sp["name"].encode("utf-8")
            rand_b = sl.sha256(f"rand-{sp['rand_label']}".encode("utf-8"))[:20]
            h20 = sl.hash160(rand_b + name_b)
            # NAME_NEW output is owned by cluster fund_key (P2WPKH) so FIRSTUPDATE can spend it directly!
            nn_spk = sl.encode_name_output("NAME_NEW", self.fund_key["p2wpkh_spk"], hash20=h20)
            f = funds[idx * 3]
            change = f["value_sat"] - MIN_NAME_SAT - FEE_SAT
            txid, raw_hex = build_signed_tx(
                [f],
                [(MIN_NAME_SAT, nn_spk), (change, self.fund_key["p2wpkh_spk"])],
                version=NAMECOIN_TX_VERSION,
            )
            self.rpc(0, "sendrawtransaction", raw_hex)
            nn_txids.add(txid)
            new_recs.append({"spec": sp, "rand_b": rand_b, "new_txid": txid, "new_raw": raw_hex})
        assert self.until(lambda: nn_txids <= set(self.rpc(1, "getrawmempool")), limit=25.0)
        self.mine(13)  # 1 block to confirm NAME_NEW + 12 blocks maturity!

        out_map: dict[str, dict[str, Any]] = {}
        fu_txids: set[str] = set()
        for idx, nr in enumerate(new_recs):
            sp = nr["spec"]
            name = sp["name"]
            val_b = sl.jcs_encode(sp["value_obj"])
            assert len(val_b) <= 520, f"Name value > 520B: {len(val_b)}"
            trailing_spk, ws = sl.compile_script_policy(sp["owner_policy"])
            fu_spk = sl.encode_name_output(
                "NAME_FIRSTUPDATE", trailing_spk, name=name.encode("utf-8"), rand=nr["rand_b"], value=val_b
            )
            f_extra = funds[idx * 3 + 1]
            nn_in = {"txid": nr["new_txid"], "vout": 0, "value_sat": MIN_NAME_SAT, "kind": "p2wpkh", "signer": self.fund_key}
            change = f_extra["value_sat"] - FEE_SAT
            fu_txid, fu_raw = build_signed_tx(
                [nn_in, f_extra],
                [(MIN_NAME_SAT, fu_spk), (change, self.fund_key["p2wpkh_spk"])],
                version=NAMECOIN_TX_VERSION,
            )
            self.rpc(0, "sendrawtransaction", fu_raw)
            fu_txids.add(fu_txid)
            self.name_owner_policies[(name, fu_txid, 0)] = sp["owner_policy"]
            out_map[name] = {
                "registration": {"txid": fu_txid, "vout": 0},
                "first_txid": fu_txid,
                "first_raw": fu_raw,
                "new_txid": nr["new_txid"],
                "new_raw": nr["new_raw"],
                "current_txid": fu_txid,
                "current_vout": 0,
                "value_sat": MIN_NAME_SAT,
                "owner_policy": sp["owner_policy"],
                "witness_script": ws,
            }
        assert self.until(lambda: fu_txids <= set(self.rpc(1, "getrawmempool")), limit=25.0)
        self.mine(1)
        tip_h = self.rpc(1, "getblockcount")
        for name, rec in out_map.items():
            rec["height"] = tip_h
            shown = self.rpc(1, "name_show", name)
            assert shown["txid"] == rec["first_txid"], f"peer B name_show mismatch for {name}"
            self.name_history_entries[name] = [
                {"txid": rec["first_txid"], "vout": 0, "op": "NAME_FIRSTUPDATE", "owner_policy": rec["owner_policy"]}
            ]

        # Batch owner-authored OP_NAME_UPDATE (SL-LDGR-007 SIGHASH_ALL writer proof) for all P2WPKH names!
        upd_txids: set[str] = set()
        upd_pending: list[tuple[str, str, str, dict[str, Any]]] = []
        for idx, nr in enumerate(new_recs):
            sp = nr["spec"]
            owner_kp = sp.get("owner_kp")
            if owner_kp is None:
                continue
            name = sp["name"]
            rec = out_map[name]
            val_b = sl.jcs_encode(sp["value_obj"])
            trailing_spk, _ = sl.compile_script_policy(rec["owner_policy"])
            upd_spk = sl.encode_name_output("NAME_UPDATE", trailing_spk, name=name.encode("utf-8"), value=val_b)
            f_upd = funds[idx * 3 + 2]
            name_in = {"txid": rec["current_txid"], "vout": 0, "value_sat": MIN_NAME_SAT, "kind": "p2wpkh", "signer": owner_kp}
            u_txid, u_raw = build_signed_tx(
                [name_in, f_upd],
                [(MIN_NAME_SAT, upd_spk), (f_upd["value_sat"] - FEE_SAT, self.fund_key["p2wpkh_spk"])],
                version=NAMECOIN_TX_VERSION,
            )
            self.rpc(0, "sendrawtransaction", u_raw)
            upd_txids.add(u_txid)
            upd_pending.append((name, u_txid, u_raw, rec["owner_policy"]))
        if upd_txids:
            assert self.until(lambda: upd_txids <= set(self.rpc(1, "getrawmempool")), limit=25.0)
            self.mine(1)
            tip_h = self.rpc(1, "getblockcount")
            for name, u_txid, u_raw, pol in upd_pending:
                rec = out_map[name]
                rec["current_txid"] = u_txid
                rec["current_vout"] = 0
                rec["update_txid"] = u_txid
                rec["update_raw"] = u_raw
                rec["height"] = tip_h
                self.name_owner_policies[(name, u_txid, 0)] = pol
                self.name_history_entries[name].append(
                    {"txid": u_txid, "vout": 0, "op": "NAME_UPDATE", "owner_policy": pol, "prev_owner_policy": pol}
                )
        return out_map

    def update_name_p2wpkh(
        self,
        name_rec: dict[str, Any],
        name: str,
        owner_kp: dict[str, Any],
        new_value_obj: dict[str, Any],
        new_owner_policy: dict[str, Any] | None = None,
        extra_outputs: list[tuple[int, bytes]] | None = None,
    ) -> tuple[str, str]:
        """Perform a real OP_NAME_UPDATE spending a P2WPKH name UTXO and mine 1 block."""
        val_b = sl.jcs_encode(new_value_obj)
        assert len(val_b) <= 520
        pol = new_owner_policy or name_rec["owner_policy"]
        trailing_spk, ws = sl.compile_script_policy(pol)
        upd_spk = sl.encode_name_output("NAME_UPDATE", trailing_spk, name=name.encode("utf-8"), value=val_b)
        fee_in = self.split_funding(1, each_sat=500_000)[0]
        name_in = {
            "txid": name_rec["current_txid"],
            "vout": name_rec["current_vout"],
            "value_sat": MIN_NAME_SAT,
            "kind": "p2wpkh",
            "signer": owner_kp,
        }
        outs: list[tuple[int, bytes]] = [(MIN_NAME_SAT, upd_spk)]
        if extra_outputs:
            outs.extend(extra_outputs)
        extra_sat = sum(v for v, _ in (extra_outputs or []))
        outs.append((fee_in["value_sat"] - extra_sat - FEE_SAT, self.fund_key["p2wpkh_spk"]))
        txid, raw_hex = build_signed_tx([name_in, fee_in], outs, version=NAMECOIN_TX_VERSION)
        self.broadcast_and_wait_peer(raw_hex)
        self.mine(1)
        shown = self.rpc(1, "name_show", name)
        assert shown["txid"] == txid
        prev_pol = name_rec["owner_policy"]
        name_rec["current_txid"] = txid
        name_rec["current_vout"] = 0
        name_rec["owner_policy"] = pol
        name_rec["witness_script"] = ws
        self.name_owner_policies[(name, txid, 0)] = pol
        self.name_history_entries[name].append(
            {"txid": txid, "vout": 0, "op": "NAME_UPDATE", "owner_policy": pol, "prev_owner_policy": prev_pol}
        )
        return txid, raw_hex

    def update_name_p2wsh_multisig_via_namepsbt(
        self,
        name_rec: dict[str, Any],
        name: str,
        signers: list[dict[str, Any]],
        new_value_obj: dict[str, Any],
    ) -> dict[str, Any]:
        """Prove nc28.0 `createpsbt` + `namepsbt` + BIP-143 P2WSH 2-of-3 multisig OP_NAME_UPDATE!

        1. Calls Node A `createpsbt` + `namepsbt` with `{"op": "name_update", "name": name, "value": jcs}`
           to obtain nc28.0's own consensus-encoded `OP_NAME_UPDATE` + P2WSH scriptPubKey.
        2. Calls `decodepsbt` and verifies nc28.0's output script equals `sl.encode_name_output(...)` byte-for-byte!
        3. Signs the P2WSH 2-of-3 multisig input with 2-of-3 signers (BIP-143 witness `[b"", sig1, sig2, ws]`),
           broadcasts on Node A, waits for peer B mempool observation, mines 1 block, and verifies `name_show` on Node B!
        """
        val_str = sl.jcs_encode(new_value_obj).decode("utf-8")
        assert len(val_str.encode("utf-8")) <= 520
        pol = name_rec["owner_policy"]
        trailing_spk, ws = sl.compile_script_policy(pol)
        assert ws is not None

        # Derive bech32 P2WSH address for trailing_spk via nc28.0 RPC
        p2wsh_desc = self.rpc(0, "getdescriptorinfo", f"wsh(sortedmulti({pol['m']},{','.join(pol['pks'])}))")["descriptor"]
        p2wsh_addr = self.rpc(0, "deriveaddresses", p2wsh_desc)[0]

        fee_in = self.split_funding(1, each_sat=500_000)[0]
        change_nmc = float(Decimal(fee_in["value_sat"] - FEE_SAT) / Decimal(100_000_000))
        psbt0 = self.rpc(
            0,
            "createpsbt",
            [
                {"txid": name_rec["current_txid"], "vout": name_rec["current_vout"]},
                {"txid": fee_in["txid"], "vout": fee_in["vout"]},
            ],
            [
                {p2wsh_addr: 0.01},
                {self.fund_addr: change_nmc},
            ],
        )
        psbt_named = self.rpc(
            0,
            "namepsbt",
            psbt0,
            0,
            {"op": "name_update", "name": name, "value": val_str},
        )
        psbt_named_str = psbt_named["psbt"] if isinstance(psbt_named, dict) else psbt_named
        decoded_psbt = self.rpc(0, "decodepsbt", psbt_named_str)
        nc_out_spk_hex = decoded_psbt["tx"]["vout"][0]["scriptPubKey"]["hex"]
        expected_upd_spk = sl.encode_name_output("NAME_UPDATE", trailing_spk, name=name.encode("utf-8"), value=val_str.encode("utf-8"))
        assert nc_out_spk_hex == expected_upd_spk.hex(), "nc28.0 namepsbt output script differed from SealLink encoder!"
        assert decoded_psbt["tx"]["version"] == NAMECOIN_TX_VERSION

        # Sign the exact transaction produced by namepsbt with BIP-143 P2WSH 2-of-3 witness + fee input!
        name_in = {
            "txid": name_rec["current_txid"],
            "vout": name_rec["current_vout"],
            "value_sat": MIN_NAME_SAT,
            "kind": "p2wsh_multisig",
            "witness_script": ws,
            "signers": signers,
        }
        txid, raw_hex = build_signed_tx(
            [name_in, fee_in],
            [
                (MIN_NAME_SAT, bytes.fromhex(nc_out_spk_hex)),
                (fee_in["value_sat"] - FEE_SAT, self.fund_key["p2wpkh_spk"]),
            ],
            version=NAMECOIN_TX_VERSION,
        )
        self.broadcast_and_wait_peer(raw_hex)
        self.mine(1)
        shown = self.rpc(1, "name_show", name)
        assert shown["txid"] == txid and shown["value"] == val_str
        name_rec["current_txid"] = txid
        name_rec["current_vout"] = 0
        self.name_owner_policies[(name, txid, 0)] = pol
        self.name_history_entries[name].append(
            {"txid": txid, "vout": 0, "op": "NAME_UPDATE", "owner_policy": pol, "prev_owner_policy": pol}
        )
        return {
            "txid": txid,
            "raw_hex": raw_hex,
            "p2wsh_address": p2wsh_addr,
            "namepsbt_script_matched_seallink_encoder": True,
            "decoded_psbt_version": decoded_psbt["tx"]["version"],
            "witness_script_hex": ws.hex(),
            "confirmed_height": self.rpc(1, "getblockcount"),
        }

    def extract_chain_view(
        self,
        *,
        tracked_txids: list[str],
        tracked_names: list[str],
        tracked_block_hashes: list[str] | None = None,
        manifests: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Extract a live SealLink ChainView strictly from peer Node B RPC + Node A comparison peer!"""
        b_info = self.rpc(1, "getblockchaininfo")
        a_info = self.rpc(0, "getblockchaininfo")
        tip_h = int(b_info["blocks"])
        tip_hash = b_info["bestblockhash"]
        tip_hdr = self.rpc(1, "getblockheader", tip_hash)
        tip_time = int(tip_hdr["time"])
        now_ts = tip_time + 30

        mempool_set = set(self.rpc(1, "getrawmempool"))

        # Collect all relevant txids (including all name history txs + mempool txs)
        all_txids: list[str] = []
        seen_t: set[str] = set()
        for t in list(tracked_txids) + list(mempool_set):
            if t and t not in seen_t:
                seen_t.add(t)
                all_txids.append(t)
        for nm in tracked_names:
            for ent in self.name_history_entries.get(nm, []):
                if ent["txid"] not in seen_t:
                    seen_t.add(ent["txid"])
                    all_txids.append(ent["txid"])

        # Decode every transaction strictly via peer Node B `getrawtransaction(txid, True)`
        raw_decoded: dict[str, dict[str, Any]] = {}
        spent_map: dict[tuple[str, int], str] = {}
        for txid in all_txids:
            try:
                txd = self.rpc(1, "getrawtransaction", txid, True)
            except RuntimeError:
                continue
            raw_decoded[txid] = txd
            for vin in txd.get("vin", []):
                if "txid" in vin and "vout" in vin:
                    spent_map[(vin["txid"], int(vin["vout"]))] = txid

        txs_view: dict[str, Any] = {}
        for txid, txd in raw_decoded.items():
            conf_h: int | None = None
            if "blockhash" in txd:
                bhdr = self.rpc(1, "getblockheader", txd["blockhash"])
                conf_h = int(bhdr["height"])
            inputs_v = []
            for vin in txd.get("vin", []):
                if "txid" in vin:
                    inputs_v.append({
                        "prev_txid": vin["txid"],
                        "prev_vout": int(vin["vout"]),
                        "script_sig_hex": vin.get("scriptSig", {}).get("hex", ""),
                        "witness": list(vin.get("txinwitness", [])),
                    })
            outputs_v: dict[str, Any] = {}
            opret_hex: str | None = None
            for vout in txd.get("vout", []):
                n = int(vout["n"])
                spk_hex = vout["scriptPubKey"]["hex"]
                o_ent: dict[str, Any] = {"script_pubkey_hex": spk_hex}
                if (txid, n) in spent_map:
                    o_ent["spent_by_txid"] = spent_map[(txid, n)]
                outputs_v[str(n)] = o_ent
                # Extract full SLNK OP_RETURN scriptPubKey (`6a28534c4e4b...`) for Tier1Verifier
                spk_b = bytes.fromhex(spk_hex)
                if len(spk_b) >= 6 and spk_b[0] == 0x6A and spk_b[2:6] == b"SLNK":
                    opret_hex = spk_hex
            tx_obj: dict[str, Any] = {
                "confirmed_height": conf_h,
                "in_mempool": txid in mempool_set,
                "inputs": inputs_v,
                "outputs": outputs_v,
            }
            if opret_hex is not None:
                tx_obj["opreturn_hex"] = opret_hex
            txs_view[txid] = tx_obj

        blocks_view: dict[str, int] = {tip_hash: tip_h}
        for bh in (tracked_block_hashes or []):
            bhdr = self.rpc(1, "getblockheader", bh)
            blocks_view[bh] = int(bhdr["height"])

        names_view: dict[str, Any] = {}
        for nm in tracked_names:
            hist = self.name_history_entries.get(nm, [])
            if not hist:
                continue
            updates_v: list[dict[str, Any]] = []
            for idx, ent in enumerate(hist):
                txid = ent["txid"]
                vout = ent["vout"]
                txd = raw_decoded[txid]
                bhdr = self.rpc(1, "getblockheader", txd["blockhash"])
                h_conf = int(bhdr["height"])
                out_spk_hex = next(o["scriptPubKey"]["hex"] for o in txd["vout"] if int(o["n"]) == vout)
                u_obj: dict[str, Any] = {
                    "confirmed_height": h_conf,
                    "op": ent["op"],
                    "output_script_hex": out_spk_hex,
                    "owner_policy": ent["owner_policy"],
                    "txid": txid,
                    "vout": vout,
                }
                if idx > 0:
                    prev_ent = hist[idx - 1]
                    # Extract actual DER sighash bytes strictly from txinwitness of the input spending prev_ent!
                    spent_vin = next(
                        v for v in txd["vin"]
                        if v.get("txid") == prev_ent["txid"] and int(v.get("vout", -1)) == prev_ent["vout"]
                    )
                    wit_items = spent_vin.get("txinwitness", [])
                    sh_bytes = [
                        int(item[-2:], 16)
                        for item in wit_items
                        if len(item) >= 16 and item.startswith("30")
                    ]
                    u_obj["prev_input"] = {
                        "sighash_bytes": sh_bytes,
                        "txid": prev_ent["txid"],
                        "vout": prev_ent["vout"],
                        "witness_policy": prev_ent["owner_policy"],
                    }
                if txs_view[txid].get("opreturn_hex"):
                    u_obj["opreturn_hex"] = txs_view[txid]["opreturn_hex"]
                updates_v.append(u_obj)
            names_view[nm] = {
                "registration": {"txid": hist[0]["txid"], "vout": hist[0]["vout"]},
                "updates": updates_v,
            }

        return {
            "best_header_height": int(b_info["headers"]),
            "blocks": blocks_view,
            "clock_watermark": tip_time - 60,
            "comparison_peers": [
                {
                    "hash_at_tip": a_info["bestblockhash"],
                    "healthy": True,
                    "height": int(a_info["blocks"]),
                    "id": "node-a-local",
                }
            ],
            "credible_utc_interval": [now_ts - 60, now_ts + 60],
            "future_bound_s": 600,
            "genesis": self.genesis_hash,
            "in_ibd": bool(b_info["initialblockdownload"]),
            "lag_limit": 1,
            "manifests": manifests or {},
            "names": names_view,
            "network": "regtest",
            "node_reachable": True,
            "now": now_ts,
            "tip_first_sight": tip_time,
            "tip_hash": tip_hash,
            "tip_header_time": tip_time,
            "tip_height": tip_h,
            "txindex": True,
            "txs": txs_view,
        }


# ============================================================================
# 3. Four Live End-to-End Regtest Traces
# ============================================================================

def run_trace_01(cl: RegtestCluster) -> dict[str, Any]:
    """Trace 01: Mail offline grant + live name_update + mempool P2WPKH seal revoke -> SEAL_SPENT -> GRANT_CLOSED."""
    alice_own = kp("t1-alice-own")
    alice_gr = kp("t1-alice-gr")
    alice_seal = kp("t1-alice-seal")
    host_own = kp("t1-host-own")
    host_rcpt = kp("t1-host-rcpt")
    agent_req = kp("t1-agent-req")

    alice_pol = {"kind": "key", "pk": alice_own["comp"]}
    host_pol = {"kind": "key", "pk": host_own["comp"]}
    seal_pol = {"kind": "key", "pk": alice_seal["comp"]}

    host_man = {
        "network": "regtest",
        "owner": "id/t1-mail-host",
        "seq": 1,
        "service": {
            "actions": ["mail/send"],
            "endpoint": "https://mail-t1.regtest.invalid/seallink",
            "receipt_key": host_rcpt["xonly"],
            "service_type": "mail",
        },
        "type": "seallink-manifest/1",
    }
    host_man_ca = sl.content_addr(host_man)

    names = cl.register_names_batch([
        {"name": "id/t1-alice", "owner_policy": alice_pol, "owner_kp": alice_own, "value_obj": {"link": {"grant": alice_gr["xonly"]}}, "rand_label": "t1-alice"},
        {"name": "id/t1-mail-host", "owner_policy": host_pol, "owner_kp": host_own, "value_obj": {"m": {"h": host_man_ca, "s": 1}}, "rand_label": "t1-host"},
    ])
    upd_txid, upd_raw = names["id/t1-alice"]["update_txid"], names["id/t1-alice"]["update_raw"]

    # Create Alice's P2WPKH seal UTXO (vout=0) + issuance funding output (vout=1)
    f = cl.split_funding(1, each_sat=3_000_000)[0]
    seal_spk, _ = sl.compile_script_policy(seal_pol)
    seal_txid, seal_raw = build_signed_tx(
        [f],
        [(SEAL_SAT, seal_spk), (SEAL_SAT, seal_spk), (f["value_sat"] - 2 * SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(seal_raw)
    recent_blk = cl.mine(1)[0]
    tip_h = cl.rpc(1, "getblockcount")

    grant_p = {
        "capabilities": [{"action": "mail/send", "quotas": [{"kind": "count", "max": "5", "resource": "mail/send", "unit": "calls", "window": "term"}], "target": "mailbox:work", "where": {}}],
        "executor": {"key": host_rcpt["xonly"], "name": "id/t1-mail-host"},
        "genesis": cl.genesis_hash,
        "issuer": {"name": "id/t1-alice", "owner_policy": alice_pol, "registration": names["id/t1-alice"]["registration"], "role_policy": {"m": 1, "pks": [alice_gr["xonly"]]}},
        "network": "regtest",
        "not_after_height": tip_h + 25,
        "not_before_height": tip_h - 1,
        "recent_block": recent_blk,
        "recipient": {"key": agent_req["xonly"], "mode": "key"},
        "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": seal_pol, "txid": seal_txid, "vout": 0}},
        "type": "seallink-grant/1",
    }
    grant_env = sl.sign_envelope(grant_p, [alice_gr["sk"]])
    gid = sl.object_id(grant_p)

    # Broadcast real 0x01 OP_RETURN issuance tx spending seal_txid:1 (Witness Profile W!)
    iss_prep = {"genesis": cl.genesis_hash, "grant_content_addr": sl.content_addr(grant_env), "grant_id": gid, "type": "seallink-issuance/1"}
    iss_digest_hex = sl.signing_digest(iss_prep).hex()
    iss_txid, iss_raw = build_signed_tx(
        [{"txid": seal_txid, "vout": 1, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": alice_seal}],
        [(0, op_return_spk(0x01, iss_digest_hex)), (SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(iss_raw)
    cl.mine(1)

    tracked = [names["id/t1-alice"]["first_txid"], upd_txid, names["id/t1-mail-host"]["first_txid"], seal_txid, iss_txid]
    ch1_dict = cl.extract_chain_view(
        tracked_txids=tracked,
        tracked_names=["id/t1-alice", "id/t1-mail-host"],
        tracked_block_hashes=[recent_blk],
        manifests={host_man_ca: host_man},
    )
    ch1 = sv.ChainView(ch1_dict)
    v = sv.Tier1Verifier(pinned_network="regtest", pinned_genesis=cl.genesis_hash, require_jsonschema=True)
    journal = sv.FencedJournal(sl.sha256(b"t1-regtest-j").hex())
    exec_cfg = {"key": host_rcpt["xonly"], "name": "id/t1-mail-host"}

    def _mk_inv(tag: str, now_s: int) -> dict[str, Any]:
        return sl.sign_envelope(
            {
                "action": "mail/send",
                "arguments": {"body_sha256": sl.sha256(tag.encode()).hex(), "size_bytes": "128", "subject": f"Regtest {tag}", "to": "bob@example.com"},
                "executor": exec_cfg,
                "exp": now_s + 600,
                "genesis": cl.genesis_hash,
                "iat": now_s - 10,
                "network": "regtest",
                "nonce": sl.sha256(f"t1-n-{tag}".encode()).hex(),
                "proof_path": [{"grant_id": gid, "issuance_txid": iss_txid}],
                "target": "mailbox:work",
                "type": "seallink-invocation/1",
            },
            [agent_req["sk"]],
        )

    res_admit = v.verify_invocation(_mk_inv("step1", ch1.now), {"grants": [grant_env], "manifests": {host_man_ca: host_man}}, ch1, journal, exec_cfg)
    assert res_admit.verdict == "ADMIT", f"Trace 01 step 1 failed: {res_admit}"

    # Broadcast Alice's P2WPKH seal revocation spend -> observe on peer B mempool BEFORE mining!
    rev_txid, rev_raw = build_signed_tx(
        [{"txid": seal_txid, "vout": 0, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": alice_seal}],
        [(SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(rev_txid_raw := rev_raw)
    seen_mempool_b = rev_txid in cl.rpc(1, "getrawmempool")
    assert seen_mempool_b

    ch2_dict = cl.extract_chain_view(
        tracked_txids=tracked + [rev_txid],
        tracked_names=["id/t1-alice", "id/t1-mail-host"],
        tracked_block_hashes=[recent_blk],
        manifests={host_man_ca: host_man},
    )
    assert ch2_dict["txs"][rev_txid]["in_mempool"] is True and ch2_dict["txs"][rev_txid]["confirmed_height"] is None
    res_mempool_revoke = v.verify_invocation(_mk_inv("step2", ch2_dict["now"]), {"grants": [grant_env], "manifests": {host_man_ca: host_man}}, sv.ChainView(ch2_dict), journal, exec_cfg)
    assert (res_mempool_revoke.verdict, res_mempool_revoke.refusal_code) == ("REFUSE", "SEAL_SPENT"), f"Trace 01 mempool revoke got {res_mempool_revoke}"

    cl.mine(1)
    ch3_dict = cl.extract_chain_view(
        tracked_txids=tracked + [rev_txid],
        tracked_names=["id/t1-alice", "id/t1-mail-host"],
        tracked_block_hashes=[recent_blk],
        manifests={host_man_ca: host_man},
    )
    res_closed = v.verify_invocation(_mk_inv("step3", ch3_dict["now"]), {"grants": [grant_env], "manifests": {host_man_ca: host_man}}, sv.ChainView(ch3_dict), journal, exec_cfg)
    assert (res_closed.verdict, res_closed.refusal_code) == ("REFUSE", "GRANT_CLOSED"), f"Trace 01 post-closure got {res_closed}"

    return {
        "name_new_alice_txid": names["id/t1-alice"]["new_txid"],
        "name_firstupdate_alice_txid": names["id/t1-alice"]["first_txid"],
        "name_update_alice_txid": upd_txid,
        "name_update_alice_raw_hex": upd_raw,
        "seal_txid": seal_txid,
        "seal_raw_hex": seal_raw,
        "issuance_0x01_txid": iss_txid,
        "issuance_0x01_raw_hex": iss_raw,
        "revoke_txid": rev_txid,
        "revoke_raw_hex": rev_txid_raw,
        "revoke_seen_in_peer_b_mempool_before_mining": seen_mempool_b,
        "verdicts": {
            "initial_invocation": {"verdict": res_admit.verdict, "outcome": res_admit.outcome},
            "mempool_revocation": {"verdict": res_mempool_revoke.verdict, "refusal_code": res_mempool_revoke.refusal_code},
            "subsequent_invocation": {"verdict": res_closed.verdict, "refusal_code": res_closed.refusal_code},
        },
    }


def run_trace_02(cl: RegtestCluster) -> dict[str, Any]:
    """Trace 02: Origin (0x09+0x0c), P2WSH 2-of-3 multisig namepsbt update, 0x12 active slot,
    halt spend, 0x0d guardian_slot_pending CSV (non-BIP68-final negative control + post-CSV 0x0e),
    0x0f roster transition, 0x10 RECOVERY_CANCEL, and live Tier1Verifier.verify_assent!"""
    reg_own = kp("t2-reg-own")
    reg_cred = kp("t2-reg-cred")
    disp = kp("t2-disp")
    arb = kp("t2-arb")
    chal = kp("t2-chal")
    bind_seal = kp("t2-bind")
    stat_cap = kp("t2-scap")
    stat_end = kp("t2-send")
    rec_disp = kp("t2-rdisp")
    rec_arb = kp("t2-rarb")
    g1_own = kp("t2-g1-own")
    g1_gr = kp("t2-g1-gr")
    g1_seal = kp("t2-g1-seal")
    g2_own = kp("t2-g2-own")
    g2_gr = kp("t2-g2-gr")
    g2_seal = kp("t2-g2-seal")
    ward_gr = kp("t2-ward-gr")
    # 3 distinct keys for REAL P2WSH 2-of-3 multisig ward name ownership!
    wm1, wm2, wm3 = kp("t2-wm1"), kp("t2-wm2"), kp("t2-wm3")
    ward_ms_pol = {"kind": "multisig", "m": 2, "pks": sorted([wm1["comp"], wm2["comp"], wm3["comp"]])}

    reg_pol = {"kind": "key", "pk": reg_own["comp"]}
    g1_pol = {"kind": "key", "pk": g1_own["comp"]}
    g2_pol = {"kind": "key", "pk": g2_own["comp"]}

    vac_pol = {"kind": "branch", "template": "both_of_2", "keys": {"a": disp["comp"], "b": arb["comp"]}}
    stat_pol = {"kind": "branch", "template": "either_of_2", "keys": {"a": stat_cap["comp"], "b": stat_end["comp"]}}
    rec_pol = {"kind": "branch", "template": "both_of_2", "keys": {"a": rec_disp["comp"], "b": rec_arb["comp"]}}
    bind_pol = {"kind": "key", "pk": bind_seal["comp"]}
    g1_act_pol = {"kind": "branch", "template": "either_of_2", "keys": {"a": disp["comp"], "b": g1_seal["comp"]}}
    g2_act_pol = {"kind": "branch", "template": "either_of_2", "keys": {"a": disp["comp"], "b": g2_seal["comp"]}}
    delay_blocks = 3
    pend_pol = {
        "kind": "branch",
        "template": "guardian_slot_pending",
        "delay_blocks": delay_blocks,
        "keys": {"disposer": disp["comp"], "challenger": chal["comp"], "guardian": g2_seal["comp"]},
    }

    vac_spk, vac_ws = sl.compile_script_policy(vac_pol)
    stat_spk, _ = sl.compile_script_policy(stat_pol)
    rec_spk, rec_ws = sl.compile_script_policy(rec_pol)
    bind_spk, _ = sl.compile_script_policy(bind_pol)
    g1_act_spk, g1_act_ws = sl.compile_script_policy(g1_act_pol)
    g2_act_spk, _ = sl.compile_script_policy(g2_act_pol)
    pend_spk, pend_ws = sl.compile_script_policy(pend_pol)
    assert vac_ws and rec_ws and g1_act_ws and pend_ws

    # Register all 4 identities on-chain (id/t2-child-leo directly with P2WSH 2-of-3 multisig!)
    names = cl.register_names_batch([
        {"name": "id/t2-civil-registry", "owner_policy": reg_pol, "owner_kp": reg_own, "value_obj": {"link": {"cred": reg_cred["xonly"]}}, "rand_label": "t2-reg"},
        {"name": "id/t2-parent-a", "owner_policy": g1_pol, "owner_kp": g1_own, "value_obj": {"link": {"grant": g1_gr["xonly"]}}, "rand_label": "t2-g1"},
        {"name": "id/t2-carol", "owner_policy": g2_pol, "owner_kp": g2_own, "value_obj": {"link": {"grant": g2_gr["xonly"]}}, "rand_label": "t2-g2"},
        {"name": "id/t2-child-leo", "owner_policy": ward_ms_pol, "value_obj": {"link": {"grant": ward_gr["xonly"]}}, "rand_label": "t2-ward"},
    ])

    # Pre-fund origin seals in a single confirmed setup tx (binding=0, status=1, recovery=2, roster=3, slot1_vacant=4, extra_fee=5..9)
    f_orig = cl.split_funding(6, each_sat=5_000_000)
    seals_txid, seals_raw = build_signed_tx(
        [f_orig[0]],
        [
            (SEAL_SAT, bind_spk),
            (SEAL_SAT, stat_spk),
            (SEAL_SAT, rec_spk),
            (SEAL_SAT, vac_spk),
            (SEAL_SAT, vac_spk),
            (f_orig[0]["value_sat"] - 5 * SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(seals_raw)
    cl.mine(1)

    tip_time = int(cl.rpc(1, "getblockheader", cl.rpc(1, "getbestblockhash"))["time"])
    maj_unix = tip_time + 100_000_000
    maj_salt = sl.sha256(b"t2-maj-salt").hex()
    g1_salt = sl.sha256(b"t2-g1-salt").hex()
    g1_pin = {"name": "id/t2-parent-a", "owner_policy": g1_pol, "registration": names["id/t2-parent-a"]["registration"]}
    g2_pin = {"name": "id/t2-carol", "owner_policy": g2_pol, "registration": names["id/t2-carol"]["registration"]}

    origin_p = {
        "binding_seal": {"script_policy": bind_pol, "txid": seals_txid, "vout": 0},
        "claims": {
            "intended_name": "id/t2-child-leo",
            "intended_owner_policy": ward_ms_pol,
            "majority_commitment": sl.clause_commit(maj_salt, {"majority_unix": maj_unix}),
        },
        "genesis": cl.genesis_hash,
        "guardian_policy": {
            "appointment_delay_blocks": delay_blocks,
            "arbiter_pk": arb["comp"],
            "challenger_pk": chal["comp"],
            "disposer_pk": disp["comp"],
            "quorums": {
                "contract_assent": {"den": 1, "min": 1, "num": 1},
                "custody_change": {"den": 1, "min": 1, "num": 1},
                "effect_grant": {"den": 1, "min": 1, "num": 1},
                "routine_read": {"den": 1, "min": 1, "num": 1},
            },
            "revision": 1,
            "revision_size": 1,
            "roster_seal": {"script_policy": vac_pol, "txid": seals_txid, "vout": 3},
            "slots": [
                {
                    "initial_guardian_commitment": sl.clause_commit(g1_salt, g1_pin),
                    "slot": 1,
                    "vacant_utxo": {"txid": seals_txid, "vout": 4},
                }
            ],
        },
        "issuer": {"name": "id/t2-civil-registry", "owner_policy": reg_pol, "registration": names["id/t2-civil-registry"]["registration"], "role_policy": {"m": 1, "pks": [reg_cred["xonly"]]}},
        "name_recovery": {
            "arbiter_pk": rec_arb["comp"],
            "delay_blocks": 144,
            "disposer_pk": rec_disp["comp"],
            "mode": "dual_party_delayed",
            "recovery_seal": {"script_policy": rec_pol, "txid": seals_txid, "vout": 2},
        },
        "network": "regtest",
        "origin_class": "person",
        "request_sha256": sl.sha256(b"t2-origin-req").hex(),
        "status_seal": {"script_policy": stat_pol, "txid": seals_txid, "vout": 1},
        "subject_initial_key": ward_gr["xonly"],
        "type": "seallink-origin/1",
    }
    origin_env = sl.sign_envelope(origin_p, [reg_cred["sk"]])
    origin_id = sl.object_id(origin_p)

    # Anchor 0x09 Origin on-chain!
    anc09_txid, anc09_raw = build_signed_tx(
        [f_orig[1]],
        [(0, op_return_spk(0x09, sl.content_addr(origin_env))), (f_orig[1]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(anc09_raw)
    cl.mine(1)

    # Update id/t2-child-leo (P2WSH 2-of-3 multisig!) via REAL `createpsbt` + `namepsbt` + BIP-143 P2WSH 2-of-3 witness to bind origin_id!
    p2wsh_psbt_proof = cl.update_name_p2wsh_multisig_via_namepsbt(
        names["id/t2-child-leo"],
        "id/t2-child-leo",
        [wm1, wm3],  # 2-of-3 keys!
        {"link": {"grant": ward_gr["xonly"], "origin": origin_id}},
    )

    # Anchor 0x0c Name Binding strictly AFTER 0x09 height, spending origin.binding_seal!
    binding = {
        "genesis": cl.genesis_hash,
        "name": "id/t2-child-leo",
        "network": "regtest",
        "origin_id": origin_id,
        "owner_policy": ward_ms_pol,
        "registration": names["id/t2-child-leo"]["registration"],
        "seq": 1,
        "type": "seallink-name-binding/1",
    }
    anc0c_txid, anc0c_raw = build_signed_tx(
        [
            {"txid": seals_txid, "vout": 0, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": bind_seal},
            f_orig[2],
        ],
        [(0, op_return_spk(0x0C, sl.object_id(binding))), (f_orig[2]["value_sat"] + SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(anc0c_raw)
    cl.mine(1)

    # 0x12 Initial activation of slot 1 (spending both_of_2 P2WSH vacant_slot_seal -> either_of_2 active seal!)
    g1_rec_p = {
        "activation_mode": "initial",
        "active_policy": g1_act_pol,
        "active_vout": 0,
        "genesis": cl.genesis_hash,
        "guardian": g1_pin,
        "issuer": origin_p["issuer"],
        "network": "regtest",
        "origin_id": origin_id,
        "prev_outpoint": {"txid": seals_txid, "vout": 4},
        "revision": 1,
        "slot": 1,
        "term": {"mode": "indefinite"},
        "type": "seallink-guardian/1",
    }
    g1_rec = sl.sign_envelope(g1_rec_p, [reg_cred["sk"]])
    g1_assent = sl.sign_envelope(
        {
            "expires_at": tip_time + 200_000,
            "genesis": cl.genesis_hash,
            "issued_at": tip_time,
            "network": "regtest",
            "nonce": sl.sha256(b"t2-g1-assent").hex(),
            "party_id": "guardian-slot-1",
            "party_name": "id/t2-parent-a",
            "party_role": "guardian",
            "target_id": sl.object_id(g1_rec_p),
            "target_type": "seallink-guardian/1",
            "type": "seallink-assent/1",
        },
        [g1_gr["sk"]],
    )
    init12_txid, init12_raw = build_signed_tx(
        [
            {"txid": seals_txid, "vout": 4, "value_sat": SEAL_SAT, "kind": "p2wsh_multisig", "witness_script": vac_ws, "signers": [disp, arb]},
            f_orig[3],
        ],
        [
            (SEAL_SAT, g1_act_spk),
            (0, op_return_spk(0x12, sl.content_addr(g1_rec))),
            (f_orig[3]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(init12_raw)
    cl.mine(1)

    # Halt spend of slot 1's active either_of_2 seal (disposer key) -> creates new vacant slot 1 seal at vout=0!
    halt_txid, halt_raw = build_signed_tx(
        [
            {"txid": init12_txid, "vout": 0, "value_sat": SEAL_SAT, "kind": "p2wsh_multisig", "witness_script": g1_act_ws, "signers": [disp]},
            f_orig[4],
        ],
        [(SEAL_SAT, vac_spk), (f_orig[4]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(halt_raw)
    cl.mine(1)

    # 0x0f Roster transition to revision 2 creating a fresh vacant slot 1 seal (vout=1) & next roster seal (vout=0)
    f_more = cl.split_funding(6, each_sat=2_000_000)
    roster2_p = {
        "arbiter_pk": arb["comp"],
        "challenger_pk": chal["comp"],
        "disposer_pk": disp["comp"],
        "effective_delay_blocks": 1,
        "genesis": cl.genesis_hash,
        "issuer": origin_p["issuer"],
        "network": "regtest",
        "next_roster_policy": vac_pol,
        "next_roster_vout": 0,
        "origin_id": origin_id,
        "prev_revision": 1,
        "prev_roster_outpoint": {"txid": seals_txid, "vout": 3},
        "quorums": origin_p["guardian_policy"]["quorums"],
        "revision": 2,
        "revision_size": 1,
        "slots": [{"action": "new_vacant", "new_vacant_policy": vac_pol, "new_vacant_vout": 1, "slot": 1}],
        "type": "seallink-guardian-roster/1",
    }
    roster2 = sl.sign_envelope(roster2_p, [reg_cred["sk"]])
    rost0f_txid, rost0f_raw = build_signed_tx(
        [
            {"txid": seals_txid, "vout": 3, "value_sat": SEAL_SAT, "kind": "p2wsh_multisig", "witness_script": vac_ws, "signers": [disp, arb]},
            f_more[0],
        ],
        [
            (SEAL_SAT, vac_spk),
            (SEAL_SAT, vac_spk),
            (0, op_return_spk(0x0F, sl.content_addr(roster2))),
            (f_more[0]["value_sat"] - SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(rost0f_raw)
    cl.mine(1)

    # 0x0d Pending appointment of Carol on rev 2 slot 1 -> creates REAL guardian_slot_pending CSV P2WSH output!
    g2_rec_p = {
        "activation_mode": "appointed",
        "active_policy": g2_act_pol,
        "effective_delay_blocks": delay_blocks,
        "genesis": cl.genesis_hash,
        "guardian": g2_pin,
        "issuer": origin_p["issuer"],
        "network": "regtest",
        "origin_id": origin_id,
        "pending_policy": pend_pol,
        "pending_vout": 0,
        "prev_outpoint": {"txid": rost0f_txid, "vout": 1},
        "revision": 2,
        "slot": 1,
        "term": {"mode": "indefinite"},
        "type": "seallink-guardian/1",
    }
    g2_rec = sl.sign_envelope(g2_rec_p, [reg_cred["sk"]])
    g2_assent = sl.sign_envelope(
        {
            "expires_at": tip_time + 200_000,
            "genesis": cl.genesis_hash,
            "issued_at": tip_time,
            "network": "regtest",
            "nonce": sl.sha256(b"t2-g2-assent").hex(),
            "party_id": "guardian-slot-1-rev2",
            "party_name": "id/t2-carol",
            "party_role": "guardian",
            "target_id": sl.object_id(g2_rec_p),
            "target_type": "seallink-guardian/1",
            "type": "seallink-assent/1",
        },
        [g2_gr["sk"]],
    )
    pend0d_txid, pend0d_raw = build_signed_tx(
        [
            {"txid": rost0f_txid, "vout": 1, "value_sat": SEAL_SAT, "kind": "p2wsh_multisig", "witness_script": vac_ws, "signers": [disp, arb]},
            f_more[1],
        ],
        [
            (SEAL_SAT, pend_spk),
            (0, op_return_spk(0x0D, sl.content_addr(g2_rec))),
            (f_more[1]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(pend0d_raw)
    cl.mine(1)  # Pending depth = 1 (< delay_blocks = 3!)

    # Build 0x0e activation spend of guardian_slot_pending CSV branch (witness = [sig_g2, b"", b"", pend_ws], sequence = delay_blocks!)
    act0e_txid, act0e_raw = build_signed_tx(
        [
            {
                "txid": pend0d_txid,
                "vout": 0,
                "value_sat": SEAL_SAT,
                "sequence": delay_blocks,
                "kind": "p2wsh_single_key_branch",
                "witness_script": pend_ws,
                "signer": g2_seal,
                "selectors": [b"", b""],  # OP_ELSE -> OP_ELSE -> CSV -> guardian CHECKSIG!
            },
            f_more[2],
        ],
        [
            (SEAL_SAT, g2_act_spk),
            (0, op_return_spk(0x0E, sl.object_id(g2_rec_p))),
            (f_more[2]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
        version=2,
    )

    # NEGATIVE CONTROL ON LIVE nc28.0: premature CSV spend MUST fail BIP-68 (`non-BIP68-final`)!
    premature_check = cl.rpc(0, "testmempoolaccept", [act0e_raw])[0]
    assert not premature_check["allowed"] and "non-BIP68-final" in premature_check.get("reject-reason", ""), f"Expected non-BIP68-final, got {premature_check}"

    # Advance (delay_blocks - 1) more blocks so relative depth reaches delay_blocks, then broadcast SAME 0x0e tx!
    cl.mine(delay_blocks - 1)
    cl.broadcast_and_wait_peer(act0e_raw)
    cl.mine(1)

    # Execute live 0x0c recovery attempt spending recovery_seal (both_of_2), THEN cancel it via P2WSH 2-of-3 OP_NAME_UPDATE carrying 0x10 RECOVERY_CANCEL!
    cand_b2 = {
        "genesis": cl.genesis_hash,
        "name": "id/t2-child-leo-recovered",
        "network": "regtest",
        "next_recovery_policy": rec_pol,
        "next_recovery_vout": 0,
        "origin_id": origin_id,
        "owner_policy": ward_ms_pol,
        "registration": {"txid": sl.sha256(b"t2-cand-reg").hex(), "vout": 0},
        "seq": 2,
        "supersedes_binding_id": sl.object_id(binding),
        "type": "seallink-name-binding/1",
    }
    cand_b2_id = sl.object_id(cand_b2)
    rec0c_txid, rec0c_raw = build_signed_tx(
        [
            {"txid": seals_txid, "vout": 2, "value_sat": SEAL_SAT, "kind": "p2wsh_multisig", "witness_script": rec_ws, "signers": [rec_disp, rec_arb]},
            f_more[3],
        ],
        [
            (SEAL_SAT, rec_spk),
            (0, op_return_spk(0x0C, cand_b2_id)),
            (f_more[3]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(rec0c_raw)
    cl.mine(1)

    # Owner-authored P2WSH 2-of-3 OP_NAME_UPDATE on id/t2-child-leo carrying 0x10 RECOVERY_CANCEL!
    ward_spk, ward_ws = sl.compile_script_policy(ward_ms_pol)
    assert ward_ws is not None
    cancel_val_b = sl.jcs_encode({"link": {"grant": ward_gr["xonly"], "origin": origin_id}})
    cancel_name_spk = sl.encode_name_output("NAME_UPDATE", ward_spk, name=b"id/t2-child-leo", value=cancel_val_b)
    rec10_txid, rec10_raw = build_signed_tx(
        [
            {
                "txid": names["id/t2-child-leo"]["current_txid"],
                "vout": names["id/t2-child-leo"]["current_vout"],
                "value_sat": MIN_NAME_SAT,
                "kind": "p2wsh_multisig",
                "witness_script": ward_ws,
                "signers": [wm2, wm3],  # Another 2-of-3 pair!
            },
            f_more[4],
        ],
        [
            (MIN_NAME_SAT, cancel_name_spk),
            (0, op_return_spk(0x10, cand_b2_id)),
            (f_more[4]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
        version=NAMECOIN_TX_VERSION,
    )
    cl.broadcast_and_wait_peer(rec10_raw)
    cl.mine(1)
    names["id/t2-child-leo"]["current_txid"] = rec10_txid
    names["id/t2-child-leo"]["current_vout"] = 0
    cl.name_history_entries["id/t2-child-leo"].append(
        {"txid": rec10_txid, "vout": 0, "op": "NAME_UPDATE", "owner_policy": ward_ms_pol, "prev_owner_policy": ward_ms_pol}
    )

    # Extract LIVE ChainView from peer Node B and run Tier1Verifier.verify_assent on all 3 cases!
    tracked = [seals_txid, anc09_txid, anc0c_txid, init12_txid, halt_txid, rost0f_txid, pend0d_txid, act0e_txid, rec0c_txid, rec10_txid]
    ch_dict = cl.extract_chain_view(
        tracked_txids=tracked,
        tracked_names=["id/t2-civil-registry", "id/t2-parent-a", "id/t2-carol", "id/t2-child-leo"],
    )
    ch = sv.ChainView(ch_dict)
    v = sv.Tier1Verifier(
        pinned_network="regtest",
        pinned_genesis=cl.genesis_hash,
        trusted_origin_issuers={"id/t2-civil-registry"},
        require_jsonschema=True,
    )
    origin_bundle = {
        "guardian_assents": [g1_assent, g2_assent],
        "guardian_records": [g1_rec, g2_rec],
        "initial_guardian_disclosures": {"1": {"salt_hex": g1_salt}},
        "majority_salt_hex": maj_salt,
        "name_binding": binding,
        "name_binding_txid": anc0c_txid,
        "opened_majority_unix": maj_unix,
        "origin": origin_env,
        "origin_anchor_txid": anc09_txid,
        "recovery_bindings": [cand_b2],
        "roster_records": [roster2],
    }
    wstate_chk, werr_chk = v.verify_origin_and_status(origin_bundle, ch)
    assert werr_chk is None and wstate_chk is not None, f"Trace 02 origin status failed: {werr_chk}"
    assert wstate_chk["recovery_events"] and wstate_chk["recovery_events"][0]["outcome"] == "cancelled_restored"
    sch_k = kp("t2-school")
    contract = {
        "clause_commitments": [sl.clause_commit(sl.sha256(b"t2-c0").hex(), {"text": "Enrollment"})],
        "contract_salt": sl.sha256(b"t2-csalt").hex(),
        "genesis": cl.genesis_hash,
        "network": "regtest",
        "parties": [
            {"name_pin": {"name": "id/t2-child-leo", "owner_policy": ward_ms_pol, "registration": names["id/t2-child-leo"]["registration"]}, "party_id": "student-1", "role": "student_ward", "ward_origin_id": origin_id},
            {"party_id": "school-1", "role": "school", "signing_policy": {"m": 1, "pks": [sch_k["xonly"]]}},
        ],
        "profile": "school-enrollment-v1",
        "type": "seallink-contract/1",
        "window": {"not_after_height": ch.tip_height + 20, "not_before_height": ch.tip_height - 10},
    }
    cid = sl.object_id(contract)
    base_ap = {
        "expires_at": ch.now + 100_000,
        "genesis": cl.genesis_hash,
        "issued_at": ch.now - 10,
        "network": "regtest",
        "party_id": "student-1",
        "party_name": "id/t2-child-leo",
        "party_role": "student_ward",
        "target_id": cid,
        "target_type": "seallink-contract/1",
        "type": "seallink-assent/1",
    }
    assent_ward_self = sl.sign_envelope({**base_ap, "nonce": sl.sha256(b"t2-a-self").hex()}, [ward_gr["sk"]])
    assent_old_g1 = sl.sign_guardian_envelope(
        {**base_ap, "guardian_context": {"event_class": "contract_assent", "origin_id": origin_id, "revision": 2, "ward_name": "id/t2-child-leo"}, "nonce": sl.sha256(b"t2-a-old").hex()},
        [{"slot": 1, "revision": 2, "guardian_name": "id/t2-parent-a", "signers": [g1_gr["sk"]]}],
    )
    assent_new_g2 = sl.sign_guardian_envelope(
        {**base_ap, "guardian_context": {"event_class": "contract_assent", "origin_id": origin_id, "revision": 2, "ward_name": "id/t2-child-leo"}, "nonce": sl.sha256(b"t2-a-new").hex()},
        [{"slot": 1, "revision": 2, "guardian_name": "id/t2-carol", "signers": [g2_gr["sk"]]}],
    )

    r_self = v.verify_assent(assent_ward_self, contract, origin_bundle, ch)
    r_old = v.verify_assent(assent_old_g1, contract, origin_bundle, ch)
    r_new = v.verify_assent(assent_new_g2, contract, origin_bundle, ch)
    assert (r_self.verdict, r_self.refusal_code) == ("REFUSE", "WARD_AUTONOMOUS_FORBIDDEN"), f"Trace 02 self got {r_self}"
    assert (r_old.verdict, r_old.refusal_code) == ("REFUSE", "GUARDIAN_INACTIVE"), f"Trace 02 old got {r_old}"
    assert r_new.verdict == "ADMIT", f"Trace 02 new Carol got {r_new}"

    return {
        "p2wsh_2of3_namepsbt_update": p2wsh_psbt_proof,
        "origin_seals_txid": seals_txid,
        "origin_0x09_txid": anc09_txid,
        "origin_0x09_raw_hex": anc09_raw,
        "binding_0x0c_txid": anc0c_txid,
        "binding_0x0c_raw_hex": anc0c_raw,
        "init_0x12_txid": init12_txid,
        "init_0x12_raw_hex": init12_raw,
        "halt_either_of_2_txid": halt_txid,
        "halt_either_of_2_raw_hex": halt_raw,
        "roster_0x0f_txid": rost0f_txid,
        "roster_0x0f_raw_hex": rost0f_raw,
        "pending_0x0d_csv_txid": pend0d_txid,
        "pending_0x0d_csv_raw_hex": pend0d_raw,
        "pending_csv_witness_script_hex": pend_ws.hex(),
        "premature_csv_spend_rejected_by_nc28": not premature_check["allowed"],
        "premature_csv_reject_reason": premature_check.get("reject-reason"),
        "activate_0x0e_csv_txid": act0e_txid,
        "activate_0x0e_csv_raw_hex": act0e_raw,
        "recovery_attempt_0x0c_txid": rec0c_txid,
        "recovery_attempt_0x0c_raw_hex": rec0c_raw,
        "recovery_cancel_0x10_txid": rec10_txid,
        "recovery_cancel_0x10_raw_hex": rec10_raw,
        "recovery_cancelled_restored_verified": True,
        "verdicts": {
            "ward_self_assent": {"verdict": r_self.verdict, "refusal_code": r_self.refusal_code},
            "halted_guardian_assent": {"verdict": r_old.verdict, "refusal_code": r_old.refusal_code},
            "csv_activated_successor_assent": {"verdict": r_new.verdict, "outcome": r_new.outcome},
        },
    }


def run_trace_03(cl: RegtestCluster) -> dict[str, Any]:
    """Trace 03: single_use_1_of_2 P2WSH (branch-0 grantee 0x11 vs branch-1 issuer revoke)
    + TRUC v3 zero-fee P2A (0x51024e73) CPFP parent revocation package via submitpackage -> peer B mempool!"""
    alice_own = kp("t3-alice-own")
    alice_gr = kp("t3-alice-gr")
    alice_p_seal = kp("t3-alice-pseal")
    host_own = kp("t3-host-own")
    host_rcpt = kp("t3-host-rcpt")
    su_iss = kp("t3-su-iss")
    su_gr1 = kp("t3-su-gr1")
    su_gr2 = kp("t3-su-gr2")
    agent_req = kp("t3-agent-req")

    alice_pol = {"kind": "key", "pk": alice_own["comp"]}
    host_pol = {"kind": "key", "pk": host_own["comp"]}
    pseal_pol = {"kind": "key", "pk": alice_p_seal["comp"]}
    su1_pol = {"kind": "branch", "template": "single_use_1_of_2", "keys": {"issuer": su_iss["comp"], "grantee": su_gr1["comp"]}}
    su2_pol = {"kind": "branch", "template": "single_use_1_of_2", "keys": {"issuer": su_iss["comp"], "grantee": su_gr2["comp"]}}

    pseal_spk, _ = sl.compile_script_policy(pseal_pol)
    su1_spk, su1_ws = sl.compile_script_policy(su1_pol)
    su2_spk, su2_ws = sl.compile_script_policy(su2_pol)
    assert su1_ws and su2_ws

    host_man = {
        "network": "regtest",
        "owner": "id/t3-mail-host",
        "seq": 1,
        "service": {
            "actions": ["mail/send"],
            "endpoint": "https://mail-t3.regtest.invalid/seallink",
            "receipt_key": host_rcpt["xonly"],
            "service_type": "mail",
        },
        "type": "seallink-manifest/1",
    }
    host_man_ca = sl.content_addr(host_man)
    names = cl.register_names_batch([
        {"name": "id/t3-alice", "owner_policy": alice_pol, "owner_kp": alice_own, "value_obj": {"link": {"grant": alice_gr["xonly"]}}, "rand_label": "t3-alice"},
        {"name": "id/t3-mail-host", "owner_policy": host_pol, "owner_kp": host_own, "value_obj": {"m": {"h": host_man_ca, "s": 1}}, "rand_label": "t3-host"},
    ])

    f = cl.split_funding(6, each_sat=5_000_000)
    seals_txid, seals_raw = build_signed_tx(
        [f[0]],
        [
            (1_500_000, pseal_spk),  # vout 0: revocable seal for TRUC v3 P2A revocation test!
            (SEAL_SAT, su1_spk),     # vout 1: single_use_1_of_2 #1 (grantee branch 0 + 0x11)
            (SEAL_SAT, su2_spk),     # vout 2: single_use_1_of_2 #2 (issuer branch 1 revoke)
            (SEAL_SAT, pseal_spk),   # vout 3: issuance W input
            (f[0]["value_sat"] - 1_500_000 - 3 * SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(seals_raw)
    recent_blk = cl.mine(1)[0]
    tip_h = cl.rpc(1, "getblockcount")
    tip_time = int(cl.rpc(1, "getblockheader", recent_blk)["time"])

    exec_cfg = {"key": host_rcpt["xonly"], "name": "id/t3-mail-host"}

    def _mk_su_grant(vout: int, pol: dict[str, Any], tag: str) -> tuple[dict[str, Any], str]:
        gp = {
            "capabilities": [{"action": "mail/send", "target": f"mailbox:{tag}", "where": {}}],
            "executor": exec_cfg,
            "genesis": cl.genesis_hash,
            "issuer": {"name": "id/t3-alice", "owner_policy": alice_pol, "registration": names["id/t3-alice"]["registration"], "role_policy": {"m": 1, "pks": [alice_gr["xonly"]]}},
            "network": "regtest",
            "not_after_height": tip_h + 25,
            "not_before_height": tip_h - 1,
            "recent_block": recent_blk,
            "recipient": {"key": agent_req["xonly"], "mode": "key"},
            "revocation": {"construction": "W", "kind": "single_use", "mode": "seal", "seal": {"script_policy": pol, "txid": seals_txid, "vout": vout}},
            "type": "seallink-grant/1",
        }
        return sl.sign_envelope(gp, [alice_gr["sk"]]), sl.object_id(gp)

    g1_env, g1_id = _mk_su_grant(1, su1_pol, "su1")
    g2_env, g2_id = _mk_su_grant(2, su2_pol, "su2")
    # Also create a revocable grant anchored on seals_txid:0 to prove TRUC v3 P2A revocation!
    gp_rev = {
        "capabilities": [{"action": "mail/send", "target": "mailbox:p2a", "where": {}}],
        "executor": exec_cfg,
        "genesis": cl.genesis_hash,
        "issuer": {"name": "id/t3-alice", "owner_policy": alice_pol, "registration": names["id/t3-alice"]["registration"], "role_policy": {"m": 1, "pks": [alice_gr["xonly"]]}},
        "network": "regtest",
        "not_after_height": tip_h + 25,
        "not_before_height": tip_h - 1,
        "recent_block": recent_blk,
        "recipient": {"key": agent_req["xonly"], "mode": "key"},
        "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": pseal_pol, "txid": seals_txid, "vout": 0}},
        "type": "seallink-grant/1",
    }
    grev_env = sl.sign_envelope(gp_rev, [alice_gr["sk"]])
    grev_id = sl.object_id(gp_rev)

    # Issue all 3 grants via real 0x01 OP_RETURN transactions
    def _issue(g_env: dict[str, Any], gid: str, fund_u: dict[str, Any]) -> tuple[str, str]:
        d_hex = sl.signing_digest({"genesis": cl.genesis_hash, "grant_content_addr": sl.content_addr(g_env), "grant_id": gid, "type": "seallink-issuance/1"}).hex()
        txid, raw_h = build_signed_tx([fund_u], [(0, op_return_spk(0x01, d_hex)), (fund_u["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"])])
        cl.broadcast_and_wait_peer(raw_h)
        return txid, raw_h

    iss1_txid, iss1_raw = _issue(g1_env, g1_id, f[1])
    iss2_txid, iss2_raw = _issue(g2_env, g2_id, f[2])
    issr_txid, issr_raw = _issue(grev_env, grev_id, f[3])
    cl.mine(1)

    # Child #1: Grantee spends single_use_1_of_2 via BRANCH 0 (selector=b"") + 0x11 OP_RETURN committing to inv1 content_addr!
    inv1_env = sl.sign_envelope(
        {
            "action": "mail/send",
            "arguments": {"body_sha256": sl.sha256(b"su1-body").hex(), "size_bytes": "128", "subject": "SU1", "to": "su1@example.com"},
            "executor": exec_cfg,
            "exp": tip_time + 1200,
            "genesis": cl.genesis_hash,
            "iat": tip_time - 10,
            "network": "regtest",
            "nonce": sl.sha256(b"t3-su1-n").hex(),
            "proof_path": [{"grant_id": g1_id, "issuance_txid": iss1_txid}],
            "target": "mailbox:su1",
            "type": "seallink-invocation/1",
        },
        [agent_req["sk"]],
    )
    use1_txid, use1_raw = build_signed_tx(
        [
            {"txid": seals_txid, "vout": 1, "value_sat": SEAL_SAT, "kind": "p2wsh_single_key_branch", "witness_script": su1_ws, "signer": su_gr1, "selectors": [b""]},
            f[4],
        ],
        [
            (0, op_return_spk(0x11, sl.content_addr(inv1_env))),
            (f[4]["value_sat"] + SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(use1_raw)

    # Child #2: Issuer revokes single_use_1_of_2 via BRANCH 1 (selector=b"\x01", NO 0x11)!
    rev2_txid, rev2_raw = build_signed_tx(
        [{"txid": seals_txid, "vout": 2, "value_sat": SEAL_SAT, "kind": "p2wsh_single_key_branch", "witness_script": su2_ws, "signer": su_iss, "selectors": [b"\x01"]}],
        [(SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(rev2_raw)
    cl.mine(1)

    # TRUC v3 zero-fee parent revocation of seals_txid:0 with P2A (0x51024e73) + v3 child CPFP via submitpackage!
    p2a_parent_txid, p2a_parent_raw = build_signed_tx(
        [{"txid": seals_txid, "vout": 0, "value_sat": 1_500_000, "kind": "p2wpkh", "signer": alice_p_seal}],
        [(1_400_000, cl.fund_key["p2wpkh_spk"]), (100_000, sl.P2A_SCRIPTPUBKEY)],  # 0 fee!
        version=3,
    )
    p2a_child_txid, p2a_child_raw = build_signed_tx(
        [
            {"txid": p2a_parent_txid, "vout": 1, "value_sat": 100_000, "kind": "p2a"},
            f[5],
        ],
        [(f[5]["value_sat"] + 100_000 - 500_000, cl.fund_key["p2wpkh_spk"])],  # 500,000 sat CPFP fee!
        version=3,
    )
    alone_res = cl.rpc(0, "testmempoolaccept", [p2a_parent_raw])[0]
    assert not alone_res["allowed"] and alone_res.get("reject-reason") == "min relay fee not met", f"Expected min relay fee not met, got {alone_res}"

    pkg_res = cl.rpc(0, "submitpackage", [p2a_parent_raw, p2a_child_raw])
    assert pkg_res["package_msg"] == "success", f"submitpackage failed: {pkg_res}"
    peer_saw_p2a = cl.until(lambda: {p2a_parent_txid, p2a_child_txid} <= set(cl.rpc(1, "getrawmempool")), limit=30.0)
    assert peer_saw_p2a, "Peer B did not observe TRUC v3 P2A revocation package in mempool before mining!"

    # Extract LIVE ChainView from peer Node B (while TRUC v3 P2A revocation is in peer B's mempool!)
    tracked = [seals_txid, iss1_txid, iss2_txid, issr_txid, use1_txid, rev2_txid, p2a_parent_txid, p2a_child_txid]
    ch_dict = cl.extract_chain_view(
        tracked_txids=tracked,
        tracked_names=["id/t3-alice", "id/t3-mail-host"],
        tracked_block_hashes=[recent_blk],
        manifests={host_man_ca: host_man},
    )
    ch = sv.ChainView(ch_dict)
    v = sv.Tier1Verifier(pinned_network="regtest", pinned_genesis=cl.genesis_hash, require_jsonschema=True)
    journal = sv.FencedJournal(sl.sha256(b"t3-regtest-j").hex())

    # 1. Single-use #1 branch-0 0x11 -> ADMIT, then new-nonce replay -> INVOKE_REPLAY
    r_su1 = v.verify_invocation(inv1_env, {"grants": [g1_env], "manifests": {host_man_ca: host_man}}, ch, journal, exec_cfg, use_txid=use1_txid)
    assert r_su1.verdict == "ADMIT", f"Trace 03 su1 failed: {r_su1}"
    inv1_replay = sl.sign_envelope({**inv1_env["payload"], "nonce": sl.sha256(b"t3-su1-replay").hex()}, [agent_req["sk"]])
    r_su1_rep = v.verify_invocation(inv1_replay, {"grants": [g1_env], "manifests": {host_man_ca: host_man}}, ch, journal, exec_cfg, use_txid=use1_txid)
    assert (r_su1_rep.verdict, r_su1_rep.refusal_code) == ("REFUSE", "INVOKE_REPLAY"), f"Trace 03 su1 replay got {r_su1_rep}"

    # 2. Single-use #2 branch-1 issuer revoke -> SEAL_SPENT -> GRANT_CLOSED
    inv2_env = sl.sign_envelope(
        {
            "action": "mail/send",
            "arguments": {"body_sha256": sl.sha256(b"su2-body").hex(), "size_bytes": "128", "subject": "SU2", "to": "su2@example.com"},
            "executor": exec_cfg,
            "exp": ch.now + 600,
            "genesis": cl.genesis_hash,
            "iat": ch.now - 10,
            "network": "regtest",
            "nonce": sl.sha256(b"t3-su2-n1").hex(),
            "proof_path": [{"grant_id": g2_id, "issuance_txid": iss2_txid}],
            "target": "mailbox:su2",
            "type": "seallink-invocation/1",
        },
        [agent_req["sk"]],
    )
    r_su2 = v.verify_invocation(inv2_env, {"grants": [g2_env], "manifests": {host_man_ca: host_man}}, ch, journal, exec_cfg)
    assert (r_su2.verdict, r_su2.refusal_code) == ("REFUSE", "SEAL_SPENT"), f"Trace 03 su2 got {r_su2}"
    inv2_sub = sl.sign_envelope({**inv2_env["payload"], "nonce": sl.sha256(b"t3-su2-n2").hex()}, [agent_req["sk"]])
    r_su2_sub = v.verify_invocation(inv2_sub, {"grants": [g2_env], "manifests": {host_man_ca: host_man}}, ch, journal, exec_cfg)
    assert (r_su2_sub.verdict, r_su2_sub.refusal_code) == ("REFUSE", "GRANT_CLOSED"), f"Trace 03 su2 sub got {r_su2_sub}"

    # 3. TRUC v3 P2A-boosted revocation observed in peer B mempool -> SEAL_SPENT!
    inv_p2a = sl.sign_envelope(
        {
            "action": "mail/send",
            "arguments": {"body_sha256": sl.sha256(b"p2a-body").hex(), "size_bytes": "128", "subject": "P2A", "to": "p2a@example.com"},
            "executor": exec_cfg,
            "exp": ch.now + 600,
            "genesis": cl.genesis_hash,
            "iat": ch.now - 10,
            "network": "regtest",
            "nonce": sl.sha256(b"t3-p2a-n").hex(),
            "proof_path": [{"grant_id": grev_id, "issuance_txid": issr_txid}],
            "target": "mailbox:p2a",
            "type": "seallink-invocation/1",
        },
        [agent_req["sk"]],
    )
    r_p2a = v.verify_invocation(inv_p2a, {"grants": [grev_env], "manifests": {host_man_ca: host_man}}, ch, journal, exec_cfg)
    assert (r_p2a.verdict, r_p2a.refusal_code) == ("REFUSE", "SEAL_SPENT"), f"Trace 03 P2A mempool revoke got {r_p2a}"

    # Mine block and verify BOTH TRUC v3 package txs confirm on peer B!
    tip_p2a = cl.mine(1)[0]
    p2a_confirmed_b = {p2a_parent_txid, p2a_child_txid} <= set(cl.rpc(1, "getblock", tip_p2a, 1)["tx"])
    assert p2a_confirmed_b

    return {
        "seals_txid": seals_txid,
        "single_use_1_branch0_0x11_txid": use1_txid,
        "single_use_1_branch0_0x11_raw_hex": use1_raw,
        "single_use_2_branch1_revoke_txid": rev2_txid,
        "single_use_2_branch1_revoke_raw_hex": rev2_raw,
        "truc_v3_p2a_parent_alone_rejected": not alone_res["allowed"],
        "truc_v3_p2a_parent_alone_reason": alone_res.get("reject-reason"),
        "truc_v3_p2a_parent_txid": p2a_parent_txid,
        "truc_v3_p2a_parent_raw_hex": p2a_parent_raw,
        "truc_v3_p2a_child_txid": p2a_child_txid,
        "truc_v3_p2a_child_raw_hex": p2a_child_raw,
        "truc_v3_p2a_peer_b_mempool_before_mining": peer_saw_p2a,
        "truc_v3_p2a_both_confirmed_on_peer_b": p2a_confirmed_b,
        "verdicts": {
            "single_use_branch_0_first": {"verdict": r_su1.verdict, "outcome": r_su1.outcome},
            "single_use_branch_0_replay": {"verdict": r_su1_rep.verdict, "refusal_code": r_su1_rep.refusal_code},
            "single_use_branch_1_revoke": {"verdict": r_su2.verdict, "refusal_code": r_su2.refusal_code},
            "single_use_branch_1_subsequent": {"verdict": r_su2_sub.verdict, "refusal_code": r_su2_sub.refusal_code},
            "p2a_mempool_revocation": {"verdict": r_p2a.verdict, "refusal_code": r_p2a.refusal_code},
        },
    }


def run_trace_04(cl: RegtestCluster) -> dict[str, Any]:
    """Trace 04: Anchored ward origin with 2-of-2 active either_of_2 guardians + live agent/guardian-message ADMIT!"""
    reg_own, reg_cred = kp("t4-reg-own"), kp("t4-reg-cred")
    disp, arb, chal = kp("t4-disp"), kp("t4-arb"), kp("t4-chal")
    bind_seal, stat_cap, stat_end = kp("t4-bind"), kp("t4-scap"), kp("t4-send")
    ga_own, ga_gr, ga_seal = kp("t4-ga-own"), kp("t4-ga-gr"), kp("t4-ga-seal")
    gb_own, gb_gr, gb_seal = kp("t4-gb-own"), kp("t4-gb-gr"), kp("t4-gb-seal")
    ward_own, bridge_req, station_rcpt, gseal_k = kp("t4-ward-own"), kp("t4-bridge"), kp("t4-station"), kp("t4-gseal")

    reg_pol = {"kind": "key", "pk": reg_own["comp"]}
    ga_pol = {"kind": "key", "pk": ga_own["comp"]}
    gb_pol = {"kind": "key", "pk": gb_own["comp"]}
    ward_pol = {"kind": "key", "pk": ward_own["comp"]}
    vac_pol = {"kind": "branch", "template": "both_of_2", "keys": {"a": disp["comp"], "b": arb["comp"]}}
    stat_pol = {"kind": "branch", "template": "either_of_2", "keys": {"a": stat_cap["comp"], "b": stat_end["comp"]}}
    bind_pol = {"kind": "key", "pk": bind_seal["comp"]}
    ga_act_pol = {"kind": "branch", "template": "either_of_2", "keys": {"a": disp["comp"], "b": ga_seal["comp"]}}
    gb_act_pol = {"kind": "branch", "template": "either_of_2", "keys": {"a": disp["comp"], "b": gb_seal["comp"]}}
    gseal_pol = {"kind": "key", "pk": gseal_k["comp"]}

    vac_spk, vac_ws = sl.compile_script_policy(vac_pol)
    stat_spk, _ = sl.compile_script_policy(stat_pol)
    bind_spk, _ = sl.compile_script_policy(bind_pol)
    ga_act_spk, _ = sl.compile_script_policy(ga_act_pol)
    gb_act_spk, _ = sl.compile_script_policy(gb_act_pol)
    gseal_spk, _ = sl.compile_script_policy(gseal_pol)
    assert vac_ws

    names = cl.register_names_batch([
        {"name": "id/t4-civil-registry", "owner_policy": reg_pol, "owner_kp": reg_own, "value_obj": {"link": {"cred": reg_cred["xonly"]}}, "rand_label": "t4-reg"},
        {"name": "id/t4-guardian-a", "owner_policy": ga_pol, "owner_kp": ga_own, "value_obj": {"link": {"grant": ga_gr["xonly"]}}, "rand_label": "t4-ga"},
        {"name": "id/t4-guardian-b", "owner_policy": gb_pol, "owner_kp": gb_own, "value_obj": {"link": {"grant": gb_gr["xonly"]}}, "rand_label": "t4-gb"},
        {"name": "id/t4-ward", "owner_policy": ward_pol, "owner_kp": ward_own, "value_obj": {"link": {"grant": ga_gr["xonly"]}}, "rand_label": "t4-ward"},
    ])

    f = cl.split_funding(7, each_sat=5_000_000)
    seals_txid, seals_raw = build_signed_tx(
        [f[0]],
        [
            (SEAL_SAT, bind_spk),   # 0: binding_seal
            (SEAL_SAT, stat_spk),   # 1: status_seal
            (SEAL_SAT, vac_spk),    # 2: roster_seal
            (SEAL_SAT, vac_spk),    # 3: slot 1 vacant
            (SEAL_SAT, vac_spk),    # 4: slot 2 vacant
            (SEAL_SAT, gseal_spk),  # 5: grant seal
            (SEAL_SAT, gseal_spk),  # 6: issuance input
            (f[0]["value_sat"] - 7 * SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(seals_raw)
    recent_blk = cl.mine(1)[0]
    tip_h = cl.rpc(1, "getblockcount")
    tip_time = int(cl.rpc(1, "getblockheader", recent_blk)["time"])
    maj_unix = tip_time + 100_000_000
    maj_salt = sl.sha256(b"t4-maj-salt").hex()
    sa = sl.sha256(b"t4-sa").hex()
    sb = sl.sha256(b"t4-sb").hex()
    ga_pin = {"name": "id/t4-guardian-a", "owner_policy": ga_pol, "registration": names["id/t4-guardian-a"]["registration"]}
    gb_pin = {"name": "id/t4-guardian-b", "owner_policy": gb_pol, "registration": names["id/t4-guardian-b"]["registration"]}

    origin_p = {
        "binding_seal": {"script_policy": bind_pol, "txid": seals_txid, "vout": 0},
        "claims": {
            "intended_name": "id/t4-ward",
            "intended_owner_policy": ward_pol,
            "majority_commitment": sl.clause_commit(maj_salt, {"majority_unix": maj_unix}),
        },
        "genesis": cl.genesis_hash,
        "guardian_policy": {
            "appointment_delay_blocks": 3,
            "arbiter_pk": arb["comp"],
            "challenger_pk": chal["comp"],
            "disposer_pk": disp["comp"],
            "quorums": {
                "contract_assent": {"den": 1, "min": 2, "num": 1},
                "custody_change": {"den": 1, "min": 2, "num": 1},
                "effect_grant": {"den": 1, "min": 2, "num": 1},
                "routine_read": {"den": 2, "min": 1, "num": 1},
            },
            "revision": 1,
            "revision_size": 2,
            "roster_seal": {"script_policy": vac_pol, "txid": seals_txid, "vout": 2},
            "slots": [
                {"initial_guardian_commitment": sl.clause_commit(sa, ga_pin), "slot": 1, "vacant_utxo": {"txid": seals_txid, "vout": 3}},
                {"initial_guardian_commitment": sl.clause_commit(sb, gb_pin), "slot": 2, "vacant_utxo": {"txid": seals_txid, "vout": 4}},
            ],
        },
        "issuer": {"name": "id/t4-civil-registry", "owner_policy": reg_pol, "registration": names["id/t4-civil-registry"]["registration"], "role_policy": {"m": 1, "pks": [reg_cred["xonly"]]}},
        "name_recovery": {"mode": "none"},
        "network": "regtest",
        "origin_class": "person",
        "request_sha256": sl.sha256(b"t4-origin-req").hex(),
        "status_seal": {"script_policy": stat_pol, "txid": seals_txid, "vout": 1},
        "subject_initial_key": ga_gr["xonly"],
        "type": "seallink-origin/1",
    }
    origin_env = sl.sign_envelope(origin_p, [reg_cred["sk"]])
    origin_id = sl.object_id(origin_p)

    anc09_txid, anc09_raw = build_signed_tx(
        [f[1]],
        [(0, op_return_spk(0x09, sl.content_addr(origin_env))), (f[1]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(anc09_raw)
    cl.mine(1)

    upd_w_txid, _ = cl.update_name_p2wpkh(names["id/t4-ward"], "id/t4-ward", ward_own, {"link": {"grant": ga_gr["xonly"], "origin": origin_id}})
    binding = {
        "genesis": cl.genesis_hash,
        "name": "id/t4-ward",
        "network": "regtest",
        "origin_id": origin_id,
        "owner_policy": ward_pol,
        "registration": names["id/t4-ward"]["registration"],
        "seq": 1,
        "type": "seallink-name-binding/1",
    }
    anc0c_txid, anc0c_raw = build_signed_tx(
        [
            {"txid": seals_txid, "vout": 0, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": bind_seal},
            f[2],
        ],
        [(0, op_return_spk(0x0C, sl.object_id(binding))), (f[2]["value_sat"] + SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(anc0c_raw)

    # Activate BOTH slots 1 and 2 via real 0x12 both_of_2 spends!
    def _activate_slot(slot: int, pin: dict[str, Any], salt_h: str, act_pol: dict[str, Any], act_spk: bytes, vac_vout: int, g_gr: dict[str, Any], f_u: dict[str, Any]):
        gp = {
            "activation_mode": "initial",
            "active_policy": act_pol,
            "active_vout": 0,
            "genesis": cl.genesis_hash,
            "guardian": pin,
            "issuer": origin_p["issuer"],
            "network": "regtest",
            "origin_id": origin_id,
            "prev_outpoint": {"txid": seals_txid, "vout": vac_vout},
            "revision": 1,
            "slot": slot,
            "term": {"mode": "indefinite"},
            "type": "seallink-guardian/1",
        }
        grec = sl.sign_envelope(gp, [reg_cred["sk"]])
        gass = sl.sign_envelope(
            {
                "expires_at": tip_time + 200_000,
                "genesis": cl.genesis_hash,
                "issued_at": tip_time,
                "network": "regtest",
                "nonce": sl.sha256(f"t4-gass-{slot}".encode()).hex(),
                "party_id": f"guardian-slot-{slot}",
                "party_name": pin["name"],
                "party_role": "guardian",
                "target_id": sl.object_id(gp),
                "target_type": "seallink-guardian/1",
                "type": "seallink-assent/1",
            },
            [g_gr["sk"]],
        )
        txid, raw_h = build_signed_tx(
            [
                {"txid": seals_txid, "vout": vac_vout, "value_sat": SEAL_SAT, "kind": "p2wsh_multisig", "witness_script": vac_ws, "signers": [disp, arb]},
                f_u,
            ],
            [
                (SEAL_SAT, act_spk),
                (0, op_return_spk(0x12, sl.content_addr(grec))),
                (f_u["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
            ],
        )
        cl.broadcast_and_wait_peer(raw_h)
        return grec, gass, txid, raw_h

    ga_rec, ga_ass, act1_txid, act1_raw = _activate_slot(1, ga_pin, sa, ga_act_pol, ga_act_spk, 3, ga_gr, f[3])
    gb_rec, gb_ass, act2_txid, act2_raw = _activate_slot(2, gb_pin, sb, gb_act_pol, gb_act_spk, 4, gb_gr, f[4])

    exec_cfg = {"key": station_rcpt["xonly"], "name": "id/t4-station", "pinned_ward_origin_id": origin_id}
    raw_msg = b"Homework reminder: math worksheet by 18:00."
    msg_sha = sl.sha256(raw_msg).hex()

    def _mk_ward_grant(ev_cls: str, approvs: list[dict[str, Any]], f_u: dict[str, Any]):
        gp = {
            "capabilities": [{"action": "agent/guardian-message", "target": f"ward:{origin_id}", "where": {}}],
            "executor": {"key": station_rcpt["xonly"], "name": "id/t4-station"},
            "genesis": cl.genesis_hash,
            "guardian_context": {"event_class": ev_cls, "origin_id": origin_id, "revision": 1, "ward_name": "id/t4-ward"},
            "issuer": {"name": "id/t4-ward", "owner_policy": ward_pol, "registration": names["id/t4-ward"]["registration"]},
            "network": "regtest",
            "not_after_height": tip_h + 25,
            "not_before_height": tip_h - 1,
            "recent_block": recent_blk,
            "recipient": {"key": bridge_req["xonly"], "mode": "key"},
            "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": gseal_pol, "txid": seals_txid, "vout": 5}},
            "type": "seallink-grant/1",
        }
        genv = sl.sign_guardian_envelope(gp, approvs)
        gid = sl.object_id(gp)
        d_hex = sl.signing_digest({"genesis": cl.genesis_hash, "grant_content_addr": sl.content_addr(genv), "grant_id": gid, "type": "seallink-issuance/1"}).hex()
        itx, iraw = build_signed_tx([f_u], [(0, op_return_spk(0x01, d_hex)), (f_u["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"])])
        cl.broadcast_and_wait_peer(iraw)
        return genv, gid, itx, iraw

    g_2of2, gid_2of2, iss_ok_txid, iss_ok_raw = _mk_ward_grant(
        "effect_grant",
        [
            {"slot": 1, "revision": 1, "guardian_name": "id/t4-guardian-a", "signers": [ga_gr["sk"]]},
            {"slot": 2, "revision": 1, "guardian_name": "id/t4-guardian-b", "signers": [gb_gr["sk"]]},
        ],
        f[5],
    )
    g_1of2, gid_1of2, iss_bad_txid, iss_bad_raw = _mk_ward_grant(
        "routine_read",
        [{"slot": 1, "revision": 1, "guardian_name": "id/t4-guardian-a", "signers": [ga_gr["sk"]]}],
        f[6],
    )
    cl.mine(1)

    tracked = [seals_txid, anc09_txid, upd_w_txid, anc0c_txid, act1_txid, act2_txid, iss_ok_txid, iss_bad_txid]
    ch_dict = cl.extract_chain_view(
        tracked_txids=tracked,
        tracked_names=["id/t4-civil-registry", "id/t4-guardian-a", "id/t4-guardian-b", "id/t4-ward"],
        tracked_block_hashes=[recent_blk],
    )
    ch = sv.ChainView(ch_dict)
    v = sv.Tier1Verifier(
        pinned_network="regtest",
        pinned_genesis=cl.genesis_hash,
        trusted_origin_issuers={"id/t4-civil-registry"},
        require_jsonschema=True,
    )
    journal = sv.FencedJournal(sl.sha256(b"t4-regtest-j").hex())
    origin_bundle = {
        "guardian_assents": [ga_ass, gb_ass],
        "guardian_records": [ga_rec, gb_rec],
        "initial_guardian_disclosures": {"1": {"salt_hex": sa}, "2": {"salt_hex": sb}},
        "majority_salt_hex": maj_salt,
        "name_binding": binding,
        "name_binding_txid": anc0c_txid,
        "opened_majority_unix": maj_unix,
        "origin": origin_env,
        "origin_anchor_txid": anc09_txid,
    }

    def _mk_agm_inv(gid: str, itx: str, tag: str) -> dict[str, Any]:
        return sl.sign_envelope(
            {
                "action": "agent/guardian-message",
                "arguments": {
                    "channel": "direct",
                    "delivery_mode": "strict_drop",
                    "message_sha256": msg_sha,
                    "origin_id": origin_id,
                    "revision": 1,
                    "subject_ward_name": "id/t4-ward",
                },
                "executor": {"key": station_rcpt["xonly"], "name": "id/t4-station"},
                "exp": ch.now + 600,
                "genesis": cl.genesis_hash,
                "iat": ch.now - 10,
                "network": "regtest",
                "nonce": sl.sha256(f"t4-inv-{tag}".encode()).hex(),
                "proof_path": [{"grant_id": gid, "issuance_txid": itx}],
                "target": f"ward:{origin_id}",
                "type": "seallink-invocation/1",
            },
            [bridge_req["sk"]],
        )

    r_bad = v.verify_invocation(_mk_agm_inv(gid_1of2, iss_bad_txid, "1of2"), {"grants": [g_1of2], "origin_bundle": origin_bundle}, ch, journal, exec_cfg, raw_message_bytes=raw_msg)
    r_ok = v.verify_invocation(_mk_agm_inv(gid_2of2, iss_ok_txid, "2of2"), {"grants": [g_2of2], "origin_bundle": origin_bundle}, ch, journal, exec_cfg, raw_message_bytes=raw_msg)
    assert (r_bad.verdict, r_bad.refusal_code) == ("REFUSE", "GUARDIAN_QUORUM_UNMET"), f"Trace 04 downgrade got {r_bad}"
    assert r_ok.verdict == "ADMIT", f"Trace 04 2-of-2 ADMIT got {r_ok}"

    return {
        "origin_0x09_txid": anc09_txid,
        "origin_0x09_raw_hex": anc09_raw,
        "binding_0x0c_txid": anc0c_txid,
        "binding_0x0c_raw_hex": anc0c_raw,
        "slot_1_0x12_txid": act1_txid,
        "slot_1_0x12_raw_hex": act1_raw,
        "slot_2_0x12_txid": act2_txid,
        "slot_2_0x12_raw_hex": act2_raw,
        "grant_2of2_0x01_txid": iss_ok_txid,
        "grant_2of2_0x01_raw_hex": iss_ok_raw,
        "verdicts": {
            "downgraded_1of2_routine_read": {"verdict": r_bad.verdict, "refusal_code": r_bad.refusal_code},
            "full_2of2_effect_grant_strict_drop": {"verdict": r_ok.verdict, "outcome": r_ok.outcome},
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Execute all 4 SealLink traces live on two Namecoin Core nc28.0 regtest nodes.")
    ap.add_argument("--bin-dir", required=True, type=Path, help="Directory containing nc28.0 namecoind and namecoin-cli")
    ap.add_argument("--output-json", required=True, type=Path, help="Output JSON file path for observed-traces.json")
    args = ap.parse_args()

    work_dir = Path(tempfile.mkdtemp(prefix="seallink-traces-regtest-")).resolve()
    cl = RegtestCluster(args.bin_dir, work_dir)
    t0 = time.monotonic()
    try:
        meta = cl.start()
        t1 = run_trace_01(cl)
        t2 = run_trace_02(cl)
        t3 = run_trace_03(cl)
        t4 = run_trace_04(cl)
        elapsed = round(time.monotonic() - t0, 2)
        report = {
            "suite": "seallink-nc28-live-traces-regtest",
            "spec_version": "1.0.0-draft.4",
            "chain": "regtest",
            "policy": "standard (-acceptnonstdtxn=0 -txindex=1), two loopback-only nodes (node A writer + node B read-only peer)",
            "node_meta": meta,
            "final_tip_height": cl.rpc(1, "getblockcount"),
            "elapsed_seconds": elapsed,
            "trace_01_mail_offline_revoke": t1,
            "trace_02_guardian_succession_p2wsh_csv": t2,
            "trace_03_delegation_single_use_p2a": t3,
            "trace_04_ward_agent_intake": t4,
        }
    finally:
        stopped = cl.stop()
        shutil.rmtree(work_dir, ignore_errors=True)

    report["stopped_all_owned_processes"] = stopped
    assert stopped, "Failed to stop all regtest namecoind processes cleanly"
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"PASS: All 4 SealLink traces verified live on Namecoin Core {meta['subversion']} regtest in {elapsed}s -> {args.output_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
