#!/usr/bin/env python3
"""
Live Two-Node Namecoin Core nc28.0 Regtest Conformance Harness for SealLink v1.0.0-draft.11.

Executes seven end-to-end SealLink protocol traces on two fresh loopback-only
Namecoin Core 28 regtest nodes under strict standard policy (`-acceptnonstdtxn=0`,
`-txindex=1`, `-namehistory=1`), extracting live ChainViews via a stateless cold
`ColdNamecoinObserver` (`tools/nc_rpc_adapter.py`) talking strictly to the independent
read-only peer node B (`-disablewallet=1`, dedicated 9-method `rpcwhitelist` credential
with `-rpcwhitelistdefault=0`) with ZERO writer-side state, and verifying
every step with `tools/seallink_verifier.py`
(`Tier1Verifier(pinned_network="regtest", require_jsonschema=True)`).

Exercises on real nc28.0 regtest:
  - Trace 01: Full `PROFILE-mail-v1` `mail/read` with `executor_ref` provider discovery
              (`id/t1-alice` manifest -> `id/t1-mail-host`), named recipient
              (`recipient.mode="name"`, `id/t1-bob`), `actual_message_meta` MIME/folder
              check, live `ADMIT`, negative constraint check, and real mempool P2WPKH
              revocation observed on peer B BEFORE mining -> `SEAL_SPENT` -> `GRANT_CLOSED`.
  - Trace 02: Live `0x09` origin anchor + `0x0c` name binding; real `P2WSH` 2-of-3
              multisig ward name ownership updated via `createpsbt` + `namepsbt` +
              BIP-143 P2WSH multisig witness; `0x12` initial activation (`both_of_2`),
              active `either_of_2` halt spend, `0x0d` `guardian_slot_pending` CSV
              branch proving BOTH premature `non-BIP68-final` rejection AND post-CSV
              `0x0e` activation, `0x0f` roster transition, `0x10` RECOVERY_CANCEL,
              and live `Tier1Verifier.verify_assent` verdicts.
  - Trace 03: Real depth-2 delegation with parent `seconds:3600` pool, 2 live on-chain
              row coins (`row_ordinal` 1 and 2) and sibling child grants, crash-before-
              settlement `UNCERTAIN`, serialized journal + `receipt_store` restart replay
              proving preserved `seconds:*` clock watermarks (`QUOTA_CLOCK_REGRESSION`)
              and cached receipt retries (0 writes); PLUS `single_use_1_of_2` P2WSH
              (`0x11` branch-0 grantee consumption vs branch-1 issuer revoke) AND TRUC v3
              zero-fee `P2A` (`0x51024e73`) CPFP revocation package propagated via
              `submitpackage` from node A to peer node B before mining.
  - Trace 04: Live anchored ward origin with 2-of-2 active `either_of_2` guardians
              and `agent/guardian-message` (`strict_drop`, `effect_grant`) `ADMIT` plus
              1-of-2 downgrade refusal (`GUARDIAN_QUORUM_UNMET`).
  - Trace 05: Historical eternal credential across live regtest 30-block name expiry AND
              lawful re-registration of the exact same spelling (`id/t5-school`) by a new
              owner — verified from ONE cold-observer `ChainView` proving simultaneously:
              live new owner `ADMIT`, live old-owner pin `NAME_OWNER_MISMATCH`, historical
              eternal diploma `ADMIT`, and post-expiry anchor `NAME_EXPIRED`.

Zero external cryptographic dependencies beyond Python stdlib + `jsonschema` +
repository `tools/seallink_ref.py`, `tools/seallink_verifier.py`, and `tools/nc_rpc_adapter.py`.
"""

from __future__ import annotations

import argparse
import copy
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

import nc_rpc_adapter as nca  # noqa: E402
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
        elif kind == "p2wsh_branch_both":
            # Native P2WSH both_of_2(a_spec, b_spec) supporting 1-key OR m-of-n BranchKeySpec (Decision 6A)
            ws = inp["witness_script"]
            sh = _bip143_sighash(version, inputs, outputs, locktime, idx, ws, inp["value_sat"])
            a_spec, b_spec = inp["a_spec"], inp["b_spec"]
            lo, hi = sorted([a_spec, b_spec], key=sl._branch_spec_sort_key)
            def _clause_items(spec: Any, signers_for: list[dict[str, Any]]) -> list[bytes]:
                if isinstance(spec, str):
                    return [ecdsa_sign_der_low_s(sh, signers_for[0]["sk"])]
                ordered = sorted(signers_for, key=lambda x: x["comp"])
                return [b""] + [ecdsa_sign_der_low_s(sh, k["sk"]) for k in ordered]
            lo_signers = inp["a_signers"] if lo == a_spec else inp["b_signers"]
            hi_signers = inp["b_signers"] if lo == a_spec else inp["a_signers"]
            # Script executes lo (VERIFY) then hi -> witness pushes hi first, then lo on top!
            witnesses.append(_clause_items(hi, hi_signers) + _clause_items(lo, lo_signers) + [ws])
        elif kind == "p2wsh_branch_either":
            # Native P2WSH either_of_2(a_spec, b_spec) with BranchKeySpec (OP_IF lo OP_ELSE hi OP_ENDIF)
            ws = inp["witness_script"]
            sh = _bip143_sighash(version, inputs, outputs, locktime, idx, ws, inp["value_sat"])
            a_spec, b_spec = inp["a_spec"], inp["b_spec"]
            lo, _hi = sorted([a_spec, b_spec], key=sl._branch_spec_sort_key)
            chosen_spec = inp["chosen_spec"]
            chosen_signers = inp["signers"]
            if isinstance(chosen_spec, str):
                items = [ecdsa_sign_der_low_s(sh, chosen_signers[0]["sk"])]
            else:
                ordered = sorted(chosen_signers, key=lambda x: x["comp"])
                items = [b""] + [ecdsa_sign_der_low_s(sh, k["sk"]) for k in ordered]
            selector = b"\x01" if chosen_spec == lo else b""
            witnesses.append(items + [selector, ws])
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
        # A-14: Dedicated least-privilege read-only RPC credentials for Node B ColdNamecoinObserver
        self.obs_user = "seallink_obs"
        self.obs_password = "seallink-regtest-readonly-obs-pass"
        self.admin_user = "harness_admin"
        self.admin_password = "seallink-regtest-harness-admin-pass"
        self.obs_whitelist = (
            "getblock,getblockchaininfo,getblockhash,getblockheader,"
            "getindexinfo,getrawmempool,getrawtransaction,gettxout,name_history"
        )
        self.admin_whitelist = (
            self.obs_whitelist
            + ",getbestblockhash,getblockcount,getpeerinfo,invalidateblock,name_show,reconsiderblock,stop"
        )

    @staticmethod
    def _rpcauth_line(username: str, password: str, salt_hex: str) -> str:
        pw_hmac = hmac.new(salt_hex.encode("utf-8"), password.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{username}:{salt_hex}${pw_hmac}"

    def new_cold_observer(self, *, rpc_counter: dict[str, int] | None = None) -> nca.ColdNamecoinObserver:
        """Instantiate a fresh stateless ColdNamecoinObserver with ZERO writer-side state using Node B's read-only rpcwhitelist user."""
        raw_read = nca.make_cli_rpc(
            self.bin_dir,
            self.dirs[1],
            self.ports[1],
            regtest=True,
            rpcuser=self.obs_user,
            rpcpassword=self.obs_password,
        )
        if rpc_counter is not None:
            def _counted_read(method: str, *args: Any, wait: bool = False) -> Any:
                rpc_counter[method] = rpc_counter.get(method, 0) + 1
                return raw_read(method, *args, wait=wait)
            read_fn = _counted_read
        else:
            read_fn = raw_read
        return nca.ColdNamecoinObserver(
            read_fn,
            [("node-a-local", nca.make_cli_rpc(self.bin_dir, self.dirs[0], self.ports[0], regtest=True))],
            network="regtest",
            clock_mode="regtest_deterministic",
        )

    def rpc(self, node: int, method: str, *args: Any, wait: bool = False) -> Any:
        cmd = [
            str(self.bin_dir / "namecoin-cli"),
            "-regtest",
            f"-datadir={self.dirs[node]}",
            f"-rpcport={self.ports[node]}",
            "-rpcconnect=127.0.0.1",
            "-stdin",
        ]
        if node == 1:
            cmd.extend([f"-rpcuser={self.admin_user}", f"-rpcpassword={self.admin_password}"])
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
    def until(pred: Any, limit: float = 180.0) -> bool:
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
            "-namehistory=1",
            "-acceptnonstdtxn=0",
            "-printtoconsole=0",
            "-par=2",
        ]
        for i in range(2):
            if i == 1:
                extra = [
                    "-disablewallet=1",
                    f"-rpcauth={self._rpcauth_line(self.obs_user, self.obs_password, 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4')}",
                    f"-rpcauth={self._rpcauth_line(self.admin_user, self.admin_password, 'f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3')}",
                    "-rpcwhitelistdefault=0",
                    f"-rpcwhitelist={self.obs_user}:{self.obs_whitelist}",
                    f"-rpcwhitelist={self.admin_user}:{self.admin_whitelist}",
                ]
            else:
                extra = []
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
        # A-14 live proof: verify read-only observer user CANNOT invoke privileged RPCs (sendrawtransaction/invalidateblock)!
        obs_rpc_probe = nca.make_cli_rpc(
            self.bin_dir, self.dirs[1], self.ports[1], regtest=True, rpcuser=self.obs_user, rpcpassword=self.obs_password
        )
        assert obs_rpc_probe("getblockchaininfo")["chain"] == "regtest"
        try:
            obs_rpc_probe("sendrawtransaction", "00")
            raise AssertionError("Node B rpcwhitelist unexpectedly permitted sendrawtransaction for seallink_obs!")
        except RuntimeError as exc:
            assert "403" in str(exc) or "forbidden" in str(exc).lower() or "not allowed" in str(exc).lower(), (
                f"Expected HTTP 403 / forbidden from rpcwhitelist, got: {exc}"
            )
        # Connect outbound from Node A -> Node B so Node A uses fast 2s outbound inventory trickle (not 5s inbound)
        self.rpc(0, "addnode", f"127.0.0.1:{self.ports[3]}", "onetry")
        assert self.until(
            lambda: all(len(self.rpc(i, "getpeerinfo")) == 1 and self.rpc(i, "getpeerinfo")[0]["version"] > 0 for i in range(2)),
            limit=60.0,
        ), "node A and node B failed to establish loopback peer connection"

        self.genesis_hash = self.rpc(0, "getblockhash", 0)
        assert self.rpc(1, "getblockhash", 0) == self.genesis_hash
        net_info = self.rpc(0, "getnetworkinfo")

        # Derive bech32 address for cluster funder key and mine 175 blocks -> 75 mature coinbase UTXOs
        desc = self.rpc(0, "getdescriptorinfo", f"wpkh({self.fund_key['comp']})")["descriptor"]
        self.fund_addr = self.rpc(0, "deriveaddresses", desc)[0]
        blocks = self.rpc(0, "generatetoaddress", 175, self.fund_addr)
        assert self.until(lambda: self.rpc(1, "getbestblockhash") == blocks[-1], limit=180.0)
        for bh in blocks[:75]:
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
        assert self.until(lambda: self.rpc(1, "getbestblockhash") == blocks[-1], limit=180.0), "peer B did not sync mined block"
        return blocks

    def broadcast_and_wait_peer(self, raw_hex: str) -> str:
        txid = self.rpc(0, "sendrawtransaction", raw_hex)
        assert self.until(lambda: txid in self.rpc(1, "getrawmempool"), limit=180.0), f"tx {txid} not observed in peer B mempool"
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
        assert self.until(lambda: nn_txids <= set(self.rpc(1, "getrawmempool")), limit=180.0)
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
        assert self.until(lambda: fu_txids <= set(self.rpc(1, "getrawmempool")), limit=180.0)
        self.mine(1)
        tip_h = self.rpc(1, "getblockcount")
        for name, rec in out_map.items():
            rec["height"] = tip_h
            shown = self.rpc(1, "name_show", name)
            assert shown["txid"] == rec["first_txid"], f"peer B name_show mismatch for {name}"

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
            assert self.until(lambda: upd_txids <= set(self.rpc(1, "getrawmempool")), limit=180.0)
            self.mine(1)
            tip_h = self.rpc(1, "getblockcount")
            for name, u_txid, u_raw, pol in upd_pending:
                rec = out_map[name]
                rec["current_txid"] = u_txid
                rec["current_vout"] = 0
                rec["update_txid"] = u_txid
                rec["update_raw"] = u_raw
                rec["height"] = tip_h
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
        extra_sat = sum(v for v, _ in (extra_outputs or []))
        fee_in = self.split_funding(1, each_sat=max(500_000, extra_sat + FEE_SAT + 100_000))[0]
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
        outs.append((fee_in["value_sat"] - extra_sat - FEE_SAT, self.fund_key["p2wpkh_spk"]))
        txid, raw_hex = build_signed_tx([name_in, fee_in], outs, version=NAMECOIN_TX_VERSION)
        self.broadcast_and_wait_peer(raw_hex)
        self.mine(1)
        shown = self.rpc(1, "name_show", name)
        assert shown["txid"] == txid
        name_rec["current_txid"] = txid
        name_rec["current_vout"] = 0
        name_rec["owner_policy"] = pol
        name_rec["witness_script"] = ws
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
        return {
            "txid": txid,
            "raw_hex": raw_hex,
            "p2wsh_address": p2wsh_addr,
            "namepsbt_script_matched_seallink_encoder": True,
            "decoded_psbt_version": decoded_psbt["tx"]["version"],
            "witness_script_hex": ws.hex(),
            "confirmed_height": self.rpc(1, "getblockcount"),
        }


# ============================================================================
# 3. Five Live End-to-End Regtest Traces (Cold-Observer Verification)
# ============================================================================

def run_trace_01(cl: RegtestCluster) -> dict[str, Any]:
    """Trace 01: Full PROFILE-mail-v1 mail/read with executor_ref provider discovery, named recipient
    (recipient.mode='name'), MIME actual_message_meta enforcement, and cold-observer mempool revoke."""
    alice_own = kp("t1-alice-own")
    alice_gr = kp("t1-alice-gr")
    alice_seal = kp("t1-alice-seal")
    host_own = kp("t1-host-own")
    host_rcpt = kp("t1-host-rcpt")
    bob_own = kp("t1-bob-own")
    bob_req = kp("t1-bob-req")

    alice_pol = {"kind": "key", "pk": alice_own["comp"]}
    host_pol = {"kind": "key", "pk": host_own["comp"]}
    bob_pol = {"kind": "key", "pk": bob_own["comp"]}
    seal_pol = {"kind": "key", "pk": alice_seal["comp"]}

    host_man = {
        "network": "regtest",
        "owner": "id/t1-mail-host",
        "seq": 1,
        "service": {
            "actions": ["mail/read", "mail/send"],
            "endpoint": "https://mail-t1.regtest.invalid/seallink",
            "receipt_key": host_rcpt["xonly"],
            "service_type": "mail",
            "tls_spki_sha256": sl.sha256(b"t1-mail-host-tls-spki").hex(),
        },
        "type": "seallink-manifest/1",
    }
    host_man_ca = sl.content_addr(host_man)

    # Register host + bob first so Alice's manifest can pin host's live registration outpoint!
    names_a = cl.register_names_batch([
        {"name": "id/t1-mail-host", "owner_policy": host_pol, "owner_kp": host_own, "value_obj": {"m": {"h": host_man_ca, "s": 1}}, "rand_label": "t1-host"},
        {"name": "id/t1-bob", "owner_policy": bob_pol, "owner_kp": bob_own, "value_obj": {"nostr": bob_req["xonly"]}, "rand_label": "t1-bob"},
    ])
    alice_man = {
        "network": "regtest",
        "owner": "id/t1-alice",
        "providers": [
            {
                "label": "work",
                "provider": {
                    "name": "id/t1-mail-host",
                    "owner_policy": host_pol,
                    "registration": names_a["id/t1-mail-host"]["registration"],
                },
                "service_type": "mail",
            }
        ],
        "seq": 1,
        "type": "seallink-manifest/1",
    }
    alice_man_ca = sl.content_addr(alice_man)
    mal_own, mal_gr = kp("t1-mal-own"), kp("t1-mal-gr")
    mal_pol = {"kind": "key", "pk": mal_own["comp"]}
    names_b = cl.register_names_batch([
        {"name": "id/t1-alice", "owner_policy": alice_pol, "owner_kp": alice_own, "value_obj": {"link": {"grant": alice_gr["xonly"]}, "m": {"h": alice_man_ca, "s": 1}}, "rand_label": "t1-alice"},
        {"name": "id/t1-mallory", "owner_policy": mal_pol, "owner_kp": mal_own, "value_obj": {"link": {"grant": mal_gr["xonly"]}}, "rand_label": "t1-mallory"},
    ])
    names = {**names_a, **names_b}
    upd_txid, upd_raw = names["id/t1-alice"]["update_txid"], names["id/t1-alice"]["update_raw"]

    # Create Alice's P2WPKH seal UTXO (vout=0) + linkage (vout=1), plus Mallory's seal (vout=2) + linkage (vout=3)
    f = cl.split_funding(1, each_sat=5_000_000)[0]
    seal_spk, _ = sl.compile_script_policy(seal_pol)
    seal_txid, seal_raw = build_signed_tx(
        [f],
        [
            (SEAL_SAT, seal_spk),
            (SEAL_SAT, seal_spk),
            (SEAL_SAT, seal_spk),
            (SEAL_SAT, seal_spk),
            (f["value_sat"] - 4 * SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(seal_raw)
    recent_blk = cl.mine(1)[0]
    tip_h = cl.rpc(1, "getblockcount")

    grant_p = {
        "capabilities": [
            {
                "action": "mail/read",
                "target": "mailbox:id/t1-alice:work",
                "where": {"folder": {"in": ["Invoices"]}, "sender_domain": {"in": ["billing.example"]}},
            }
        ],
        "executor_ref": {"label": "work", "provider_of": "id/t1-alice", "service_type": "mail"},
        "genesis": cl.genesis_hash,
        "issuer": {"name": "id/t1-alice", "owner_policy": alice_pol, "registration": names["id/t1-alice"]["registration"], "role_policy": {"m": 1, "pks": [alice_gr["xonly"]]}},
        "network": "regtest",
        "not_after_height": tip_h + 25,
        "not_before_height": tip_h - 1,
        "recent_block": recent_blk,
        "recipient": {"mode": "name", "name": "id/t1-bob", "owner_policy": bob_pol, "registration": names["id/t1-bob"]["registration"]},
        "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": seal_pol, "txid": seal_txid, "vout": 0}},
        "type": "seallink-grant/1",
    }
    grant_env = sl.sign_envelope(grant_p, [alice_gr["sk"]])
    gid = sl.object_id(grant_p)

    # Foreign-issuer B-1 attack grant: id/t1-mallory targeting mailbox:id/t1-alice:work
    mal_grant_p = {
        **copy.deepcopy(grant_p),
        "issuer": {"name": "id/t1-mallory", "owner_policy": mal_pol, "registration": names["id/t1-mallory"]["registration"], "role_policy": {"m": 1, "pks": [mal_gr["xonly"]]}},
        "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": seal_pol, "txid": seal_txid, "vout": 2}},
    }
    mal_grant_env = sl.sign_envelope(mal_grant_p, [mal_gr["sk"]])
    mal_gid = sl.object_id(mal_grant_p)

    # Broadcast real 0x01 OP_RETURN issuance txs spending (seal_txid, seal_vout + 1) (Witness Profile W + R3-H1!)
    iss_prep = {"genesis": cl.genesis_hash, "grant_content_addr": sl.content_addr(grant_env), "grant_id": gid, "type": "seallink-issuance/1"}
    iss_digest_hex = sl.signing_digest(iss_prep).hex()
    iss_txid, iss_raw = build_signed_tx(
        [{"txid": seal_txid, "vout": 1, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": alice_seal}],
        [(0, op_return_spk(0x01, iss_digest_hex)), (SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    mal_iss_digest = sl.signing_digest({"genesis": cl.genesis_hash, "grant_content_addr": sl.content_addr(mal_grant_env), "grant_id": mal_gid, "type": "seallink-issuance/1"}).hex()
    mal_iss_txid, mal_iss_raw = build_signed_tx(
        [{"txid": seal_txid, "vout": 3, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": alice_seal}],
        [(0, op_return_spk(0x01, mal_iss_digest)), (SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(iss_raw)
    cl.broadcast_and_wait_peer(mal_iss_raw)
    cl.mine(1)

    manifests = {alice_man_ca: alice_man, host_man_ca: host_man}
    exec_ref = {"key": host_rcpt["xonly"], "name": "id/t1-mail-host"}
    exec_cfg = {**exec_ref, "pin": {"name": "id/t1-mail-host", "owner_policy": host_pol, "registration": names_a["id/t1-mail-host"]["registration"]}}
    v = sv.Tier1Verifier(pinned_network="regtest", pinned_genesis=cl.genesis_hash, require_jsonschema=True, require_observation_bracket=True)
    journal = sv.FencedJournal(sl.sha256(b"t1-regtest-j").hex())

    def _mk_inv(tag: str, now_s: int, use_gid: str = gid, use_itx: str = iss_txid) -> dict[str, Any]:
        return sl.sign_envelope(
            {
                "action": "mail/read",
                "arguments": {"folder": "Invoices", "message_id": f"msg-{tag}", "sender_domain": "billing.example"},
                "executor": exec_ref,
                "exp": now_s + 600,
                "genesis": cl.genesis_hash,
                "iat": now_s - 10,
                "network": "regtest",
                "nonce": sl.sha256(f"t1-n-{tag}".encode()).hex(),
                "proof_path": [{"grant_id": use_gid, "issuance_txid": use_itx}],
                "target": "mailbox:id/t1-alice:work",
                "type": "seallink-invocation/1",
            },
            [bob_req["sk"]],
        )

    # Cold observer #1 (brand-new stateless observer with ZERO writer state + full bracket + pre_effect_recheck!)
    t1_ctr: dict[str, int] = {}
    obs1 = cl.new_cold_observer(rpc_counter=t1_ctr)
    inv_step1 = _mk_inv("step1", int(cl.rpc(1, "getblockheader", cl.rpc(1, "getbestblockhash"))["time"]) + 30)
    inv_mal = _mk_inv("mal-b1", int(cl.rpc(1, "getblockheader", cl.rpc(1, "getbestblockhash"))["time"]) + 30, use_gid=mal_gid, use_itx=mal_iss_txid)
    ch1_dict = obs1.build_chain_view(wire_objects=[grant_env, mal_grant_env, inv_step1, inv_mal], manifests=manifests)
    assert t1_ctr.get("getblockchaininfo", 0) >= 2 and ch1_dict["observation_bracket"]["consistent"] is True
    ch1_pre_dict = obs1.pre_effect_recheck(ch1_dict, [(seal_txid, 0)])
    assert ch1_pre_dict["observation_bracket"]["pre_effect_rechecked"] is True
    ch1 = sv.ChainView(ch1_pre_dict)
    # Two-phase R1-A execution: admit_and_reserve() -> execute -> commit_result(late real receipt) -> idempotent retry!
    p1_admit = v.admit_and_reserve(
        inv_step1,
        {"grants": [grant_env], "manifests": manifests},
        ch1,
        journal,
        exec_cfg,
        actual_message_meta={"folder": "Invoices", "sender_domain": "billing.example"},
    )
    assert p1_admit.verdict == "ADMIT", f"Trace 01 step 1 admit_and_reserve failed: {p1_admit}"
    rcpt_step1 = sl.sign_envelope(
        {
            "action": "mail/read",
            "executor_name": exec_cfg["name"],
            "genesis": cl.genesis_hash,
            "grant_id": gid,
            "invocation_id": sl.object_id(inv_step1["payload"]),
            "network": "regtest",
            "outcome": "executed",
            "recorded_at": p1_admit.details["recorded_at"],
            "result_sha256": sl.sha256(b"t1-step1-mime-result").hex(),
            "tip_hash": ch1.tip_hash,
            "tip_height": ch1.tip_height,
            "type": "seallink-receipt/1",
        },
        [host_rcpt["sk"]],
    )
    res_admit = v.commit_result(
        rcpt_step1,
        journal,
        exec_cfg,
        invocation_id=p1_admit.details["invocation_id"],
        grant_id=p1_admit.details["grant_id"],
    )
    assert res_admit.verdict == "ADMIT" and res_admit.cached_receipt_content_addr == sl.content_addr(rcpt_step1), f"Trace 01 commit_result failed: {res_admit}"

    # B-1 foreign-issuer mailbox attack MUST refuse GRANT_TARGET_UNAUTHORIZED on live regtest!
    res_mal_b1 = v.verify_invocation(
        inv_mal,
        {"grants": [mal_grant_env], "manifests": manifests},
        ch1,
        journal,
        exec_cfg,
        actual_message_meta={"folder": "Invoices", "sender_domain": "billing.example"},
    )
    assert (res_mal_b1.verdict, res_mal_b1.refusal_code) == ("REFUSE", "GRANT_TARGET_UNAUTHORIZED"), f"Trace 01 B-1 foreign issuer got {res_mal_b1}"

    # Server MIME metadata mismatch negative control (spoofed sender_domain in MIME headers!)
    inv_mime_bad = _mk_inv("mime-bad", ch1.now)
    res_mime_bad = v.verify_invocation(
        inv_mime_bad,
        {"grants": [grant_env], "manifests": manifests},
        ch1,
        journal,
        exec_cfg,
        actual_message_meta={"folder": "Invoices", "sender_domain": "spoofed.invalid"},
    )
    assert (res_mime_bad.verdict, res_mime_bad.refusal_code) == ("REFUSE", "INVOKE_CONSTRAINT_FAILED"), f"Trace 01 MIME mismatch got {res_mime_bad}"

    # Broadcast Alice's P2WPKH seal revocation spend -> observe on peer B mempool BEFORE mining!
    rev_txid, rev_raw = build_signed_tx(
        [{"txid": seal_txid, "vout": 0, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": alice_seal}],
        [(SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(rev_txid_raw := rev_raw)
    seen_mempool_b = rev_txid in cl.rpc(1, "getrawmempool")
    assert seen_mempool_b

    # Fresh pre_effect_recheck discovers mempool revocation strictly from Node B `gettxout` + `getrawmempool`!
    inv_step2 = _mk_inv("step2", ch1.now)
    ch2_dict = obs1.pre_effect_recheck(ch1_dict, [(seal_txid, 0)])
    assert ch2_dict["txs"][rev_txid]["in_mempool"] is True and ch2_dict["txs"][rev_txid]["confirmed_height"] is None
    res_mempool_revoke = v.verify_invocation(
        inv_step2,
        {"grants": [grant_env], "manifests": manifests},
        sv.ChainView(ch2_dict),
        journal,
        exec_cfg,
        actual_message_meta={"folder": "Invoices", "sender_domain": "billing.example"},
    )
    assert (res_mempool_revoke.verdict, res_mempool_revoke.refusal_code) == ("REFUSE", "SEAL_SPENT"), f"Trace 01 mempool revoke got {res_mempool_revoke}"

    cl.mine(1)
    # Cold observer #3 discovers confirmed revocation from Node B!
    inv_step3 = _mk_inv("step3", int(cl.rpc(1, "getblockheader", cl.rpc(1, "getbestblockhash"))["time"]) + 30)
    ch3_dict = cl.new_cold_observer().build_chain_view(wire_objects=[grant_env, inv_step3], manifests=manifests)
    res_closed = v.verify_invocation(
        inv_step3,
        {"grants": [grant_env], "manifests": manifests},
        sv.ChainView(ch3_dict),
        journal,
        exec_cfg,
        actual_message_meta={"folder": "Invoices", "sender_domain": "billing.example"},
    )
    assert (res_closed.verdict, res_closed.refusal_code) == ("REFUSE", "GRANT_CLOSED"), f"Trace 01 post-closure got {res_closed}"

    return {
        "profile": "PROFILE-mail-v1 (mail/read + executor_ref + recipient.mode=name + actual_message_meta + pre_effect_recheck)",
        "cold_observer_adapter": "tools/nc_rpc_adapter.py:ColdNamecoinObserver",
        "cold_observer_initial_gbi_calls": t1_ctr["getblockchaininfo"],
        "pre_effect_recheck_verified": True,
        "name_new_alice_txid": names["id/t1-alice"]["new_txid"],
        "name_firstupdate_alice_txid": names["id/t1-alice"]["first_txid"],
        "name_update_alice_txid": upd_txid,
        "name_update_alice_raw_hex": upd_raw,
        "name_firstupdate_bob_txid": names["id/t1-bob"]["first_txid"],
        "name_firstupdate_host_txid": names["id/t1-mail-host"]["first_txid"],
        "seal_txid": seal_txid,
        "seal_raw_hex": seal_raw,
        "issuance_0x01_txid": iss_txid,
        "issuance_0x01_raw_hex": iss_raw,
        "revoke_txid": rev_txid,
        "revoke_raw_hex": rev_txid_raw,
        "revoke_seen_in_peer_b_mempool_before_mining": seen_mempool_b,
        "verdicts": {
            "initial_mail_read_executor_ref_named_recipient": {"verdict": res_admit.verdict, "outcome": res_admit.outcome},
            "foreign_issuer_b1_mailbox_target": {"verdict": res_mal_b1.verdict, "refusal_code": res_mal_b1.refusal_code},
            "mime_metadata_mismatch": {"verdict": res_mime_bad.verdict, "refusal_code": res_mime_bad.refusal_code},
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
    # Decision 6A (OQ-007): Native P2WSH 2-of-3 BranchKeySpec for institutional disposer_pk LIVE on nc28.0!
    disp1, disp2, disp3 = kp("t2-disp-1"), kp("t2-disp-2"), kp("t2-disp-3")
    disp_spec = {"m": 2, "pks": sorted([disp1["comp"], disp2["comp"], disp3["comp"]])}
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

    vac_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(disp_spec, arb["comp"])}
    stat_pol = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(stat_cap["comp"], stat_end["comp"])}
    rec_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(rec_disp["comp"], rec_arb["comp"])}
    bind_pol = {"kind": "key", "pk": bind_seal["comp"]}
    g1_act_pol = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(disp_spec, g1_seal["comp"])}
    g2_act_pol = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(disp_spec, g2_seal["comp"])}
    delay_blocks = 3
    pend_pol = {
        "kind": "branch",
        "template": "guardian_slot_pending",
        "delay_blocks": delay_blocks,
        "keys": {"disposer": disp_spec, "challenger": chal["comp"], "guardian": g2_seal["comp"]},
    }

    vac_spk, vac_ws = sl.compile_script_policy(vac_pol)
    stat_spk, stat_ws = sl.compile_script_policy(stat_pol)
    rec_spk, rec_ws = sl.compile_script_policy(rec_pol)
    bind_spk, _ = sl.compile_script_policy(bind_pol)
    g1_act_spk, g1_act_ws = sl.compile_script_policy(g1_act_pol)
    g2_act_spk, _ = sl.compile_script_policy(g2_act_pol)
    pend_spk, pend_ws = sl.compile_script_policy(pend_pol)
    assert vac_ws and stat_ws and rec_ws and g1_act_ws and pend_ws

    # Register registry & guardians BEFORE origin 0x09 (ward name registered STRICTLY AFTER 0x09 per R3-B3!)
    names_pre = cl.register_names_batch([
        {"name": "id/t2-civil-registry", "owner_policy": reg_pol, "owner_kp": reg_own, "value_obj": {"link": {"cred": reg_cred["xonly"]}}, "rand_label": "t2-reg"},
        {"name": "id/t2-parent-a", "owner_policy": g1_pol, "owner_kp": g1_own, "value_obj": {"link": {"grant": g1_gr["xonly"]}}, "rand_label": "t2-g1"},
        {"name": "id/t2-carol", "owner_policy": g2_pol, "owner_kp": g2_own, "value_obj": {"link": {"grant": g2_gr["xonly"]}}, "rand_label": "t2-g2"},
    ])

    # Pre-fund origin seals in a single confirmed setup tx (binding=0, status=1, recovery=2, roster=3, slot1_vacant=4)
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
    g1_pin = {"name": "id/t2-parent-a", "owner_policy": g1_pol, "registration": names_pre["id/t2-parent-a"]["registration"]}
    g2_pin = {"name": "id/t2-carol", "owner_policy": g2_pol, "registration": names_pre["id/t2-carol"]["registration"]}

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
            "disposer_pk": disp_spec,
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
        "issuer": {"name": "id/t2-civil-registry", "owner_policy": reg_pol, "registration": names_pre["id/t2-civil-registry"]["registration"], "role_policy": {"m": 1, "pks": [reg_cred["xonly"]]}},
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

    # Anchor 0x09 Origin on-chain FIRST (h_origin < h_firstupdate per R3-B3)!
    anc09_txid, anc09_raw = build_signed_tx(
        [f_orig[1]],
        [(0, op_return_spk(0x09, sl.content_addr(origin_env))), (f_orig[1]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(anc09_raw)
    cl.mine(1)

    # Register id/t2-child-leo (P2WSH 2-of-3 multisig!) strictly AFTER 0x09 origin anchor (R3-B3)!
    names_ward = cl.register_names_batch([
        {"name": "id/t2-child-leo", "owner_policy": ward_ms_pol, "value_obj": {"link": {"grant": ward_gr["xonly"]}}, "rand_label": "t2-ward"},
    ])
    names = {**names_pre, **names_ward}
    # Renew pre-registered names once so none approach regtest's 30-block TTL during the trace!
    cl.update_name_p2wpkh(names["id/t2-civil-registry"], "id/t2-civil-registry", reg_own, {"link": {"cred": reg_cred["xonly"]}})
    cl.update_name_p2wpkh(names["id/t2-parent-a"], "id/t2-parent-a", g1_own, {"link": {"grant": g1_gr["xonly"]}})
    cl.update_name_p2wpkh(names["id/t2-carol"], "id/t2-carol", g2_own, {"link": {"grant": g2_gr["xonly"]}})

    # Update id/t2-child-leo (P2WSH 2-of-3 multisig!) via REAL `createpsbt` + `namepsbt` + BIP-143 P2WSH 2-of-3 witness to bind origin_id!
    p2wsh_psbt_proof = cl.update_name_p2wsh_multisig_via_namepsbt(
        names["id/t2-child-leo"],
        "id/t2-child-leo",
        [wm1, wm3],  # 2-of-3 keys!
        {"link": {"grant": ward_gr["xonly"], "origin": origin_id}},
    )

    # Anchor 0x0c Name Binding strictly AFTER 0x09 height & FIRSTUPDATE, spending origin.binding_seal!
    binding = {
        "binding_mode": "initial",
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

    # 0x12 Initial activation of slot 1 (spending both_of_2(2-of-3 disposer, arbiter) P2WSH -> either_of_2 active seal!)
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
            {"txid": seals_txid, "vout": 4, "value_sat": SEAL_SAT, "kind": "p2wsh_branch_both", "witness_script": vac_ws, "a_spec": disp_spec, "b_spec": arb["comp"], "a_signers": [disp1, disp2], "b_signers": [arb]},
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

    # R1 #1 live proof: Anchor a real historical ward contract (`0x07`) at rev=1 signed by id/t2-parent-a (K1)
    # BEFORE slot 1 halt, BEFORE 0x0f roster transition to rev=2, and BEFORE id/t2-parent-a rotates link.grant K1 -> K2!
    sch_k = kp("t2-school")
    h_init_tip = cl.rpc(1, "getblockcount")
    t_init_tip = int(cl.rpc(1, "getblockheader", cl.rpc(1, "getbestblockhash"))["time"])
    hist_contract = {
        "clause_commitments": [sl.clause_commit(sl.sha256(b"t2-hist-c0").hex(), {"text": "Historical Term 1 Enrollment", "title": "Enrollment"})],
        "contract_salt": sl.sha256(b"t2-hist-csalt").hex(),
        "genesis": cl.genesis_hash,
        "network": "regtest",
        "parties": [
            {"name_pin": {"name": "id/t2-child-leo", "owner_policy": ward_ms_pol, "registration": names["id/t2-child-leo"]["registration"]}, "party_id": "student-1", "role": "student_ward", "ward_origin_id": origin_id},
            {"party_id": "school-1", "role": "school", "signing_policy": {"m": 1, "pks": [sch_k["xonly"]]}},
        ],
        "profile": "school-enrollment-v1",
        "type": "seallink-contract/1",
        "window": {"not_after_height": h_init_tip + 30, "not_before_height": h_init_tip - 5},
    }
    hist_cid = sl.object_id(hist_contract)
    hist_0x07_txid, hist_0x07_raw = build_signed_tx(
        [f_orig[5]],
        [(0, op_return_spk(0x07, hist_cid)), (f_orig[5]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(hist_0x07_raw)
    hist_blk = cl.mine(1)[0]
    h_hist_0x07 = cl.rpc(1, "getblockcount")
    t_hist_0x07 = int(cl.rpc(1, "getblockheader", hist_blk)["time"])
    assent_hist_g1 = sl.sign_guardian_envelope(
        {
            "expires_at": t_hist_0x07 + 200_000,
            "genesis": cl.genesis_hash,
            "guardian_context": {"event_class": "contract_assent", "origin_id": origin_id, "revision": 1, "ward_name": "id/t2-child-leo"},
            "issued_at": t_hist_0x07 - 10,
            "network": "regtest",
            "nonce": sl.sha256(b"t2-hist-a-g1").hex(),
            "party_id": "student-1",
            "party_name": "id/t2-child-leo",
            "party_role": "student_ward",
            "target_id": hist_cid,
            "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [{"slot": 1, "revision": 1, "guardian_name": "id/t2-parent-a", "signers": [g1_gr["sk"]]}],
    )

    # Halt spend of slot 1's active either_of_2(2-of-3 disposer, g1_seal) seal using 2-of-3 disposer branch -> vacant!
    halt_txid, halt_raw = build_signed_tx(
        [
            {"txid": init12_txid, "vout": 0, "value_sat": SEAL_SAT, "kind": "p2wsh_branch_either", "witness_script": g1_act_ws, "a_spec": disp_spec, "b_spec": g1_seal["comp"], "chosen_spec": disp_spec, "signers": [disp1, disp3]},
            f_orig[4],
        ],
        [(SEAL_SAT, vac_spk), (f_orig[4]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(halt_raw)
    cl.mine(1)

    # 0x0f Roster transition to revision 2 (effective_delay_blocks == appointment_delay_blocks per B-15!)
    f_more = cl.split_funding(6, each_sat=2_000_000)
    roster2_p = {
        "arbiter_pk": arb["comp"],
        "challenger_pk": chal["comp"],
        "disposer_pk": disp_spec,
        "effective_delay_blocks": delay_blocks,
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
            {"txid": seals_txid, "vout": 3, "value_sat": SEAL_SAT, "kind": "p2wsh_branch_both", "witness_script": vac_ws, "a_spec": disp_spec, "b_spec": arb["comp"], "a_signers": [disp2, disp3], "b_signers": [arb]},
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
    cl.mine(delay_blocks + 1)  # Wait for roster effective_delay_blocks to elapse BEFORE 0x0d on new_vacant (B-15)!

    # 0x0d Pending appointment of Carol on rev 2 slot 1 -> places guardian_slot_pending CSV P2WSH at lawful pending_vout=2!
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
        "pending_vout": 2,
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
            {"txid": rost0f_txid, "vout": 1, "value_sat": SEAL_SAT, "kind": "p2wsh_branch_both", "witness_script": vac_ws, "a_spec": disp_spec, "b_spec": arb["comp"], "a_signers": [disp1, disp2], "b_signers": [arb]},
            f_more[1],
        ],
        [
            (0, op_return_spk(0x0D, sl.content_addr(g2_rec))),
            (f_more[1]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
            (SEAL_SAT, pend_spk),
        ],
    )
    cl.broadcast_and_wait_peer(pend0d_raw)
    cl.mine(1)  # Pending depth = 1 (< delay_blocks = 3!)

    # Build 0x0e activation spend of guardian_slot_pending CSV branch at vout=2 -> active seal at mandatory vout=0!
    act0e_txid, act0e_raw = build_signed_tx(
        [
            {
                "txid": pend0d_txid,
                "vout": 2,
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

    # Rotate id/t2-parent-a's link.grant K1 -> K2 AFTER h_hist_0x07 (proving R1 #1 survives guardian key rotation too!)
    g1_gr_rot = kp("t2-g1-gr-rot")
    g1_rot_txid, _ = cl.update_name_p2wpkh(
        names["id/t2-parent-a"], "id/t2-parent-a", g1_own, {"link": {"grant": g1_gr_rot["xonly"]}}
    )

    # Execute live 0x0c recovery attempt spending recovery_seal (both_of_2), THEN cancel it via P2WSH 2-of-3 OP_NAME_UPDATE carrying 0x10 RECOVERY_CANCEL!
    cand_b2 = {
        "binding_mode": "recovery",
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

    # Build LIVE ChainView via fresh ColdNamecoinObserver (ZERO writer state!) and verify ALL assents (incl. R1 #1 historical survival)!
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
    t2_ctr: dict[str, int] = {}
    ch_dict = cl.new_cold_observer(rpc_counter=t2_ctr).build_chain_view(wire_objects=[origin_bundle], extra_txids=[hist_0x07_txid])
    assert t2_ctr.get("getblockchaininfo", 0) >= 2 and ch_dict["observation_bracket"]["consistent"] is True
    ch = sv.ChainView(ch_dict)
    reg_pin_t2 = {k: origin_env["payload"]["issuer"][k] for k in ("name", "owner_policy", "registration")}
    v = sv.Tier1Verifier(
        pinned_network="regtest",
        pinned_genesis=cl.genesis_hash,
        trusted_origin_issuer_pins=[reg_pin_t2],
        require_jsonschema=True,
        require_observation_bracket=True,
    )
    wstate_chk, werr_chk = v.verify_origin_and_status(origin_bundle, ch)
    assert werr_chk is None and wstate_chk is not None, f"Trace 02 origin status failed: {werr_chk}"
    assert wstate_chk["recovery_events"] and wstate_chk["recovery_events"][0]["outcome"] == "cancelled_restored"
    contract = {
        "clause_commitments": [sl.clause_commit(sl.sha256(b"t2-c0").hex(), {"text": "Enrollment", "title": "Enrollment"})],
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
    # R1 #1 live verification: historical ward contract anchored at h_hist_0x07 (rev=1, K1) SURVIVES 0x0f (rev=2) + K1->K2 rotation!
    r_hist_ok = v.verify_assent(assent_hist_g1, hist_contract, origin_bundle, ch, anchor_height=h_hist_0x07, anchor_time=t_hist_0x07)
    assert (r_self.verdict, r_self.refusal_code) == ("REFUSE", "WARD_AUTONOMOUS_FORBIDDEN"), f"Trace 02 self got {r_self}"
    assert (r_old.verdict, r_old.refusal_code) == ("REFUSE", "GUARDIAN_INACTIVE"), f"Trace 02 old got {r_old}"
    assert r_new.verdict == "ADMIT", f"Trace 02 new Carol got {r_new}"
    assert r_hist_ok.verdict == "ADMIT", f"Trace 02 R1 #1 historical ward contract survival failed: {r_hist_ok}"

    # Decision 1B / R2G-04 live proof: Emancipate id/t2-child-leo via confirmed seallink-capacity/1 (spending status_seal)
    # + P2WSH 2-of-3 custodian handover + adult subject SIGHASH_ALL self-update -> State 4 autonomous assent ADMIT!
    cl.update_name_p2wpkh(names["id/t2-civil-registry"], "id/t2-civil-registry", reg_own, {"link": {"cred": reg_cred["xonly"]}})
    f_s4 = cl.split_funding(3, each_sat=2_000_000)
    adult_own, adult_gr = kp("t2-adult-own"), kp("t2-adult-gr")
    adult_pol = {"kind": "key", "pk": adult_own["comp"]}
    adult_spk, _ = sl.compile_script_policy(adult_pol)
    cap_s4_p = {
        "basis_sha256": sl.sha256(b"t2-capacity-order").hex(),
        "genesis": cl.genesis_hash,
        "issued_at": ch.now,
        "issuer": origin_p["issuer"],
        "network": "regtest",
        "next_status_policy": stat_pol,
        "next_status_vout": 0,
        "origin_id": origin_id,
        "status_prev_outpoint": {"txid": seals_txid, "vout": 1},
        "subject_new_owner_policy": adult_pol,
        "type": "seallink-capacity/1",
    }
    cap_s4_env = sl.sign_envelope(cap_s4_p, [reg_cred["sk"]])
    cap_txid, cap_raw = build_signed_tx(
        [
            {"txid": seals_txid, "vout": 1, "value_sat": SEAL_SAT, "kind": "p2wsh_multisig", "witness_script": stat_ws, "signers": [stat_cap]},
            f_s4[0],
        ],
        [
            (SEAL_SAT, stat_spk),
            (0, op_return_spk(0x09, sl.content_addr(cap_s4_env))),
            (f_s4[0]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(cap_raw)
    cl.mine(1)

    # Custodian P2WSH 2-of-3 handover OP_NAME_UPDATE transferring id/t2-child-leo -> adult_pol
    handover_val = sl.jcs_encode({"link": {"grant": adult_gr["xonly"], "origin": origin_id}})
    handover_spk = sl.encode_name_output("NAME_UPDATE", adult_spk, name=b"id/t2-child-leo", value=handover_val)
    ho_txid, ho_raw = build_signed_tx(
        [
            {"txid": names["id/t2-child-leo"]["current_txid"], "vout": names["id/t2-child-leo"]["current_vout"], "value_sat": MIN_NAME_SAT, "kind": "p2wsh_multisig", "witness_script": ward_ws, "signers": [wm1, wm2]},
            f_s4[1],
        ],
        [(MIN_NAME_SAT, handover_spk), (f_s4[1]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
        version=NAMECOIN_TX_VERSION,
    )
    cl.broadcast_and_wait_peer(ho_raw)
    cl.mine(1)
    names["id/t2-child-leo"]["current_txid"] = ho_txid
    names["id/t2-child-leo"]["current_vout"] = 0
    names["id/t2-child-leo"]["owner_policy"] = adult_pol

    # Adult subject's own SIGHASH_ALL OP_NAME_UPDATE confirming autonomy under adult_pol!
    adult_self_txid, _ = cl.update_name_p2wpkh(
        names["id/t2-child-leo"], "id/t2-child-leo", adult_own, {"link": {"grant": adult_gr["xonly"], "origin": origin_id}}
    )
    origin_bundle_s4 = {**origin_bundle, "capacity_record": cap_s4_env}
    ch_s4_dict = cl.new_cold_observer().build_chain_view(wire_objects=[origin_bundle_s4])
    ch_s4 = sv.ChainView(ch_s4_dict)
    wstate_s4, werr_s4 = v.verify_origin_and_status(origin_bundle_s4, ch_s4)
    assert werr_s4 is None and wstate_s4 is not None and wstate_s4["capacity"] == "autonomous", f"Trace 02 State 4 emancipation failed: {(wstate_s4, werr_s4)}"
    assert wstate_s4["effective_binding"]["owner_policy"] == adult_pol
    adult_contract = {
        **copy.deepcopy(contract),
        "contract_salt": sl.sha256(b"t2-adult-csalt").hex(),
        "parties": [
            {"name_pin": {"name": "id/t2-child-leo", "owner_policy": adult_pol, "registration": names["id/t2-child-leo"]["registration"]}, "party_id": "student-1", "role": "student_adult", "signing_policy": {"m": 1, "pks": [adult_gr["xonly"]]}},
            {"party_id": "school-1", "role": "school", "signing_policy": {"m": 1, "pks": [sch_k["xonly"]]}},
        ],
        "window": {"not_after_height": ch_s4.tip_height + 20, "not_before_height": ch_s4.tip_height - 10},
    }
    assent_adult_s4 = sl.sign_envelope(
        {
            "expires_at": ch_s4.now + 100_000,
            "genesis": cl.genesis_hash,
            "issued_at": ch_s4.now - 10,
            "network": "regtest",
            "nonce": sl.sha256(b"t2-adult-s4-assent").hex(),
            "party_id": "student-1",
            "party_name": "id/t2-child-leo",
            "party_role": "student_adult",
            "target_id": sl.object_id(adult_contract),
            "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [adult_gr["sk"]],
    )
    r_adult_s4 = v.verify_assent(assent_adult_s4, adult_contract, origin_bundle_s4, ch_s4)
    assert r_adult_s4.verdict == "ADMIT", f"Trace 02 Decision 1B State-4 autonomous assent failed: {r_adult_s4}"

    return {
        "decision_6a_branch_key_spec_2of3_verified": True,
        "p2wsh_2of3_namepsbt_update": p2wsh_psbt_proof,
        "origin_seals_txid": seals_txid,
        "origin_0x09_txid": anc09_txid,
        "origin_0x09_raw_hex": anc09_raw,
        "binding_0x0c_txid": anc0c_txid,
        "binding_0x0c_raw_hex": anc0c_raw,
        "init_0x12_txid": init12_txid,
        "init_0x12_raw_hex": init12_raw,
        "historical_ward_contract_0x07_txid": hist_0x07_txid,
        "historical_ward_contract_anchor_height": h_hist_0x07,
        "guardian_1_key_rotation_txid": g1_rot_txid,
        "halt_either_of_2_txid": halt_txid,
        "halt_either_of_2_raw_hex": halt_raw,
        "roster_0x0f_txid": rost0f_txid,
        "roster_0x0f_raw_hex": rost0f_raw,
        "pending_0x0d_csv_txid": pend0d_txid,
        "pending_0x0d_csv_raw_hex": pend0d_raw,
        "pending_0x0d_vout": 2,
        "activate_0x0e_active_vout": 0,
        "cold_observer_gbi_calls": t2_ctr["getblockchaininfo"],
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
        "emancipation_capacity_0x09_txid": cap_txid,
        "emancipation_handover_txid": ho_txid,
        "emancipation_adult_self_update_txid": adult_self_txid,
        "verdicts": {
            "ward_self_assent": {"verdict": r_self.verdict, "refusal_code": r_self.refusal_code},
            "halted_guardian_assent": {"verdict": r_old.verdict, "refusal_code": r_old.refusal_code},
            "csv_activated_successor_assent": {"verdict": r_new.verdict, "outcome": r_new.outcome},
            "historical_ward_contract_survives_0x0f_and_key_rot": {"verdict": r_hist_ok.verdict, "outcome": r_hist_ok.outcome},
            "decision_1b_state4_emancipated_autonomous_assent": {"verdict": r_adult_s4.verdict, "outcome": r_adult_s4.outcome},
        },
    }


def run_trace_03(cl: RegtestCluster) -> dict[str, Any]:
    """Trace 03: Real depth-2 delegation (parent seconds:3600 pool + 2 live row coins + sibling row_ordinal
    1 & 2 + crash/restart recovery preserving watermarks & receipt_store), single_use_1_of_2 P2WSH
    (branch-0 grantee 0x11 vs branch-1 issuer revoke), AND TRUC v3 zero-fee P2A CPFP revocation package!"""
    alice_own = kp("t3-alice-own")
    alice_gr = kp("t3-alice-gr")
    alice_p_seal = kp("t3-alice-pseal")
    host_own = kp("t3-host-own")
    host_rcpt = kp("t3-host-rcpt")
    su_iss = kp("t3-su-iss")
    su_gr1 = kp("t3-su-gr1")
    su_gr2 = kp("t3-su-gr2")
    agent_req = kp("t3-agent-req")
    # Depth-2 delegation keys
    del_k = kp("t3-del-key")
    row_k = kp("t3-row-key")
    cseal_k = kp("t3-cseal-key")
    child_req = kp("t3-child-req")

    alice_pol = {"kind": "key", "pk": alice_own["comp"]}
    host_pol = {"kind": "key", "pk": host_own["comp"]}
    pseal_pol = {"kind": "key", "pk": alice_p_seal["comp"]}
    row_pol = {"kind": "key", "pk": row_k["comp"]}
    cseal_pol = {"kind": "key", "pk": cseal_k["comp"]}
    su1_pol = {"kind": "branch", "template": "single_use_1_of_2", "keys": {"issuer": su_iss["comp"], "grantee": su_gr1["comp"]}}
    su2_pol = {"kind": "branch", "template": "single_use_1_of_2", "keys": {"issuer": su_iss["comp"], "grantee": su_gr2["comp"]}}

    pseal_spk, _ = sl.compile_script_policy(pseal_pol)
    row_spk, _ = sl.compile_script_policy(row_pol)
    cseal_spk, _ = sl.compile_script_policy(cseal_pol)
    su1_spk, su1_ws = sl.compile_script_policy(su1_pol)
    su2_spk, su2_ws = sl.compile_script_policy(su2_pol)
    assert su1_ws and su2_ws

    host_man = {
        "network": "regtest",
        "owner": "id/t3-mail-host",
        "seq": 1,
        "service": {
            "actions": ["mail/read", "mail/send"],
            "endpoint": "https://mail-t3.regtest.invalid/seallink",
            "receipt_key": host_rcpt["xonly"],
            "service_type": "mail",
            "tls_spki_sha256": sl.sha256(b"t3-mail-host-tls-spki").hex(),
        },
        "type": "seallink-manifest/1",
    }
    host_man_ca = sl.content_addr(host_man)
    names_h = cl.register_names_batch([
        {"name": "id/t3-mail-host", "owner_policy": host_pol, "owner_kp": host_own, "value_obj": {"m": {"h": host_man_ca, "s": 1}}, "rand_label": "t3-host"},
    ])
    host_pin_t3 = {"name": "id/t3-mail-host", "owner_policy": host_pol, "registration": names_h["id/t3-mail-host"]["registration"]}
    alice_man = {
        "network": "regtest",
        "owner": "id/t3-alice",
        "providers": [
            {"label": lbl, "provider": host_pin_t3, "service_type": "mail"}
            for lbl in ("del", "su1", "su2", "p2a")
        ],
        "seq": 1,
        "type": "seallink-manifest/1",
    }
    alice_man_ca = sl.content_addr(alice_man)
    names_a = cl.register_names_batch([
        {"name": "id/t3-alice", "owner_policy": alice_pol, "owner_kp": alice_own, "value_obj": {"link": {"grant": alice_gr["xonly"]}, "m": {"h": alice_man_ca, "s": 1}}, "rand_label": "t3-alice"},
    ])
    names = {**names_h, **names_a}
    cl.update_name_p2wpkh(names["id/t3-mail-host"], "id/t3-mail-host", host_own, {"m": {"h": host_man_ca, "s": 1}})
    t3_manifests = {host_man_ca: host_man, alice_man_ca: alice_man}

    f = cl.split_funding(8, each_sat=10_000_000)
    # Tx 1: Even vouts = seals, Odd vouts = companion linkage coins (seal_vout + 1 per R3-H1!)
    seals_txid, seals_raw = build_signed_tx(
        [f[0]],
        [
            (1_500_000, pseal_spk),          # vout 0: revocable seal for TRUC v3 P2A revocation
            (SEAL_SAT, cl.fund_key["p2wpkh_spk"]),  # vout 1: linkage for grev
            (SEAL_SAT, su1_spk),             # vout 2: single_use_1_of_2 #1 (grantee branch 0 + 0x11)
            (SEAL_SAT, cl.fund_key["p2wpkh_spk"]),  # vout 3: linkage for su1
            (SEAL_SAT, su2_spk),             # vout 4: single_use_1_of_2 #2 (issuer branch 1 revoke)
            (SEAL_SAT, cl.fund_key["p2wpkh_spk"]),  # vout 5: linkage for su2
            (SEAL_SAT, pseal_spk),           # vout 6: depth-2 parent grant seal
            (SEAL_SAT, cl.fund_key["p2wpkh_spk"]),  # vout 7: linkage for parent
            (SEAL_SAT, cseal_spk),           # vout 8: child #1 (row 1) seal
            (SEAL_SAT, cl.fund_key["p2wpkh_spk"]),  # vout 9: linkage for child #1
            (SEAL_SAT, cseal_spk),           # vout 10: child #2 (row 2) seal
            (SEAL_SAT, cl.fund_key["p2wpkh_spk"]),  # vout 11: linkage for child #2
            (f[0]["value_sat"] - 1_500_000 - 11 * SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(seals_raw)

    # Tx 2: 2 contiguous live row coins for depth-2 delegation (vout 0 -> ordinal 1, vout 1 -> ordinal 2)!
    rows_txid, rows_raw = build_signed_tx(
        [f[6]],
        [
            (SEAL_SAT, row_spk),  # vout 0 -> row ordinal 1
            (SEAL_SAT, row_spk),  # vout 1 -> row ordinal 2
            (f[6]["value_sat"] - 2 * SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(rows_raw)
    recent_blk = cl.mine(1)[0]
    tip_h = cl.rpc(1, "getblockcount")
    tip_time = int(cl.rpc(1, "getblockheader", recent_blk)["time"])

    exec_ref = {"key": host_rcpt["xonly"], "name": "id/t3-mail-host"}
    exec_cfg = {**exec_ref, "pin": host_pin_t3}

    # --- Part A: Real Depth-2 Delegation + Sibling row_ordinal (1 & 2) + Crash/Restart Recovery ---
    parent_gp = {
        "capabilities": [{"action": "mail/read", "quotas": [{"kind": "seallink/count", "max": "10", "resource": "mailbox:id/t3-alice:del", "unit": "calls", "window": "seconds:3600"}], "target": "mailbox:id/t3-alice:del", "where": {}}],
        "delegate": {
            "child_seal_key": cseal_k["comp"],
            "groups": [{
                "ranges": [{"count": 2, "first": 0, "script_policy": row_pol, "txid": rows_txid}],
                "template": {
                    "capabilities": [{"action": "mail/read", "quotas": [{"kind": "seallink/count", "max": "2", "resource": "mailbox:id/t3-alice:del", "unit": "calls", "window": "seconds:3600"}], "target": "mailbox:id/t3-alice:del", "where": {}}],
                    "executor": exec_ref,
                    "notary_mode": "none",
                    "recipient_rule": {"key": child_req["xonly"], "mode": "exact_key"},
                },
            }],
            "key": del_k["xonly"],
            "pools": [{"kind": "seallink/count", "max": "4", "resource": "mailbox:id/t3-alice:del", "unit": "calls", "window": "seconds:3600"}],
        },
        "executor": exec_ref,
        "genesis": cl.genesis_hash,
        "issuer": {"name": "id/t3-alice", "owner_policy": alice_pol, "registration": names["id/t3-alice"]["registration"], "role_policy": {"m": 1, "pks": [alice_gr["xonly"]]}},
        "network": "regtest",
        "not_after_height": tip_h + 25,
        "not_before_height": tip_h - 1,
        "recent_block": recent_blk,
        "recipient": {"key": agent_req["xonly"], "mode": "key"},
        "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": pseal_pol, "txid": seals_txid, "vout": 6}},
        "type": "seallink-grant/1",
    }
    parent_env = sl.sign_envelope(parent_gp, [alice_gr["sk"]])
    parent_gid = sl.object_id(parent_gp)

    def _mk_child(ordinal: int, seal_vout: int, row_max: str) -> tuple[dict[str, Any], str]:
        cp = {
            "capabilities": [{"action": "mail/read", "quotas": [{"kind": "seallink/count", "max": row_max, "resource": "mailbox:id/t3-alice:del", "unit": "calls", "window": "seconds:3600"}], "target": "mailbox:id/t3-alice:del", "where": {}}],
            "executor": exec_ref,
            "genesis": cl.genesis_hash,
            "network": "regtest",
            "not_after_height": tip_h + 24,
            "not_before_height": tip_h - 1,
            "parent": {"grant_id": parent_gid, "ordinal": ordinal},
            "recent_block": recent_blk,
            "recipient": {"key": child_req["xonly"], "mode": "key"},
            "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": cseal_pol, "txid": seals_txid, "vout": seal_vout}},
            "type": "seallink-grant/1",
        }
        return sl.sign_envelope(cp, [del_k["sk"]]), sl.object_id(cp)

    c1_env, c1_gid = _mk_child(1, 8, "2")
    c2_env, c2_gid = _mk_child(2, 10, "2")

    def _mk_su_grant(vout: int, pol: dict[str, Any], tag: str) -> tuple[dict[str, Any], str]:
        tgt = f"mailbox:id/t3-alice:{tag}"
        gp = {
            "capabilities": [{
                "action": "mail/send",
                "quotas": [{"kind": "seallink/count", "max": "5", "resource": tgt, "unit": "messages", "window": "term"}],
                "target": tgt,
                "where": {},
            }],
            "executor": exec_ref,
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

    g1_env, g1_id = _mk_su_grant(2, su1_pol, "su1")
    g2_env, g2_id = _mk_su_grant(4, su2_pol, "su2")
    gp_rev = {
        "capabilities": [{
            "action": "mail/send",
            "quotas": [{"kind": "seallink/count", "max": "5", "resource": "mailbox:id/t3-alice:p2a", "unit": "messages", "window": "term"}],
            "target": "mailbox:id/t3-alice:p2a",
            "where": {},
        }],
        "executor": exec_ref,
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

    def _issue(g_env: dict[str, Any], gid: str, link_vout: int) -> tuple[str, str]:
        d_hex = sl.signing_digest({"genesis": cl.genesis_hash, "grant_content_addr": sl.content_addr(g_env), "grant_id": gid, "type": "seallink-issuance/1"}).hex()
        txid, raw_h = build_signed_tx(
            [{"txid": seals_txid, "vout": link_vout, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": cl.fund_key}],
            [(0, op_return_spk(0x01, d_hex)), (SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
        )
        cl.broadcast_and_wait_peer(raw_h)
        return txid, raw_h

    def _issue_child_spending_row(c_env: dict[str, Any], c_gid: str, row_vout: int, link_vout: int) -> tuple[str, str]:
        d_hex = sl.signing_digest({"genesis": cl.genesis_hash, "grant_content_addr": sl.content_addr(c_env), "grant_id": c_gid, "type": "seallink-issuance/1"}).hex()
        txid, raw_h = build_signed_tx(
            [
                {"txid": rows_txid, "vout": row_vout, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": row_k},
                {"txid": seals_txid, "vout": link_vout, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": cl.fund_key},
            ],
            [(0, op_return_spk(0x01, d_hex)), (2 * SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
        )
        cl.broadcast_and_wait_peer(raw_h)
        return txid, raw_h

    iss_par_txid, iss_par_raw = _issue(parent_env, parent_gid, 7)
    iss_c1_txid, iss_c1_raw = _issue_child_spending_row(c1_env, c1_gid, 0, 9)
    iss_c2_txid, iss_c2_raw = _issue_child_spending_row(c2_env, c2_gid, 1, 11)
    iss1_txid, iss1_raw = _issue(g1_env, g1_id, 3)
    iss2_txid, iss2_raw = _issue(g2_env, g2_id, 5)
    issr_txid, issr_raw = _issue(grev_env, grev_id, 1)
    cl.mine(1)

    # Child #1 single_use: Grantee spends single_use_1_of_2 via BRANCH 0 (selector=b"") + 0x11 OP_RETURN!
    inv1_env = sl.sign_envelope(
        {
            "action": "mail/send",
            "arguments": {"body_sha256": sl.sha256(b"su1-body").hex(), "size_bytes": "128", "subject": "SU1", "to": "su1@example.com"},
            "executor": exec_ref,
            "exp": tip_time + 1200,
            "genesis": cl.genesis_hash,
            "iat": tip_time - 10,
            "network": "regtest",
            "nonce": sl.sha256(b"t3-su1-n").hex(),
            "proof_path": [{"grant_id": g1_id, "issuance_txid": iss1_txid}],
            "target": "mailbox:id/t3-alice:su1",
            "type": "seallink-invocation/1",
        },
        [agent_req["sk"]],
    )
    use1_txid, use1_raw = build_signed_tx(
        [
            {"txid": seals_txid, "vout": 2, "value_sat": SEAL_SAT, "kind": "p2wsh_single_key_branch", "witness_script": su1_ws, "signer": su_gr1, "selectors": [b""]},
            f[4],
        ],
        [
            (0, op_return_spk(0x11, sl.content_addr(inv1_env))),
            (f[4]["value_sat"] + SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(use1_raw)

    # Child #2 single_use: Issuer revokes single_use_1_of_2 via BRANCH 1 (selector=b"\x01", NO 0x11)!
    rev2_txid, rev2_raw = build_signed_tx(
        [{"txid": seals_txid, "vout": 4, "value_sat": SEAL_SAT, "kind": "p2wsh_single_key_branch", "witness_script": su2_ws, "signer": su_iss, "selectors": [b"\x01"]}],
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
    peer_saw_p2a = cl.until(lambda: {p2a_parent_txid, p2a_child_txid} <= set(cl.rpc(1, "getrawmempool")), limit=180.0)
    assert peer_saw_p2a, "Peer B did not observe TRUC v3 P2A revocation package in mempool before mining!"

    # Build LIVE ChainView via fresh ColdNamecoinObserver (ZERO writer state!)
    ch_dict = cl.new_cold_observer().build_chain_view(
        wire_objects=[parent_env, c1_env, c2_env, g1_env, g2_env, grev_env, inv1_env],
        extra_txids=[iss_par_txid, iss_c1_txid, iss_c2_txid, iss1_txid, iss2_txid, issr_txid, use1_txid],
        manifests=t3_manifests,
    )
    ch = sv.ChainView(ch_dict)
    v = sv.Tier1Verifier(pinned_network="regtest", pinned_genesis=cl.genesis_hash, require_jsonschema=True, require_observation_bracket=True)
    journal = sv.FencedJournal(sl.sha256(b"t3-regtest-j").hex())

    # 1. Depth-2 sibling row_ordinal (row 1 + row 2) + pool enforcement + crash/restart recovery!
    def _mk_del_inv(child_gid: str, child_itx: str, tag: str) -> dict[str, Any]:
        return sl.sign_envelope(
            {
                "action": "mail/read",
                "arguments": {"folder": "INBOX", "message_id": f"del-{tag}"},
                "executor": exec_ref,
                "exp": ch.now + 600,
                "genesis": cl.genesis_hash,
                "iat": ch.now - 10,
                "network": "regtest",
                "nonce": sl.sha256(f"t3-del-{tag}".encode()).hex(),
                "proof_path": [{"grant_id": parent_gid, "issuance_txid": iss_par_txid}, {"grant_id": child_gid, "issuance_txid": child_itx}],
                "target": "mailbox:id/t3-alice:del",
                "type": "seallink-invocation/1",
            },
            [child_req["sk"]],
        )

    del_bundle = {"grants": [parent_env, c1_env, c2_env], "manifests": t3_manifests}
    inv_r1_1 = _mk_del_inv(c1_gid, iss_c1_txid, "r1-1")
    rcpt_r1_1 = sl.sign_envelope(
        {
            "action": "mail/read",
            "executor_name": exec_cfg["name"],
            "genesis": cl.genesis_hash,
            "grant_id": c1_gid,
            "invocation_id": sl.object_id(inv_r1_1["payload"]),
            "network": "regtest",
            "outcome": "executed",
            "recorded_at": ch.now,
            "result_sha256": sl.sha256(b"t3-r1-1-res").hex(),
            "settlements": [
                {"account": "own", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "mailbox:id/t3-alice:del", "settled": "1", "unit": "calls", "window": "seconds:3600"},
                {"account": "row", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "mailbox:id/t3-alice:del", "row_ordinal": 1, "settled": "1", "unit": "calls", "window": "seconds:3600"},
            ],
            "tip_hash": ch.tip_hash,
            "tip_height": ch.tip_height,
            "type": "seallink-receipt/1",
        },
        [host_rcpt["sk"]],
    )
    r_d_r1 = v.verify_invocation(inv_r1_1, del_bundle, ch, journal, exec_cfg, receipt_env_for_cache=rcpt_r1_1)
    assert r_d_r1.verdict == "ADMIT", f"Trace 03 depth-2 row 1 failed: {r_d_r1}"
    inv_r2_1 = _mk_del_inv(c2_gid, iss_c2_txid, "r2-1")
    rcpt_r2_1 = sl.sign_envelope(
        {**rcpt_r1_1["payload"], "grant_id": c2_gid, "invocation_id": sl.object_id(inv_r2_1["payload"]), "result_sha256": sl.sha256(b"t3-r2-1-res").hex(),
         "settlements": [{"account": "own", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "mailbox:id/t3-alice:del", "settled": "1", "unit": "calls", "window": "seconds:3600"},
                         {"account": "row", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "mailbox:id/t3-alice:del", "row_ordinal": 2, "settled": "1", "unit": "calls", "window": "seconds:3600"}]},
        [host_rcpt["sk"]],
    )
    inv_r2_2 = _mk_del_inv(c2_gid, iss_c2_txid, "r2-2")
    rcpt_r2_2 = sl.sign_envelope({**rcpt_r2_1["payload"], "invocation_id": sl.object_id(inv_r2_2["payload"]), "result_sha256": sl.sha256(b"t3-r2-2-res").hex()}, [host_rcpt["sk"]])
    r_d_r2_1 = v.verify_invocation(inv_r2_1, del_bundle, ch, journal, exec_cfg, receipt_env_for_cache=rcpt_r2_1)
    r_d_r2_2 = v.verify_invocation(inv_r2_2, del_bundle, ch, journal, exec_cfg, receipt_env_for_cache=rcpt_r2_2)
    assert r_d_r2_1.verdict == "ADMIT" and r_d_r2_2.verdict == "ADMIT", f"Trace 03 row 2 calls failed: {r_d_r2_1}, {r_d_r2_2}"
    # Row 2 now at 2/2 -> next call on row 2 MUST refuse QUOTA_EXCEEDED with 0 writes!
    before_over = len(journal.entries)
    r_d_over = v.verify_invocation(_mk_del_inv(c2_gid, iss_c2_txid, "r2-over"), del_bundle, ch, journal, exec_cfg)
    assert (r_d_over.verdict, r_d_over.refusal_code) == ("REFUSE", "QUOTA_EXCEEDED") and len(journal.entries) == before_over

    # Persist journal + receipt_store to JSON, reconstruct fresh FencedJournal via witness-verified replay_persisted_entries!
    persisted_entries = json.loads(json.dumps(journal.entries))
    persisted_store = json.loads(json.dumps(journal.receipt_store))
    restarted_j = sv.FencedJournal.replay_persisted_entries(
        journal.journal_id, persisted_entries, receipt_store=persisted_store,
        witness_pos=journal.witness_pos, witness_commitment=journal.witness_commitment,
    )
    assert restarted_j.check_continuity() is None
    assert restarted_j.commitment == journal.commitment and restarted_j.quotas_used == journal.quotas_used
    assert restarted_j.quota_watermarks == journal.quota_watermarks
    # H-8: truncated rollback relative to witness_pos MUST refuse JOURNAL_LOST!
    rollback_j = sv.FencedJournal.replay_persisted_entries(
        journal.journal_id, persisted_entries[:-1], receipt_store=persisted_store,
        witness_pos=journal.witness_pos, witness_commitment=journal.witness_commitment,
    )
    assert rollback_j.check_continuity() == "JOURNAL_LOST", f"Expected JOURNAL_LOST on rollback, got {rollback_j.check_continuity()}"
    # Check distinct row_ordinal accounts preserved!
    r1_scopes = [v_u for (sc, _q, _b), v_u in restarted_j.quotas_used.items() if sc == f"row:{parent_gid}:1"]
    r2_scopes = [v_u for (sc, _q, _b), v_u in restarted_j.quotas_used.items() if sc == f"row:{parent_gid}:2"]
    assert r1_scopes == [1] and r2_scopes == [2], f"Distinct row_ordinal accounts failed: r1={r1_scopes}, r2={r2_scopes}"

    # Post-restart clock rollback (fresh observer clock starting 1s behind persisted journal watermark) MUST refuse QUOTA_CLOCK_REGRESSION!
    ch_back_dict = json.loads(json.dumps(ch_dict))
    ch_back_dict["now"] = ch.now - 1
    ch_back_dict["clock_watermark"] = ch.now - 1
    if isinstance(ch_back_dict.get("rebracket_tip"), dict):
        ch_back_dict["rebracket_tip"]["now"] = ch.now - 1
    r_d_back = v.verify_invocation(_mk_del_inv(c1_gid, iss_c1_txid, "r1-back"), del_bundle, sv.ChainView(ch_back_dict), restarted_j, exec_cfg)
    assert (r_d_back.verdict, r_d_back.refusal_code) == ("REFUSE", "QUOTA_CLOCK_REGRESSION"), f"Post-restart clock rollback got {r_d_back}"

    # Post-restart idempotent retry of row 1 call #1 MUST return exact cached signed receipt with 0 writes!
    before_retry = len(restarted_j.entries)
    r_d_retry = v.verify_invocation(inv_r1_1, del_bundle, ch, restarted_j, exec_cfg)
    assert r_d_retry.verdict == "ADMIT" and len(restarted_j.entries) == before_retry
    assert r_d_retry.cached_receipt_content_addr == sl.content_addr(rcpt_r1_1)

    # Simulated crash before settlement on a fresh journal -> UNCERTAIN!
    crash_j = sv.FencedJournal(sl.sha256(b"t3-crash-j").hex())
    inv_crash = _mk_del_inv(c1_gid, iss_c1_txid, "r1-crash")
    r_d_crash = v.verify_invocation(inv_crash, del_bundle, ch, crash_j, exec_cfg, simulate_crash_before_settlement=True)
    assert r_d_crash.verdict == "UNCERTAIN"

    # 2. Single-use #1 branch-0 0x11 -> two-phase ADMIT + commit_result(real receipt), then new-nonce replay -> INVOKE_REPLAY
    rcpt_su1 = sl.sign_envelope(
        {
            "action": "mail/send",
            "executor_name": exec_cfg["name"],
            "genesis": cl.genesis_hash,
            "grant_id": g1_id,
            "invocation_id": sl.object_id(inv1_env["payload"]),
            "network": "regtest",
            "outcome": "executed",
            "recorded_at": ch.now,
            "result_sha256": sl.sha256(b"t3-su1-res").hex(),
            "settlements": [{"account": "own", "kind": "seallink/count", "released": "0", "reserved": "1", "resource": "mailbox:id/t3-alice:su1", "settled": "1", "unit": "messages", "window": "term"}],
            "tip_hash": ch.tip_hash,
            "tip_height": ch.tip_height,
            "type": "seallink-receipt/1",
        },
        [host_rcpt["sk"]],
    )
    # D8-M3 + R3 Blocker #2: True two-phase self-contained single_use restart recovery strictly from JournalEntry[] + witness!
    p1_su1 = v.admit_and_reserve(inv1_env, {"grants": [g1_env], "manifests": t3_manifests}, ch, restarted_j, exec_cfg, use_txid=use1_txid)
    assert p1_su1.verdict == "ADMIT" and len(p1_su1.journal_writes) == 1, f"Trace 03 su1 Phase 1 failed: {p1_su1}"
    assert p1_su1.journal_writes[0]["entry"]["body"].get("single_use") is True and p1_su1.journal_writes[0]["entry"]["body"].get("use_txid") == use1_txid
    restarted_j = sv.FencedJournal.replay_persisted_entries(
        restarted_j.journal_id,
        json.loads(json.dumps(restarted_j.entries)),
        receipt_store=json.loads(json.dumps(restarted_j.receipt_store)),
        witness_pos=restarted_j.witness_pos,
        witness_commitment=restarted_j.witness_commitment,
    )
    p2_su1 = v.commit_result(
        rcpt_su1,
        restarted_j,
        exec_cfg,
        invocation_id=sl.object_id(inv1_env["payload"]),
        grant_id=g1_id,
    )
    assert p2_su1.verdict == "ADMIT" and len(p2_su1.journal_writes) == 1, f"Trace 03 su1 self-contained Phase 2 failed: {p2_su1}"
    assert p2_su1.journal_writes[0]["entry"]["kind"] == "settlement" and p2_su1.journal_writes[0]["entry"]["body"].get("single_use_consumed") is True and p2_su1.journal_writes[0]["entry"]["body"].get("use_txid") == use1_txid
    r_su1 = p2_su1
    inv1_replay = sl.sign_envelope({**inv1_env["payload"], "nonce": sl.sha256(b"t3-su1-replay").hex()}, [agent_req["sk"]])
    r_su1_rep = v.verify_invocation(inv1_replay, {"grants": [g1_env], "manifests": t3_manifests}, ch, restarted_j, exec_cfg, use_txid=use1_txid)
    assert (r_su1_rep.verdict, r_su1_rep.refusal_code) == ("REFUSE", "INVOKE_REPLAY"), f"Trace 03 su1 replay got {r_su1_rep}"

    # 3. Single-use #2 branch-1 issuer revoke -> SEAL_SPENT -> GRANT_CLOSED
    inv2_env = sl.sign_envelope(
        {
            "action": "mail/send",
            "arguments": {"body_sha256": sl.sha256(b"su2-body").hex(), "size_bytes": "128", "subject": "SU2", "to": "su2@example.com"},
            "executor": exec_ref,
            "exp": ch.now + 600,
            "genesis": cl.genesis_hash,
            "iat": ch.now - 10,
            "network": "regtest",
            "nonce": sl.sha256(b"t3-su2-n1").hex(),
            "proof_path": [{"grant_id": g2_id, "issuance_txid": iss2_txid}],
            "target": "mailbox:id/t3-alice:su2",
            "type": "seallink-invocation/1",
        },
        [agent_req["sk"]],
    )
    r_su2 = v.verify_invocation(inv2_env, {"grants": [g2_env], "manifests": t3_manifests}, ch, restarted_j, exec_cfg)
    assert (r_su2.verdict, r_su2.refusal_code) == ("REFUSE", "SEAL_SPENT"), f"Trace 03 su2 got {r_su2}"
    inv2_sub = sl.sign_envelope({**inv2_env["payload"], "nonce": sl.sha256(b"t3-su2-n2").hex()}, [agent_req["sk"]])
    r_su2_sub = v.verify_invocation(inv2_sub, {"grants": [g2_env], "manifests": t3_manifests}, ch, restarted_j, exec_cfg)
    assert (r_su2_sub.verdict, r_su2_sub.refusal_code) == ("REFUSE", "GRANT_CLOSED"), f"Trace 03 su2 sub got {r_su2_sub}"

    # 4. TRUC v3 P2A-boosted revocation observed in peer B mempool -> SEAL_SPENT!
    inv_p2a = sl.sign_envelope(
        {
            "action": "mail/send",
            "arguments": {"body_sha256": sl.sha256(b"p2a-body").hex(), "size_bytes": "128", "subject": "P2A", "to": "p2a@example.com"},
            "executor": exec_ref,
            "exp": ch.now + 600,
            "genesis": cl.genesis_hash,
            "iat": ch.now - 10,
            "network": "regtest",
            "nonce": sl.sha256(b"t3-p2a-n").hex(),
            "proof_path": [{"grant_id": grev_id, "issuance_txid": issr_txid}],
            "target": "mailbox:id/t3-alice:p2a",
            "type": "seallink-invocation/1",
        },
        [agent_req["sk"]],
    )
    r_p2a = v.verify_invocation(inv_p2a, {"grants": [grev_env], "manifests": t3_manifests}, ch, restarted_j, exec_cfg)
    assert (r_p2a.verdict, r_p2a.refusal_code) == ("REFUSE", "SEAL_SPENT"), f"Trace 03 P2A mempool revoke got {r_p2a}"

    # Mine block and verify BOTH TRUC v3 package txs confirm on peer B!
    tip_p2a = cl.mine(1)[0]
    p2a_confirmed_b = {p2a_parent_txid, p2a_child_txid} <= set(cl.rpc(1, "getblock", tip_p2a, 1)["tx"])
    assert p2a_confirmed_b

    return {
        "cold_observer_adapter": "tools/nc_rpc_adapter.py:ColdNamecoinObserver",
        "seals_txid": seals_txid,
        "depth2_rows_txid": rows_txid,
        "depth2_parent_0x01_txid": iss_par_txid,
        "depth2_child_row1_0x01_txid": iss_c1_txid,
        "depth2_child_row2_0x01_txid": iss_c2_txid,
        "depth2_post_restart_row1_used": r1_scopes[0],
        "depth2_post_restart_row2_used": r2_scopes[0],
        "depth2_post_restart_cached_receipt_ca": r_d_retry.cached_receipt_content_addr,
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
            "depth2_row1_call1": {"verdict": r_d_r1.verdict, "outcome": r_d_r1.outcome},
            "depth2_row2_call1_and_2": {"verdict": r_d_r2_2.verdict, "outcome": r_d_r2_2.outcome},
            "depth2_pool_exceeded": {"verdict": r_d_over.verdict, "refusal_code": r_d_over.refusal_code},
            "depth2_crash_before_settlement": {"verdict": r_d_crash.verdict, "outcome": r_d_crash.outcome},
            "depth2_post_restart_clock_rollback": {"verdict": r_d_back.verdict, "refusal_code": r_d_back.refusal_code},
            "depth2_post_restart_cached_receipt_retry": {"verdict": r_d_retry.verdict, "writes": 0},
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
    vac_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(disp["comp"], arb["comp"])}
    stat_pol = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(stat_cap["comp"], stat_end["comp"])}
    bind_pol = {"kind": "key", "pk": bind_seal["comp"]}
    ga_act_pol = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(disp["comp"], ga_seal["comp"])}
    gb_act_pol = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(disp["comp"], gb_seal["comp"])}
    rec_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(disp["comp"], arb["comp"])}
    gseal_pol = {"kind": "key", "pk": gseal_k["comp"]}

    vac_spk, vac_ws = sl.compile_script_policy(vac_pol)
    stat_spk, _ = sl.compile_script_policy(stat_pol)
    bind_spk, _ = sl.compile_script_policy(bind_pol)
    ga_act_spk, _ = sl.compile_script_policy(ga_act_pol)
    gb_act_spk, _ = sl.compile_script_policy(gb_act_pol)
    rec_spk, _ = sl.compile_script_policy(rec_pol)
    gseal_spk, _ = sl.compile_script_policy(gseal_pol)
    assert vac_ws

    # Register registry & guardians BEFORE origin 0x09 (id/t4-ward registered strictly AFTER 0x09 per R3-B3!)
    names_pre = cl.register_names_batch([
        {"name": "id/t4-civil-registry", "owner_policy": reg_pol, "owner_kp": reg_own, "value_obj": {"link": {"cred": reg_cred["xonly"]}}, "rand_label": "t4-reg"},
        {"name": "id/t4-guardian-a", "owner_policy": ga_pol, "owner_kp": ga_own, "value_obj": {"link": {"grant": ga_gr["xonly"]}}, "rand_label": "t4-ga"},
        {"name": "id/t4-guardian-b", "owner_policy": gb_pol, "owner_kp": gb_own, "value_obj": {"link": {"grant": gb_gr["xonly"]}}, "rand_label": "t4-gb"},
    ])

    f = cl.split_funding(7, each_sat=10_000_000)
    seals_txid, seals_raw = build_signed_tx(
        [f[0]],
        [
            (SEAL_SAT, bind_spk),                    # 0: binding_seal
            (SEAL_SAT, stat_spk),                    # 1: status_seal
            (SEAL_SAT, vac_spk),                     # 2: roster_seal
            (SEAL_SAT, vac_spk),                     # 3: slot 1 vacant
            (SEAL_SAT, vac_spk),                     # 4: slot 2 vacant
            (SEAL_SAT, rec_spk),                     # 5: recovery_seal (D-2)
            (SEAL_SAT, gseal_spk),                   # 6: g_2of2 grant seal
            (SEAL_SAT, cl.fund_key["p2wpkh_spk"]),   # 7: g_2of2 linkage (R3-H1)
            (SEAL_SAT, gseal_spk),                   # 8: g_1of2 grant seal
            (SEAL_SAT, cl.fund_key["p2wpkh_spk"]),   # 9: g_1of2 linkage (R3-H1)
            (f[0]["value_sat"] - 10 * SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
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
    ga_pin = {"name": "id/t4-guardian-a", "owner_policy": ga_pol, "registration": names_pre["id/t4-guardian-a"]["registration"]}
    gb_pin = {"name": "id/t4-guardian-b", "owner_policy": gb_pol, "registration": names_pre["id/t4-guardian-b"]["registration"]}

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
        "issuer": {"name": "id/t4-civil-registry", "owner_policy": reg_pol, "registration": names_pre["id/t4-civil-registry"]["registration"], "role_policy": {"m": 1, "pks": [reg_cred["xonly"]]}},
        "name_recovery": {
            "arbiter_pk": arb["comp"],
            "delay_blocks": 144,
            "disposer_pk": disp["comp"],
            "mode": "dual_party_delayed",
            "recovery_seal": {"script_policy": rec_pol, "txid": seals_txid, "vout": 5},
        },
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

    # Register id/t4-ward strictly AFTER 0x09 origin anchor (R3-B3), and renew pre-registered names once!
    names_ward = cl.register_names_batch([
        {"name": "id/t4-ward", "owner_policy": ward_pol, "owner_kp": ward_own, "value_obj": {"link": {"grant": ga_gr["xonly"], "origin": origin_id}}, "rand_label": "t4-ward"},
    ])
    names = {**names_pre, **names_ward}
    cl.update_name_p2wpkh(names["id/t4-civil-registry"], "id/t4-civil-registry", reg_own, {"link": {"cred": reg_cred["xonly"]}})
    cl.update_name_p2wpkh(names["id/t4-guardian-a"], "id/t4-guardian-a", ga_own, {"link": {"grant": ga_gr["xonly"]}})
    cl.update_name_p2wpkh(names["id/t4-guardian-b"], "id/t4-guardian-b", gb_own, {"link": {"grant": gb_gr["xonly"]}})
    recent_blk = cl.rpc(1, "getbestblockhash")
    tip_h = cl.rpc(1, "getblockcount")
    tip_time = int(cl.rpc(1, "getblockheader", recent_blk)["time"])

    binding = {
        "binding_mode": "initial",
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

    def _mk_ward_grant(ev_cls: str, approvs: list[dict[str, Any]], seal_vout: int, link_vout: int):
        gp = {
            "capabilities": [{"action": "agent/guardian-message", "target": f"ward:{origin_id}", "where": {}}],
            "executor": {"key": station_rcpt["xonly"], "name": "id/t4-station"},
            "genesis": cl.genesis_hash,
            "guardian_context": {"event_class": ev_cls, "origin_id": origin_id, "revision": 1, "ward_name": "id/t4-ward"},
            "issuer": {"name": "id/t4-ward", "owner_policy": ward_pol, "registration": names["id/t4-ward"]["registration"]},
            "network": "regtest",
            "not_after_height": tip_h + 15,
            "not_before_height": tip_h - 1,
            "recent_block": recent_blk,
            "recipient": {"key": bridge_req["xonly"], "mode": "key"},
            "revocation": {"construction": "W", "kind": "revocable", "mode": "seal", "seal": {"script_policy": gseal_pol, "txid": seals_txid, "vout": seal_vout}},
            "type": "seallink-grant/1",
        }
        genv = sl.sign_guardian_envelope(gp, approvs)
        gid = sl.object_id(gp)
        d_hex = sl.signing_digest({"genesis": cl.genesis_hash, "grant_content_addr": sl.content_addr(genv), "grant_id": gid, "type": "seallink-issuance/1"}).hex()
        itx, iraw = build_signed_tx(
            [{"txid": seals_txid, "vout": link_vout, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": cl.fund_key}],
            [(0, op_return_spk(0x01, d_hex)), (SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
        )
        cl.broadcast_and_wait_peer(iraw)
        return genv, gid, itx, iraw

    g_2of2, gid_2of2, iss_ok_txid, iss_ok_raw = _mk_ward_grant(
        "effect_grant",
        [
            {"slot": 1, "revision": 1, "guardian_name": "id/t4-guardian-a", "signers": [ga_gr["sk"]]},
            {"slot": 2, "revision": 1, "guardian_name": "id/t4-guardian-b", "signers": [gb_gr["sk"]]},
        ],
        6,
        7,
    )
    g_1of2, gid_1of2, iss_bad_txid, iss_bad_raw = _mk_ward_grant(
        "routine_read",
        [{"slot": 1, "revision": 1, "guardian_name": "id/t4-guardian-a", "signers": [ga_gr["sk"]]}],
        8,
        9,
    )
    cl.mine(1)

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
    t4_ctr: dict[str, int] = {}
    ch_dict = cl.new_cold_observer(rpc_counter=t4_ctr).build_chain_view(
        wire_objects=[origin_bundle, g_2of2, g_1of2],
        extra_txids=[iss_ok_txid, iss_bad_txid],
    )
    assert t4_ctr.get("getblockchaininfo", 0) >= 2 and ch_dict["observation_bracket"]["consistent"] is True
    ch = sv.ChainView(ch_dict)
    reg_pin_t4 = {k: origin_env["payload"]["issuer"][k] for k in ("name", "owner_policy", "registration")}
    v = sv.Tier1Verifier(
        pinned_network="regtest",
        pinned_genesis=cl.genesis_hash,
        trusted_origin_issuer_pins=[reg_pin_t4],
        require_jsonschema=True,
        require_observation_bracket=True,
    )
    journal = sv.FencedJournal(sl.sha256(b"t4-regtest-j").hex())

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

    inv_bad = _mk_agm_inv(gid_1of2, iss_bad_txid, "1of2")
    inv_ok = _mk_agm_inv(gid_2of2, iss_ok_txid, "2of2")
    gm_result = {
        "authority_frame_sha256": sl.sha256(b"t4-authority-frame:" + raw_msg).hex(),
        "delivered": True,
        "message_sha256": msg_sha,
        "verified_guardians": ["id/t4-guardian-a", "id/t4-guardian-b"],
        "verified_revision": 1,
    }
    rcpt_ok = sl.sign_envelope(
        {
            "action": "agent/guardian-message",
            "executor_name": "id/t4-station",
            "genesis": cl.genesis_hash,
            "grant_id": gid_2of2,
            "invocation_id": sl.object_id(inv_ok["payload"]),
            "network": "regtest",
            "outcome": "executed",
            "recorded_at": ch.now,
            "result_sha256": sl.sha256(sl.jcs_encode(gm_result)).hex(),
            "tip_hash": ch.tip_hash,
            "tip_height": ch.tip_height,
            "type": "seallink-receipt/1",
        },
        [station_rcpt["sk"]],
    )
    rcpt_ok_ca = sl.content_addr(rcpt_ok)

    # R1-A: True two-phase execution! Phase 1 admit_and_reserve() WITHOUT upfront receipt ->
    # execute effect -> sign real receipt -> Phase 2 commit_result(rcpt_ok) -> separate-process restart!
    r_bad = v.verify_invocation(inv_bad, {"grants": [g_1of2], "origin_bundle": origin_bundle}, ch, journal, exec_cfg, raw_message_bytes=raw_msg)
    p1_t4 = v.admit_and_reserve(inv_ok, {"grants": [g_2of2], "origin_bundle": origin_bundle}, ch, journal, exec_cfg, raw_message_bytes=raw_msg)
    assert (r_bad.verdict, r_bad.refusal_code) == ("REFUSE", "GUARDIAN_QUORUM_UNMET"), f"Trace 04 downgrade got {r_bad}"
    assert p1_t4.verdict == "ADMIT" and len(p1_t4.journal_writes) == 1, f"Trace 04 Phase 1 failed: {p1_t4}"
    r_ok = v.commit_result(
        rcpt_ok,
        journal,
        exec_cfg,
        invocation_id=p1_t4.details["invocation_id"],
        grant_id=p1_t4.details["grant_id"],
    )
    assert r_ok.verdict == "ADMIT" and len(r_ok.journal_writes) == 1 and r_ok.journal_writes[0]["entry"]["kind"] == "settlement", f"Trace 04 Phase 2 commit_result failed: {r_ok}"

    # Separate-process witness-verified restart recovery proof for quota-free late-receipt commit (R1-A, SL-GRNT-014, SL-AGNT-003)!
    restart_file = cl.work_dir / "t4-quota-free-restart.json"
    restart_file.write_text(
        json.dumps(
            {
                "journal_id": journal.journal_id,
                "commitment": journal.commitment,
                "witness_pos": journal.witness_pos,
                "witness_commitment": journal.witness_commitment,
                "entries": journal.entries,
                "receipt_store": journal.receipt_store,
                "chain": ch_dict,
                "inv_ok": inv_ok,
                "grant": g_2of2,
                "origin_bundle": origin_bundle,
                "exec_cfg": exec_cfg,
                "raw_msg_hex": raw_msg.hex(),
                "genesis": cl.genesis_hash,
                "trusted_origin_issuer_pins": [reg_pin_t4],
                "expected_rcpt_ca": rcpt_ok_ca,
                "expected_rcpt_jcs_hex": sl.jcs_encode(rcpt_ok).hex(),
            }
        ),
        encoding="utf-8",
    )
    child_code = (
        "import json, sys; from pathlib import Path; "
        f"sys.path.insert(0, {str(REPO_ROOT / 'tools')!r}); "
        "import seallink_ref as sl, seallink_verifier as sv; "
        "d = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8')); "
        "rj = sv.FencedJournal.replay_persisted_entries(d['journal_id'], d['entries'], receipt_store=d['receipt_store'], witness_pos=d['witness_pos'], witness_commitment=d['witness_commitment']); "
        "assert rj.check_continuity() is None; "
        "assert rj.commitment == d['commitment']; "
        "assert len(rj.receipts) == 1, f'Expected 1 indexed receipt after restart, got {len(rj.receipts)}'; "
        "inv_id = sl.object_id(d['inv_ok']['payload']); "
        "assert sl.jcs_encode(rj.receipts[inv_id]).hex() == d['expected_rcpt_jcs_hex']; "
        "v = sv.Tier1Verifier(pinned_network='regtest', pinned_genesis=d['genesis'], trusted_origin_issuer_pins=d['trusted_origin_issuer_pins'], require_jsonschema=True, require_observation_bracket=True); "
        "before_n = len(rj.entries); "
        "res = v.verify_invocation(d['inv_ok'], {'grants': [d['grant']], 'origin_bundle': d['origin_bundle']}, sv.ChainView(d['chain']), rj, d['exec_cfg'], raw_message_bytes=bytes.fromhex(d['raw_msg_hex'])); "
        "assert res.verdict == 'ADMIT' and res.details.get('cached_receipt') is True and res.cached_receipt_content_addr == d['expected_rcpt_ca'] and len(rj.entries) == before_n, res; "
        "print('SEPARATE_PROCESS_QUOTA_FREE_RESTART_OK')"
    )
    proc = subprocess.run([sys.executable, "-c", child_code, str(restart_file)], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0 and "SEPARATE_PROCESS_QUOTA_FREE_RESTART_OK" in proc.stdout, (
        f"Separate-process quota-free restart check failed: rc={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )

    return {
        "cold_observer_gbi_calls": t4_ctr["getblockchaininfo"],
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
        "quota_free_terminal_settlement_committed": True,
        "quota_free_separate_process_restart_receipt_ca": rcpt_ok_ca,
        "verdicts": {
            "downgraded_1of2_routine_read": {"verdict": r_bad.verdict, "refusal_code": r_bad.refusal_code},
            "full_2of2_effect_grant_strict_drop": {"verdict": r_ok.verdict, "outcome": r_ok.outcome},
            "quota_free_post_restart_separate_process_cached_retry": {"verdict": "ADMIT", "writes": 0, "second_delivery": False},
        },
    }


def run_trace_05(cl: RegtestCluster) -> dict[str, Any]:
    """Trace 05: Cold-observer historical eternal diploma across live regtest 30-block expiry
    AND lawful re-registration of the exact same spelling (`id/t5-school`) by a new owner."""
    sch1_own, sch1_cred = kp("t5-sch1-own"), kp("t5-sch1-cred")
    sch2_own, sch2_cred = kp("t5-sch2-own"), kp("t5-sch2-cred")
    grad_k = kp("t5-grad")
    sch1_pol = {"kind": "key", "pk": sch1_own["comp"]}
    sch2_pol = {"kind": "key", "pk": sch2_own["comp"]}

    # 1. Register id/t5-school (Registration #1, Owner #1)
    n1 = cl.register_names_batch([
        {"name": "id/t5-school", "owner_policy": sch1_pol, "owner_kp": sch1_own, "value_obj": {"link": {"cred": sch1_cred["xonly"]}}, "rand_label": "t5-sch-reg1"},
    ])
    reg1 = n1["id/t5-school"]["registration"]
    h_reg1_upd = n1["id/t5-school"]["height"]
    tip_time_1 = int(cl.rpc(1, "getblockheader", cl.rpc(1, "getbestblockhash"))["time"])

    # 2. Issue eternal diploma and anchor 0x09 on-chain while Reg #1 is live!
    dip_ok_p = {
        "claims": {"degree": "MSc Distributed Systems", "graduated": 2026},
        "credential_kind": "education/diploma",
        "genesis": cl.genesis_hash,
        "issued_at": tip_time_1,
        "issuer": {"name": "id/t5-school", "owner_policy": sch1_pol, "registration": reg1, "role_policy": {"m": 1, "pks": [sch1_cred["xonly"]]}},
        "lifecycle": "eternal",
        "network": "regtest",
        "not_before_height": h_reg1_upd,
        "subject": {"key": grad_k["xonly"], "mode": "key"},
        "type": "seallink-credential/1",
    }
    dip_ok = sl.sign_envelope(dip_ok_p, [sch1_cred["sk"]])
    f = cl.split_funding(2, each_sat=2_000_000)
    dip_ok_txid, dip_ok_raw = build_signed_tx(
        [f[0]],
        [(0, op_return_spk(0x09, sl.content_addr(dip_ok))), (f[0]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(dip_ok_raw)
    cl.mine(1)
    h_dip_ok = cl.rpc(1, "getblockcount")

    v = sv.Tier1Verifier(pinned_network="regtest", pinned_genesis=cl.genesis_hash, operator_min_depth=1, require_jsonschema=True, require_observation_bracket=True)

    # Cold check A: while Reg #1 is live -> ADMIT!
    ch_live = sv.ChainView(cl.new_cold_observer().build_chain_view(wire_objects=[dip_ok], extra_txids=[dip_ok_txid]))
    r_live = v.verify_credential(dip_ok, dip_ok_txid, ch_live)
    assert r_live.verdict == "ADMIT", f"Trace 05 live diploma failed: {r_live}"

    # 3. Mine 32 blocks past Namecoin Core regtest's 30-block expiry -> verify id/t5-school expired on Node B!
    cl.mine(32)
    try:
        cl.rpc(1, "name_show", "id/t5-school")
        raise AssertionError("Expected Node B name_show to reject expired id/t5-school")
    except RuntimeError as exc:
        assert "name expired" in str(exc).lower(), f"Unexpected name_show error: {exc}"
    hist_exp = cl.rpc(1, "name_history", "id/t5-school")
    assert hist_exp and hist_exp[-1]["expired"] is True, f"Expected expired entry in name_history, got {hist_exp}"
    h_expired = cl.rpc(1, "getblockcount")

    # Cold check B: eternal diploma AFTER expiry (before re-registration) -> ADMIT!
    ch_exp = sv.ChainView(cl.new_cold_observer().build_chain_view(wire_objects=[dip_ok], extra_txids=[dip_ok_txid]))
    r_after_exp = v.verify_credential(dip_ok, dip_ok_txid, ch_exp)
    assert r_after_exp.verdict == "ADMIT", f"Trace 05 post-expiry diploma failed: {r_after_exp}"

    # 4. Anchor a post-expiry credential signed by School #1 AFTER expiry -> MUST refuse NAME_EXPIRED!
    dip_exp_p = {**dip_ok_p, "claims": {"degree": "Post-Expiry Forgery", "graduated": 2026}, "not_before_height": h_expired}
    dip_exp = sl.sign_envelope(dip_exp_p, [sch1_cred["sk"]])
    dip_exp_txid, dip_exp_raw = build_signed_tx(
        [f[1]],
        [(0, op_return_spk(0x09, sl.content_addr(dip_exp))), (f[1]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(dip_exp_raw)
    cl.mine(1)
    h_dip_exp = cl.rpc(1, "getblockcount")

    # 5. Owner #2 lawfully re-registers the EXACT SAME spelling `id/t5-school` (Registration #2)!
    n2 = cl.register_names_batch([
        {"name": "id/t5-school", "owner_policy": sch2_pol, "owner_kp": sch2_own, "value_obj": {"link": {"cred": sch2_cred["xonly"]}}, "rand_label": "t5-sch-reg2"},
    ])
    reg2 = n2["id/t5-school"]["registration"]
    assert reg2["txid"] != reg1["txid"]
    shown_rereg = cl.rpc(1, "name_show", "id/t5-school")
    assert shown_rereg["expired"] is False and shown_rereg["txid"] == n2["id/t5-school"]["update_txid"]

    # 6. ONE single brand-new ColdNamecoinObserver snapshot at the final tip height MUST answer ALL 4 queries!
    ch_final_dict = cl.new_cold_observer().build_chain_view(
        wire_objects=[dip_ok, dip_exp],
        extra_txids=[dip_ok_txid, dip_exp_txid],
    )
    assert len(ch_final_dict["name_registrations"]["id/t5-school"]) == 2, (
        f"Cold observer expected 2 registration lineages from Node B name_history, got {len(ch_final_dict['name_registrations'].get('id/t5-school', []))}"
    )
    ch_final = sv.ChainView(ch_final_dict)

    # 6a. Live current-owner lookup resolves to Owner #2 (derived purely from Node B witness!) -> ADMIT
    _, err_live_new = v.resolve_name("id/t5-school", ch_final, expected_owner_policy=sch2_pol, expected_registration=reg2)
    assert err_live_new is None, f"Live lookup for new Owner #2 failed: {err_live_new}"
    # 6b. Live lookup pinned to old Owner #1 / Reg #1 -> REFUSE NAME_OWNER_MISMATCH
    _, err_live_old = v.resolve_name("id/t5-school", ch_final, expected_owner_policy=sch1_pol, expected_registration=reg1)
    assert err_live_old == "NAME_OWNER_MISMATCH", f"Expected NAME_OWNER_MISMATCH for old owner live lookup, got {err_live_old}"
    # 6c. Historical eternal diploma anchored while Reg #1 was live -> ADMIT!
    r_after_rereg = v.verify_credential(dip_ok, dip_ok_txid, ch_final)
    assert r_after_rereg.verdict == "ADMIT", f"Historical eternal diploma failed after re-registration: {r_after_rereg}"
    # 6d. Post-expiry credential anchored after Reg #1 expired -> REFUSE NAME_EXPIRED!
    r_post_exp_forgery = v.verify_credential(dip_exp, dip_exp_txid, ch_final)
    assert (r_post_exp_forgery.verdict, r_post_exp_forgery.refusal_code) == ("REFUSE", "NAME_EXPIRED"), (
        f"Expected NAME_EXPIRED for post-expiry anchor, got {r_post_exp_forgery}"
    )

    # 7. Live mid-read tip transition bracket test on REAL nc28.0 nodes!
    #    Mine 1 real block between the observer's opening and closing getblockchaininfo calls:
    #    - retry_on_tip_change=0 -> Tier1Verifier(require_observation_bracket=True) refuses CHAIN_OBSERVATION_VOID!
    #    - retry_on_tip_change=1 -> ColdNamecoinObserver discards straddling snapshot, re-reads new tip -> ADMIT!
    def _make_straddling_observer() -> nca.ColdNamecoinObserver:
        raw_read = nca.make_cli_rpc(
            cl.bin_dir, cl.dirs[1], cl.ports[1], regtest=True, rpcuser=cl.obs_user, rpcpassword=cl.obs_password
        )
        fired = {"mined": False, "gbi": 0}
        def _hooked_read(method: str, *args: Any, wait: bool = False) -> Any:
            res = raw_read(method, *args, wait=wait)
            if method == "getblockchaininfo":
                fired["gbi"] += 1
                if fired["gbi"] == 1 and not fired["mined"]:
                    fired["mined"] = True
                    cl.mine(1)
            return res
        return nca.ColdNamecoinObserver(
            _hooked_read,
            [("node-a-local", nca.make_cli_rpc(cl.bin_dir, cl.dirs[0], cl.ports[0], regtest=True))],
            network="regtest",
            clock_mode="regtest_deterministic",
        )

    ch_void_dict = _make_straddling_observer().build_chain_view(wire_objects=[dip_ok], extra_txids=[dip_ok_txid], retry_on_tip_change=0)
    assert ch_void_dict["observation_bracket"]["consistent"] is False
    r_mid_tip_void = v.verify_credential(dip_ok, dip_ok_txid, sv.ChainView(ch_void_dict))
    assert (r_mid_tip_void.verdict, r_mid_tip_void.refusal_code) == ("REFUSE", "CHAIN_OBSERVATION_VOID"), (
        f"Expected CHAIN_OBSERVATION_VOID on live mid-read tip change, got {r_mid_tip_void}"
    )

    ch_retry_dict = _make_straddling_observer().build_chain_view(wire_objects=[dip_ok], extra_txids=[dip_ok_txid], retry_on_tip_change=1)
    assert ch_retry_dict["observation_bracket"]["consistent"] is True and ch_retry_dict["observation_bracket"]["attempts"] == 2
    r_mid_tip_retry = v.verify_credential(dip_ok, dip_ok_txid, sv.ChainView(ch_retry_dict))
    assert r_mid_tip_retry.verdict == "ADMIT", f"Expected ADMIT after bracket retry on new tip, got {r_mid_tip_retry}"

    # 8. Live B-9 transfer-written value check on REAL nc28.0:
    #    Outgoing Owner #2 transfers id/t5-school to Owner #3 while writing Owner #3's value -> NAME_WRITER_UNVERIFIED!
    #    Then Owner #3 signs its own OP_NAME_UPDATE -> ADMIT!
    sch3_own, sch3_cred = kp("t5-sch3-own"), kp("t5-sch3-cred")
    sch3_pol = {"kind": "key", "pk": sch3_own["comp"]}
    xfer_txid, _ = cl.update_name_p2wpkh(
        n2["id/t5-school"], "id/t5-school", sch2_own, {"link": {"cred": sch3_cred["xonly"]}}, new_owner_policy=sch3_pol
    )
    ch_xfer = sv.ChainView(cl.new_cold_observer().build_chain_view(wire_objects=[], extra_names=["id/t5-school"], extra_policies=[sch3_pol]))
    _, err_xfer_b9 = v.resolve_name("id/t5-school", ch_xfer, expected_owner_policy=sch3_pol, expected_registration=reg2)
    assert err_xfer_b9 == "NAME_WRITER_UNVERIFIED", f"Live B-9 transfer-written value expected NAME_WRITER_UNVERIFIED, got {err_xfer_b9}"
    self_upd_txid, _ = cl.update_name_p2wpkh(
        n2["id/t5-school"], "id/t5-school", sch3_own, {"link": {"cred": sch3_cred["xonly"]}}
    )
    ch_self = sv.ChainView(cl.new_cold_observer().build_chain_view(wire_objects=[], extra_names=["id/t5-school"], extra_policies=[sch3_pol]))
    _, err_self_ok = v.resolve_name("id/t5-school", ch_self, expected_owner_policy=sch3_pol, expected_registration=reg2)
    assert err_self_ok is None, f"Live B-9 post-self-update expected ADMIT, got {err_self_ok}"

    # 9. Live A-2 invalidateblock active-chain reorg check on Node B:
    #    Disconnect Node B's tip block (orphan), verify ColdNamecoinObserver refuses peer divergence / non-active block,
    #    then reconsiderblock to restore full Node A <-> Node B sync!
    reorg_blk = cl.mine(1)[0]
    cl.rpc(1, "invalidateblock", reorg_blk)
    ch_reorg_dict = cl.new_cold_observer().build_chain_view(wire_objects=[], extra_txids=[self_upd_txid], extra_block_hashes=[reorg_blk])
    assert reorg_blk not in ch_reorg_dict.get("blocks", {}), "Orphaned block after invalidateblock must NOT appear in active-chain blocks map!"
    cl.rpc(1, "reconsiderblock", reorg_blk)
    assert cl.until(lambda: cl.rpc(1, "getbestblockhash") == reorg_blk, limit=60.0)

    return {
        "cold_observer_adapter": "tools/nc_rpc_adapter.py:ColdNamecoinObserver",
        "name": "id/t5-school",
        "reg1_firstupdate_txid": reg1["txid"],
        "reg1_update_height": h_reg1_upd,
        "diploma_ok_0x09_txid": dip_ok_txid,
        "diploma_ok_0x09_raw_hex": dip_ok_raw,
        "diploma_ok_anchor_height": h_dip_ok,
        "expired_height_verified_on_peer_b": h_expired,
        "post_expiry_forgery_0x09_txid": dip_exp_txid,
        "post_expiry_forgery_anchor_height": h_dip_exp,
        "reg2_firstupdate_txid": reg2["txid"],
        "reg2_update_txid": n2["id/t5-school"]["update_txid"],
        "b9_transfer_txid": xfer_txid,
        "b9_owner3_self_update_txid": self_upd_txid,
        "a2_invalidated_reorg_block_excluded": True,
        "cold_discovered_registration_lineages": len(ch_final_dict["name_registrations"]["id/t5-school"]),
        "live_mid_read_tip_change_retry_attempts": ch_retry_dict["observation_bracket"]["attempts"],
        "verdicts": {
            "diploma_while_reg1_live": {"verdict": r_live.verdict, "outcome": r_live.outcome},
            "diploma_after_30_block_expiry": {"verdict": r_after_exp.verdict, "outcome": r_after_exp.outcome},
            "same_chainview_live_new_owner": {"verdict": "ADMIT", "refusal_code": err_live_new},
            "same_chainview_live_old_owner_pin": {"verdict": "REFUSE", "refusal_code": err_live_old},
            "same_chainview_historical_diploma_after_reregistration": {"verdict": r_after_rereg.verdict, "outcome": r_after_rereg.outcome},
            "same_chainview_post_expiry_forgery": {"verdict": r_post_exp_forgery.verdict, "refusal_code": r_post_exp_forgery.refusal_code},
            "live_mid_read_tip_change_no_retry": {"verdict": r_mid_tip_void.verdict, "refusal_code": r_mid_tip_void.refusal_code},
            "live_mid_read_tip_change_with_retry": {"verdict": r_mid_tip_retry.verdict, "outcome": r_mid_tip_retry.outcome},
            "live_b9_transfer_written_value": {"verdict": "REFUSE", "refusal_code": err_xfer_b9},
            "live_b9_new_owner_self_update": {"verdict": "ADMIT", "refusal_code": err_self_ok},
        },
    }


# ============================================================================
# Trace 06: Live 0x13 VOLUNTARY_REBIND (T_offer -> T_rebind -> D=144 -> Step 3
#           -> real 30-block B_1 expiry -> alien legacy P2PKH re-registration)
# ============================================================================

def run_trace_06(cl: RegtestCluster) -> dict[str, Any]:
    reg_own, reg_cred = kp("t6-reg-own"), kp("t6-reg-cred")
    b1_own, b1_gr, b1_cred = kp("t6-b1-own"), kp("t6-b1-gr"), kp("t6-b1-cred")
    b2_own, b2_gr = kp("t6-b2-own"), kp("t6-b2-gr")
    bseal_k, stat_k = kp("t6-bseal"), kp("t6-stat")
    hijack_k = kp("t6-hijack-p2pkh")
    other_party_k = kp("t6-other-party")

    reg_pol = {"kind": "key", "pk": reg_own["comp"]}
    b1_pol = {"kind": "key", "pk": b1_own["comp"]}
    b2_pol = {"kind": "key", "pk": b2_own["comp"]}
    bseal_pol = {"kind": "key", "pk": bseal_k["comp"]}
    stat_pol = {"kind": "key", "pk": stat_k["comp"]}

    # 1. Register id/t6-registry and mint binding_seal + status_seal, then anchor 0x09 autonomous origin (mode="none")!
    n_reg = cl.register_names_batch([
        {"name": "id/t6-registry", "owner_policy": reg_pol, "owner_kp": reg_own, "value_obj": {"link": {"cred": reg_cred["xonly"]}}, "rand_label": "t6-reg"},
    ])
    reg_pin = {"name": "id/t6-registry", "owner_policy": reg_pol, "registration": n_reg["id/t6-registry"]["registration"]}
    reg_issuer = {**reg_pin, "role_policy": {"m": 1, "pks": [reg_cred["xonly"]]}}

    f = cl.split_funding(8, each_sat=3_000_000)
    seals_txid, seals_raw = build_signed_tx(
        [f[0]],
        [
            (SEAL_SAT, bseal_k["p2wpkh_spk"]),
            (SEAL_SAT, stat_k["p2wpkh_spk"]),
            (f[0]["value_sat"] - 2 * SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(seals_raw)
    cl.mine(1)

    orig_p = {
        "binding_seal": {"script_policy": bseal_pol, "txid": seals_txid, "vout": 0},
        "claims": {"intended_name": "id/t6-alice-v1", "intended_owner_policy": b1_pol},
        "genesis": cl.genesis_hash,
        "issuer": reg_issuer,
        "name_recovery": {"mode": "none"},
        "network": "regtest",
        "origin_class": "person",
        "request_sha256": sl.sha256(b"t6-orig-req").hex(),
        "status_seal": {"script_policy": stat_pol, "txid": seals_txid, "vout": 1},
        "subject_initial_key": b1_gr["xonly"],
        "type": "seallink-origin/1",
    }
    orig_env = sl.sign_envelope(orig_p, [reg_cred["sk"]])
    oid = sl.object_id(orig_p)
    anc09_txid, anc09_raw = build_signed_tx(
        [f[1]],
        [(0, op_return_spk(0x09, sl.content_addr(orig_env))), (f[1]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(anc09_raw)
    cl.mine(1)

    # 2. Register id/t6-alice-v1 (B_1) and id/t6-alice-v2 (B_2, value="{}") strictly AFTER h_origin!
    n_ab = cl.register_names_batch([
        {"name": "id/t6-alice-v1", "owner_policy": b1_pol, "owner_kp": b1_own, "value_obj": {"link": {"cred": b1_cred["xonly"], "grant": b1_gr["xonly"], "origin": oid}}, "rand_label": "t6-b1"},
        {"name": "id/t6-alice-v2", "owner_policy": b2_pol, "owner_kp": b2_own, "value_obj": {}, "rand_label": "t6-b2"},
    ])
    b1_rec = n_ab["id/t6-alice-v1"]
    b2_rec = n_ab["id/t6-alice-v2"]

    b1_obj = {
        "binding_mode": "initial",
        "genesis": cl.genesis_hash,
        "name": "id/t6-alice-v1",
        "network": "regtest",
        "origin_id": oid,
        "owner_policy": b1_pol,
        "registration": b1_rec["registration"],
        "seq": 1,
        "type": "seallink-name-binding/1",
    }
    b1_id = sl.object_id(b1_obj)
    anc0c_txid, anc0c_raw = build_signed_tx(
        [{"txid": seals_txid, "vout": 0, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": bseal_k}, f[2]],
        [(0, op_return_spk(0x0C, b1_id)), (f[2]["value_sat"] + SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(anc0c_raw)
    cl.mine(1)

    # 3. Anchor an eternal credential signed by B_1's link.cred at h_dip < h_13 (must survive 0x13 + expiry + alien hijack!)
    tip_t_dip = int(cl.rpc(1, "getblockheader", cl.rpc(1, "getbestblockhash"))["time"])
    dip_b1_p = {
        "claims": {"note": "Pre-rebind eternal attestation on B_1"},
        "credential_kind": "education/diploma",
        "genesis": cl.genesis_hash,
        "issued_at": tip_t_dip,
        "issuer": {"name": "id/t6-alice-v1", "owner_policy": b1_pol, "registration": b1_rec["registration"], "role_policy": {"m": 1, "pks": [b1_cred["xonly"]]}},
        "lifecycle": "eternal",
        "network": "regtest",
        "not_before_height": b1_rec["height"],
        "subject": {"key": other_party_k["xonly"], "mode": "key"},
        "type": "seallink-credential/1",
    }
    dip_b1 = sl.sign_envelope(dip_b1_p, [b1_cred["sk"]])
    dip_b1_txid, dip_b1_raw = build_signed_tx(
        [f[3]],
        [(0, op_return_spk(0x09, sl.content_addr(dip_b1))), (f[3]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(dip_b1_raw)
    cl.mine(1)
    h_dip_b1 = cl.rpc(1, "getblockcount")

    # 4. Broadcast & mine T_offer (nVersion=0x7100 OP_NAME_UPDATE on id/t6-alice-v2 value="{}" + non-name consent_utxo at vout=1!)
    t_offer_txid, t_offer_raw = cl.update_name_p2wpkh(
        b2_rec, "id/t6-alice-v2", b2_own, {}, extra_outputs=[(SEAL_SAT, b2_own["p2wpkh_spk"])]
    )
    h_offer = cl.rpc(1, "getblockcount")

    # 5. Build voluntary NameBinding B_2 (delay_blocks=144) and broadcast T_rebind with NON-DEFAULT vin/vout order!
    #    vin[0]=fee, vin[1]=consent_utxo (T_offer:1), vin[2]=B_1 name UTXO
    #    vout[0]=change, vout[1]=OP_NAME_UPDATE B_1 value="{}" preserving b1_pol, vout[2]=OP_RETURN 0x13 object_id(B_2)
    b2_obj = {
        "binding_mode": "voluntary",
        "consent_outpoint": {"txid": t_offer_txid, "vout": 1},
        "delay_blocks": 144,
        "genesis": cl.genesis_hash,
        "name": "id/t6-alice-v2",
        "network": "regtest",
        "origin_id": oid,
        "owner_policy": b2_pol,
        "registration": b2_rec["registration"],
        "seq": 2,
        "supersedes_binding_id": b1_id,
        "type": "seallink-name-binding/1",
    }
    b2_id = sl.object_id(b2_obj)
    b1_rebind_spk = sl.encode_name_output("NAME_UPDATE", b1_own["p2wpkh_spk"], name=b"id/t6-alice-v1", value=b"{}")
    t_rebind_txid, t_rebind_raw = build_signed_tx(
        [
            f[4],
            {"txid": t_offer_txid, "vout": 1, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": b2_own},
            {"txid": b1_rec["current_txid"], "vout": b1_rec["current_vout"], "value_sat": MIN_NAME_SAT, "kind": "p2wpkh", "signer": b1_own},
        ],
        [
            (f[4]["value_sat"] + SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
            (MIN_NAME_SAT, b1_rebind_spk),
            (0, op_return_spk(0x13, b2_id)),
        ],
        version=NAMECOIN_TX_VERSION,
    )
    cl.broadcast_and_wait_peer(t_rebind_raw)
    cl.mine(1)
    h_13 = cl.rpc(1, "getblockcount")
    b1_rec["current_txid"] = t_rebind_txid
    b1_rec["current_vout"] = 1

    ob = {
        "name_binding": b1_obj,
        "name_binding_txid": anc0c_txid,
        "origin": orig_env,
        "origin_anchor_txid": anc09_txid,
        "recovery_bindings": [],
        "voluntary_rebind_bindings": [b2_obj],
    }
    v = sv.Tier1Verifier(
        pinned_network="regtest",
        pinned_genesis=cl.genesis_hash,
        operator_min_depth=1,
        trusted_origin_issuer_pins=[reg_pin],
        require_jsonschema=True,
        require_observation_bracket=True,
    )

    # Verdict 1: Inside delay window (h_13 < tip < h_13 + 144) -> REFUSE RECOVERY_FORBIDDEN!
    cl.mine(1)
    ch_win = sv.ChainView(cl.new_cold_observer().build_chain_view(wire_objects=[ob]))
    _, err_win = v.verify_origin_and_status(ob, ch_win)
    assert err_win == "RECOVERY_FORBIDDEN", f"Trace 06 in-window expected RECOVERY_FORBIDDEN, got {err_win}"

    # Mine through D=144 while renewing id/t6-alice-v2 (value="{}") every 20 blocks so B_2 never expires on regtest (30-block TTL)!
    h_maturity = h_13 + 144
    while cl.rpc(1, "getblockcount") < h_maturity:
        cur_h = cl.rpc(1, "getblockcount")
        rem = h_maturity - cur_h
        if rem > 20:
            cl.mine(19)
            cl.update_name_p2wpkh(b2_rec, "id/t6-alice-v2", b2_own, {})
        else:
            # Renew B_2 once right before maturity if needed so it has fresh TTL at h_maturity
            if rem > 5:
                cl.mine(rem - 2)
                cl.update_name_p2wpkh(b2_rec, "id/t6-alice-v2", b2_own, {})
                rem = h_maturity - cl.rpc(1, "getblockcount")
            if rem > 0:
                cl.mine(rem)
    assert cl.rpc(1, "getblockcount") == h_maturity

    # Verdict 2: At exact maturity h_13 + 144 BEFORE Step 3 activation (awaiting_activation) -> REFUSE ORIGIN_BINDING_INVALID!
    ch_await_dict = cl.new_cold_observer().build_chain_view(wire_objects=[ob])
    assert str(h_maturity) in ch_await_dict.get("block_times", {}), "Cold observer must auto-populate quiet maturity MTP in block_times!"
    _, err_await = v.verify_origin_and_status(ob, sv.ChainView(ch_await_dict))
    assert err_await == "ORIGIN_BINDING_INVALID", f"Trace 06 awaiting_activation expected ORIGIN_BINDING_INVALID, got {err_await}"

    # 6. Step 3 activation on B_2 (OP_NAME_UPDATE writing link.origin == oid + link.grant == b2_gr)!
    step3_txid, _ = cl.update_name_p2wpkh(
        b2_rec, "id/t6-alice-v2", b2_own, {"link": {"grant": b2_gr["xonly"], "origin": oid}}
    )
    h_act = cl.rpc(1, "getblockcount")

    # 7. Verify B_1 has ALREADY expired on live nc28.0 regtest (h_act - h_13 >= 145 >> 30), then ALIEN hijacker re-registers
    #    id/t6-alice-v1 with a LEGACY P2PKH scriptPubKey (OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG)!
    try:
        cl.rpc(1, "name_show", "id/t6-alice-v1")
        raise AssertionError("Expected id/t6-alice-v1 to be expired after 144+ blocks on regtest")
    except RuntimeError as exc:
        assert "name expired" in str(exc).lower(), f"Unexpected name_show error on expired B_1: {exc}"

    p2pkh_spk = b"\x76\xa9\x14" + sl.hash160(hijack_k["comp_bytes"]) + b"\x88\xac"
    rand_hij = sl.sha256(b"t6-alien-p2pkh-rand")[:20]
    h20_hij = sl.hash160(rand_hij + b"id/t6-alice-v1")
    nn_hij_spk = sl.encode_name_output("NAME_NEW", cl.fund_key["p2wpkh_spk"], hash20=h20_hij)
    nn_hij_txid, nn_hij_raw = build_signed_tx(
        [f[5]],
        [(MIN_NAME_SAT, nn_hij_spk), (f[5]["value_sat"] - MIN_NAME_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
        version=NAMECOIN_TX_VERSION,
    )
    cl.broadcast_and_wait_peer(nn_hij_raw)
    cl.mine(13)
    # Keep B_2 fresh while hijacking B_1!
    cl.update_name_p2wpkh(b2_rec, "id/t6-alice-v2", b2_own, {"link": {"grant": b2_gr["xonly"], "origin": oid}})
    fu_hij_spk = sl.encode_name_output("NAME_FIRSTUPDATE", p2pkh_spk, name=b"id/t6-alice-v1", rand=rand_hij, value=b'{"hijacked":true}')
    fu_hij_txid, fu_hij_raw = build_signed_tx(
        [{"txid": nn_hij_txid, "vout": 0, "value_sat": MIN_NAME_SAT, "kind": "p2wpkh", "signer": cl.fund_key}, f[6]],
        [(MIN_NAME_SAT, fu_hij_spk), (f[6]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
        version=NAMECOIN_TX_VERSION,
    )
    cl.broadcast_and_wait_peer(fu_hij_raw)
    cl.mine(1)
    shown_hij = cl.rpc(1, "name_show", "id/t6-alice-v1")
    assert shown_hij["txid"] == fu_hij_txid

    # 8. Build ONE single cold-observer ChainView from Node B at final tip and verify ALL 4 final verdicts!
    ch_fin_dict = cl.new_cold_observer().build_chain_view(wire_objects=[ob, dip_b1], extra_txids=[dip_b1_txid])
    assert len(ch_fin_dict["name_registrations"]["id/t6-alice-v1"]) == 2, "Expected 2 lineages on id/t6-alice-v1 (B_1 + alien P2PKH)"
    assert str(h_maturity) in ch_fin_dict.get("block_times", {}), "Quiet maturity MTP must persist in final cold ChainView!"
    ch_fin = sv.ChainView(ch_fin_dict)

    # Verdict 3: verify_origin_and_status -> ADMIT_AUTONOMOUS with active B_2!
    st_fin, err_fin = v.verify_origin_and_status(ob, ch_fin)
    assert err_fin is None and st_fin is not None, f"Trace 06 final origin_status failed: {err_fin}"
    assert st_fin["capacity"] == "autonomous" and st_fin["binding"]["name"] == "id/t6-alice-v2"
    assert st_fin["voluntary_rebind_events"][-1]["outcome"] == "promoted"

    # Verdict 4: Historical eternal diploma issued by B_1 at h_dip < h_13 -> ADMIT!
    r_dip_fin = v.verify_credential(dip_b1, dip_b1_txid, ch_fin)
    assert r_dip_fin.verdict == "ADMIT", f"Trace 06 historical B_1 diploma failed after rebind + alien P2PKH hijack: {r_dip_fin}"

    # Verdict 5: Autonomous contract assent under active B_2 -> ADMIT!
    c_seal_pol = {"kind": "key", "pk": other_party_k["comp"]}
    c_b2 = {
        "clause_commitments": [sl.clause_commit(sl.sha256(b"t6-c0").hex(), {"text": "Post-rebind contract"})],
        "contract_salt": sl.sha256(b"t6-cs").hex(),
        "genesis": cl.genesis_hash,
        "network": "regtest",
        "parties": [
            {"name_pin": {"name": "id/t6-alice-v2", "owner_policy": b2_pol, "registration": b2_rec["registration"]}, "party_id": "alice", "role": "client", "signing_policy": {"m": 1, "pks": [b2_gr["xonly"]]}},
            {"party_id": "counterparty", "role": "vendor", "signing_policy": {"m": 1, "pks": [other_party_k["xonly"]]}},
        ],
        "profile": "org.seallink/generic-v1",
        "seal": {"script_policy": c_seal_pol, "txid": sl.sha256(b"t6-cseal").hex(), "vout": 0},
        "type": "seallink-contract/1",
        "window": {"not_after_height": ch_fin.tip_height + 20, "not_before_height": ch_fin.tip_height - 10},
    }
    ass_b2 = sl.sign_envelope(
        {
            "expires_at": ch_fin.now + 100_000, "genesis": cl.genesis_hash, "issued_at": ch_fin.now - 10,
            "network": "regtest", "nonce": sl.sha256(b"t6-ass-b2").hex(), "party_id": "alice",
            "party_name": "id/t6-alice-v2", "party_role": "client", "target_id": sl.object_id(c_b2),
            "target_type": "seallink-contract/1", "type": "seallink-assent/1",
        },
        [b2_gr["sk"]],
    )
    r_ass_b2 = v.verify_assent(ass_b2, c_b2, ob, ch_fin)
    assert r_ass_b2.verdict == "ADMIT", f"Trace 06 B_2 assent failed: {r_ass_b2}"

    # Verdict 6: Alien hijacker / superseded B_1 pin attempting live assent -> REFUSE!
    c_hij = {
        **copy.deepcopy(c_b2),
        "contract_salt": sl.sha256(b"t6-cs-hij").hex(),
        "parties": [
            {"name_pin": {"name": "id/t6-alice-v1", "owner_policy": b1_pol, "registration": b1_rec["registration"]}, "party_id": "alice", "role": "client", "signing_policy": {"m": 1, "pks": [b1_gr["xonly"]]}},
            {"party_id": "counterparty", "role": "vendor", "signing_policy": {"m": 1, "pks": [other_party_k["xonly"]]}},
        ],
    }
    ass_hij = sl.sign_envelope(
        {
            "expires_at": ch_fin.now + 100_000, "genesis": cl.genesis_hash, "issued_at": ch_fin.now - 10,
            "network": "regtest", "nonce": sl.sha256(b"t6-ass-hij").hex(), "party_id": "alice",
            "party_name": "id/t6-alice-v1", "party_role": "client", "target_id": sl.object_id(c_hij),
            "target_type": "seallink-contract/1", "type": "seallink-assent/1",
        },
        [b1_gr["sk"]],
    )
    r_ass_hij = v.verify_assent(ass_hij, c_hij, ob, ch_fin)
    assert (r_ass_hij.verdict, r_ass_hij.refusal_code) == ("REFUSE", "NAME_HISTORY_UNAVAILABLE"), (
        f"Trace 06 superseded/P2PKH-hijacked B_1 live assent should fail closed with NAME_HISTORY_UNAVAILABLE, got {r_ass_hij}"
    )

    return {
        "cold_observer_adapter": "tools/nc_rpc_adapter.py:ColdNamecoinObserver",
        "origin_id": oid,
        "origin_0x09_txid": anc09_txid,
        "b1_initial_0x0c_txid": anc0c_txid,
        "b1_historical_diploma_0x09_txid": dip_b1_txid,
        "b1_historical_diploma_height": h_dip_b1,
        "t_offer_txid": t_offer_txid,
        "t_offer_height": h_offer,
        "t_rebind_txid": t_rebind_txid,
        "t_rebind_raw_hex": t_rebind_raw,
        "t_rebind_height": h_13,
        "quiet_maturity_height": h_maturity,
        "quiet_maturity_mtp_captured_cold": str(h_maturity) in ch_fin_dict.get("block_times", {}),
        "b2_step3_activation_txid": step3_txid,
        "b2_step3_activation_height": h_act,
        "alien_p2pkh_hijack_firstupdate_txid": fu_hij_txid,
        "cold_discovered_b1_lineages": len(ch_fin_dict["name_registrations"]["id/t6-alice-v1"]),
        "verdicts": {
            "in_delay_window_d144": {"verdict": "REFUSE", "refusal_code": err_win},
            "matured_awaiting_step3_activation": {"verdict": "REFUSE", "refusal_code": err_await},
            "post_step3_and_alien_p2pkh_hijack_origin_status": {"verdict": "ADMIT_AUTONOMOUS", "active_name": st_fin["binding"]["name"], "rebind_outcome": st_fin["voluntary_rebind_events"][-1]["outcome"]},
            "historical_b1_diploma_after_rebind_and_hijack": {"verdict": r_dip_fin.verdict, "outcome": r_dip_fin.outcome},
            "post_rebind_b2_assent": {"verdict": r_ass_b2.verdict, "outcome": r_ass_b2.outcome},
            "superseded_b1_after_alien_p2pkh_hijack_assent": {"verdict": r_ass_hij.verdict, "refusal_code": r_ass_hij.refusal_code},
        },
    }


# ============================================================================
# Trace 07: Live 0x14 LOG_CHECKPOINT (non-default next_log_vout=2) +
#           seallink-release/1 + log_tracked seallink-notary/1 + SMT revocation +
#           PROFILE-artifact-v1 Gatekeeper + REAL MINED SegWitNameUpdateProof
# ============================================================================

def _btc_merkle_branches_from_hashes_le(hashes_le: list[bytes]) -> tuple[bytes, list[list[str]]]:
    n = len(hashes_le)
    branches: list[list[str]] = [[] for _ in range(n)]
    level = list(hashes_le)
    idxs = list(range(n))
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        for i in range(n):
            branches[i].append(level[idxs[i] ^ 1][::-1].hex())
            idxs[i] >>= 1
        level = [sl.dsha256(level[j] + level[j + 1]) for j in range(0, len(level), 2)]
    return level[0], branches


def run_trace_07(cl: RegtestCluster) -> dict[str, Any]:
    rel_own, rel_role, rel_seal = kp("t7-rel-own"), kp("t7-rel-role"), kp("t7-rel-seal")
    not_own, not_role, not_seal = kp("t7-not-own"), kp("t7-not-role"), kp("t7-not-seal")

    rel_pol = {"kind": "key", "pk": rel_own["comp"]}
    not_pol = {"kind": "key", "pk": not_own["comp"]}
    rel_seal_pol = {"kind": "key", "pk": rel_seal["comp"]}
    not_seal_pol = {"kind": "key", "pk": not_seal["comp"]}

    # 1. Register id/t7-release-op (link.release) and id/t7-notary-1 (link.notary) on live nc28.0!
    names = cl.register_names_batch([
        {"name": "id/t7-release-op", "owner_policy": rel_pol, "owner_kp": rel_own, "value_obj": {"link": {"release": rel_role["xonly"]}}, "rand_label": "t7-rel"},
        {"name": "id/t7-notary-1", "owner_policy": not_pol, "owner_kp": not_own, "value_obj": {"link": {"notary": not_role["xonly"]}}, "rand_label": "t7-not"},
    ])
    rel_rec, not_rec = names["id/t7-release-op"], names["id/t7-notary-1"]
    rel_pin = {"name": "id/t7-release-op", "owner_policy": rel_pol, "registration": rel_rec["registration"]}
    rel_role_pin = {**rel_pin, "role_policy": {"m": 1, "pks": [rel_role["xonly"]]}}
    not_pin = {"name": "id/t7-notary-1", "owner_policy": not_pol, "registration": not_rec["registration"]}
    not_role_pin = {**not_pin, "role_policy": {"m": 1, "pks": [not_role["xonly"]]}}

    # 2. Mint genesis log seals for both release log & notary log!
    f = cl.split_funding(8, each_sat=3_000_000)
    gen_txid, gen_raw = build_signed_tx(
        [f[0]],
        [
            (SEAL_SAT, rel_seal["p2wpkh_spk"]),
            (SEAL_SAT, not_seal["p2wpkh_spk"]),
            (f[0]["value_sat"] - 2 * SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(gen_raw)
    cl.mine(1)

    rel_log_id = sl.compute_log_id("regtest", cl.genesis_hash, "release", "id/t7-release-op", rel_rec["registration"], {"txid": gen_txid, "vout": 0})
    not_log_id = sl.compute_log_id("regtest", cl.genesis_hash, "notary", "id/t7-notary-1", not_rec["registration"], {"txid": gen_txid, "vout": 1})

    # 3. Create canonical fsverity-sha256 artifact (salt_hex=""), log_tracked seallink-release/1 & log_tracked seallink-notary/1
    fsv_art = {"digest": sl.sha256(b"t7-curator-bundle-v2.1").hex(), "params": {"block_size": 4096, "hash_alg": "sha256", "salt_hex": "", "version": 1}, "scheme": "fsverity-sha256"}
    fsv_tid = sl.artifact_target_id(fsv_art)
    tip_h0 = cl.rpc(1, "getblockcount")
    tip_bh0 = cl.rpc(1, "getbestblockhash")
    tip_t0 = int(cl.rpc(1, "getblockheader", tip_bh0)["time"])

    rel_p = {
        "artifact_identity": fsv_art, "genesis": cl.genesis_hash, "issuer": rel_role_pin,
        "lifecycle": "log_tracked", "log_id": rel_log_id, "network": "regtest",
        "product_id": "works.relux/curator-cli", "release_seq": 10, "released_at": tip_t0,
        "target_sha256": fsv_tid, "type": "seallink-release/1", "version_str": "2.1.0",
    }
    rel_env = sl.sign_envelope(rel_p, [rel_role["sk"]])
    rel_id = sl.object_id(rel_p)

    not_p = {
        "act_kind": "artifact-notarization", "attested_at": tip_t0,
        "details": {"artifact_identity": fsv_art, "claims": [{"claim_id": "seallink.org/build-repro", "verdict": "pass"}], "kind": "artifact-notarization"},
        "genesis": cl.genesis_hash, "lifecycle": "log_tracked", "log_id": not_log_id, "network": "regtest",
        "notary": not_role_pin, "target_sha256": fsv_tid, "tip_hash": tip_bh0, "tip_height": tip_h0,
        "type": "seallink-notary/1",
    }
    not_env = sl.sign_envelope(not_p, [not_role["sk"]])
    not_id = sl.object_id(not_p)

    # 4. Anchor 0x14 cp1 (seq=1, non-default next_log_vout=2!) and cp2 (seq=2, next_log_vout=2) for BOTH logs!
    rel_e1 = sl.log_entry_digest(0x01, sl.content_addr(rel_env))
    rel_b1_root, rel_b1_pfs = sl.build_log_batch_root([rel_e1])
    rel_cp1 = sl.sign_envelope({
        "batch_count": 1, "batch_root": rel_b1_root, "checkpoints_root": sl.EMPTY_CHECKPOINTS_ROOT,
        "cumulative_entries_count": 1, "denials_delta_root": sl.EMPTY_BATCH_ROOT, "denials_root": sl.SMT_EMPTY_ROOT,
        "genesis": cl.genesis_hash, "issuer": rel_role_pin, "log_id": rel_log_id, "network": "regtest",
        "next_log_policy": rel_seal_pol, "next_log_vout": 2, "prev_log_outpoint": {"txid": gen_txid, "vout": 0},
        "role": "release", "seq": 1, "terminal": False, "type": "seallink-log-checkpoint/1",
    }, [rel_role["sk"]])
    rel_cp1_ca = sl.content_addr(rel_cp1)
    rel_cp1_tx, rel_cp1_raw = build_signed_tx(
        [{"txid": gen_txid, "vout": 0, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": rel_seal}, f[1]],
        [
            (0, op_return_spk(0x14, rel_cp1_ca)),
            (f[1]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
            (SEAL_SAT, rel_seal["p2wpkh_spk"]),  # non-default next_log_vout = 2!
        ],
    )
    cl.broadcast_and_wait_peer(rel_cp1_raw)

    not_e1 = sl.log_entry_digest(0x01, sl.content_addr(not_env))
    not_b1_root, not_b1_pfs = sl.build_log_batch_root([not_e1])
    not_cp1 = sl.sign_envelope({
        "batch_count": 1, "batch_root": not_b1_root, "checkpoints_root": sl.EMPTY_CHECKPOINTS_ROOT,
        "cumulative_entries_count": 1, "denials_delta_root": sl.EMPTY_BATCH_ROOT, "denials_root": sl.SMT_EMPTY_ROOT,
        "genesis": cl.genesis_hash, "issuer": not_role_pin, "log_id": not_log_id, "network": "regtest",
        "next_log_policy": not_seal_pol, "next_log_vout": 2, "prev_log_outpoint": {"txid": gen_txid, "vout": 1},
        "role": "notary", "seq": 1, "terminal": False, "type": "seallink-log-checkpoint/1",
    }, [not_role["sk"]])
    not_cp1_ca = sl.content_addr(not_cp1)
    not_cp1_tx, not_cp1_raw = build_signed_tx(
        [{"txid": gen_txid, "vout": 1, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": not_seal}, f[2]],
        [
            (0, op_return_spk(0x14, not_cp1_ca)),
            (f[2]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
            (SEAL_SAT, not_seal["p2wpkh_spk"]),  # non-default next_log_vout = 2!
        ],
    )
    cl.broadcast_and_wait_peer(not_cp1_raw)
    cl.mine(1)

    # cp2 (seq=2) spending cp1:2 for BOTH logs!
    rel_l1 = [sl.ckpt_leaf(1, rel_cp1_ca)]
    rel_cp2 = sl.sign_envelope({
        "batch_count": 0, "batch_root": sl.EMPTY_BATCH_ROOT, "checkpoints_root": sl.rfc9162_mth(rel_l1).hex(),
        "cumulative_entries_count": 1, "denials_delta_root": sl.EMPTY_BATCH_ROOT, "denials_root": sl.SMT_EMPTY_ROOT,
        "genesis": cl.genesis_hash, "issuer": rel_role_pin, "log_id": rel_log_id, "network": "regtest",
        "next_log_policy": rel_seal_pol, "next_log_vout": 2, "prev_checkpoint_id": rel_cp1_ca,
        "prev_log_outpoint": {"txid": rel_cp1_tx, "vout": 2}, "role": "release", "seq": 2, "terminal": False,
        "type": "seallink-log-checkpoint/1",
    }, [rel_role["sk"]])
    rel_cp2_ca = sl.content_addr(rel_cp2)
    rel_cp2_tx, rel_cp2_raw = build_signed_tx(
        [{"txid": rel_cp1_tx, "vout": 2, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": rel_seal}, f[3]],
        [
            (0, op_return_spk(0x14, rel_cp2_ca)),
            (f[3]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
            (SEAL_SAT, rel_seal["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(rel_cp2_raw)

    not_l1 = [sl.ckpt_leaf(1, not_cp1_ca)]
    not_cp2 = sl.sign_envelope({
        "batch_count": 0, "batch_root": sl.EMPTY_BATCH_ROOT, "checkpoints_root": sl.rfc9162_mth(not_l1).hex(),
        "cumulative_entries_count": 1, "denials_delta_root": sl.EMPTY_BATCH_ROOT, "denials_root": sl.SMT_EMPTY_ROOT,
        "genesis": cl.genesis_hash, "issuer": not_role_pin, "log_id": not_log_id, "network": "regtest",
        "next_log_policy": not_seal_pol, "next_log_vout": 2, "prev_checkpoint_id": not_cp1_ca,
        "prev_log_outpoint": {"txid": not_cp1_tx, "vout": 2}, "role": "notary", "seq": 2, "terminal": False,
        "type": "seallink-log-checkpoint/1",
    }, [not_role["sk"]])
    not_cp2_ca = sl.content_addr(not_cp2)
    not_cp2_tx, not_cp2_raw = build_signed_tx(
        [{"txid": not_cp1_tx, "vout": 2, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": not_seal}, f[4]],
        [
            (0, op_return_spk(0x14, not_cp2_ca)),
            (f[4]["value_sat"] - FEE_SAT, cl.fund_key["p2wpkh_spk"]),
            (SEAL_SAT, not_seal["p2wpkh_spk"]),
        ],
    )
    cl.broadcast_and_wait_peer(not_cp2_raw)
    cl.mine(1)

    tkt_ok = {
        "artifact_identity": fsv_art, "genesis": cl.genesis_hash, "network": "regtest",
        "notarizations": [{
            "act_smt_proof": sl.smt_prove({}, f"act:{not_id}|*"),
            "batch_proof": not_b1_pfs[not_e1],
            "checkpoint": not_cp1, "checkpoint_txid": not_cp1_tx,
            "checkpoints_proof": sl.rfc9162_inclusion_proof(not_l1, 0),
            "head_checkpoint": not_cp2, "head_checkpoint_txid": not_cp2_tx,
            "notary_act": not_env,
            "target_smt_proof": sl.smt_prove({}, f"target:{fsv_tid}|*"),
        }],
        "release": rel_env, "release_batch_proof": rel_b1_pfs[rel_e1],
        "release_checkpoint": rel_cp1, "release_checkpoint_txid": rel_cp1_tx,
        "release_checkpoints_proof": sl.rfc9162_inclusion_proof(rel_l1, 0),
        "release_head_checkpoint": rel_cp2, "release_head_checkpoint_txid": rel_cp2_tx,
        "release_smt_proof": sl.smt_prove({}, f"rel:{rel_id}|*"),
        "target_sha256": fsv_tid, "type": "seallink-ticket/1",
    }
    gk_pol = {
        "allow_reinstatement": False, "mode": "hardened", "quorum_m": 1,
        "release_floor": {"works.relux/curator-cli": 10}, "require_release": True,
        "required_claims": ["seallink.org/build-repro"],
        "trusted_notaries": [{"log_id": not_log_id, "notary_pin": not_pin}],
        "trusted_release_issuers": [{"allowed_product_prefixes": ["works.relux/"], "issuer_pin": rel_pin, "log_id": rel_log_id}],
    }

    v_art = sv.Tier1Verifier(
        pinned_network="regtest", pinned_genesis=cl.genesis_hash, operator_min_depth=1,
        require_jsonschema=True, require_observation_bracket=True,
        enabled_modules=["core", "artifact-notarization"],
    )
    v_core = sv.Tier1Verifier(
        pinned_network="regtest", pinned_genesis=cl.genesis_hash, operator_min_depth=1,
        require_jsonschema=True, require_observation_bracket=True,
        enabled_modules=["core"],
    )

    ch1 = sv.ChainView(cl.new_cold_observer().build_chain_view(wire_objects=[tkt_ok, rel_cp1, not_cp1]))
    j_log = sv.FencedJournal(sl.sha256(b"t7-log-journal").hex())

    # Verdict 1: verify_log_checkpoint cp2 (chained to cp1 via non-default next_log_vout=2) + FencedJournal log-head restart replay!
    r_cp2 = v_art.verify_log_checkpoint(rel_cp2, rel_cp2_tx, ch1, prev_cp_env=rel_cp1, prev_cp_txid=rel_cp1_tx, journal=j_log)
    assert r_cp2.verdict == "ADMIT", f"Trace 07 cp2 verification failed: {r_cp2}"
    j_log_rep = sv.FencedJournal.replay_persisted_entries(
        j_log.journal_id, json.loads(json.dumps(j_log.entries)),
        witness_pos=j_log.witness_pos, witness_commitment=j_log.witness_commitment, write_token_active=True,
    )
    assert j_log_rep.check_continuity() is None and j_log_rep.log_heads == j_log.log_heads

    # Verdict 2: verify_release (log_tracked Core primitive) -> ADMIT!
    r_rel = v_core.verify_release(
        rel_env, ch1,
        log_ctx={
            "batch_proof": rel_b1_pfs[rel_e1], "checkpoint": rel_cp1, "checkpoint_txid": rel_cp1_tx,
            "checkpoints_proof": sl.rfc9162_inclusion_proof(rel_l1, 0),
            "head_checkpoint": rel_cp2, "head_checkpoint_txid": rel_cp2_tx,
            "smt_proof": sl.smt_prove({}, f"rel:{rel_id}|*"),
        },
        journal=j_log_rep,
    )
    assert r_rel.verdict == "ADMIT", f"Trace 07 verify_release failed: {r_rel}"

    # Verdict 3: verify_artifact_ticket (PROFILE-artifact-v1 Gatekeeper hardened 1-of-1 + release_floor) -> ADMIT!
    r_tkt_ok = v_art.verify_artifact_ticket(tkt_ok, gk_pol, ch1, journal=j_log_rep)
    assert r_tkt_ok.verdict == "ADMIT", f"Trace 07 Gatekeeper ADMIT failed: {r_tkt_ok}"

    # 5. Emit SMT target:<tid>|* revocation in terminal cp3 (seq=3) on notary log -> Gatekeeper MUST refuse ARTIFACT_POLICY_DENIED!
    rev_t = sl.sign_envelope({
        "denial_key": f"target:{fsv_tid}|*", "genesis": cl.genesis_hash, "issued_at": tip_t0 + 60,
        "issuer": not_role_pin, "log_id": not_log_id, "network": "regtest",
        "reason_code": "supply-chain-alert", "role": "notary", "state_seq": 1, "type": "seallink-log-revocation/1",
    }, [not_role["sk"]])
    rev_t_ca = sl.content_addr(rev_t)
    e_rev = sl.log_entry_digest(0x02, rev_t_ca)
    not_b3_root, _ = sl.build_log_batch_root([e_rev])
    not_l2 = not_l1 + [sl.ckpt_leaf(2, not_cp2_ca)]
    kv_rev = {f"target:{fsv_tid}|*": rev_t_ca}
    not_cp3 = sl.sign_envelope({
        "batch_count": 1, "batch_root": not_b3_root, "checkpoints_root": sl.rfc9162_mth(not_l2).hex(),
        "cumulative_entries_count": 2, "denials_delta_root": not_b3_root, "denials_root": sl.smt_root(kv_rev),
        "genesis": cl.genesis_hash, "issuer": not_role_pin, "log_id": not_log_id, "network": "regtest",
        "prev_checkpoint_id": not_cp2_ca, "prev_log_outpoint": {"txid": not_cp2_tx, "vout": 2},
        "role": "notary", "seq": 3, "terminal": True, "type": "seallink-log-checkpoint/1",
    }, [not_role["sk"]])
    not_cp3_ca = sl.content_addr(not_cp3)
    not_cp3_tx, not_cp3_raw = build_signed_tx(
        [{"txid": not_cp2_tx, "vout": 2, "value_sat": SEAL_SAT, "kind": "p2wpkh", "signer": not_seal}, f[5]],
        [(0, op_return_spk(0x14, not_cp3_ca)), (f[5]["value_sat"] + SEAL_SAT - FEE_SAT, cl.fund_key["p2wpkh_spk"])],
    )
    cl.broadcast_and_wait_peer(not_cp3_raw)
    cl.mine(1)

    tkt_rev = copy.deepcopy(tkt_ok)
    tkt_rev["notarizations"][0].update({
        "act_smt_proof": sl.smt_prove(kv_rev, f"act:{not_id}|*"),
        "checkpoints_proof": sl.rfc9162_inclusion_proof(not_l2, 0),
        "head_checkpoint": not_cp3, "head_checkpoint_txid": not_cp3_tx,
        "target_smt_proof": sl.smt_prove(kv_rev, f"target:{fsv_tid}|*"),
        "target_state_record": rev_t,
    })
    ch2 = sv.ChainView(cl.new_cold_observer().build_chain_view(wire_objects=[tkt_rev, not_cp1, not_cp2, rel_cp1]))
    # Verdict 4: Revoked target in cp3 SMT -> REFUSE ARTIFACT_POLICY_DENIED!
    r_tkt_rev = v_art.verify_artifact_ticket(tkt_rev, gk_pol, ch2)
    assert (r_tkt_rev.verdict, r_tkt_rev.refusal_code) == ("REFUSE", "ARTIFACT_POLICY_DENIED"), (
        f"Trace 07 revoked ticket expected ARTIFACT_POLICY_DENIED, got {r_tkt_rev}"
    )

    # 6. Extract a REAL MINED SegWitNameUpdateProof directly from Node B's 9-method read-only rpcwhitelist RPCs!
    obs_rpc = nca.make_cli_rpc(cl.bin_dir, cl.dirs[1], cl.ports[1], regtest=True, rpcuser=cl.obs_user, rpcpassword=cl.obs_password)
    upd_txid = not_rec["update_txid"]
    upd_txd = obs_rpc("getrawtransaction", upd_txid, True)
    upd_raw_hex = upd_txd["hex"]
    prev_txid = upd_txd["vin"][0]["txid"]
    prev_raw_hex = obs_rpc("getrawtransaction", prev_txid, False)
    blk_hash = upd_txd["blockhash"]
    blk_raw_hex = obs_rpc("getblock", blk_hash, 0)
    blk_hdr_hex = blk_raw_hex[:160]  # real 80-byte Namecoin Core block header!
    blk_v1 = obs_rpc("getblock", blk_hash, 1)
    blk_v2 = obs_rpc("getblock", blk_hash, 2)
    blk_height = int(blk_v2["height"])
    hdr_entry: dict[str, Any] = {"header_hex": blk_hdr_hex, "height": blk_height}
    if isinstance(blk_v1.get("auxpow"), dict):
        ap = blk_v1["auxpow"]
        pb = ap["parentblock"]
        prev_h = bytes.fromhex(pb.get("previousblockhash", "00" * 32))[::-1]
        parent_hdr = (
            struct.pack("<I", int(pb["version"]))
            + prev_h
            + bytes.fromhex(pb["merkleroot"])[::-1]
            + struct.pack("<III", int(pb["time"]), int(pb["bits"], 16), int(pb["nonce"]))
        )
        assert sl.dsha256(parent_hdr)[::-1].hex() == pb["hash"], "reconstructed parent_hdr hash mismatch"
        c_branch = list(ap["chainmerklebranch"])
        hdr_entry["auxpow"] = {
            "chain_branch": c_branch,
            "chain_merkle_nonce": 0,
            "chain_merkle_size": 1 << len(c_branch),
            "coinbase_branch": list(ap["merklebranch"]),
            "parent_coinbase_hex": ap["tx"]["hex"],
            "parent_header_hex": parent_hdr.hex(),
        }
    tx_list = blk_v2["tx"]
    tx_idx = next(i for i, tx in enumerate(tx_list) if tx["txid"] == upd_txid)
    cb_raw_hex = tx_list[0]["hex"]
    txids_le = [bytes.fromhex(tx["txid"])[::-1] for tx in tx_list]
    wtxids_le = [b"\x00" * 32] + [bytes.fromhex(tx["hash"])[::-1] for tx in tx_list[1:]]
    _, t_branches = _btc_merkle_branches_from_hashes_le(txids_le)
    _, w_branches = _btc_merkle_branches_from_hashes_le(wtxids_le)
    real_spv_proof = {
        "block_hash": blk_hash,
        "block_header_hex": blk_hdr_hex,
        "block_height": blk_height,
        "coinbase_merkle_branch": t_branches[0],
        "coinbase_tx_hex": cb_raw_hex,
        "prevout_tx_hex": prev_raw_hex,
        "tx_hex": upd_raw_hex,
        "tx_index": tx_idx,
        "txid_branch": t_branches[tx_idx],
        "wtxid_branch": w_branches[tx_idx],
        "wtxid_coinbase_branch": w_branches[0],
    }
    tier2_page = {
        "genesis": cl.genesis_hash, "has_more": False, "limit": 10,
        "name": "id/t7-notary-1", "network": "regtest",
        "registration": not_rec["registration"],
        "type": "seallink-tier2-name-history/1",
        "updates": [real_spv_proof],
    }

    # Verdict 5: REAL mined nc28.0 SegWitNameUpdateProof + real AuxPoW block header PoW -> ADMIT!
    r_spv_ok = v_art.verify_tier2_name_history_page(
        tier2_page, not_pol, headers=[hdr_entry]
    )
    assert r_spv_ok.verdict == "ADMIT", f"Trace 07 REAL mined nc28.0 SegWitNameUpdateProof failed: {r_spv_ok}"

    # Verdict 6: Core-only verifier refuses Tier-2 module page with ACTION_UNSUPPORTED!
    r_spv_core = v_core.verify_tier2_name_history_page(tier2_page, not_pol)
    assert (r_spv_core.verdict, r_spv_core.refusal_code) == ("REFUSE", "ACTION_UNSUPPORTED"), (
        f"Trace 07 core-only expected ACTION_UNSUPPORTED, got {r_spv_core}"
    )

    return {
        "cold_observer_adapter": "tools/nc_rpc_adapter.py:ColdNamecoinObserver",
        "release_log_id": rel_log_id,
        "notary_log_id": not_log_id,
        "artifact_target_sha256": fsv_tid,
        "release_cp1_0x14_txid": rel_cp1_tx,
        "release_cp2_0x14_txid": rel_cp2_tx,
        "notary_cp1_0x14_txid": not_cp1_tx,
        "notary_cp2_0x14_txid": not_cp2_tx,
        "notary_cp3_revocation_0x14_txid": not_cp3_tx,
        "non_default_next_log_vout": 2,
        "real_mined_spv_txid": upd_txid,
        "real_mined_spv_block_hash": blk_hash,
        "real_mined_spv_block_height": blk_height,
        "real_mined_spv_tx_index": tx_idx,
        "real_mined_spv_merkle_depth": len(t_branches[0]),
        "real_mined_spv_auxpow_verified": "auxpow" in hdr_entry,
        "verdicts": {
            "log_checkpoint_cp2_and_journal_replay": {"verdict": r_cp2.verdict, "outcome": r_cp2.outcome},
            "log_tracked_release_core": {"verdict": r_rel.verdict, "outcome": r_rel.outcome},
            "artifact_gatekeeper_hardened_admit": {"verdict": r_tkt_ok.verdict, "outcome": r_tkt_ok.outcome},
            "artifact_gatekeeper_post_cp3_smt_revocation": {"verdict": r_tkt_rev.verdict, "refusal_code": r_tkt_rev.refusal_code},
            "real_mined_nc28_tier2_spv_proof": {"verdict": r_spv_ok.verdict, "outcome": r_spv_ok.outcome},
            "tier2_module_core_only_gating": {"verdict": r_spv_core.verdict, "refusal_code": r_spv_core.refusal_code},
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Execute all 7 SealLink traces live on two Namecoin Core nc28.0 regtest nodes via ColdNamecoinObserver.")
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
        t5 = run_trace_05(cl)
        t6 = run_trace_06(cl)
        t7 = run_trace_07(cl)
        elapsed = round(time.monotonic() - t0, 2)
        report = {
            "suite": "seallink-nc28-live-traces-regtest",
            "spec_version": "1.0.0-draft.11",
            "chain": "regtest",
            "policy": "standard (-acceptnonstdtxn=0 -txindex=1 -namehistory=1), two loopback-only nodes (node A writer outbound -> node B read-only cold observer with -disablewallet=1 and -rpcwhitelistdefault=0)",
            "node_b_rpcwhitelist": cl.obs_whitelist.split(","),
            "node_b_rpcwhitelist_enforced": True,
            "observer_adapter": "tools/nc_rpc_adapter.py:ColdNamecoinObserver",
            "node_meta": meta,
            "final_tip_height": cl.rpc(1, "getblockcount"),
            "elapsed_seconds": elapsed,
            "trace_01_mail_read_executor_ref_offline_revoke": t1,
            "trace_02_guardian_succession_p2wsh_csv": t2,
            "trace_03_delegation_depth2_restart_single_use_p2a": t3,
            "trace_04_ward_agent_intake": t4,
            "trace_05_historical_diploma_expiry_reregistration": t5,
            "trace_06_voluntary_rebind_0x13_and_alien_p2pkh_hijack": t6,
            "trace_07_transparency_log_0x14_gatekeeper_and_real_mined_spv": t7,
        }
    finally:
        stopped = cl.stop()
        shutil.rmtree(work_dir, ignore_errors=True)

    report["stopped_all_owned_processes"] = stopped
    assert stopped, "Failed to stop all regtest namecoind processes cleanly"
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"PASS: All 7 SealLink traces verified live via ColdNamecoinObserver on Namecoin Core {meta['subversion']} regtest in {elapsed}s -> {args.output_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
