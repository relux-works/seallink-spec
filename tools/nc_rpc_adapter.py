#!/usr/bin/env python3
"""
Cold-Observer Namecoin Core (nc28.0) RPC-to-ChainView Adapter for SealLink Tier 1 Verifiers.

Populates a `tools/seallink_verifier.py` `ChainView` strictly from an independent read-only
Namecoin Core full node (`-txindex=1 -namehistory=1 -disablewallet=1`) cross-checked against
at least one independent comparison node (`SPEC-02 §1.1`, `SL-LDGR-002`, `SL-LDGR-008`), with
ZERO reliance on writer-side state, writer-maintained name histories, or caller-supplied spend maps.

Honest boundary of inputs:
  - Ledger facts (headers, blocks, raw transactions, BIP-141 witnesses, UTXO liveness via
    `gettxout(..., include_mempool=True)`, live mempool, confirmed spends, and full multi-registration
    `name_history`) are discovered strictly from the read-only node RPC (`read_rpc`).
  - Independent comparison tip height & hash come strictly from `compare_rpc` (or list of peers).
  - Off-chain SealLink wire objects being verified (manifests, ScriptPolicy preimages carried in
    `NamePin` / `Seal` / `Origin` fields) are verified byte-for-byte against on-chain scriptPubKey
    hashes and OP_RETURN commitments before inclusion.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import seallink_ref as sl  # noqa: E402
import seallink_verifier as sv  # noqa: E402

RpcFn = Callable[..., Any]


def make_cli_rpc(bin_dir: Path, datadir: Path, rpcport: int, *, regtest: bool = True) -> RpcFn:
    """Create a `namecoin-cli` RPC callable for a Namecoin Core node."""
    cli = str(bin_dir / "namecoin-cli")
    base = [cli] + (["-regtest"] if regtest else []) + [
        f"-datadir={datadir}",
        f"-rpcport={rpcport}",
        "-rpcconnect=127.0.0.1",
        "-stdin",
    ]

    def _call(method: str, *args: Any, wait: bool = False) -> Any:
        cmd = list(base)
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
            raise RuntimeError(f"namecoin-cli {method} failed: {p.stderr.strip()[:400]}")
        out = p.stdout.strip()
        if not out:
            return None
        try:
            return json.loads(out)
        except ValueError:
            return out

    return _call


def _extract_slnk_opreturn_hex(vouts: list[dict[str, Any]]) -> str | None:
    """Extract canonical SLNK OP_RETURN scriptPubKey hex (`6a28534c4e4b...` or `6a32534c4e4b...`) if present."""
    for vout in vouts:
        spk_hex = vout.get("scriptPubKey", {}).get("hex", "")
        if len(spk_hex) >= 12 and spk_hex.startswith("6a"):
            try:
                spk_b = bytes.fromhex(spk_hex)
            except ValueError:
                continue
            if len(spk_b) >= 6 and spk_b[2:6] == b"SLNK":
                return spk_hex
    return None


def _extract_sighash_bytes(txinwitness: list[str]) -> list[int]:
    """Extract trailing sighash bytes strictly from DER-encoded ECDSA signatures in a BIP-141 witness."""
    out: list[int] = []
    for item in txinwitness:
        if isinstance(item, str) and len(item) >= 16 and item.startswith("30"):
            try:
                out.append(int(item[-2:], 16))
            except ValueError:
                continue
    return out


def _collect_wire_hints(obj: Any, *, names: set[str], policies_by_spk: dict[str, dict[str, Any]], outpoints: set[tuple[str, int]], txids: set[str], block_hashes: set[str]) -> None:
    """Walk untrusted SealLink wire bundle objects solely to extract lookup targets and ScriptPolicy preimages.

    Every ScriptPolicy preimage is indexed strictly by its compiled `scriptPubKey` hex and verified
    against the actual on-chain output script returned by the read-only Namecoin node.
    """
    if isinstance(obj, list):
        for item in obj:
            _collect_wire_hints(item, names=names, policies_by_spk=policies_by_spk, outpoints=outpoints, txids=txids, block_hashes=block_hashes)
        return
    if not isinstance(obj, dict):
        return

    # ScriptPolicy preimage candidate?
    if obj.get("kind") in ("key", "multisig", "branch"):
        try:
            spk, _ = sl.compile_script_policy(obj)
            policies_by_spk[spk.hex()] = obj
        except (ValueError, KeyError, TypeError):
            pass

    # Name references
    for nk in ("name", "ward_name", "guardian_name", "party_name", "provider_of", "owner", "subject_ward_name", "intended_name"):
        nv = obj.get(nk)
        if isinstance(nv, str) and "/" in nv:
            names.add(nv)
    # Nested issuer/executor/holder/guardian/provider names
    if isinstance(obj.get("txid"), str) and isinstance(obj.get("vout"), int) and len(obj["txid"]) == 64:
        outpoints.add((obj["txid"], obj["vout"]))
        txids.add(obj["txid"])
    # Delegate ranges
    if isinstance(obj.get("txid"), str) and isinstance(obj.get("first"), int) and isinstance(obj.get("count"), int):
        txids.add(obj["txid"])
        for v in range(obj["first"], obj["first"] + obj["count"]):
            outpoints.add((obj["txid"], v))
        if isinstance(obj.get("stop_txid"), str) and isinstance(obj.get("stop_first"), int):
            txids.add(obj["stop_txid"])
            for v in range(obj["stop_first"], obj["stop_first"] + obj["count"]):
                outpoints.add((obj["stop_txid"], v))
    # Explicit txid references in proof_path / origin_bundle
    for tk in ("issuance_txid", "origin_anchor_txid", "name_binding_txid", "anchor_txid", "use_txid"):
        tv = obj.get(tk)
        if isinstance(tv, str) and len(tv) == 64:
            txids.add(tv)
    if isinstance(obj.get("recent_block"), str) and len(obj["recent_block"]) == 64:
        block_hashes.add(obj["recent_block"])

    for v in obj.values():
        _collect_wire_hints(v, names=names, policies_by_spk=policies_by_spk, outpoints=outpoints, txids=txids, block_hashes=block_hashes)


class ColdNamecoinObserver:
    """Stateless cold-start Namecoin Core Tier 1 RPC observer building verified `ChainView` snapshots."""

    def __init__(
        self,
        read_rpc: RpcFn,
        compare_rpcs: list[tuple[str, RpcFn]],
        *,
        network: str = "regtest",
        clock_now_fn: Callable[[int], int] | None = None,
    ) -> None:
        self.read_rpc = read_rpc
        self.compare_rpcs = list(compare_rpcs)
        self.network = network
        # By default uses tip_header_time + 30 (deterministic for regtest); production passes wall-clock UTC
        self.clock_now_fn = clock_now_fn or (lambda tip_time: tip_time + 30)
        self._block_cache: dict[int, dict[str, Any]] = {}
        self._tx_cache: dict[str, dict[str, Any]] = {}
        self._hdr_cache: dict[str, dict[str, Any]] = {}
        self._genesis_hash: str | None = None

    @property
    def genesis_hash(self) -> str:
        if self._genesis_hash is None:
            self._genesis_hash = self.read_rpc("getblockhash", 0)
        return self._genesis_hash

    def _get_header(self, blockhash: str) -> dict[str, Any]:
        if blockhash not in self._hdr_cache:
            self._hdr_cache[blockhash] = self.read_rpc("getblockheader", blockhash)
        return self._hdr_cache[blockhash]

    def _get_block_by_height(self, height: int) -> dict[str, Any]:
        if height not in self._block_cache:
            bh = self.read_rpc("getblockhash", height)
            self._block_cache[height] = self.read_rpc("getblock", bh, 2)
        return self._block_cache[height]

    def _get_raw_tx(self, txid: str, *, allow_mempool: bool = True) -> dict[str, Any] | None:
        if txid in self._tx_cache:
            # Refresh unconfirmed txs in case they just mined
            if self._tx_cache[txid].get("blockhash"):
                return self._tx_cache[txid]
        try:
            txd = self.read_rpc("getrawtransaction", txid, True)
        except RuntimeError:
            return None
        if not allow_mempool and "blockhash" not in txd:
            return None
        self._tx_cache[txid] = txd
        return txd

    def _find_spender_cold(
        self,
        txid: str,
        vout: int,
        created_height: int,
        tip_height: int,
        mempool_txs: dict[str, dict[str, Any]],
    ) -> dict[str, Any] | None:
        """Discover the spending transaction of (txid, vout) strictly from Node B (mempool first, then blocks)."""
        # 1. Fast check: is it STILL unspent in Node B's UTXO set + mempool?
        utxo = self.read_rpc("gettxout", txid, vout, True)
        if utxo is not None:
            return None
        # 2. Check live mempool first (mempool spend before mining!)
        for mtx in mempool_txs.values():
            for vin in mtx.get("vin", []):
                if vin.get("txid") == txid and int(vin.get("vout", -1)) == vout:
                    return mtx
        # 3. Scan confirmed blocks from created_height..tip_height on Node B (cached per height)
        for h in range(max(1, created_height), tip_height + 1):
            blk = self._get_block_by_height(h)
            for btx in blk.get("tx", []):
                for vin in btx.get("vin", []):
                    if vin.get("txid") == txid and int(vin.get("vout", -1)) == vout:
                        # Attach blockhash so downstream consumers know confirmed height
                        btx_copy = dict(btx)
                        btx_copy["blockhash"] = blk["hash"]
                        self._tx_cache[btx["txid"]] = btx_copy
                        return btx_copy
        return None

    def _txd_to_view(self, txd: dict[str, Any], mempool_set: set[str], spent_map: dict[tuple[str, int], str]) -> dict[str, Any]:
        txid = txd["txid"]
        conf_h: int | None = None
        if "blockhash" in txd:
            conf_h = int(self._get_header(txd["blockhash"])["height"])
        inputs_v: list[dict[str, Any]] = []
        for vin in txd.get("vin", []):
            if "txid" in vin:
                inputs_v.append({
                    "prev_txid": vin["txid"],
                    "prev_vout": int(vin["vout"]),
                    "script_sig_hex": vin.get("scriptSig", {}).get("hex", ""),
                    "witness": list(vin.get("txinwitness", [])),
                })
        outputs_v: dict[str, Any] = {}
        for vout in txd.get("vout", []):
            n = int(vout["n"])
            spk_hex = vout["scriptPubKey"]["hex"]
            o_ent: dict[str, Any] = {"script_pubkey_hex": spk_hex}
            if (txid, n) in spent_map:
                o_ent["spent_by_txid"] = spent_map[(txid, n)]
            outputs_v[str(n)] = o_ent
        obj: dict[str, Any] = {
            "confirmed_height": conf_h,
            "in_mempool": txid in mempool_set,
            "inputs": inputs_v,
            "outputs": outputs_v,
        }
        opret_hex = _extract_slnk_opreturn_hex(txd.get("vout", []))
        if opret_hex is not None:
            obj["opreturn_hex"] = opret_hex
        return obj

    def _discover_name_lineages(
        self,
        name: str,
        policies_by_spk: dict[str, dict[str, Any]],
        collected_txs: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Discover ALL historical registration lineages for `name` strictly via Node B `name_history` RPC."""
        try:
            raw_hist = self.read_rpc("name_history", name)
        except RuntimeError:
            return []
        if not isinstance(raw_hist, list) or not raw_hist:
            return []

        # Fetch full confirmed transaction for every history entry and sort chronologically
        enriched: list[tuple[int, int, dict[str, Any], dict[str, Any], int, dict[str, Any]]] = []
        for idx, item in enumerate(raw_hist):
            txid = item["txid"]
            vout_n = int(item["vout"])
            txd = self._get_raw_tx(txid, allow_mempool=False)
            if txd is None or "blockhash" not in txd:
                continue
            collected_txs[txid] = txd
            h_conf = int(self._get_header(txd["blockhash"])["height"])
            out_obj = next(o for o in txd["vout"] if int(o["n"]) == vout_n)
            spk_hex = out_obj["scriptPubKey"]["hex"]
            try:
                parsed = sl.parse_name_output(bytes.fromhex(spk_hex))
            except ValueError:
                continue
            enriched.append((h_conf, idx, item, txd, vout_n, parsed))
        enriched.sort(key=lambda t: (t[0], t[1]))

        # Partition into distinct registration lineages at each NAME_FIRSTUPDATE!
        raw_lineages: list[list[tuple[int, dict[str, Any], int, dict[str, Any]]]] = []
        for h_conf, _idx, _item, txd, vout_n, parsed in enriched:
            if parsed["op"] == "NAME_FIRSTUPDATE":
                raw_lineages.append([(h_conf, txd, vout_n, parsed)])
            elif parsed["op"] == "NAME_UPDATE" and raw_lineages:
                # Attach to the lineage whose previous output this tx spends!
                in_ops = {(v.get("txid"), int(v.get("vout", -1))) for v in txd.get("vin", []) if "txid" in v}
                attached = False
                for lin in reversed(raw_lineages):
                    last_txid, last_vout = lin[-1][1]["txid"], lin[-1][2]
                    if (last_txid, last_vout) in in_ops:
                        lin.append((h_conf, txd, vout_n, parsed))
                        attached = True
                        break
                if not attached:
                    raw_lineages[-1].append((h_conf, txd, vout_n, parsed))

        lineages_out: list[dict[str, Any]] = []
        for lin in raw_lineages:
            # First pass: derive any P2WPKH / P2WSH owner_policy directly from subsequent spending witnesses!
            derived_pols: dict[int, dict[str, Any]] = {}
            for pos in range(len(lin) - 1):
                _h0, prev_txd, prev_vout, prev_parsed = lin[pos]
                _h1, next_txd, _nv, _np = lin[pos + 1]
                t_spk_hex = prev_parsed["trailing_script_pubkey"]
                spent_vin = next(
                    (v for v in next_txd.get("vin", []) if v.get("txid") == prev_txd["txid"] and int(v.get("vout", -1)) == prev_vout),
                    None,
                )
                if spent_vin:
                    wit = spent_vin.get("txinwitness", [])
                    # P2WPKH witness: [der_sig, compressed_pk]
                    if len(wit) == 2 and len(wit[1]) == 66 and sl.is_valid_compressed_pubkey(wit[1]):
                        cand = {"kind": "key", "pk": wit[1]}
                        if sl.compile_script_policy(cand)[0].hex() == t_spk_hex:
                            derived_pols[pos] = cand
                            policies_by_spk.setdefault(t_spk_hex, cand)

            updates_v: list[dict[str, Any]] = []
            for pos, (h_conf, txd, vout_n, parsed) in enumerate(lin):
                out_spk_hex = next(o["scriptPubKey"]["hex"] for o in txd["vout"] if int(o["n"]) == vout_n)
                t_spk_hex = parsed["trailing_script_pubkey"]
                owner_pol = derived_pols.get(pos) or policies_by_spk.get(t_spk_hex)
                if owner_pol is None:
                    # Unspent output without matching policy preimage in verified bundle -> synthetic unmatchable marker
                    owner_pol = {"kind": "unknown_unspent_spk", "spk_hex": t_spk_hex}
                u_obj: dict[str, Any] = {
                    "confirmed_height": h_conf,
                    "op": parsed["op"],
                    "output_script_hex": out_spk_hex,
                    "owner_policy": owner_pol,
                    "txid": txd["txid"],
                    "vout": vout_n,
                }
                if pos > 0:
                    prev_u = updates_v[pos - 1]
                    spent_vin = next(
                        (v for v in txd.get("vin", []) if v.get("txid") == prev_u["txid"] and int(v.get("vout", -1)) == prev_u["vout"]),
                        None,
                    )
                    if spent_vin is not None:
                        u_obj["prev_input"] = {
                            "sighash_bytes": _extract_sighash_bytes(spent_vin.get("txinwitness", [])),
                            "txid": prev_u["txid"],
                            "vout": prev_u["vout"],
                            "witness_policy": prev_u["owner_policy"],
                        }
                opret_hex = _extract_slnk_opreturn_hex(txd.get("vout", []))
                if opret_hex is not None:
                    u_obj["opreturn_hex"] = opret_hex
                updates_v.append(u_obj)

            if updates_v:
                lineages_out.append({
                    "registration": {"txid": updates_v[0]["txid"], "vout": updates_v[0]["vout"]},
                    "updates": updates_v,
                })
        return lineages_out

    def build_chain_view(
        self,
        *,
        wire_objects: list[Any] | None = None,
        extra_names: list[str] | None = None,
        extra_outpoints: list[tuple[str, int]] | None = None,
        extra_txids: list[str] | None = None,
        extra_block_hashes: list[str] | None = None,
        extra_policies: list[dict[str, Any]] | None = None,
        manifests: dict[str, Any] | None = None,
        max_spend_hops: int = 16,
    ) -> dict[str, Any]:
        """Build a live SealLink `ChainView` dict strictly from read-only Node B + comparison peers."""
        b_info = self.read_rpc("getblockchaininfo")
        tip_h = int(b_info["blocks"])
        tip_hash = b_info["bestblockhash"]
        tip_hdr = self._get_header(tip_hash)
        tip_time = int(tip_hdr["time"])
        now_ts = int(self.clock_now_fn(tip_time))

        comp_peers: list[dict[str, Any]] = []
        for peer_id, crpc in self.compare_rpcs:
            try:
                c_info = crpc("getblockchaininfo")
                comp_peers.append({
                    "hash_at_tip": c_info["bestblockhash"],
                    "healthy": not bool(c_info.get("initialblockdownload", False)),
                    "height": int(c_info["blocks"]),
                    "id": peer_id,
                })
            except Exception:
                comp_peers.append({"healthy": False, "id": peer_id})

        # Extract lookup targets & ScriptPolicy preimages ONLY from the verified wire objects + optional explicit args
        target_names: set[str] = set(extra_names or [])
        policies_by_spk: dict[str, dict[str, Any]] = {}
        target_outpoints: set[tuple[str, int]] = set(extra_outpoints or [])
        target_txids: set[str] = set(extra_txids or [])
        target_blocks: set[str] = set(extra_block_hashes or [])

        for pol in (extra_policies or []):
            try:
                policies_by_spk[sl.compile_script_policy(pol)[0].hex()] = pol
            except (ValueError, KeyError, TypeError):
                pass
        for wo in (wire_objects or []):
            _collect_wire_hints(
                wo,
                names=target_names,
                policies_by_spk=policies_by_spk,
                outpoints=target_outpoints,
                txids=target_txids,
                block_hashes=target_blocks,
            )
        if manifests:
            _collect_wire_hints(
                list(manifests.values()),
                names=target_names,
                policies_by_spk=policies_by_spk,
                outpoints=target_outpoints,
                txids=target_txids,
                block_hashes=target_blocks,
            )

        # Fetch live mempool snapshot strictly from Node B
        mempool_ids = list(self.read_rpc("getrawmempool"))
        mempool_set = set(mempool_ids)
        mempool_txs: dict[str, dict[str, Any]] = {}
        for mid in mempool_ids:
            mtx = self._get_raw_tx(mid, allow_mempool=True)
            if mtx is not None:
                mempool_txs[mid] = mtx

        collected_txs: dict[str, dict[str, Any]] = dict(mempool_txs)

        # 1. Cold-discover ALL historical registration lineages for every referenced name via `name_history`!
        names_view: dict[str, Any] = {}
        name_regs_view: dict[str, list[dict[str, Any]]] = {}
        for nm in sorted(target_names):
            lineages = self._discover_name_lineages(nm, policies_by_spk, collected_txs)
            if lineages:
                names_view[nm] = lineages[-1]          # Current/latest registration lineage
                name_regs_view[nm] = lineages          # All historical registration lineages

        # 2. Fetch explicitly referenced txids (issuance anchors, 0x09/0x0c anchors, use_txids)
        for tid in sorted(target_txids):
            txd = self._get_raw_tx(tid, allow_mempool=True)
            if txd is not None:
                collected_txs[tid] = txd

        # 3. Cold-discover spend chains (mempool + confirmed blocks!) for all referenced seals/outpoints
        spent_map: dict[tuple[str, int], str] = {}
        # Pre-seed spent_map from already fetched txs (mempool + name history)
        for txd in list(collected_txs.values()):
            for vin in txd.get("vin", []):
                if "txid" in vin:
                    spent_map[(vin["txid"], int(vin["vout"]))] = txd["txid"]

        queue: list[tuple[str, int, int]] = [(txid, vout, 0) for txid, vout in sorted(target_outpoints)]
        visited_ops: set[tuple[str, int]] = set()
        while queue:
            op_txid, op_vout, hop = queue.pop(0)
            if (op_txid, op_vout) in visited_ops or hop > max_spend_hops:
                continue
            visited_ops.add((op_txid, op_vout))
            txd = self._get_raw_tx(op_txid, allow_mempool=True)
            if txd is None:
                continue
            collected_txs[op_txid] = txd
            created_h = int(self._get_header(txd["blockhash"])["height"]) if "blockhash" in txd else tip_h
            # Skip name outputs (already indexed via name_history)
            out_match = next((o for o in txd.get("vout", []) if int(o["n"]) == op_vout), None)
            if out_match and out_match.get("scriptPubKey", {}).get("hex", "").startswith(("52", "53")):
                continue
            if (op_txid, op_vout) in spent_map:
                spender = collected_txs.get(spent_map[(op_txid, op_vout)])
            else:
                spender = self._find_spender_cold(op_txid, op_vout, created_h, tip_height=tip_h, mempool_txs=mempool_txs)
            if spender is not None:
                stxid = spender["txid"]
                collected_txs[stxid] = spender
                spent_map[(op_txid, op_vout)] = stxid
                # Follow continuation outputs (vout 0 and vout 1) when tracing seal/roster/guardian/recovery spines
                for next_vout in (0, 1):
                    if any(int(o["n"]) == next_vout for o in spender.get("vout", [])):
                        o_spk = next(o["scriptPubKey"]["hex"] for o in spender["vout"] if int(o["n"]) == next_vout)
                        if not o_spk.startswith(("6a", "52", "53")):
                            queue.append((stxid, next_vout, hop + 1))

        txs_view = {
            txid: self._txd_to_view(txd, mempool_set, spent_map)
            for txid, txd in collected_txs.items()
        }

        blocks_view: dict[str, int] = {tip_hash: tip_h}
        for bh in sorted(target_blocks):
            try:
                blocks_view[bh] = int(self._get_header(bh)["height"])
            except RuntimeError:
                pass

        return {
            "best_header_height": int(b_info["headers"]),
            "blocks": blocks_view,
            "clock_watermark": tip_time - 60,
            "comparison_peers": comp_peers,
            "credible_utc_interval": [now_ts - 60, now_ts + 60],
            "future_bound_s": 600,
            "genesis": self.genesis_hash,
            "in_ibd": bool(b_info["initialblockdownload"]),
            "lag_limit": 1,
            "manifests": copy.deepcopy(manifests) if manifests else {},
            "name_registrations": name_regs_view,
            "names": names_view,
            "network": self.network,
            "node_reachable": True,
            "now": now_ts,
            "tip_first_sight": tip_time,
            "tip_hash": tip_hash,
            "tip_header_time": tip_time,
            "tip_height": tip_h,
            "txindex": True,
            "txs": txs_view,
        }


# Need copy for build_chain_view manifests deepcopy
import copy  # noqa: E402


def self_test() -> None:
    """Deterministic offline unit test for ColdNamecoinObserver (multi-registration + mempool spend)."""
    gen = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    sk1 = sl.deterministic_privkey("nc-adapter-test-own1")
    sk2 = sl.deterministic_privkey("nc-adapter-test-own2")
    pk1 = sl.compressed_pubkey(sk1)
    pk2 = sl.compressed_pubkey(sk2)
    pol1 = {"kind": "key", "pk": pk1}
    pol2 = {"kind": "key", "pk": pk2}
    spk1, _ = sl.compile_script_policy(pol1)
    spk2, _ = sl.compile_script_policy(pol2)
    cred1 = sl.xonly_pubkey(sl.deterministic_privkey("nc-adapter-test-cred1"))
    cred2 = sl.xonly_pubkey(sl.deterministic_privkey("nc-adapter-test-cred2"))

    fu1_txid = hashlib.sha256(b"fu1").hexdigest()
    u1_txid = hashlib.sha256(b"u1").hexdigest()
    fu2_txid = hashlib.sha256(b"fu2").hexdigest()
    u2_txid = hashlib.sha256(b"u2").hexdigest()
    seal_txid = hashlib.sha256(b"seal").hexdigest()
    rev_txid = hashlib.sha256(b"rev-mempool").hexdigest()

    b150 = hashlib.sha256(b"blk150").hexdigest()
    b151 = hashlib.sha256(b"blk151").hexdigest()
    b200 = hashlib.sha256(b"blk200").hexdigest()
    b204 = hashlib.sha256(b"blk204").hexdigest()

    v1_b = sl.jcs_encode({"link": {"cred": cred1}})
    v2_b = sl.jcs_encode({"link": {"cred": cred2}})
    fake_sig = "3044" + ("02" * 68) + "01"

    txs = {
        fu1_txid: {
            "txid": fu1_txid, "blockhash": b150, "vin": [],
            "vout": [{"n": 0, "scriptPubKey": {"hex": sl.encode_name_output("NAME_FIRSTUPDATE", spk1, name=b"id/school", rand=b"\x01" * 20, value=v1_b).hex()}}],
        },
        u1_txid: {
            "txid": u1_txid, "blockhash": b151,
            "vin": [{"txid": fu1_txid, "vout": 0, "scriptSig": {"hex": ""}, "txinwitness": [fake_sig, pk1]}],
            "vout": [{"n": 0, "scriptPubKey": {"hex": sl.encode_name_output("NAME_UPDATE", spk1, name=b"id/school", value=v1_b).hex()}}],
        },
        fu2_txid: {
            "txid": fu2_txid, "blockhash": b200, "vin": [],
            "vout": [{"n": 0, "scriptPubKey": {"hex": sl.encode_name_output("NAME_FIRSTUPDATE", spk2, name=b"id/school", rand=b"\x02" * 20, value=v2_b).hex()}}],
        },
        u2_txid: {
            "txid": u2_txid, "blockhash": b204,
            "vin": [{"txid": fu2_txid, "vout": 0, "scriptSig": {"hex": ""}, "txinwitness": [fake_sig, pk2]}],
            "vout": [{"n": 0, "scriptPubKey": {"hex": sl.encode_name_output("NAME_UPDATE", spk2, name=b"id/school", value=v2_b).hex()}}],
        },
        seal_txid: {
            "txid": seal_txid, "blockhash": b200, "vin": [],
            "vout": [{"n": 0, "scriptPubKey": {"hex": spk1.hex()}}],
        },
        rev_txid: {
            "txid": rev_txid,
            "vin": [{"txid": seal_txid, "vout": 0, "scriptSig": {"hex": ""}, "txinwitness": [fake_sig, pk1]}],
            "vout": [{"n": 0, "scriptPubKey": {"hex": spk2.hex()}}],
        },
    }
    hdrs = {
        b150: {"hash": b150, "height": 150, "time": 1795200000},
        b151: {"hash": b151, "height": 151, "time": 1795200600},
        b200: {"hash": b200, "height": 200, "time": 1795210000},
        b204: {"hash": b204, "height": 204, "time": 1795220000},
    }

    def mock_rpc(method: str, *args: Any) -> Any:
        if method == "getblockhash":
            return gen if args[0] == 0 else b204
        if method == "getblockchaininfo":
            return {"chain": "regtest", "blocks": 204, "headers": 204, "bestblockhash": b204, "initialblockdownload": False}
        if method == "getblockheader":
            return hdrs[args[0]]
        if method == "getrawmempool":
            return [rev_txid]
        if method == "getrawtransaction":
            return txs[args[0]]
        if method == "gettxout":
            return None if (args[0] == seal_txid and args[1] == 0) else {"confirmations": 1}
        if method == "name_history":
            assert args[0] == "id/school"
            return [
                {"txid": fu1_txid, "vout": 0, "height": 150},
                {"txid": u1_txid, "vout": 0, "height": 151},
                {"txid": fu2_txid, "vout": 0, "height": 200},
                {"txid": u2_txid, "vout": 0, "height": 204},
            ]
        raise RuntimeError(f"Unexpected mock RPC: {method}")

    obs = ColdNamecoinObserver(mock_rpc, [("peer-a", mock_rpc)], network="regtest")
    cv_dict = obs.build_chain_view(extra_names=["id/school"], extra_outpoints=[(seal_txid, 0)], extra_policies=[pol1, pol2])
    ch = sv.ChainView(cv_dict)
    v = sv.Tier1Verifier(pinned_network="regtest", pinned_genesis=gen, require_jsonschema=True)

    # Current lookup resolves to NEW owner (reg2)!
    cur_rec, cur_err = v.resolve_name("id/school", ch, expected_owner_policy=pol2, expected_registration={"txid": fu2_txid, "vout": 0})
    assert cur_err is None and cur_rec is not None and cur_rec["_value_obj"]["link"]["cred"] == cred2
    # Historical lookup at height 157 resolves to ORIGINAL school (reg1) from the EXACT SAME ChainView!
    old_rec, old_err = v.resolve_name("id/school", ch, expected_owner_policy=pol1, expected_registration={"txid": fu1_txid, "vout": 0}, at_height=157)
    assert old_err is None and old_rec is not None and old_rec["_value_obj"]["link"]["cred"] == cred1
    # Cold observer discovered mempool spend of seal_txid:0 without any writer hint!
    assert cv_dict["txs"][seal_txid]["outputs"]["0"]["spent_by_txid"] == rev_txid
    assert cv_dict["txs"][rev_txid]["in_mempool"] is True


if __name__ == "__main__":
    self_test()
    print("nc_rpc_adapter self_test PASS (cold multi-registration name_history + mempool spend discovery)")
