#!/usr/bin/env python3
"""
Cold-Observer Namecoin Core (nc28.0) RPC-to-ChainView Adapter for SealLink Tier 1 Verifiers.

Populates a `tools/seallink_verifier.py` `ChainView` strictly from an independent read-only
Namecoin Core full node (`-txindex=1 -namehistory=1 -disablewallet=1`) cross-checked against
at least one independent comparison node (`SPEC-02 §1.1`, `SL-LDGR-002`, `SL-LDGR-008`), with
ZERO reliance on writer-side state, writer-maintained name histories, or caller-supplied spend maps.

Key Tier 1 guarantees enforced here:
  1. Complete `SPEC-02 §4` observation bracket: reads `(hash_0, height_0)` BEFORE all ledger
     queries and `(hash_1, height_1)` AFTER all queries, populating `rebracket_tip` and
     `observation_bracket` (optionally discarding & retrying on mid-read tip transition via
     `retry_on_tip_change`). Never labels an unmeasured bracket as consistent.
  2. Pre-effect recheck (`pre_effect_recheck`): re-queries tip, comparison peers, mempool,
     and live `gettxout(..., include_mempool=True)` for active seals immediately before effect.
  3. Explicit separation of operational wall-clock / persisted freshness state
     (`clock_mode="operational"` with durable `clock_watermark` and `first_sight_by_hash`
     persisted at `state_path`) from deterministic regtest clocks (`clock_mode="regtest_deterministic"`).
  4. Schema-driven continuation traversal: follows exact signed continuation output indices
     (`pending_vout`, `active_vout`, `next_roster_vout`, `new_vacant_vout`, `next_status_vout`,
     `next_recovery_vout`, fixed `0x0e` index `0`, plus frameless halt/P2A outputs) rather than
     hardcoding output indices `(0, 1)`.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
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


def _collect_wire_hints(
    obj: Any,
    *,
    names: set[str],
    policies_by_spk: dict[str, dict[str, Any]],
    outpoints: set[tuple[str, int]],
    txids: set[str],
    block_hashes: set[str],
    continuation_vouts_by_frame: dict[tuple[str, str], set[int]],
) -> None:
    """Walk untrusted SealLink wire bundle objects solely to extract lookup targets, ScriptPolicy
    preimages, and signed continuation output indices (`pending_vout`, `active_vout`, etc.).

    Every ScriptPolicy preimage is indexed strictly by its compiled `scriptPubKey` hex and verified
    against the actual on-chain output script returned by the read-only Namecoin node; every
    continuation output index is indexed strictly by the object's cryptographic commitment (`content_addr`
    or `object_id`) matched against the on-chain `SLNK` `OP_RETURN` frame of the discovered transaction.
    """
    if isinstance(obj, list):
        for item in obj:
            _collect_wire_hints(
                item,
                names=names,
                policies_by_spk=policies_by_spk,
                outpoints=outpoints,
                txids=txids,
                block_hashes=block_hashes,
                continuation_vouts_by_frame=continuation_vouts_by_frame,
            )
        return
    if not isinstance(obj, dict):
        return

    # Index signed/unsigned continuation output indices strictly by cryptographic frame commitment!
    payload = obj.get("payload")
    if isinstance(payload, dict) and isinstance(payload.get("type"), str):
        ptype = payload["type"]
        try:
            ca = sl.content_addr(obj)
        except Exception:
            ca = None
        if ca is not None:
            if ptype == "seallink-guardian/1":
                if payload.get("activation_mode") == "appointed" and isinstance(payload.get("pending_vout"), int):
                    continuation_vouts_by_frame.setdefault(("0x0d", ca), set()).add(payload["pending_vout"])
                elif payload.get("activation_mode") == "initial" and isinstance(payload.get("active_vout"), int):
                    continuation_vouts_by_frame.setdefault(("0x12", ca), set()).add(payload["active_vout"])
            elif ptype == "seallink-guardian-roster/1":
                vset = continuation_vouts_by_frame.setdefault(("0x0f", ca), set())
                if isinstance(payload.get("next_roster_vout"), int):
                    vset.add(payload["next_roster_vout"])
                for s_item in payload.get("slots", []):
                    if isinstance(s_item, dict) and s_item.get("action") == "new_vacant" and isinstance(s_item.get("new_vacant_vout"), int):
                        vset.add(s_item["new_vacant_vout"])
            elif ptype == "seallink-capacity/1" and isinstance(payload.get("next_status_vout"), int):
                continuation_vouts_by_frame.setdefault(("0x09", ca), set()).add(payload["next_status_vout"])
    elif obj.get("type") == "seallink-name-binding/1" and isinstance(obj.get("next_recovery_vout"), int):
        try:
            bid = sl.object_id(obj)
            continuation_vouts_by_frame.setdefault(("0x0c", bid), set()).add(obj["next_recovery_vout"])
        except Exception:
            pass

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
    # Outpoints
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
        _collect_wire_hints(
            v,
            names=names,
            policies_by_spk=policies_by_spk,
            outpoints=outpoints,
            txids=txids,
            block_hashes=block_hashes,
            continuation_vouts_by_frame=continuation_vouts_by_frame,
        )


class ColdNamecoinObserver:
    """Cold-start Namecoin Core Tier 1 RPC observer building bracket-verified `ChainView` snapshots."""

    def __init__(
        self,
        read_rpc: RpcFn,
        compare_rpcs: list[tuple[str, RpcFn]],
        *,
        network: str = "regtest",
        clock_mode: str = "operational",
        clock_now_fn: Callable[[], int] | None = None,
        regtest_clock_offset_s: int = 30,
        state_path: Path | None = None,
    ) -> None:
        if clock_mode not in ("operational", "regtest_deterministic"):
            raise ValueError(f"Unsupported clock_mode: {clock_mode}")
        self.read_rpc = read_rpc
        self.compare_rpcs = list(compare_rpcs)
        self.network = network
        self.clock_mode = clock_mode
        self.clock_now_fn = clock_now_fn or (lambda: int(time.time()))
        self.regtest_clock_offset_s = int(regtest_clock_offset_s)
        self.state_path = Path(state_path) if state_path is not None else None
        self._block_cache: dict[int, dict[str, Any]] = {}
        self._tx_cache: dict[str, dict[str, Any]] = {}
        self._hdr_cache: dict[str, dict[str, Any]] = {}
        self._genesis_hash: str | None = None
        self._clock_watermark: int = 0
        self._first_sight_by_hash: dict[str, int] = {}
        if self.state_path is not None and self.state_path.exists():
            self._load_state()

    def _load_state(self) -> None:
        assert self.state_path is not None
        raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        self._clock_watermark = int(raw.get("clock_watermark", 0))
        self._first_sight_by_hash = {str(k): int(v) for k, v in raw.get("first_sight_by_hash", {}).items()}

    def _save_state(self) -> None:
        if self.state_path is None:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(
                {
                    "clock_watermark": self._clock_watermark,
                    "first_sight_by_hash": self._first_sight_by_hash,
                },
                indent=2,
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        tmp.replace(self.state_path)

    def _sample_tip(self) -> dict[str, Any]:
        """Read current tip from the reading node and update monotonic watermark / first-sight map."""
        b_info = self.read_rpc("getblockchaininfo")
        tip_h = int(b_info["blocks"])
        tip_hash = str(b_info["bestblockhash"])
        tip_hdr = self._get_header(tip_hash)
        hdr_time = int(tip_hdr["time"])

        if self.clock_mode == "operational":
            now_ts = int(self.clock_now_fn())
            prev_wm = self._clock_watermark
            if now_ts >= prev_wm:
                self._clock_watermark = now_ts
                effective_wm = prev_wm
            else:
                # Preserve higher persisted watermark so Tier1Verifier detects regression (CHAIN_CLOCK_ERROR)
                effective_wm = prev_wm
            if tip_hash not in self._first_sight_by_hash:
                self._first_sight_by_hash[tip_hash] = now_ts
            first_sight = self._first_sight_by_hash[tip_hash]
            self._save_state()
            clock_src = "operational_persisted" if self.state_path is not None else "operational_memory"
        else:
            now_ts = hdr_time + self.regtest_clock_offset_s
            prev_wm = self._clock_watermark
            if now_ts >= prev_wm:
                self._clock_watermark = now_ts
                effective_wm = min(prev_wm, now_ts) if prev_wm > 0 else hdr_time - 60
            else:
                effective_wm = prev_wm
            if tip_hash not in self._first_sight_by_hash:
                self._first_sight_by_hash[tip_hash] = hdr_time
            first_sight = self._first_sight_by_hash[tip_hash]
            self._save_state()
            clock_src = "regtest_deterministic"

        return {
            "b_info": b_info,
            "height": tip_h,
            "hash": tip_hash,
            "header_time": hdr_time,
            "first_sight": first_sight,
            "now": now_ts,
            "clock_watermark": effective_wm,
            "clock_source": clock_src,
        }

    def _poll_comparison_peers(self) -> list[dict[str, Any]]:
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
        return comp_peers

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

        raw_lineages: list[list[tuple[int, dict[str, Any], int, dict[str, Any]]]] = []
        for h_conf, _idx, _item, txd, vout_n, parsed in enriched:
            if parsed["op"] == "NAME_FIRSTUPDATE":
                raw_lineages.append([(h_conf, txd, vout_n, parsed)])
            elif parsed["op"] == "NAME_UPDATE" and raw_lineages:
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

    def _continuation_vouts_for_spender(
        self,
        spender: dict[str, Any],
        continuation_vouts_by_frame: dict[tuple[str, str], set[int]],
        policies_by_spk: dict[str, dict[str, Any]],
    ) -> list[int]:
        """Derive continuation outputs strictly from the spender's SLNK frame + verified record vout
        fields (pending_vout, active_vout, next_roster_vout, new_vacant_vout, next_status_vout,
        next_recovery_vout, fixed 0x0e vout 0) or frameless halt/P2A policy matches."""
        vouts = spender.get("vout", [])
        out_by_n = {int(o["n"]): o.get("scriptPubKey", {}).get("hex", "") for o in vouts}
        selected: set[int] = set()

        opret_hex = _extract_slnk_opreturn_hex(vouts)
        if opret_hex is not None:
            try:
                dec = sl.decode_opreturn(bytes.fromhex(opret_hex))
            except ValueError:
                dec = None
            if dec is not None:
                selected |= continuation_vouts_by_frame.get((dec["action"], dec["commitment"]), set())
                if dec["action"] == "0x0e":
                    selected.add(0)
        else:
            # Frameless spend (e.g. active/pending halt returning vacant_seal at vout 0, or P2A CPFP anchor)
            if 0 in out_by_n:
                selected.add(0)

        # Also follow any output whose on-chain scriptPubKey explicitly matches P2A or a known seal ScriptPolicy
        p2a_hex = sl.P2A_SCRIPTPUBKEY.hex()
        for n, spk_hex in out_by_n.items():
            if spk_hex == p2a_hex or spk_hex in policies_by_spk:
                selected.add(n)

        return [
            n
            for n in sorted(selected)
            if n in out_by_n and not out_by_n[n].startswith(("6a", "52", "53"))
        ]

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
        retry_on_tip_change: int = 0,
    ) -> dict[str, Any]:
        """Build a bracket-verified SealLink `ChainView` strictly from read-only Node B + comparison peers.

        Reads tip `(hash_0, height_0)` before all queries and `(hash_1, height_1)` after all queries
        (`SPEC-02 §4`). If the tip changes mid-read and `retry_on_tip_change > 0`, discards the
        inconsistent snapshot and retries on the new tip; otherwise returns the snapshot with its
        true mismatched `rebracket_tip` so `Tier1Verifier` fails closed with `CHAIN_OBSERVATION_VOID`.
        """
        target_names: set[str] = set(extra_names or [])
        policies_by_spk: dict[str, dict[str, Any]] = {}
        target_outpoints: set[tuple[str, int]] = set(extra_outpoints or [])
        target_txids: set[str] = set(extra_txids or [])
        target_blocks: set[str] = set(extra_block_hashes or [])
        continuation_vouts_by_frame: dict[tuple[str, str], set[int]] = {}

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
                continuation_vouts_by_frame=continuation_vouts_by_frame,
            )
        if manifests:
            _collect_wire_hints(
                list(manifests.values()),
                names=target_names,
                policies_by_spk=policies_by_spk,
                outpoints=target_outpoints,
                txids=target_txids,
                block_hashes=target_blocks,
                continuation_vouts_by_frame=continuation_vouts_by_frame,
            )

        max_attempts = max(1, int(retry_on_tip_change) + 1)
        last_view: dict[str, Any] = {}
        for attempt in range(1, max_attempts + 1):
            # Opening tip bracket (hash_0, height_0)
            start_s = self._sample_tip()
            b_info = start_s["b_info"]
            tip_h = start_s["height"]
            tip_hash = start_s["hash"]
            tip_time = start_s["header_time"]
            now_ts = start_s["now"]
            comp_peers = self._poll_comparison_peers()

            mempool_ids = list(self.read_rpc("getrawmempool"))
            mempool_set = set(mempool_ids)
            mempool_txs: dict[str, dict[str, Any]] = {}
            for mid in mempool_ids:
                mtx = self._get_raw_tx(mid, allow_mempool=True)
                if mtx is not None:
                    mempool_txs[mid] = mtx

            collected_txs: dict[str, dict[str, Any]] = dict(mempool_txs)

            # 1. Cold-discover ALL historical registration lineages via `name_history`
            names_view: dict[str, Any] = {}
            name_regs_view: dict[str, list[dict[str, Any]]] = {}
            for nm in sorted(target_names):
                lineages = self._discover_name_lineages(nm, policies_by_spk, collected_txs)
                if lineages:
                    names_view[nm] = lineages[-1]
                    name_regs_view[nm] = lineages

            # 2. Fetch explicitly referenced txids
            for tid in sorted(target_txids):
                txd = self._get_raw_tx(tid, allow_mempool=True)
                if txd is not None:
                    collected_txs[tid] = txd

            # 3. Cold-discover spend chains following exact signed continuation output indices
            spent_map: dict[tuple[str, int], str] = {}
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
                    for next_vout in self._continuation_vouts_for_spender(spender, continuation_vouts_by_frame, policies_by_spk):
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

            # Closing tip bracket (hash_1, height_1) AFTER all queries (`SPEC-02 §4` item 1)
            end_s = self._sample_tip()
            consistent = (start_s["hash"] == end_s["hash"] and start_s["height"] == end_s["height"])

            last_view = {
                "best_header_height": int(b_info["headers"]),
                "blocks": blocks_view,
                "clock_source": start_s["clock_source"],
                "clock_watermark": start_s["clock_watermark"],
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
                "observation_bracket": {
                    "attempts": attempt,
                    "consistent": consistent,
                    "end": {"hash": end_s["hash"], "height": end_s["height"], "now": end_s["now"]},
                    "pre_effect_rechecked": False,
                    "start": {"hash": start_s["hash"], "height": start_s["height"], "now": start_s["now"]},
                },
                "rebracket_tip": {
                    "first_sight": end_s["first_sight"],
                    "hash": end_s["hash"],
                    "header_time": end_s["header_time"],
                    "height": end_s["height"],
                    "now": end_s["now"],
                },
                "tip_first_sight": start_s["first_sight"],
                "tip_hash": tip_hash,
                "tip_header_time": tip_time,
                "tip_height": tip_h,
                "txindex": True,
                "txs": txs_view,
            }
            if consistent:
                return last_view
            # Inconsistent mid-read tip transition: invalidate caches before retrying on new tip!
            self._block_cache.clear()
            self._tx_cache.clear()
        return last_view

    def pre_effect_recheck(
        self,
        chain_view: dict[str, Any],
        seal_outpoints: list[tuple[str, int]],
    ) -> dict[str, Any]:
        """Fresh pre-effect recheck (`SPEC-02 §4` item 5): re-samples tip, comparison peers,
        mempool, and live `gettxout(..., include_mempool=True)` for active seals immediately before effect."""
        fresh = copy.deepcopy(chain_view)
        end_s = self._sample_tip()
        fresh["comparison_peers"] = self._poll_comparison_peers()
        fresh["rebracket_tip"] = {
            "first_sight": end_s["first_sight"],
            "hash": end_s["hash"],
            "header_time": end_s["header_time"],
            "height": end_s["height"],
            "now": end_s["now"],
        }
        ob = fresh.setdefault("observation_bracket", {})
        ob["pre_effect_rechecked"] = True
        ob["pre_effect_tip"] = {"hash": end_s["hash"], "height": end_s["height"], "now": end_s["now"]}
        ob["consistent"] = (end_s["hash"] == fresh["tip_hash"] and end_s["height"] == fresh["tip_height"])

        mempool_ids = list(self.read_rpc("getrawmempool"))
        mempool_set = set(mempool_ids)
        mempool_txs: dict[str, dict[str, Any]] = {}
        for mid in mempool_ids:
            mtx = self._get_raw_tx(mid, allow_mempool=True)
            if mtx is not None:
                mempool_txs[mid] = mtx

        spent_map: dict[tuple[str, int], str] = {}
        for mtx in mempool_txs.values():
            for vin in mtx.get("vin", []):
                if "txid" in vin:
                    spent_map[(vin["txid"], int(vin["vout"]))] = mtx["txid"]

        for op_txid, op_vout in seal_outpoints:
            tx_entry = fresh["txs"].get(op_txid)
            created_h = int(tx_entry["confirmed_height"]) if tx_entry and tx_entry.get("confirmed_height") is not None else end_s["height"]
            spender = self._find_spender_cold(op_txid, op_vout, created_h, tip_height=end_s["height"], mempool_txs=mempool_txs)
            if spender is not None:
                stxid = spender["txid"]
                spent_map[(op_txid, op_vout)] = stxid
                fresh["txs"][stxid] = self._txd_to_view(spender, mempool_set, spent_map)
                if tx_entry and str(op_vout) in tx_entry.get("outputs", {}):
                    tx_entry["outputs"][str(op_vout)]["spent_by_txid"] = stxid
        return fresh


def self_test() -> None:
    """Deterministic offline unit test covering:
      1. Multi-registration `name_history` + cold mempool spend discovery.
      2. Arbitrary signed `pending_vout = 2` continuation traversal (`0x0d` -> `0x0e` at vout 0).
      3. Complete observation bracket: mid-read tip transition -> `CHAIN_OBSERVATION_VOID`,
         then `retry_on_tip_change=1` -> consistent bracket -> `ADMIT`.
      4. Operational persisted `clock_watermark` & `first_sight_by_hash` across instances + rollback refusal.
      5. Fresh `pre_effect_recheck` catching a last-instant mempool seal spend -> `SEAL_SPENT`.
    """
    gen = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    sk1 = sl.deterministic_privkey("nc-adapter-test-own1")
    sk2 = sl.deterministic_privkey("nc-adapter-test-own2")
    pk1, pk2 = sl.compressed_pubkey(sk1), sl.compressed_pubkey(sk2)
    pol1, pol2 = {"kind": "key", "pk": pk1}, {"kind": "key", "pk": pk2}
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

    # Pending appointment at vout=2 (non-continuation change at vout=1, OP_RETURN at vout=0!)
    disp_pk = sl.compressed_pubkey(sl.deterministic_privkey("nc-t-disp"))
    arb_pk = sl.compressed_pubkey(sl.deterministic_privkey("nc-t-arb"))
    chal_pk = sl.compressed_pubkey(sl.deterministic_privkey("nc-t-chal"))
    g_pk = sl.compressed_pubkey(sl.deterministic_privkey("nc-t-guard"))
    reg_sk = sl.deterministic_privkey("nc-t-reg")
    vac_pol = {"kind": "branch", "template": "both_of_2", "keys": {"a": disp_pk, "b": arb_pk}}
    pend_pol = {"kind": "branch", "template": "guardian_slot_pending", "delay_blocks": 3, "keys": {"challenger": chal_pk, "disposer": disp_pk, "guardian": g_pk}}
    act_pol = {"kind": "branch", "template": "either_of_2", "keys": {"a": disp_pk, "b": g_pk}}
    vac_spk, _ = sl.compile_script_policy(vac_pol)
    pend_spk, _ = sl.compile_script_policy(pend_pol)
    act_spk, _ = sl.compile_script_policy(act_pol)
    other_spk = b"\x00\x14" + (b"\x99" * 20)

    vac_txid = hashlib.sha256(b"vac-tx").hexdigest()
    g_rec_p = {
        "activation_mode": "appointed", "active_policy": act_pol, "effective_delay_blocks": 3,
        "genesis": gen, "guardian": {"name": "id/g2", "owner_policy": pol2, "registration": {"txid": fu2_txid, "vout": 0}},
        "issuer": {"name": "id/school", "owner_policy": pol2, "registration": {"txid": fu2_txid, "vout": 0}, "role_policy": {"m": 1, "pks": [sl.xonly_pubkey(reg_sk)]}},
        "network": "regtest", "origin_id": hashlib.sha256(b"orig").hexdigest(), "pending_policy": pend_pol,
        "pending_vout": 2, "prev_outpoint": {"txid": vac_txid, "vout": 0}, "revision": 2, "slot": 1, "term": {"mode": "indefinite"},
        "type": "seallink-guardian/1",
    }
    g_rec = sl.sign_envelope(g_rec_p, [reg_sk])
    pend_txid = hashlib.sha256(b"pend-vout2-tx").hexdigest()
    act_txid = hashlib.sha256(b"act-0x0e-tx").hexdigest()

    b150 = hashlib.sha256(b"blk150").hexdigest()
    b151 = hashlib.sha256(b"blk151").hexdigest()
    b200 = hashlib.sha256(b"blk200").hexdigest()
    b204 = hashlib.sha256(b"blk204").hexdigest()
    b205 = hashlib.sha256(b"blk205").hexdigest()

    v1_b = sl.jcs_encode({"link": {"cred": cred1}})
    v2_b = sl.jcs_encode({"link": {"cred": cred2}})
    fake_sig = "3044" + ("02" * 68) + "01"

    txs: dict[str, dict[str, Any]] = {
        fu1_txid: {"txid": fu1_txid, "blockhash": b150, "vin": [], "vout": [{"n": 0, "scriptPubKey": {"hex": sl.encode_name_output("NAME_FIRSTUPDATE", spk1, name=b"id/school", rand=b"\x01" * 20, value=v1_b).hex()}}]},
        u1_txid: {"txid": u1_txid, "blockhash": b151, "vin": [{"txid": fu1_txid, "vout": 0, "scriptSig": {"hex": ""}, "txinwitness": [fake_sig, pk1]}], "vout": [{"n": 0, "scriptPubKey": {"hex": sl.encode_name_output("NAME_UPDATE", spk1, name=b"id/school", value=v1_b).hex()}}]},
        fu2_txid: {"txid": fu2_txid, "blockhash": b200, "vin": [], "vout": [{"n": 0, "scriptPubKey": {"hex": sl.encode_name_output("NAME_FIRSTUPDATE", spk2, name=b"id/school", rand=b"\x02" * 20, value=v2_b).hex()}}]},
        u2_txid: {"txid": u2_txid, "blockhash": b204, "vin": [{"txid": fu2_txid, "vout": 0, "scriptSig": {"hex": ""}, "txinwitness": [fake_sig, pk2]}], "vout": [{"n": 0, "scriptPubKey": {"hex": sl.encode_name_output("NAME_UPDATE", spk2, name=b"id/school", value=v2_b).hex()}}]},
        seal_txid: {"txid": seal_txid, "blockhash": b200, "vin": [], "vout": [{"n": 0, "scriptPubKey": {"hex": spk1.hex()}}]},
        rev_txid: {"txid": rev_txid, "vin": [{"txid": seal_txid, "vout": 0, "scriptSig": {"hex": ""}, "txinwitness": [fake_sig, pk1]}], "vout": [{"n": 0, "scriptPubKey": {"hex": spk2.hex()}}]},
        vac_txid: {"txid": vac_txid, "blockhash": b200, "vin": [], "vout": [{"n": 0, "scriptPubKey": {"hex": vac_spk.hex()}}]},
        pend_txid: {
            "txid": pend_txid, "blockhash": b200,
            "vin": [{"txid": vac_txid, "vout": 0, "scriptSig": {"hex": ""}, "txinwitness": [fake_sig]}],
            "vout": [
                {"n": 0, "scriptPubKey": {"hex": sl.encode_opreturn(0x0D, sl.content_addr(g_rec)).hex()}},
                {"n": 1, "scriptPubKey": {"hex": other_spk.hex()}},
                {"n": 2, "scriptPubKey": {"hex": pend_spk.hex()}},
            ],
        },
        act_txid: {
            "txid": act_txid, "blockhash": b204,
            "vin": [{"txid": pend_txid, "vout": 2, "scriptSig": {"hex": ""}, "txinwitness": [fake_sig]}],
            "vout": [
                {"n": 0, "scriptPubKey": {"hex": act_spk.hex()}},
                {"n": 1, "scriptPubKey": {"hex": sl.encode_opreturn(0x0E, sl.object_id(g_rec_p)).hex()}},
            ],
        },
    }
    hdrs = {
        b150: {"hash": b150, "height": 150, "time": 1795200000},
        b151: {"hash": b151, "height": 151, "time": 1795200600},
        b200: {"hash": b200, "height": 200, "time": 1795210000},
        b204: {"hash": b204, "height": 204, "time": 1795220000},
        b205: {"hash": b205, "height": 205, "time": 1795220020},
    }
    blocks_by_h = {
        200: {"hash": b200, "tx": [txs[vac_txid], txs[pend_txid]]},
        204: {"hash": b204, "tx": [txs[act_txid]]},
        205: {"hash": b205, "tx": []},
    }
    state = {"tip_h": 204, "tip_hash": b204, "mempool": [], "seal_spent": False, "gbi_calls": 0, "flip_after_first_gbi": False}

    def mock_rpc(method: str, *args: Any) -> Any:
        if method == "getblockhash":
            h = args[0]
            if h == 0:
                return gen
            return b205 if h == 205 else (b204 if h == 204 else b200)
        if method == "getblock":
            bh = args[0]
            return blocks_by_h.get(hdrs[bh]["height"], {"hash": bh, "tx": []})
        if method == "getblockchaininfo":
            state["gbi_calls"] += 1
            if state["flip_after_first_gbi"] and state["gbi_calls"] == 2:
                state["tip_h"] = 205
                state["tip_hash"] = b205
            return {"chain": "regtest", "blocks": state["tip_h"], "headers": state["tip_h"], "bestblockhash": state["tip_hash"], "initialblockdownload": False}
        if method == "getblockheader":
            return hdrs[args[0]]
        if method == "getrawmempool":
            return list(state["mempool"])
        if method == "getrawtransaction":
            return txs[args[0]]
        if method == "gettxout":
            txid_q, vout_q = args[0], args[1]
            if txid_q == vac_txid and vout_q == 0:
                return None
            if txid_q == pend_txid and vout_q == 2:
                return None
            if txid_q == seal_txid and vout_q == 0 and state["seal_spent"]:
                return None
            return {"confirmations": 1}
        if method == "name_history":
            return [
                {"txid": fu1_txid, "vout": 0, "height": 150},
                {"txid": u1_txid, "vout": 0, "height": 151},
                {"txid": fu2_txid, "vout": 0, "height": 200},
                {"txid": u2_txid, "vout": 0, "height": 204},
            ]
        raise RuntimeError(f"Unexpected mock RPC: {method}")

    def mock_compare_rpc(method: str, *args: Any) -> Any:
        if method == "getblockchaininfo":
            return {"chain": "regtest", "blocks": state["tip_h"], "headers": state["tip_h"], "bestblockhash": state["tip_hash"], "initialblockdownload": False}
        raise RuntimeError(f"Unexpected mock compare RPC: {method}")

    # Test 1 + 2: Multi-registration name_history + pending_vout=2 traversal + closed bracket (gbi_calls >= 2)!
    obs = ColdNamecoinObserver(mock_rpc, [("peer-a", mock_compare_rpc)], network="regtest", clock_mode="regtest_deterministic")
    cv_dict = obs.build_chain_view(wire_objects=[g_rec], extra_names=["id/school"], extra_outpoints=[(seal_txid, 0)], extra_policies=[pol1, pol2])
    assert state["gbi_calls"] == 2 and cv_dict["observation_bracket"]["consistent"] is True
    assert cv_dict["clock_source"] == "regtest_deterministic"
    # Cold observer MUST have discovered pend_txid:2 -> act_txid (0x0e) -> act_txid:0 WITHOUT any hint!
    assert cv_dict["txs"][vac_txid]["outputs"]["0"]["spent_by_txid"] == pend_txid
    assert cv_dict["txs"][pend_txid]["outputs"]["2"]["spent_by_txid"] == act_txid
    assert act_txid in cv_dict["txs"] and "0" in cv_dict["txs"][act_txid]["outputs"]

    ch = sv.ChainView(cv_dict)
    v_strict = sv.Tier1Verifier(pinned_network="regtest", pinned_genesis=gen, require_jsonschema=True, require_observation_bracket=True)
    assert v_strict.check_chain_observation(ch) is None
    cur_rec, cur_err = v_strict.resolve_name("id/school", ch, expected_owner_policy=pol2, expected_registration={"txid": fu2_txid, "vout": 0})
    assert cur_err is None and cur_rec is not None and cur_rec["_value_obj"]["link"]["cred"] == cred2
    old_rec, old_err = v_strict.resolve_name("id/school", ch, expected_owner_policy=pol1, expected_registration={"txid": fu1_txid, "vout": 0}, at_height=157)
    assert old_err is None and old_rec is not None and old_rec["_value_obj"]["link"]["cred"] == cred1

    # Test 3: Mid-read tip transition -> without retry MUST refuse CHAIN_OBSERVATION_VOID; with retry=1 -> consistent ADMIT!
    state["tip_h"], state["tip_hash"], state["gbi_calls"], state["flip_after_first_gbi"] = 204, b204, 0, True
    cv_void = ColdNamecoinObserver(mock_rpc, [("peer-a", mock_compare_rpc)], network="regtest", clock_mode="regtest_deterministic").build_chain_view(extra_names=["id/school"], retry_on_tip_change=0)
    assert cv_void["observation_bracket"]["consistent"] is False
    assert v_strict.check_chain_observation(sv.ChainView(cv_void)) == "CHAIN_OBSERVATION_VOID"

    state["tip_h"], state["tip_hash"], state["gbi_calls"], state["flip_after_first_gbi"] = 204, b204, 0, True
    cv_retried = ColdNamecoinObserver(mock_rpc, [("peer-a", mock_compare_rpc)], network="regtest", clock_mode="regtest_deterministic").build_chain_view(extra_names=["id/school"], retry_on_tip_change=1)
    assert cv_retried["observation_bracket"]["consistent"] is True and cv_retried["observation_bracket"]["attempts"] == 2
    assert v_strict.check_chain_observation(sv.ChainView(cv_retried)) is None

    # Test 4: Operational persisted clock_watermark & first_sight_by_hash + rollback detection!
    state["tip_h"], state["tip_hash"], state["gbi_calls"], state["flip_after_first_gbi"] = 204, b204, 0, False
    with tempfile.TemporaryDirectory(prefix="seallink-obs-state-") as td:
        sp = Path(td) / "obs-state.json"
        obs_op1 = ColdNamecoinObserver(mock_rpc, [("peer-a", mock_compare_rpc)], network="regtest", clock_mode="operational", clock_now_fn=lambda: 1795220100, state_path=sp)
        cv_op1 = obs_op1.build_chain_view(extra_names=["id/school"])
        assert cv_op1["clock_source"] == "operational_persisted" and cv_op1["tip_first_sight"] == 1795220100
        assert v_strict.check_chain_observation(sv.ChainView(cv_op1)) is None
        # Fresh instance loads persisted watermark (1795220100); clock rollback (1795220050) -> CHAIN_CLOCK_ERROR!
        obs_op2 = ColdNamecoinObserver(mock_rpc, [("peer-a", mock_compare_rpc)], network="regtest", clock_mode="operational", clock_now_fn=lambda: 1795220050, state_path=sp)
        cv_op2 = obs_op2.build_chain_view(extra_names=["id/school"])
        assert v_strict.check_chain_observation(sv.ChainView(cv_op2)) == "CHAIN_CLOCK_ERROR"

    # Test 5: pre_effect_recheck discovers fresh mempool seal spend right before effect!
    state["mempool"] = [rev_txid]
    state["seal_spent"] = True
    cv_pre = obs.pre_effect_recheck(cv_dict, [(seal_txid, 0)])
    assert cv_pre["observation_bracket"]["pre_effect_rechecked"] is True
    assert cv_pre["txs"][seal_txid]["outputs"]["0"]["spent_by_txid"] == rev_txid
    assert cv_pre["txs"][rev_txid]["in_mempool"] is True


if __name__ == "__main__":
    self_test()
    print("nc_rpc_adapter self_test PASS (multi-reg + pending_vout=2 + bracket/retry + persisted clock + pre-effect recheck)")
