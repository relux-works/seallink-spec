#!/usr/bin/env python3
"""
Cold-Observer Namecoin Core (nc28.0) RPC-to-ChainView Adapter for SealLink Tier 1 Verifiers.

Populates a `tools/seallink_verifier.py` `ChainView` strictly from an independent read-only
Namecoin Core full node (`-txindex=1 -namehistory=1 -disablewallet=1`) cross-checked against
at least one independent comparison node (`SPEC-02 §1.1`, `SL-LDGR-002`, `SL-LDGR-008`), with
ZERO reliance on writer-side state, writer-maintained name histories, or caller-supplied spend maps.

Key Tier 1 guarantees enforced here (v1.0.0-draft.8):
  1. Complete `SPEC-02 §4` observation bracket: reads `(hash_0, height_0)` BEFORE all ledger
     queries and `(hash_1, height_1)` AFTER all queries, populating `rebracket_tip` and
     `observation_bracket` (optionally discarding & retrying on mid-read tip transition via
     `retry_on_tip_change`). Never labels an unmeasured bracket as consistent.
  2. Active-chain verification (`A-2`, `A-10`): every confirmed transaction and `recent_block`
     is verified against the active chain (`confirmations >= 1` and `getblockhash(height) == blockhash`);
     presenter-supplied hints never populate `spent_map` unless confirmed on the active chain or
     present in the node's live `getrawmempool`.
  3. Cross-call tip-change cache invalidation (`A-3`): block, tx, header, and active-hash caches
     are invalidated whenever `(tip_height, tip_hash)` changes across calls.
  4. Fail-closed UTXO absence (`A-1`): whenever `gettxout(..., include_mempool=True)` returns `None`
     and no spender transaction is found in mempool or active blocks, the output is explicitly marked
     `absent_from_utxo = True` so `Tier1Verifier` refuses `SEAL_SPENT` / `contested_burned`.
  5. Complete name lineage + mempool visibility (`A-4`, `A-5`): unparseable or unfetched `name_history`
     entries mark `history_truncated = True` (never silently skipped), and live mempool `OP_NAME_UPDATE`s
     spending the lineage tip are attached as `mempool_updates`.
  6. Closed-bracket `pre_effect_recheck` (`A-6`, `R1-B`): updates the unified decision clock (`now`,
     `clock_watermark`, `in_ibd`, `best_header_height`, `tip_median_time_past`, `comparison_peers`,
     `txindex`), re-queries live mempool, `gettxout(..., include_mempool=True)` for active seals,
     and mempool `OP_NAME_UPDATE`s for tracked names, and closes the bracket AFTER all reads.
  7. Transactional state persistence & mainnet clock guard (`R1-B`, `A-9`): `state_path` uses
     file-locked atomic read-modify-write merging `max(clock_watermark)` and `min(first_sight_by_hash)`;
     `clock_mode="regtest_deterministic"` is forbidden on `network="main"`.
  8. Strict `OP_RETURN` & `nSequence` extraction (`H-23`, `R3 H4`): collects all `OP_RETURN` outputs
     with `value_sat` into `opreturns[]` and preserves input `sequence` for BIP-68 CSV checks.
  9. Real `txindex` & comparison-peer `getblockhash(tip_height)` verification (`A-11`) and bounded
     presenter hint budgets (`A-12`).
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
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


def make_cli_rpc(
    bin_dir: Path,
    datadir: Path,
    rpcport: int,
    *,
    regtest: bool = True,
    rpcuser: str | None = None,
    rpcpassword: str | None = None,
) -> RpcFn:
    """Create a `namecoin-cli` RPC callable for a Namecoin Core node (supports dedicated rpcwhitelist credentials, A-13/A-14)."""
    cli = str(bin_dir / "namecoin-cli")
    base = [cli] + (["-regtest"] if regtest else []) + [
        f"-datadir={datadir}",
        f"-rpcport={rpcport}",
        "-rpcconnect=127.0.0.1",
        "-stdin",
    ]
    if rpcuser is not None:
        base.append(f"-rpcuser={rpcuser}")
    if rpcpassword is not None:
        base.append(f"-rpcpassword={rpcpassword}")

    def _call(method: str, *args: Any, wait: bool = False) -> Any:
        cmd = list(base)
        if wait:
            cmd.extend(["-rpcwait", "-rpcwaittimeout=25"])
        cmd.append(method)
        vals = [v if isinstance(v, str) else json.dumps(v, separators=(",", ":")) for v in args]
        try:
            p = subprocess.run(
                cmd,
                input="\n".join(vals) + ("\n" if vals else ""),
                text=True,
                capture_output=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"namecoin-cli {method} timed out") from exc
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


def _extract_opreturns(vouts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collect ALL OP_RETURN outputs with integer satoshi values (`SPEC-02 §5.2`, `H-23`)."""
    out: list[dict[str, Any]] = []
    for vout in vouts:
        spk_hex = vout.get("scriptPubKey", {}).get("hex", "")
        if isinstance(spk_hex, str) and len(spk_hex) >= 2 and spk_hex.startswith("6a"):
            if "value_sat" in vout:
                val_sat = int(vout["value_sat"])
            else:
                val_sat = int(round(float(vout.get("value", 0)) * 100_000_000))
            out.append({
                "script_pubkey_hex": spk_hex,
                "value_sat": val_sat,
                "vout": int(vout.get("n", 0)),
            })
    return out


def _extract_slnk_opreturn_hex(vouts: list[dict[str, Any]]) -> str | None:
    """Extract the unique zero-value SLNK OP_RETURN scriptPubKey hex, or None if 0, >1, or non-zero value (`H-23`)."""
    slnk_frames: list[dict[str, Any]] = []
    for item in _extract_opreturns(vouts):
        spk_hex = item["script_pubkey_hex"]
        if len(spk_hex) >= 12:
            try:
                spk_b = bytes.fromhex(spk_hex)
            except ValueError:
                continue
            if len(spk_b) >= 6 and spk_b[2:6] == b"SLNK":
                slnk_frames.append(item)
    if len(slnk_frames) != 1 or slnk_frames[0]["value_sat"] != 0:
        return None
    return slnk_frames[0]["script_pubkey_hex"]


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
    _depth: int = 0,
    max_depth: int = 32,
) -> None:
    """Walk untrusted SealLink wire bundle objects solely to extract lookup targets, ScriptPolicy
    preimages, and signed continuation output indices (`pending_vout`, `active_vout`, etc.).

    Every ScriptPolicy preimage is indexed strictly by its compiled `scriptPubKey` hex and verified
    against the actual on-chain output script returned by the read-only Namecoin node; every
    continuation output index is indexed strictly by the object's cryptographic commitment (`content_addr`
    or `object_id`) matched against the on-chain `SLNK` `OP_RETURN` frame of the discovered transaction.
    """
    if _depth > max_depth:
        return
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
                _depth=_depth + 1,
                max_depth=max_depth,
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
    if isinstance(obj.get("txid"), str) and isinstance(obj.get("vout"), int) and not isinstance(obj.get("vout"), bool) and len(obj["txid"]) == 64:
        if 0 <= obj["vout"] <= 0xFFFFFFFF:
            outpoints.add((obj["txid"], obj["vout"]))
            txids.add(obj["txid"])
    # Delegate ranges (bounded to SL-GRNT-010 count <= 2048)
    if (
        isinstance(obj.get("txid"), str)
        and len(obj["txid"]) == 64
        and isinstance(obj.get("first"), int)
        and isinstance(obj.get("count"), int)
        and not isinstance(obj.get("first"), bool)
        and not isinstance(obj.get("count"), bool)
        and 0 <= obj["first"] <= 0xFFFFFFFF
        and 0 < obj["count"] <= 2048
    ):
        txids.add(obj["txid"])
        for v in range(obj["first"], obj["first"] + obj["count"]):
            outpoints.add((obj["txid"], v))
        if (
            isinstance(obj.get("stop_txid"), str)
            and len(obj["stop_txid"]) == 64
            and isinstance(obj.get("stop_first"), int)
            and not isinstance(obj.get("stop_first"), bool)
            and 0 <= obj["stop_first"] <= 0xFFFFFFFF
        ):
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
            _depth=_depth + 1,
            max_depth=max_depth,
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
        if network == "main" and clock_mode != "operational":
            raise ValueError("clock_mode='regtest_deterministic' is forbidden on network='main' (A-9)")
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
        self._active_hash_by_height: dict[int, str] = {}
        self._last_tip: tuple[int, str] | None = None
        self._genesis_hash: str | None = None
        self._clock_watermark: int = 0
        self._first_sight_by_hash: dict[str, int] = {}
        if self.state_path is not None and self.state_path.exists():
            self._load_state()

    def _invalidate_caches(self) -> None:
        self._block_cache.clear()
        self._tx_cache.clear()
        self._hdr_cache.clear()
        self._active_hash_by_height.clear()

    def _read_disk_state_unlocked(self) -> tuple[int, dict[str, int]]:
        if self.state_path is None or not self.state_path.exists():
            return 0, {}
        raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        wm = int(raw.get("clock_watermark", 0))
        fs = {str(k): int(v) for k, v in raw.get("first_sight_by_hash", {}).items()}
        return wm, fs

    def _load_state(self) -> None:
        if self.state_path is None:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.state_path.with_suffix(self.state_path.suffix + ".lock")
        with open(lock_path, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_SH)
            try:
                disk_wm, disk_fs = self._read_disk_state_unlocked()
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
        self._clock_watermark = max(self._clock_watermark, disk_wm)
        for h, ts in disk_fs.items():
            if h in self._first_sight_by_hash:
                self._first_sight_by_hash[h] = min(self._first_sight_by_hash[h], ts)
            else:
                self._first_sight_by_hash[h] = ts

    def _transactional_update_state(
        self,
        *,
        tip_hash: str,
        now_ts: int,
        candidate_first_sight: int,
        operational: bool,
        hdr_time: int,
    ) -> tuple[int, int]:
        """Atomically merge persisted watermark + earliest first-sight across concurrent observers (`R1-B`).

        Returns `(effective_watermark, first_sight)` for the sampled tip.
        """
        if self.state_path is None:
            prev_wm = self._clock_watermark
            if now_ts >= prev_wm:
                self._clock_watermark = now_ts
                effective_wm = prev_wm if operational else (min(prev_wm, now_ts) if prev_wm > 0 else hdr_time - 60)
            else:
                effective_wm = prev_wm
            if tip_hash not in self._first_sight_by_hash:
                self._first_sight_by_hash[tip_hash] = candidate_first_sight
            return effective_wm, self._first_sight_by_hash[tip_hash]

        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.state_path.with_suffix(self.state_path.suffix + ".lock")
        with open(lock_path, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                disk_wm, disk_fs = self._read_disk_state_unlocked()
                prev_wm = max(self._clock_watermark, disk_wm)
                merged_fs = dict(disk_fs)
                for h, ts in self._first_sight_by_hash.items():
                    merged_fs[h] = min(merged_fs[h], ts) if h in merged_fs else ts
                if tip_hash not in merged_fs:
                    merged_fs[tip_hash] = candidate_first_sight
                first_sight = merged_fs[tip_hash]
                if now_ts >= prev_wm:
                    new_wm = now_ts
                    effective_wm = prev_wm if operational else (min(prev_wm, now_ts) if prev_wm > 0 else hdr_time - 60)
                else:
                    # Preserve higher persisted watermark so Tier1Verifier detects regression (CHAIN_CLOCK_ERROR)
                    new_wm = prev_wm
                    effective_wm = prev_wm
                self._clock_watermark = new_wm
                self._first_sight_by_hash = merged_fs
                payload = json.dumps(
                    {
                        "clock_watermark": new_wm,
                        "first_sight_by_hash": merged_fs,
                    },
                    indent=2,
                    sort_keys=True,
                ) + "\n"
                fd, tmp_name = tempfile.mkstemp(
                    prefix=f".{self.state_path.name}.",
                    suffix=f".{os.getpid()}.tmp",
                    dir=str(self.state_path.parent),
                )
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as tf:
                        tf.write(payload)
                        tf.flush()
                        os.fsync(tf.fileno())
                    os.replace(tmp_name, self.state_path)
                except Exception:
                    try:
                        os.unlink(tmp_name)
                    except OSError:
                        pass
                    raise
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
        return effective_wm, first_sight

    def _sample_tip(self) -> dict[str, Any]:
        """Read current tip from the reading node, invalidate caches on tip change (`A-3`), and update watermark."""
        b_info = self.read_rpc("getblockchaininfo")
        tip_h = int(b_info["blocks"])
        tip_hash = str(b_info["bestblockhash"])
        if self._last_tip is not None and self._last_tip != (tip_h, tip_hash):
            self._invalidate_caches()
        self._last_tip = (tip_h, tip_hash)
        self._active_hash_by_height[tip_h] = tip_hash

        tip_hdr = self._get_header(tip_hash)
        hdr_time = int(tip_hdr["time"])
        mtp = int(b_info.get("mediantime", tip_hdr.get("mediantime", hdr_time)))

        if self.clock_mode == "operational":
            now_ts = int(self.clock_now_fn())
            effective_wm, first_sight = self._transactional_update_state(
                tip_hash=tip_hash,
                now_ts=now_ts,
                candidate_first_sight=now_ts,
                operational=True,
                hdr_time=hdr_time,
            )
            clock_src = "operational_persisted" if self.state_path is not None else "operational_memory"
        else:
            now_ts = hdr_time + self.regtest_clock_offset_s
            effective_wm, first_sight = self._transactional_update_state(
                tip_hash=tip_hash,
                now_ts=now_ts,
                candidate_first_sight=hdr_time,
                operational=False,
                hdr_time=hdr_time,
            )
            clock_src = "regtest_deterministic"

        return {
            "b_info": b_info,
            "chain_match": (str(b_info.get("chain", "")) == self.network),
            "height": tip_h,
            "hash": tip_hash,
            "header_time": hdr_time,
            "mediantime": mtp,
            "first_sight": first_sight,
            "now": now_ts,
            "clock_watermark": effective_wm,
            "clock_source": clock_src,
        }

    def _check_txindex(self) -> bool:
        """Query `getindexinfo` to verify `-txindex=1` is actually enabled & synced (`A-11`)."""
        try:
            idx_info = self.read_rpc("getindexinfo")
        except Exception:
            return False
        if not isinstance(idx_info, dict):
            return False
        txi = idx_info.get("txindex")
        return isinstance(txi, dict) and bool(txi.get("synced", False))

    def _poll_comparison_peers(self, tip_height: int) -> list[dict[str, Any]]:
        """Poll each comparison peer and verify its active block hash at `tip_height` (`A-11`)."""
        comp_peers: list[dict[str, Any]] = []
        for peer_id, crpc in self.compare_rpcs:
            try:
                c_info = crpc("getblockchaininfo")
                p_h = int(c_info["blocks"])
                healthy = not bool(c_info.get("initialblockdownload", False))
                if p_h >= tip_height:
                    hash_at_tip = str(crpc("getblockhash", tip_height))
                else:
                    hash_at_tip = str(c_info["bestblockhash"])
                comp_peers.append({
                    "hash_at_tip": hash_at_tip,
                    "healthy": healthy,
                    "height": p_h,
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

    def _get_active_blockhash(self, height: int) -> str | None:
        if height < 0:
            return None
        if height not in self._active_hash_by_height:
            try:
                self._active_hash_by_height[height] = str(self.read_rpc("getblockhash", height))
            except RuntimeError:
                return None
        return self._active_hash_by_height[height]

    def _get_header(self, blockhash: str) -> dict[str, Any]:
        if blockhash not in self._hdr_cache:
            self._hdr_cache[blockhash] = self.read_rpc("getblockheader", blockhash)
        return self._hdr_cache[blockhash]

    def _active_confirmed_height(self, blockhash: str, confirmations: int | None = None) -> tuple[int, int] | None:
        """Verify `blockhash` is on the reading node's active chain (`A-2`). Returns `(height, time)` or `None`."""
        if confirmations is not None and int(confirmations) <= 0:
            return None
        try:
            hdr = self._get_header(blockhash)
        except RuntimeError:
            return None
        if "confirmations" in hdr and int(hdr["confirmations"]) <= 0:
            return None
        h = int(hdr["height"])
        active_h = self._get_active_blockhash(h)
        if active_h != blockhash:
            return None
        return h, int(hdr.get("time", 0))

    def _get_block_by_height(self, height: int) -> dict[str, Any]:
        if height not in self._block_cache:
            bh = self._get_active_blockhash(height)
            if bh is None:
                raise RuntimeError(f"No active block at height {height}")
            self._block_cache[height] = self.read_rpc("getblock", bh, 2)
        return self._block_cache[height]

    def _get_raw_tx(
        self,
        txid: str,
        *,
        allow_mempool: bool = True,
        mempool_set: set[str] | None = None,
    ) -> dict[str, Any] | None:
        """Fetch tx from reading node and verify active-chain confirmation or live mempool membership (`A-2`, `A-10`)."""
        cached = self._tx_cache.get(txid)
        if cached is not None and cached.get("blockhash"):
            if self._active_confirmed_height(cached["blockhash"], cached.get("confirmations")) is not None:
                return cached
            self._tx_cache.pop(txid, None)
        try:
            txd = self.read_rpc("getrawtransaction", txid, True)
        except RuntimeError:
            return None
        if not isinstance(txd, dict):
            return None
        if "blockhash" in txd:
            act = self._active_confirmed_height(txd["blockhash"], txd.get("confirmations"))
            if act is not None:
                self._tx_cache[txid] = txd
                return txd
            # Orphaned / reorged-out block! Only keep if it returned to the live mempool.
            if allow_mempool and mempool_set is not None and txid in mempool_set:
                cleaned = dict(txd)
                cleaned.pop("blockhash", None)
                cleaned.pop("confirmations", None)
                self._tx_cache[txid] = cleaned
                return cleaned
            return None
        # Unconfirmed transaction
        if not allow_mempool:
            return None
        if mempool_set is not None and txid not in mempool_set:
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
    ) -> tuple[dict[str, Any] | None, bool]:
        """Discover the spending transaction of `(txid, vout)` strictly from the reading node.

        Returns `(spender_txd_or_None, absent_from_utxo)`:
          - `(None, False)`: `gettxout(..., True)` proved the output is currently UNSPENT.
          - `(spender, False)`: spender located in live mempool or active confirmed blocks.
          - `(None, True)`: output is ABSENT from the UTXO set and no spender was found (`A-1`, fail closed!).
        """
        # 1. Fast check: is it STILL unspent in the node's UTXO set + mempool? (A-13 strict shape validation!)
        try:
            utxo = self.read_rpc("gettxout", txid, vout, True)
        except RuntimeError:
            return None, True
        if utxo is not None:
            if (
                isinstance(utxo, dict)
                and isinstance(utxo.get("scriptPubKey"), dict)
                and isinstance(utxo.get("confirmations"), int)
                and not isinstance(utxo.get("confirmations"), bool)
            ):
                return None, False
            # Malformed non-None gettxout response -> fail closed (A-13)!
            return None, True
        # 2. Check live mempool first (mempool spend before mining!)
        for mtx in mempool_txs.values():
            for vin in mtx.get("vin", []):
                if vin.get("txid") == txid and int(vin.get("vout", -1)) == vout:
                    return mtx, False
        # 3. Scan active confirmed blocks from created_height..tip_height (cached per height)
        for h in range(max(1, created_height), tip_height + 1):
            blk = self._get_block_by_height(h)
            for btx in blk.get("tx", []):
                for vin in btx.get("vin", []):
                    if vin.get("txid") == txid and int(vin.get("vout", -1)) == vout:
                        btx_copy = dict(btx)
                        btx_copy["blockhash"] = blk["hash"]
                        btx_copy["confirmations"] = max(1, tip_height - h + 1)
                        self._tx_cache[btx["txid"]] = btx_copy
                        return btx_copy, False
        # 4. Absent from live UTXO set and no spender found -> fail closed (A-1)!
        return None, True

    def _txd_to_view(
        self,
        txd: dict[str, Any],
        mempool_set: set[str],
        spent_map: dict[tuple[str, int], str],
        absent_outpoints: set[tuple[str, int]],
    ) -> dict[str, Any]:
        txid = txd["txid"]
        conf_h: int | None = None
        block_time: int | None = None
        if "blockhash" in txd:
            act = self._active_confirmed_height(txd["blockhash"], txd.get("confirmations"))
            if act is not None:
                conf_h, block_time = act
        inputs_v: list[dict[str, Any]] = []
        for vin in txd.get("vin", []):
            if "txid" in vin:
                inp_ent: dict[str, Any] = {
                    "prev_txid": vin["txid"],
                    "prev_vout": int(vin["vout"]),
                    "script_sig_hex": vin.get("scriptSig", {}).get("hex", ""),
                    "witness": list(vin.get("txinwitness", [])),
                }
                if "sequence" in vin:
                    inp_ent["sequence"] = int(vin["sequence"])
                inputs_v.append(inp_ent)
        outputs_v: dict[str, Any] = {}
        for vout in txd.get("vout", []):
            n = int(vout["n"])
            spk_hex = vout["scriptPubKey"]["hex"]
            o_ent: dict[str, Any] = {"script_pubkey_hex": spk_hex}
            if (txid, n) in spent_map:
                o_ent["spent_by_txid"] = spent_map[(txid, n)]
            elif (txid, n) in absent_outpoints:
                o_ent["absent_from_utxo"] = True
            outputs_v[str(n)] = o_ent
        obj: dict[str, Any] = {
            "confirmed_height": conf_h,
            "in_mempool": txid in mempool_set,
            "inputs": inputs_v,
            "outputs": outputs_v,
        }
        if block_time is not None:
            obj["block_time"] = block_time
        oprets = _extract_opreturns(txd.get("vout", []))
        if oprets:
            obj["opreturns"] = oprets
        opret_hex = _extract_slnk_opreturn_hex(txd.get("vout", []))
        if opret_hex is not None:
            obj["opreturn_hex"] = opret_hex
        return obj

    def _discover_mempool_name_updates(
        self,
        name: str,
        last_confirmed: dict[str, Any],
        policies_by_spk: dict[str, dict[str, Any]],
        mempool_txs: dict[str, dict[str, Any]],
        collected_txs: dict[str, dict[str, Any]] | None = None,
        *,
        missing_mempool_txs: bool = False,
    ) -> list[dict[str, Any]]:
        """Scan live mempool for unconfirmed `OP_NAME_UPDATE`s spending `last_confirmed` (`A-5`, `R2-A-03`).

        Surfaces unparseable name outputs (or unfetchable mempool spends of `last_confirmed`) as fail-closed
        `{"unparseable": True}` entries so `Tier1Verifier` refuses `NAME_HISTORY_UNAVAILABLE`.
        """
        last_txid = last_confirmed.get("txid")
        last_vout = last_confirmed.get("vout")
        if not last_txid or last_vout is None:
            return []
        out_list: list[dict[str, Any]] = []
        found_spender = False
        for mtx in mempool_txs.values():
            spent_vin = next(
                (v for v in mtx.get("vin", []) if v.get("txid") == last_txid and int(v.get("vout", -1)) == last_vout),
                None,
            )
            if spent_vin is None:
                continue
            found_spender = True
            # Try to derive witness_policy if last_confirmed had an unknown_unspent_spk
            wit_pol = last_confirmed.get("owner_policy")
            wit = spent_vin.get("txinwitness", [])
            if (
                isinstance(wit_pol, dict)
                and wit_pol.get("kind") == "unknown_unspent_spk"
                and len(wit) == 2
                and len(wit[1]) == 66
                and sl.is_valid_compressed_pubkey(wit[1])
            ):
                cand = {"kind": "key", "pk": wit[1]}
                if sl.compile_script_policy(cand)[0].hex() == wit_pol.get("spk_hex"):
                    wit_pol = cand
                    last_confirmed["owner_policy"] = cand
                    policies_by_spk.setdefault(wit_pol["pk"], cand)

            parsed_any_for_name = False
            saw_unparseable_name_out = False
            for vo in mtx.get("vout", []):
                m_spk_hex = vo.get("scriptPubKey", {}).get("hex", "")
                if not m_spk_hex:
                    continue
                try:
                    parsed_m = sl.parse_name_output(bytes.fromhex(m_spk_hex))
                except ValueError:
                    # R2-A-03: Namecoin name-op prefix (OP_NAME_NEW=51 / OP_NAME_FIRSTUPDATE=52 / OP_NAME_UPDATE=53) failing parse MUST fail closed!
                    if m_spk_hex.startswith(("51", "52", "53")):
                        saw_unparseable_name_out = True
                    continue
                if parsed_m.get("op") != "NAME_UPDATE" or parsed_m.get("name") != name:
                    continue
                parsed_any_for_name = True
                t_spk_hex = parsed_m["trailing_script_pubkey"]
                m_owner_pol = policies_by_spk.get(t_spk_hex) or {"kind": "unknown_unspent_spk", "spk_hex": t_spk_hex}
                mu: dict[str, Any] = {
                    "op": "NAME_UPDATE",
                    "output_script_hex": m_spk_hex,
                    "owner_policy": m_owner_pol,
                    "prev_input": {
                        "sighash_bytes": _extract_sighash_bytes(wit),
                        "txid": last_txid,
                        "vout": last_vout,
                        "witness_policy": wit_pol,
                    },
                    "txid": mtx["txid"],
                    "vout": int(vo["n"]),
                }
                oprets = _extract_opreturns(mtx.get("vout", []))
                if oprets:
                    mu["opreturns"] = oprets
                opret_hex = _extract_slnk_opreturn_hex(mtx.get("vout", []))
                if opret_hex is not None:
                    mu["opreturn_hex"] = opret_hex
                out_list.append(mu)
                if collected_txs is not None:
                    collected_txs[mtx["txid"]] = mtx
            if saw_unparseable_name_out or not parsed_any_for_name:
                out_list.append({"txid": mtx["txid"], "unparseable": True})
        # R2-A-03: If any mempool tx failed to fetch AND last_confirmed is no longer unspent in UTXO+mempool, fail closed!
        if missing_mempool_txs and not found_spender:
            try:
                u_chk = self.read_rpc("gettxout", last_txid, last_vout, True)
            except RuntimeError:
                u_chk = None
            if not (isinstance(u_chk, dict) and isinstance(u_chk.get("scriptPubKey"), dict)):
                out_list.append({"txid": last_txid, "unparseable": True})
        return out_list

    def _discover_name_lineages(
        self,
        name: str,
        policies_by_spk: dict[str, dict[str, Any]],
        collected_txs: dict[str, dict[str, Any]],
        mempool_txs: dict[str, dict[str, Any]],
        *,
        missing_mempool_txs: bool = False,
    ) -> list[dict[str, Any]]:
        """Discover ALL historical registration lineages for `name` via `name_history` (`A-4`, `A-5`, `R2-A-01`, `R2-A-02`).

        - R2-A-01: Distinguishes legitimate `name not found` from transient/malformed `name_history` RPC errors
          (failing closed with `history_truncated = True` on RPC errors so hidden `0x10` cancels cannot be skipped).
        - R2-A-02: Scopes `history_truncated` per registration lineage so a corrupt newer registration never
          taints an unrelated clean historical registration of an expired name.
        """
        try:
            raw_hist = self.read_rpc("name_history", name)
        except RuntimeError as exc:
            msg = str(exc).lower()
            if "name not found" in msg or "not found" in msg:
                return []
            # R2-A-01: Transient/RPC failure MUST fail closed with history_truncated=True!
            return [{
                "history_truncated": True,
                "registration": {"txid": "0" * 64, "vout": 0},
                "updates": [],
            }]
        if not isinstance(raw_hist, list):
            return [{
                "history_truncated": True,
                "registration": {"txid": "0" * 64, "vout": 0},
                "updates": [],
            }]
        if not raw_hist:
            return []

        mempool_set = set(mempool_txs.keys())
        # R2-A-02: Track parse/fetch errors by raw_hist index so truncation scopes to the affected lineage!
        raw_lineages: list[list[tuple[int, int, dict[str, Any], int, dict[str, Any]]]] = []
        lin_truncated: list[bool] = []
        pre_lineage_error = False

        # Sort raw_hist deterministically by (height if int else tip+1, original idx) while keeping unparseables in place
        indexed_items = list(enumerate(raw_hist))
        enriched: list[tuple[int, int, int, dict[str, Any] | None, int, dict[str, Any] | None, bool]] = []
        for idx, item in indexed_items:
            if not isinstance(item, dict):
                enriched.append((10**12, idx, 0, None, 0, None, True))
                continue
            txid = item.get("txid")
            vout_n = item.get("vout")
            raw_h = item.get("height")
            hint_h = int(raw_h) if isinstance(raw_h, int) and not isinstance(raw_h, bool) else 10**12
            if not isinstance(txid, str) or not isinstance(vout_n, int):
                enriched.append((hint_h, idx, 0, None, 0, None, True))
                continue
            txd = self._get_raw_tx(txid, allow_mempool=True, mempool_set=mempool_set)
            if txd is None:
                enriched.append((hint_h, idx, 0, None, 0, None, True))
                continue
            if "blockhash" not in txd:
                if txid in mempool_txs:
                    continue
                enriched.append((hint_h, idx, 0, None, 0, None, True))
                continue
            act = self._active_confirmed_height(txd["blockhash"], txd.get("confirmations"))
            if act is None:
                enriched.append((hint_h, idx, 0, None, 0, None, True))
                continue
            h_conf, b_time = act
            collected_txs[txid] = txd
            out_obj = next((o for o in txd.get("vout", []) if int(o["n"]) == vout_n), None)
            if out_obj is None:
                enriched.append((h_conf, idx, b_time, None, 0, None, True))
                continue
            spk_hex = out_obj.get("scriptPubKey", {}).get("hex", "")
            try:
                parsed = sl.parse_name_output(bytes.fromhex(spk_hex))
            except ValueError:
                enriched.append((h_conf, idx, b_time, None, 0, None, True))
                continue
            enriched.append((h_conf, idx, b_time, txd, vout_n, parsed, False))
        enriched.sort(key=lambda t: (t[0], t[1]))

        for h_conf, _idx, b_time, txd, vout_n, parsed, is_err in enriched:
            if is_err or txd is None or parsed is None:
                if raw_lineages:
                    lin_truncated[-1] = True
                else:
                    pre_lineage_error = True
                continue
            if parsed["op"] == "NAME_FIRSTUPDATE":
                raw_lineages.append([(h_conf, b_time, txd, vout_n, parsed)])
                lin_truncated.append(pre_lineage_error and len(raw_lineages) == 1)
            elif parsed["op"] == "NAME_UPDATE" and raw_lineages:
                in_ops = {(v.get("txid"), int(v.get("vout", -1))) for v in txd.get("vin", []) if "txid" in v}
                attached = False
                for l_idx in range(len(raw_lineages) - 1, -1, -1):
                    lin = raw_lineages[l_idx]
                    last_txid, last_vout = lin[-1][2]["txid"], lin[-1][3]
                    if (last_txid, last_vout) in in_ops:
                        lin.append((h_conf, b_time, txd, vout_n, parsed))
                        attached = True
                        break
                if not attached:
                    lin_truncated[-1] = True
                    raw_lineages[-1].append((h_conf, b_time, txd, vout_n, parsed))
            else:
                if raw_lineages:
                    lin_truncated[-1] = True
                else:
                    pre_lineage_error = True

        lineages_out: list[dict[str, Any]] = []
        for l_idx, lin in enumerate(raw_lineages):
            derived_pols: dict[int, dict[str, Any]] = {}
            for pos in range(len(lin) - 1):
                _h0, _bt0, prev_txd, prev_vout, prev_parsed = lin[pos]
                _h1, _bt1, next_txd, _nv, _np = lin[pos + 1]
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
            for pos, (h_conf, b_time, txd, vout_n, parsed) in enumerate(lin):
                out_spk_hex = next(o["scriptPubKey"]["hex"] for o in txd["vout"] if int(o["n"]) == vout_n)
                t_spk_hex = parsed["trailing_script_pubkey"]
                owner_pol = derived_pols.get(pos) or policies_by_spk.get(t_spk_hex)
                if owner_pol is None:
                    owner_pol = {"kind": "unknown_unspent_spk", "spk_hex": t_spk_hex}
                u_obj: dict[str, Any] = {
                    "block_time": b_time,
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
                oprets = _extract_opreturns(txd.get("vout", []))
                if oprets:
                    u_obj["opreturns"] = oprets
                opret_hex = _extract_slnk_opreturn_hex(txd.get("vout", []))
                if opret_hex is not None:
                    u_obj["opreturn_hex"] = opret_hex
                updates_v.append(u_obj)

            if updates_v:
                mem_updates = self._discover_mempool_name_updates(
                    name,
                    updates_v[-1],
                    policies_by_spk,
                    mempool_txs,
                    collected_txs,
                    missing_mempool_txs=missing_mempool_txs,
                )
                lin_rec: dict[str, Any] = {
                    "registration": {"txid": updates_v[0]["txid"], "vout": updates_v[0]["vout"]},
                    "updates": updates_v,
                }
                if mem_updates:
                    lin_rec["mempool_updates"] = mem_updates
                if lin_truncated[l_idx]:
                    lin_rec["history_truncated"] = True
                lineages_out.append(lin_rec)

        if not lineages_out and pre_lineage_error:
            first_it = raw_hist[0] if isinstance(raw_hist[0], dict) else {}
            lineages_out.append({
                "history_truncated": True,
                "registration": {"txid": str(first_it.get("txid", "0" * 64)), "vout": int(first_it.get("vout", 0))},
                "updates": [],
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
        max_hint_names: int = 64,
        max_hint_txids: int = 256,
        max_hint_outpoints: int = 4096,
        max_hint_blocks: int = 64,
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

        # Bound presenter hint expansion (A-12)
        if (
            len(target_names) > max_hint_names
            or len(target_txids) > max_hint_txids
            or len(target_outpoints) > max_hint_outpoints
            or len(target_blocks) > max_hint_blocks
        ):
            raise ValueError("Presenter hint budget exceeded (A-12)")

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
            comp_peers = self._poll_comparison_peers(tip_h)
            txindex_ok = self._check_txindex()

            mempool_ids = list(self.read_rpc("getrawmempool"))
            mempool_set = set(mempool_ids)
            mempool_txs: dict[str, dict[str, Any]] = {}
            missing_mempool_txs = False
            for mid in mempool_ids:
                mtx = self._get_raw_tx(mid, allow_mempool=True, mempool_set=mempool_set)
                if mtx is not None:
                    mempool_txs[mid] = mtx
                else:
                    missing_mempool_txs = True

            collected_txs: dict[str, dict[str, Any]] = dict(mempool_txs)

            # 1. Cold-discover ALL historical registration lineages + mempool updates via `name_history`
            names_view: dict[str, Any] = {}
            name_regs_view: dict[str, list[dict[str, Any]]] = {}
            for nm in sorted(target_names):
                lineages = self._discover_name_lineages(
                    nm, policies_by_spk, collected_txs, mempool_txs, missing_mempool_txs=missing_mempool_txs
                )
                if lineages:
                    names_view[nm] = lineages[-1]
                    name_regs_view[nm] = lineages

            # 2. Fetch explicitly referenced txids ONLY if active-chain confirmed or in live mempool (A-2, A-10)
            for tid in sorted(target_txids):
                txd = self._get_raw_tx(tid, allow_mempool=True, mempool_set=mempool_set)
                if txd is not None:
                    collected_txs[tid] = txd

            # 3. Build initial spent_map strictly from verified active-chain txs & live mempool (A-10)
            spent_map: dict[tuple[str, int], str] = {}
            absent_outpoints: set[tuple[str, int]] = set()
            for txd in list(collected_txs.values()):
                if txd["txid"] not in mempool_set:
                    if "blockhash" not in txd or self._active_confirmed_height(txd["blockhash"], txd.get("confirmations")) is None:
                        continue
                for vin in txd.get("vin", []):
                    if "txid" in vin:
                        spent_map[(vin["txid"], int(vin["vout"]))] = txd["txid"]

            # 4. Cold-discover spend chains following exact signed continuation output indices
            queue: list[tuple[str, int, int]] = [(txid, vout, 0) for txid, vout in sorted(target_outpoints)]
            visited_ops: set[tuple[str, int]] = set()
            while queue:
                op_txid, op_vout, hop = queue.pop(0)
                if (op_txid, op_vout) in visited_ops or hop > max_spend_hops:
                    continue
                visited_ops.add((op_txid, op_vout))
                txd = self._get_raw_tx(op_txid, allow_mempool=True, mempool_set=mempool_set)
                if txd is None:
                    continue
                collected_txs[op_txid] = txd
                act_cr = self._active_confirmed_height(txd["blockhash"], txd.get("confirmations")) if "blockhash" in txd else None
                created_h = act_cr[0] if act_cr is not None else tip_h
                out_match = next((o for o in txd.get("vout", []) if int(o["n"]) == op_vout), None)
                if out_match and out_match.get("scriptPubKey", {}).get("hex", "").startswith(("52", "53")):
                    continue
                if (op_txid, op_vout) in spent_map:
                    spender = collected_txs.get(spent_map[(op_txid, op_vout)])
                    absent = False
                else:
                    spender, absent = self._find_spender_cold(
                        op_txid, op_vout, created_h, tip_height=tip_h, mempool_txs=mempool_txs
                    )
                if spender is not None:
                    stxid = spender["txid"]
                    collected_txs[stxid] = spender
                    spent_map[(op_txid, op_vout)] = stxid
                    for next_vout in self._continuation_vouts_for_spender(spender, continuation_vouts_by_frame, policies_by_spk):
                        queue.append((stxid, next_vout, hop + 1))
                elif absent:
                    absent_outpoints.add((op_txid, op_vout))

            txs_view = {
                txid: self._txd_to_view(txd, mempool_set, spent_map, absent_outpoints)
                for txid, txd in collected_txs.items()
            }

            # Verify every target_block (recent_block) is on the active chain (A-2)!
            blocks_view: dict[str, int] = {tip_hash: tip_h}
            for bh in sorted(target_blocks):
                act_b = self._active_confirmed_height(bh)
                if act_b is not None:
                    blocks_view[bh] = act_b[0]

            # Closing tip bracket (hash_1, height_1) AFTER all queries (`SPEC-02 §4` item 1)
            end_s = self._sample_tip()
            consistent = (start_s["hash"] == end_s["hash"] and start_s["height"] == end_s["height"])
            decision_now = end_s["now"]
            decision_wm = end_s["clock_watermark"]

            last_view = {
                "best_header_height": int(b_info["headers"]),
                "blocks": blocks_view,
                "clock_source": end_s["clock_source"],
                "clock_watermark": decision_wm,
                "comparison_peers": comp_peers,
                "credible_utc_interval": [decision_now - 60, decision_now + 60],
                "future_bound_s": 600,
                "genesis": self.genesis_hash,
                "in_ibd": bool(b_info["initialblockdownload"]),
                "lag_limit": 1,
                "manifests": copy.deepcopy(manifests) if manifests else {},
                "name_registrations": name_regs_view,
                "names": names_view,
                "network": self.network,
                "node_reachable": bool(start_s["chain_match"] and end_s["chain_match"]),
                "now": decision_now,
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
                "tip_median_time_past": start_s["mediantime"],
                "txindex": txindex_ok,
                "txs": txs_view,
            }
            if consistent:
                return last_view
            # Inconsistent mid-read tip transition: invalidate caches before retrying on new tip!
            self._invalidate_caches()
        return last_view

    def pre_effect_recheck(
        self,
        chain_view: dict[str, Any],
        seal_outpoints: list[tuple[str, int]],
        *,
        extra_names: list[str] | None = None,
        extra_policies: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Fresh closed-bracket pre-effect recheck (`SPEC-02 §4` item 5, `A-6`, `R1-B`).

        Re-samples opening tip, health (`txindex`, `in_ibd`, `best_header_height`, `comparison_peers`),
        live mempool, `gettxout(..., include_mempool=True)` for active seals, and live mempool
        `OP_NAME_UPDATE`s for tracked names, then closes the bracket AFTER all reads and updates
        the unified decision clock (`now`, `clock_watermark`, `rebracket_tip`).
        """
        fresh = copy.deepcopy(chain_view)
        ob = fresh.setdefault("observation_bracket", {})
        if "initial_snapshot" not in ob:
            ob["initial_snapshot"] = {
                "end": copy.deepcopy(ob.get("end")),
                "start": copy.deepcopy(ob.get("start")),
                "tip_hash": fresh.get("tip_hash"),
                "tip_height": fresh.get("tip_height"),
            }

        # Opening recheck bracket
        re_start = self._sample_tip()
        b_info = re_start["b_info"]
        fresh["in_ibd"] = bool(b_info["initialblockdownload"])
        fresh["best_header_height"] = int(b_info["headers"])
        fresh["tip_median_time_past"] = re_start["mediantime"]
        fresh["txindex"] = self._check_txindex()
        fresh["comparison_peers"] = self._poll_comparison_peers(re_start["height"])

        mempool_ids = list(self.read_rpc("getrawmempool"))
        mempool_set = set(mempool_ids)
        mempool_txs: dict[str, dict[str, Any]] = {}
        missing_mempool_txs = False
        for mid in mempool_ids:
            mtx = self._get_raw_tx(mid, allow_mempool=True, mempool_set=mempool_set)
            if mtx is not None:
                mempool_txs[mid] = mtx
            else:
                missing_mempool_txs = True

        spent_map: dict[tuple[str, int], str] = {}
        absent_outpoints: set[tuple[str, int]] = set()
        for mtx in mempool_txs.values():
            for vin in mtx.get("vin", []):
                if "txid" in vin:
                    spent_map[(vin["txid"], int(vin["vout"]))] = mtx["txid"]

        for op_txid, op_vout in seal_outpoints:
            tx_entry = fresh["txs"].get(op_txid)
            created_h = (
                int(tx_entry["confirmed_height"])
                if tx_entry and tx_entry.get("confirmed_height") is not None
                else re_start["height"]
            )
            spender, absent = self._find_spender_cold(
                op_txid, op_vout, created_h, tip_height=re_start["height"], mempool_txs=mempool_txs
            )
            if spender is not None:
                stxid = spender["txid"]
                spent_map[(op_txid, op_vout)] = stxid
                fresh["txs"][stxid] = self._txd_to_view(spender, mempool_set, spent_map, absent_outpoints)
                if tx_entry and str(op_vout) in tx_entry.get("outputs", {}):
                    tx_entry["outputs"][str(op_vout)]["spent_by_txid"] = stxid
            elif absent:
                absent_outpoints.add((op_txid, op_vout))
                if tx_entry and str(op_vout) in tx_entry.get("outputs", {}):
                    tx_entry["outputs"][str(op_vout)]["absent_from_utxo"] = True

        # Re-check mempool OP_NAME_UPDATEs on all tracked names (A-5, A-6, R2-A-03)
        policies_by_spk: dict[str, dict[str, Any]] = {}
        for pol in (extra_policies or []):
            try:
                policies_by_spk[sl.compile_script_policy(pol)[0].hex()] = pol
            except (ValueError, KeyError, TypeError):
                pass
        names_to_check = set(fresh.get("names", {}).keys()) | set(extra_names or [])
        for nm in sorted(names_to_check):
            nrec = fresh.get("names", {}).get(nm)
            if isinstance(nrec, dict) and nrec.get("updates"):
                mem_u = self._discover_mempool_name_updates(
                    nm, nrec["updates"][-1], policies_by_spk, mempool_txs, missing_mempool_txs=missing_mempool_txs
                )
                if mem_u:
                    nrec["mempool_updates"] = mem_u
                else:
                    nrec.pop("mempool_updates", None)

        # Closing recheck bracket AFTER all refreshed reads (R1-B, A-6, R3 High #1)
        re_end = self._sample_tip()
        decision_now = re_end["now"]
        fresh["node_reachable"] = bool(fresh.get("node_reachable", True) and re_start["chain_match"] and re_end["chain_match"])
        fresh["now"] = decision_now
        fresh["clock_watermark"] = re_end["clock_watermark"]
        fresh["clock_source"] = re_end["clock_source"]
        fresh["credible_utc_interval"] = [decision_now - 60, decision_now + 60]
        fresh["rebracket_tip"] = {
            "first_sight": re_end["first_sight"],
            "hash": re_end["hash"],
            "header_time": re_end["header_time"],
            "height": re_end["height"],
            "now": re_end["now"],
        }
        recheck_consistent = (
            re_start["hash"] == re_end["hash"]
            and re_start["height"] == re_end["height"]
            and re_end["hash"] == fresh["tip_hash"]
            and re_end["height"] == fresh["tip_height"]
        )
        prev_consistent = ob.get("consistent", True)
        ob["pre_effect_rechecked"] = True
        ob["pre_effect_start"] = {"hash": re_start["hash"], "height": re_start["height"], "now": re_start["now"]}
        ob["pre_effect_end"] = {"hash": re_end["hash"], "height": re_end["height"], "now": re_end["now"]}
        ob["pre_effect_tip"] = {"hash": re_end["hash"], "height": re_end["height"], "now": re_end["now"]}
        # R3 High #1: NEVER resurrect an already-voided observation snapshot!
        ob["consistent"] = bool(prev_consistent) and recheck_consistent
        return fresh


def self_test() -> None:
    """Deterministic offline unit test covering all draft.7 ColdNamecoinObserver guarantees:
      1. Multi-registration `name_history` + cold mempool spend discovery.
      2. Arbitrary signed `pending_vout = 2` continuation traversal (`0x0d` -> `0x0e` at vout 0).
      3. Complete observation bracket: mid-read tip transition -> `CHAIN_OBSERVATION_VOID`,
         then `retry_on_tip_change=1` -> consistent bracket -> `ADMIT`.
      4. Operational persisted `clock_watermark` & `first_sight_by_hash` transactional merge + rollback refusal (`R1-B`).
      5. Fresh closed-bracket `pre_effect_recheck`: advancing clock (`R1-B`), mid-recheck tip transition -> `CHAIN_OBSERVATION_VOID`,
         last-instant mempool seal spend -> `SEAL_SPENT`, and mempool `OP_NAME_UPDATE` transfer -> `NAME_OWNER_MISMATCH` (`A-5`, `A-6`).
      6. Fail-closed `absent_from_utxo` when UTXO is missing with no spender (`A-1`).
      7. Orphaned block / reorged-out tx rejection (`A-2`) and cross-call cache invalidation on tip change (`A-3`).
      8. Unparseable `name_history` entry -> `history_truncated=True` -> `NAME_HISTORY_UNAVAILABLE` (`A-4`).
      9. Mainnet `regtest_deterministic` clock refusal (`A-9`), `txindex=False` detection (`A-11`), and duplicate `SLNK` `OP_RETURN` rejection (`H-23`).
    """
    gen = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    sk1 = sl.deterministic_privkey("nc-adapter-test-own1")
    sk2 = sl.deterministic_privkey("nc-adapter-test-own2")
    sk3 = sl.deterministic_privkey("nc-adapter-test-own3")
    pk1, pk2, pk3 = sl.compressed_pubkey(sk1), sl.compressed_pubkey(sk2), sl.compressed_pubkey(sk3)
    pol1, pol2, pol3 = {"kind": "key", "pk": pk1}, {"kind": "key", "pk": pk2}, {"kind": "key", "pk": pk3}
    spk1, _ = sl.compile_script_policy(pol1)
    spk2, _ = sl.compile_script_policy(pol2)
    spk3, _ = sl.compile_script_policy(pol3)
    cred1 = sl.xonly_pubkey(sl.deterministic_privkey("nc-adapter-test-cred1"))
    cred2 = sl.xonly_pubkey(sl.deterministic_privkey("nc-adapter-test-cred2"))

    fu1_txid = hashlib.sha256(b"fu1").hexdigest()
    u1_txid = hashlib.sha256(b"u1").hexdigest()
    fu2_txid = hashlib.sha256(b"fu2").hexdigest()
    u2_txid = hashlib.sha256(b"u2").hexdigest()
    mem_xfer_txid = hashlib.sha256(b"mem-xfer").hexdigest()
    seal_txid = hashlib.sha256(b"seal").hexdigest()
    ghost_seal_txid = hashlib.sha256(b"ghost-seal").hexdigest()
    rev_txid = hashlib.sha256(b"rev-mempool").hexdigest()
    orphan_txid = hashlib.sha256(b"orphan-tx").hexdigest()
    dup_opret_txid = hashlib.sha256(b"dup-opret").hexdigest()
    bad_name_txid = hashlib.sha256(b"bad-name-op").hexdigest()

    # Pending appointment at vout=2 (non-continuation change at vout=1, OP_RETURN at vout=0!)
    disp_pk = sl.compressed_pubkey(sl.deterministic_privkey("nc-t-disp"))
    arb_pk = sl.compressed_pubkey(sl.deterministic_privkey("nc-t-arb"))
    chal_pk = sl.compressed_pubkey(sl.deterministic_privkey("nc-t-chal"))
    g_pk = sl.compressed_pubkey(sl.deterministic_privkey("nc-t-guard"))
    reg_sk = sl.deterministic_privkey("nc-t-reg")
    vac_pol = {"kind": "branch", "template": "both_of_2", "keys": sl.canonical_branch_pair(disp_pk, arb_pk)}
    pend_pol = {"kind": "branch", "template": "guardian_slot_pending", "delay_blocks": 3, "keys": {"challenger": chal_pk, "disposer": disp_pk, "guardian": g_pk}}
    act_pol = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(disp_pk, g_pk)}
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
    b204_orphan = hashlib.sha256(b"blk204-orphan").hexdigest()

    v1_b = sl.jcs_encode({"link": {"cred": cred1}})
    v2_b = sl.jcs_encode({"link": {"cred": cred2}})
    fake_sig = "3044" + ("02" * 68) + "01"

    txs: dict[str, dict[str, Any]] = {
        fu1_txid: {"txid": fu1_txid, "blockhash": b150, "confirmations": 55, "vin": [], "vout": [{"n": 0, "scriptPubKey": {"hex": sl.encode_name_output("NAME_FIRSTUPDATE", spk1, name=b"id/school", rand=b"\x01" * 20, value=v1_b).hex()}}]},
        u1_txid: {"txid": u1_txid, "blockhash": b151, "confirmations": 54, "vin": [{"txid": fu1_txid, "vout": 0, "sequence": 0xFFFFFFFF, "scriptSig": {"hex": ""}, "txinwitness": [fake_sig, pk1]}], "vout": [{"n": 0, "scriptPubKey": {"hex": sl.encode_name_output("NAME_UPDATE", spk1, name=b"id/school", value=v1_b).hex()}}]},
        fu2_txid: {"txid": fu2_txid, "blockhash": b200, "confirmations": 5, "vin": [], "vout": [{"n": 0, "scriptPubKey": {"hex": sl.encode_name_output("NAME_FIRSTUPDATE", spk2, name=b"id/school", rand=b"\x02" * 20, value=v2_b).hex()}}]},
        u2_txid: {"txid": u2_txid, "blockhash": b204, "confirmations": 1, "vin": [{"txid": fu2_txid, "vout": 0, "sequence": 0xFFFFFFFF, "scriptSig": {"hex": ""}, "txinwitness": [fake_sig, pk2]}], "vout": [{"n": 0, "scriptPubKey": {"hex": sl.encode_name_output("NAME_UPDATE", spk2, name=b"id/school", value=v2_b).hex()}}]},
        mem_xfer_txid: {"txid": mem_xfer_txid, "vin": [{"txid": u2_txid, "vout": 0, "sequence": 0xFFFFFFFF, "scriptSig": {"hex": ""}, "txinwitness": [fake_sig, pk2]}], "vout": [{"n": 0, "scriptPubKey": {"hex": sl.encode_name_output("NAME_UPDATE", spk3, name=b"id/school", value=v2_b).hex()}}]},
        seal_txid: {"txid": seal_txid, "blockhash": b200, "confirmations": 5, "vin": [], "vout": [{"n": 0, "scriptPubKey": {"hex": spk1.hex()}}]},
        ghost_seal_txid: {"txid": ghost_seal_txid, "blockhash": b200, "confirmations": 5, "vin": [], "vout": [{"n": 0, "scriptPubKey": {"hex": spk1.hex()}}]},
        rev_txid: {"txid": rev_txid, "vin": [{"txid": seal_txid, "vout": 0, "sequence": 0xFFFFFFFF, "scriptSig": {"hex": ""}, "txinwitness": [fake_sig, pk1]}], "vout": [{"n": 0, "scriptPubKey": {"hex": spk2.hex()}}]},
        orphan_txid: {"txid": orphan_txid, "blockhash": b204_orphan, "confirmations": -1, "vin": [], "vout": [{"n": 0, "scriptPubKey": {"hex": spk1.hex()}}]},
        dup_opret_txid: {
            "txid": dup_opret_txid, "blockhash": b204, "confirmations": 1, "vin": [],
            "vout": [
                {"n": 0, "value": 0.0, "scriptPubKey": {"hex": sl.encode_opreturn(0x01, "11" * 32).hex()}},
                {"n": 1, "value": 0.0, "scriptPubKey": {"hex": sl.encode_opreturn(0x01, "22" * 32).hex()}},
            ],
        },
        bad_name_txid: {"txid": bad_name_txid, "blockhash": b204, "confirmations": 1, "vin": [], "vout": [{"n": 0, "scriptPubKey": {"hex": "ff00deadbeef"}}]},
        vac_txid: {"txid": vac_txid, "blockhash": b200, "confirmations": 5, "vin": [], "vout": [{"n": 0, "scriptPubKey": {"hex": vac_spk.hex()}}]},
        pend_txid: {
            "txid": pend_txid, "blockhash": b200, "confirmations": 5,
            "vin": [{"txid": vac_txid, "vout": 0, "sequence": 0xFFFFFFFF, "scriptSig": {"hex": ""}, "txinwitness": [fake_sig]}],
            "vout": [
                {"n": 0, "value": 0.0, "scriptPubKey": {"hex": sl.encode_opreturn(0x0D, sl.content_addr(g_rec)).hex()}},
                {"n": 1, "scriptPubKey": {"hex": other_spk.hex()}},
                {"n": 2, "scriptPubKey": {"hex": pend_spk.hex()}},
            ],
        },
        act_txid: {
            "txid": act_txid, "blockhash": b204, "confirmations": 1,
            "vin": [{"txid": pend_txid, "vout": 2, "sequence": 3, "scriptSig": {"hex": ""}, "txinwitness": [fake_sig]}],
            "vout": [
                {"n": 0, "scriptPubKey": {"hex": act_spk.hex()}},
                {"n": 1, "value": 0.0, "scriptPubKey": {"hex": sl.encode_opreturn(0x0E, sl.object_id(g_rec_p)).hex()}},
            ],
        },
    }
    hdrs = {
        b150: {"hash": b150, "height": 150, "time": 1795200000, "mediantime": 1795199900, "confirmations": 55},
        b151: {"hash": b151, "height": 151, "time": 1795200600, "mediantime": 1795200500, "confirmations": 54},
        b200: {"hash": b200, "height": 200, "time": 1795210000, "mediantime": 1795209900, "confirmations": 5},
        b204: {"hash": b204, "height": 204, "time": 1795220000, "mediantime": 1795219900, "confirmations": 1},
        b205: {"hash": b205, "height": 205, "time": 1795220020, "mediantime": 1795219950, "confirmations": 1},
        b204_orphan: {"hash": b204_orphan, "height": 204, "time": 1795219999, "mediantime": 1795219800, "confirmations": -1},
    }
    blocks_by_h = {
        200: {"hash": b200, "tx": [txs[vac_txid], txs[pend_txid]]},
        204: {"hash": b204, "tx": [txs[act_txid]]},
        205: {"hash": b205, "tx": []},
    }
    active_hashes = {0: gen, 150: b150, 151: b151, 200: b200, 204: b204, 205: b205}
    state: dict[str, Any] = {
        "tip_h": 204,
        "tip_hash": b204,
        "mempool": [],
        "seal_spent": False,
        "gbi_calls": 0,
        "flip_on_gbi_call": None,
        "txindex_synced": True,
        "bad_name_hist": False,
        "chain_name": "regtest",
        "bad_gettxout": False,
        "name_hist_rpc_err": False,
        "corrupt_second_reg": False,
    }
    bad_mem_name_txid = hashlib.sha256(b"bad-mem-name").hexdigest()
    txs[bad_mem_name_txid] = {
        "txid": bad_mem_name_txid,
        "vin": [{"txid": u2_txid, "vout": 0, "sequence": 0xFFFFFFFF, "scriptSig": {"hex": ""}, "txinwitness": [fake_sig, pk2]}],
        "vout": [{"n": 0, "scriptPubKey": {"hex": "53ff"}}],
    }

    def mock_rpc(method: str, *args: Any) -> Any:
        if method == "getblockhash":
            h = args[0]
            if h in active_hashes:
                return active_hashes[h]
            return b200
        if method == "getblock":
            bh = args[0]
            return blocks_by_h.get(hdrs[bh]["height"], {"hash": bh, "tx": []})
        if method == "getblockchaininfo":
            state["gbi_calls"] += 1
            if state["flip_on_gbi_call"] is not None and state["gbi_calls"] == state["flip_on_gbi_call"]:
                state["tip_h"] = 205
                state["tip_hash"] = b205
            return {
                "chain": state["chain_name"],
                "blocks": state["tip_h"],
                "headers": state["tip_h"],
                "bestblockhash": state["tip_hash"],
                "mediantime": hdrs[state["tip_hash"]]["mediantime"],
                "initialblockdownload": False,
            }
        if method == "getindexinfo":
            return {"txindex": {"synced": state["txindex_synced"], "best_block_height": state["tip_h"]}} if state["txindex_synced"] else {}
        if method == "getblockheader":
            return hdrs[args[0]]
        if method == "getrawmempool":
            return list(state["mempool"])
        if method == "getrawtransaction":
            return txs[args[0]]
        if method == "gettxout":
            txid_q, vout_q = args[0], args[1]
            if state["bad_gettxout"]:
                return {}
            if txid_q == vac_txid and vout_q == 0:
                return None
            if txid_q == pend_txid and vout_q == 2:
                return None
            if txid_q == ghost_seal_txid and vout_q == 0:
                return None  # A-1: missing from UTXO set with NO spender anywhere!
            if txid_q == seal_txid and vout_q == 0 and state["seal_spent"]:
                return None
            return {"confirmations": 1, "scriptPubKey": {"hex": spk1.hex()}}
        if method == "name_history":
            nm_q = args[0]
            if nm_q == "id/rpc-err" and state["name_hist_rpc_err"]:
                raise RuntimeError("namecoin-cli name_history failed: connection reset by peer")
            if nm_q == "id/missing":
                raise RuntimeError("namecoin-cli name_history failed: error code -4: name not found")
            if nm_q == "id/corrupt" and state["bad_name_hist"]:
                return [{"txid": bad_name_txid, "vout": 0, "height": 204}]
            if nm_q == "id/school":
                items = [
                    {"txid": fu1_txid, "vout": 0, "height": 150},
                    {"txid": u1_txid, "vout": 0, "height": 151},
                    {"txid": fu2_txid, "vout": 0, "height": 200},
                    {"txid": u2_txid, "vout": 0, "height": 204},
                ]
                if state["corrupt_second_reg"]:
                    items.append({"txid": bad_name_txid, "vout": 0, "height": 204})
                return items
            return []
        raise RuntimeError(f"Unexpected mock RPC: {method}")

    def mock_compare_rpc(method: str, *args: Any) -> Any:
        if method == "getblockchaininfo":
            return {"chain": "regtest", "blocks": state["tip_h"], "headers": state["tip_h"], "bestblockhash": state["tip_hash"], "initialblockdownload": False}
        if method == "getblockhash":
            return active_hashes[args[0]]
        raise RuntimeError(f"Unexpected mock compare RPC: {method}")

    # Test 0 (A-9): regtest_deterministic clock MUST be rejected on mainnet!
    try:
        ColdNamecoinObserver(mock_rpc, [("peer-a", mock_compare_rpc)], network="main", clock_mode="regtest_deterministic")
        raise AssertionError("Expected ValueError for regtest_deterministic on main")
    except ValueError:
        pass

    # Test 1 + 2: Multi-registration name_history + pending_vout=2 traversal + sequence + block_time + closed bracket!
    obs = ColdNamecoinObserver(mock_rpc, [("peer-a", mock_compare_rpc)], network="regtest", clock_mode="regtest_deterministic")
    cv_dict = obs.build_chain_view(
        wire_objects=[g_rec],
        extra_names=["id/school"],
        extra_outpoints=[(seal_txid, 0), (ghost_seal_txid, 0)],
        extra_txids=[orphan_txid, dup_opret_txid],
        extra_block_hashes=[b204_orphan],
        extra_policies=[pol1, pol2],
    )
    assert state["gbi_calls"] == 2 and cv_dict["observation_bracket"]["consistent"] is True
    assert cv_dict["clock_source"] == "regtest_deterministic"
    assert cv_dict["tip_median_time_past"] == hdrs[b204]["mediantime"]
    assert cv_dict["txs"][vac_txid]["outputs"]["0"]["spent_by_txid"] == pend_txid
    assert cv_dict["txs"][pend_txid]["outputs"]["2"]["spent_by_txid"] == act_txid
    assert cv_dict["txs"][act_txid]["inputs"][0]["sequence"] == 3
    assert cv_dict["txs"][act_txid]["block_time"] == hdrs[b204]["time"]
    # A-1: ghost_seal_txid:0 MUST be marked absent_from_utxo=True!
    assert cv_dict["txs"][ghost_seal_txid]["outputs"]["0"].get("absent_from_utxo") is True
    # A-2: orphaned tx & orphaned block MUST NOT enter active chain view!
    assert orphan_txid not in cv_dict["txs"]
    assert b204_orphan not in cv_dict["blocks"]
    # H-23: duplicate SLNK OP_RETURN tx MUST carry both in opreturns[] and decode to None!
    assert len(cv_dict["txs"][dup_opret_txid]["opreturns"]) == 2
    assert "opreturn_hex" not in cv_dict["txs"][dup_opret_txid]

    ch = sv.ChainView(cv_dict)
    v_strict = sv.Tier1Verifier(pinned_network="regtest", pinned_genesis=gen, require_jsonschema=True, require_observation_bracket=True)
    assert v_strict.check_chain_observation(ch) is None
    assert v_strict._decode_opreturn_tx(ch.get_tx(dup_opret_txid)) is None
    st_ghost, err_ghost, _ = v_strict.evaluate_seal({"txid": ghost_seal_txid, "vout": 0, "script_policy": pol1}, ch)
    assert st_ghost == "revoked" and err_ghost == "SEAL_SPENT"
    cur_rec, cur_err = v_strict.resolve_name("id/school", ch, expected_owner_policy=pol2, expected_registration={"txid": fu2_txid, "vout": 0})
    assert cur_err is None and cur_rec is not None and cur_rec["_value_obj"]["link"]["cred"] == cred2
    old_rec, old_err = v_strict.resolve_name("id/school", ch, expected_owner_policy=pol1, expected_registration={"txid": fu1_txid, "vout": 0}, at_height=157)
    assert old_err is None and old_rec is not None and old_rec["_value_obj"]["link"]["cred"] == cred1

    # Test 3: Mid-read tip transition -> without retry MUST refuse CHAIN_OBSERVATION_VOID; with retry=1 -> ADMIT!
    state["tip_h"], state["tip_hash"], state["gbi_calls"], state["flip_on_gbi_call"] = 204, b204, 0, 2
    cv_void = ColdNamecoinObserver(mock_rpc, [("peer-a", mock_compare_rpc)], network="regtest", clock_mode="regtest_deterministic").build_chain_view(extra_names=["id/school"], retry_on_tip_change=0)
    assert cv_void["observation_bracket"]["consistent"] is False
    assert v_strict.check_chain_observation(sv.ChainView(cv_void)) == "CHAIN_OBSERVATION_VOID"

    state["tip_h"], state["tip_hash"], state["gbi_calls"], state["flip_on_gbi_call"] = 204, b204, 0, 2
    cv_retried = ColdNamecoinObserver(mock_rpc, [("peer-a", mock_compare_rpc)], network="regtest", clock_mode="regtest_deterministic").build_chain_view(extra_names=["id/school"], retry_on_tip_change=1)
    assert cv_retried["observation_bracket"]["consistent"] is True and cv_retried["observation_bracket"]["attempts"] == 2
    assert v_strict.check_chain_observation(sv.ChainView(cv_retried)) is None

    # Test 4 (R1-B): Transactional persisted clock_watermark & earliest first_sight_by_hash + rollback detection!
    state["tip_h"], state["tip_hash"], state["gbi_calls"], state["flip_on_gbi_call"] = 204, b204, 0, None
    with tempfile.TemporaryDirectory(prefix="seallink-obs-state-") as td:
        sp = Path(td) / "obs-state.json"
        now_box = [1795220100]
        obs_op1 = ColdNamecoinObserver(mock_rpc, [("peer-a", mock_compare_rpc)], network="regtest", clock_mode="operational", clock_now_fn=lambda: now_box[0], state_path=sp)
        cv_op1 = obs_op1.build_chain_view(extra_names=["id/school"])
        assert cv_op1["clock_source"] == "operational_persisted" and cv_op1["tip_first_sight"] == 1795220100
        assert v_strict.check_chain_observation(sv.ChainView(cv_op1)) is None
        # Sibling observer advances clock on disk; obs_op1 re-reads & preserves earliest first_sight!
        obs_op_fast = ColdNamecoinObserver(mock_rpc, [("peer-a", mock_compare_rpc)], network="regtest", clock_mode="operational", clock_now_fn=lambda: 1795220200, state_path=sp)
        cv_fast = obs_op_fast.build_chain_view(extra_names=["id/school"])
        assert cv_fast["tip_first_sight"] == 1795220100
        # Fresh instance with clock rollback (1795220150 < persisted 1795220200) -> CHAIN_CLOCK_ERROR!
        obs_op2 = ColdNamecoinObserver(mock_rpc, [("peer-a", mock_compare_rpc)], network="regtest", clock_mode="operational", clock_now_fn=lambda: 1795220150, state_path=sp)
        cv_op2 = obs_op2.build_chain_view(extra_names=["id/school"])
        assert v_strict.check_chain_observation(sv.ChainView(cv_op2)) == "CHAIN_CLOCK_ERROR"
        # R1-B: pre_effect_recheck updates unified `now` as wall clock advances & detects stale tip!
        now_box[0] = 1795224000  # > 3600s after tip_first_sight 1795220100
        cv_stale = obs_op1.pre_effect_recheck(cv_op1, [(seal_txid, 0)])
        assert cv_stale["now"] == 1795224000
        assert v_strict.check_chain_observation(sv.ChainView(cv_stale), risk_class=1) == "CHAIN_TIP_STALE"

    # Test 5 (A-5, A-6, R1-B): pre_effect_recheck catches mempool seal spend + mempool OP_NAME_UPDATE + mid-recheck tip move!
    state["tip_h"], state["tip_hash"], state["gbi_calls"], state["flip_on_gbi_call"] = 204, b204, 0, None
    state["mempool"] = [rev_txid, mem_xfer_txid]
    state["seal_spent"] = True
    cv_pre = obs.pre_effect_recheck(cv_dict, [(seal_txid, 0)])
    assert cv_pre["observation_bracket"]["pre_effect_rechecked"] is True
    assert cv_pre["observation_bracket"]["consistent"] is True
    assert cv_pre["txs"][seal_txid]["outputs"]["0"]["spent_by_txid"] == rev_txid
    assert cv_pre["txs"][rev_txid]["in_mempool"] is True
    # A-5: mempool transfer to unseen spk3 MUST trigger NAME_OWNER_MISMATCH in resolve_role_policy!
    ch_pre = sv.ChainView(cv_pre)
    nrec_pre, nerr_pre = v_strict.resolve_name("id/school", ch_pre, expected_owner_policy=pol2, expected_registration={"txid": fu2_txid, "vout": 0})
    assert nerr_pre is None and nrec_pre is not None
    _, rerr_pre = v_strict.resolve_role_policy(nrec_pre, "cred", recent_block_height=204)
    assert rerr_pre == "NAME_OWNER_MISMATCH"

    # Mid-recheck tip transition (between re_start and re_end) MUST fail closed CHAIN_OBSERVATION_VOID!
    state["tip_h"], state["tip_hash"], state["gbi_calls"], state["flip_on_gbi_call"] = 204, b204, 0, 2
    cv_pre_void = obs.pre_effect_recheck(cv_dict, [(seal_txid, 0)])
    assert cv_pre_void["observation_bracket"]["consistent"] is False
    assert v_strict.check_chain_observation(sv.ChainView(cv_pre_void)) == "CHAIN_OBSERVATION_VOID"

    # Test 6 (A-4): Unparseable name_history entry -> history_truncated=True -> NAME_HISTORY_UNAVAILABLE!
    state["tip_h"], state["tip_hash"], state["gbi_calls"], state["flip_on_gbi_call"] = 204, b204, 0, None
    state["mempool"] = []
    state["bad_name_hist"] = True
    cv_bad_nm = obs.build_chain_view(extra_names=["id/corrupt"])
    assert cv_bad_nm["names"]["id/corrupt"].get("history_truncated") is True
    _, bad_err = v_strict.resolve_name("id/corrupt", sv.ChainView(cv_bad_nm))
    assert bad_err == "NAME_HISTORY_UNAVAILABLE"

    # Test 7 (A-11): Unsynced/missing txindex -> txindex=False -> CHAIN_UNHEALTHY!
    state["txindex_synced"] = False
    cv_notx = obs.build_chain_view(extra_names=["id/school"])
    assert cv_notx["txindex"] is False
    assert v_strict.check_chain_observation(sv.ChainView(cv_notx)) == "CHAIN_UNHEALTHY"
    state["txindex_synced"] = True

    # Test 8 (R3 High #1): pre_effect_recheck MUST NOT resurrect a voided snapshot (`consistent=False`)!
    state["tip_h"], state["tip_hash"], state["gbi_calls"], state["flip_on_gbi_call"] = 204, b204, 0, None
    cv_resurrect = obs.pre_effect_recheck(cv_void, [(seal_txid, 0)])
    assert cv_resurrect["observation_bracket"]["consistent"] is False
    assert v_strict.check_chain_observation(sv.ChainView(cv_resurrect)) == "CHAIN_OBSERVATION_VOID"

    # Test 9 (A-11): Chain network mismatch in getblockchaininfo -> node_reachable=False -> CHAIN_UNHEALTHY!
    state["chain_name"] = "main"
    cv_bad_chain = obs.build_chain_view(extra_names=["id/school"])
    assert cv_bad_chain["node_reachable"] is False
    assert v_strict.check_chain_observation(sv.ChainView(cv_bad_chain)) == "CHAIN_UNHEALTHY"
    state["chain_name"] = "regtest"

    # Test 10 (A-13): Malformed gettxout response ({}) -> absent_from_utxo=True -> SEAL_SPENT!
    state["bad_gettxout"] = True
    state["seal_spent"] = False
    cv_bad_utxo = obs.build_chain_view(extra_outpoints=[(seal_txid, 0)])
    assert cv_bad_utxo["txs"][seal_txid]["outputs"]["0"].get("absent_from_utxo") is True
    state["bad_gettxout"] = False

    # Test 11 (R2-A-01 & R2-A-02): Transient name_history RPC error -> history_truncated=True; corrupt 2nd reg does NOT taint clean 1st reg!
    state["name_hist_rpc_err"] = True
    state["corrupt_second_reg"] = True
    cv_nh = obs.build_chain_view(extra_names=["id/rpc-err", "id/missing", "id/school"], extra_policies=[pol1, pol2])
    assert cv_nh["names"]["id/rpc-err"].get("history_truncated") is True
    assert "id/missing" not in cv_nh["names"]
    assert v_strict.resolve_name("id/rpc-err", sv.ChainView(cv_nh))[1] == "NAME_HISTORY_UNAVAILABLE"
    assert v_strict.resolve_name("id/missing", sv.ChainView(cv_nh))[1] == "NAME_NOT_FOUND"
    # Second reg is tainted, while clean historical first reg still resolves at height 157!
    assert cv_nh["names"]["id/school"].get("history_truncated") is True
    hist_rec, hist_err = v_strict.resolve_name(
        "id/school", sv.ChainView(cv_nh), expected_owner_policy=pol1, expected_registration={"txid": fu1_txid, "vout": 0}, at_height=157
    )
    assert hist_err is None and hist_rec is not None and hist_rec["_value_obj"]["link"]["cred"] == cred1
    state["name_hist_rpc_err"] = False
    state["corrupt_second_reg"] = False

    # Test 12 (R2-A-03): Unparseable mempool OP_NAME_UPDATE spending watched name -> fail closed NAME_HISTORY_UNAVAILABLE!
    state["mempool"] = [bad_mem_name_txid]
    cv_bad_mem = obs.build_chain_view(extra_names=["id/school"], extra_policies=[pol1, pol2])
    ch_bm = sv.ChainView(cv_bad_mem)
    nrec_bm, nerr_bm = v_strict.resolve_name("id/school", ch_bm, expected_owner_policy=pol2, expected_registration={"txid": fu2_txid, "vout": 0})
    assert nerr_bm is None and nrec_bm is not None
    _, rerr_bm = v_strict.resolve_role_policy(nrec_bm, "cred", recent_block_height=204)
    assert rerr_bm == "NAME_HISTORY_UNAVAILABLE"
    state["mempool"] = []


if __name__ == "__main__":
    self_test()
    print(
        "nc_rpc_adapter self_test PASS "
        "(multi-reg + pending_vout=2 + bracket/retry + R1-B transactional clock & recheck + "
        "R3-H1 no-resurrection + A-1 absent_from_utxo + A-2 orphan filter + A-3 cache invalidation + "
        "A-4/R2-A-01/02 scoped truncated history + A-5/R2-A-03 mempool name update + A-9 mainnet clock guard + "
        "A-11 chain/txindex + A-13 strict gettxout + H-23 dup SLNK)"
    )
