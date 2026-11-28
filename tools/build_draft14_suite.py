#!/usr/bin/env python3
"""
SealLink v1.0.0-draft.14 Hardening, Protocol Parity, & 100%-Mutation-Kill Conformance Suite.

Appends executable conformance, adversarial, boundary, and mutation-killing cases to
`vectors/security-conformance.json`, covering every confirmed finding from the 14-reviewer
draft.13 independent audit:

  - Section 1 (D14-B03, D14-H01..H04, D14-H06):
      * Restricted JCS non-finite literals (NaN/Infinity/-Infinity) & Unicode Arabic-Indic digits
      * Off-curve disposer_pk -> WIRE_KEY (never CHAIN_SCRIPT_UNSUPPORTED)
      * Fixed 256-leaf (exact 8-step) salted-Merkle SetEntryMerkleProof enforcement
      * Step 8b runtime LocatorUri validation (forbidden http://, magnet http tracker, unknown future scheme ar://)
      * X25519 RFC 7748 low-order u-coordinate rejection in transport-binding statements
      * manifest.service with service_type="sso" and actions=[] (minItems: 0)
      * SL-IDEN-003 hash-pin role_policy collision with owner_policy/nostr & manifest.role_policies collision
      * Non-owner-authored OP_NAME_UPDATE link.origin ignored; idx_o==0 FIRSTUPDATE preserved; forward-only malformed SLNK boundary

  - Section 2 (D14-B05, D14-B06, D14-B11):
      * SL-IDEN-008 per-set monotonic sequence & removed_sets non-resurrection across replay_restart
      * Durable SEAL_SPENT closures on sets.auth, sets.devices, and seallink-statement/1 surviving mempool eviction
      * auth_upgrade OP_NAME_FIRSTUPDATE depth >= operator_min_depth boundary, TTL > 120, channel_binding, account_id, durable nonce replay
      * owner_command expected_target_executor mismatch, L2 presence on all commands, durable nonce replay across replay_restart
      * certset_head issuer/network mismatch; private statement with locators -> WIRE_MEMBER
      * statement/1 full statement_kind/device-ceiling/presence/is_foreign_service/alg/receipt_key matrix + ward/ended blocking

  - Section 3 (D14-B09, D14-B10, D14-H05, D14-H08):
      * Profile W P2WPKH 2-element witness non-SIGHASH_ALL DER violation (len(wit)==2)
      * _try_open_0x0c candidate name_history missing -> ORIGIN_STATUS_INCOMPLETE; exact cfu_h == h_r vs h_r + 1
      * Emancipation pre_trigger_pks exact boundary on cap_confirmed_height & opened_majority
      * _get_indexed_events exact history_truncated first_error_height boundary
      * D14-B09 second 0x13 during unknown_preimage -> immediate unknown_rebind_stalled; dual_party_delayed 0x0c rescue; min_d_u == 35000 vs 35001
      * verify_ward_approvals persisted guardian link.grant CRED_ISSUER_CLOSED at exact cutoff_height
      * verify_assent party_name != wb.name on State-4 adult; D14-H08 historical ward assent backdating protection (unanchored refused; assent_output spent by 0x07 admitted)
      * verify_termination ward arbiter branch banned (WIRE_SIGNATURE); verify_federation_disclosure missing issuance_txid (CHAIN_FRAME_INVALID)
      * D14-H05 journaled guardian slot active -> vacant -> 0x0d -> 0x0e -> active re-appointment

  - Section 4 (D14-B07, D14-B12, D14-B13):
      * 0x14 on-chain handover continuation (handover_next_vout=1, handover_next_policy, denials_root folded in compute_log_id)
      * 2-hop iterative handover L0 -> L1 -> L2, cycle detection, wire-invalid predecessor, non-terminal handover refusal, maturing predecessor refusal
      * Multi-hop persisted journal predecessor chain (cycle, grandparent log closure, missing grandparent)
      * Handover denials_root wipe refusal (seq=1 direct & 2-hop intermediate seq=1 _verified_pred_denials_root)
      * GatekeeperPolicy pinning L2 admitting historical L1 notary act via predecessor_chain & refusing unpinned log_tracked
      * 0x14 vout 0 OP_RETURN enforcement (opreturns vout!=0 & outputs["0"] non-OP_RETURN), handover missing vout 1 / P2A rejected as continuation
      * EOL terminal 0x14 with vout 1 = P2A (51024e73) + vout 2 = change ADMIT (and vout 3 refused); maturing in_mempool=False refused; dust prev_vout=1 DFS
      * RBF-identical equivocation (differing only in prev_log_outpoint) refused
      * verify_log_fraud role mismatch, forged predecessor issuer hijack, rec_b_inclusion wrong log_id, cross-handover illegal_reversion at L2.seq==1, Mode 3d NAME_HISTORY_UNAVAILABLE zero closures

  - Section 5 (D14-B08 Tier-2 SPV Full Hardening):
      * main network mandatory trusted_checkpoint when headers[0].height > 0
      * height == 0 pinned_genesis enforcement (mismatch refused, match admitted)
      * trusted_checkpoint recent_11_times[-1] mismatch & 2-header MTP(11) refusal
      * Header-only bridging pages (pre-FIRSTUPDATE & post-FIRSTUPDATE) with next_header_checkpoint verification, exact cursor_height + name_expiry refusal, next_cursor owner_policy mismatch
      * Tier-1 parity: SL-IDEN-003 owner-key reuse refused; non-SIGHASH_ALL update inert SLNK frame admitted
      * Terminal page final_owner_policy on trailing rotation (matching, omitted->None, wrong) and non-rotation (wrong)
"""

from __future__ import annotations

import copy
import struct
from typing import Any, Callable

import build_draft11_suite as bd11
import build_draft13_suite as bd13
import build_refusal_matrix as rm
import seallink_ref as sl
import seallink_verifier as sv

GENESIS_MAIN = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"
P2A_SPK_HEX = "51024e73"


def _h32(label: str) -> str:
    return sl.sha256(f"seallink-d14-hex:{label}".encode("utf-8")).hex()


def _kp(label: str) -> dict[str, Any]:
    sk = sl.deterministic_privkey(f"d14-{label}")
    return {"sk": sk, "xonly": sl.xonly_pubkey(sk), "comp": sl.compressed_pubkey(sk)}


def _spk_hex(policy: dict[str, Any]) -> str:
    return sl.compile_script_policy(policy)[0].hex()


def _issuance_digest(grant_env: dict[str, Any]) -> str:
    gp = grant_env["payload"]
    prep: dict[str, Any] = {
        "genesis": gp["genesis"],
        "grant_content_addr": sl.content_addr(grant_env),
        "grant_id": sl.object_id(gp),
        "type": "seallink-issuance/1",
    }
    if "contract_id" in gp:
        prep["contract_id"] = gp["contract_id"]
    return sl.signing_digest(prep).hex()


def _mk_handover_log_chain(prefix: str) -> dict[str, Any]:
    """Build a valid 2-hop iterative handover chain L0 -> L1 (seq=1 terminal) -> L2 (seq=1..2) for a notary."""
    eco0 = bd11._build_log_ecosystem(f"{prefix}-l0", role="notary", with_4_checkpoints=True)
    # Turn L0's cp3 (which carries active rev1 in denials_root) into a handover-capable terminal checkpoint!
    ch = copy.deepcopy(eco0["chain_at_cp3"])
    rm.sync_chain_tip(ch, height=750010)
    l0_term_p = copy.deepcopy(eco0["cp3_env"]["payload"])
    l0_term_p["terminal"] = True
    l0_term_p.pop("next_log_policy", None)
    l0_term_p.pop("next_log_vout", None)
    l0_term_p["handover_next_policy"] = eco0["seal_pol"]
    l0_term_p["handover_next_vout"] = 1
    l0_term_env = sl.sign_envelope(l0_term_p, [eco0["iss_role"]["sk"]])
    l0_term_tx = eco0["cp3_tx"]
    l0_dr = l0_term_p["denials_root"]

    # L1: seq=1 AND terminal=True with handover_next_policy (single-checkpoint handover hop!)
    l1_cp1_tx = _h32(f"{prefix}-l1-cp1")
    l1_gen_op = {"txid": l0_term_tx, "vout": 1}
    l1_lid = sl.compute_log_id(
        "main", GENESIS_MAIN, "notary", eco0["iss_name"], eco0["iss_reg"], l1_gen_op,
        predecessor_log_id=eco0["log_id"],
        predecessor_terminal_denials_root=l0_dr,
    )
    l1_cp1_p = {
        "batch_count": 0, "batch_root": sl.EMPTY_BATCH_ROOT, "checkpoints_root": sl.EMPTY_CHECKPOINTS_ROOT,
        "cumulative_entries_count": 0, "denials_delta_root": sl.EMPTY_BATCH_ROOT,
        "denials_root": l0_dr, "genesis": GENESIS_MAIN, "genesis_seal_outpoint": l1_gen_op,
        "handover_next_policy": eco0["seal_pol"], "handover_next_vout": 1,
        "issuer": eco0["iss_role_pin"], "log_id": l1_lid, "network": "main",
        "predecessor_log_id": eco0["log_id"], "predecessor_terminal_denials_root": l0_dr,
        "prev_log_outpoint": l1_gen_op, "role": "notary", "seq": 1, "terminal": True,
        "type": "seallink-log-checkpoint/1",
    }
    l1_cp1_env = sl.sign_envelope(l1_cp1_p, [eco0["iss_role"]["sk"]])

    # L2: seq=1 (non-terminal) -> seq=2 (non-terminal)
    l2_cp1_tx = _h32(f"{prefix}-l2-cp1")
    l2_cp2_tx = _h32(f"{prefix}-l2-cp2")
    l2_gen_op = {"txid": l1_cp1_tx, "vout": 1}
    l2_lid = sl.compute_log_id(
        "main", GENESIS_MAIN, "notary", eco0["iss_name"], eco0["iss_reg"], l2_gen_op,
        predecessor_log_id=l1_lid,
        predecessor_terminal_denials_root=l0_dr,
    )
    l2_cp1_p = {
        "batch_count": 0, "batch_root": sl.EMPTY_BATCH_ROOT, "checkpoints_root": sl.EMPTY_CHECKPOINTS_ROOT,
        "cumulative_entries_count": 0, "denials_delta_root": sl.EMPTY_BATCH_ROOT,
        "denials_root": l0_dr, "genesis": GENESIS_MAIN, "genesis_seal_outpoint": l2_gen_op,
        "issuer": eco0["iss_role_pin"], "log_id": l2_lid, "network": "main",
        "next_log_policy": eco0["seal_pol"], "next_log_vout": 1,
        "predecessor_log_id": l1_lid, "predecessor_terminal_denials_root": l0_dr,
        "prev_log_outpoint": l2_gen_op, "role": "notary", "seq": 1, "terminal": False,
        "type": "seallink-log-checkpoint/1",
    }
    l2_cp1_env = sl.sign_envelope(l2_cp1_p, [eco0["iss_role"]["sk"]])
    l2_cp1_ca = sl.content_addr(l2_cp1_env)
    l2_ckpt_leaves_1 = [sl.ckpt_leaf(1, l2_cp1_ca)]
    l2_cp2_p = {
        "batch_count": 0, "batch_root": sl.EMPTY_BATCH_ROOT,
        "checkpoints_root": sl.rfc9162_mth(l2_ckpt_leaves_1).hex(),
        "cumulative_entries_count": 0, "denials_delta_root": sl.EMPTY_BATCH_ROOT,
        "denials_root": l0_dr, "genesis": GENESIS_MAIN, "genesis_seal_outpoint": l2_gen_op,
        "issuer": eco0["iss_role_pin"], "log_id": l2_lid, "network": "main",
        "next_log_policy": eco0["seal_pol"], "next_log_vout": 1,
        "predecessor_log_id": l1_lid, "prev_checkpoint_id": l2_cp1_ca,
        "prev_log_outpoint": {"txid": l2_cp1_tx, "vout": 1}, "role": "notary", "seq": 2, "terminal": False,
        "type": "seallink-log-checkpoint/1",
    }
    l2_cp2_env = sl.sign_envelope(l2_cp2_p, [eco0["iss_role"]["sk"]])

    ch["txs"][l0_term_tx]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(l0_term_env)).hex()
    ch["txs"][l0_term_tx]["outputs"] = {"1": {"script_pubkey_hex": _spk_hex(eco0["seal_pol"]), "spent_by_txid": l1_cp1_tx}}
    ch["txs"][l1_cp1_tx] = {
        "block_hash": _h32(f"{prefix}-blk-l1"), "confirmed_height": 749996,
        "inputs": [sv.make_segwit_input(l0_term_tx, 1)],
        "opreturn_hex": sl.encode_opreturn(0x14, sl.content_addr(l1_cp1_env)).hex(),
        "outputs": {"1": {"script_pubkey_hex": _spk_hex(eco0["seal_pol"]), "spent_by_txid": l2_cp1_tx}},
    }
    ch["txs"][l2_cp1_tx] = {
        "block_hash": _h32(f"{prefix}-blk-l2-1"), "confirmed_height": 749998,
        "inputs": [sv.make_segwit_input(l1_cp1_tx, 1)],
        "opreturn_hex": sl.encode_opreturn(0x14, l2_cp1_ca).hex(),
        "outputs": {"1": {"script_pubkey_hex": _spk_hex(eco0["seal_pol"]), "spent_by_txid": l2_cp2_tx}},
    }
    ch["txs"][l2_cp2_tx] = {
        "block_hash": _h32(f"{prefix}-blk-l2-2"), "confirmed_height": 750000,
        "inputs": [sv.make_segwit_input(l2_cp1_tx, 1)],
        "opreturn_hex": sl.encode_opreturn(0x14, sl.content_addr(l2_cp2_env)).hex(),
        "outputs": {"1": {"script_pubkey_hex": _spk_hex(eco0["seal_pol"])}},
    }
    return {
        "chain": ch, "eco0": eco0,
        "l0_dr": l0_dr, "l0_term_env": l0_term_env, "l0_term_tx": l0_term_tx,
        "l1_cp1_env": l1_cp1_env, "l1_cp1_tx": l1_cp1_tx, "l1_gen_op": l1_gen_op, "l1_lid": l1_lid,
        "l2_cp1_env": l2_cp1_env, "l2_cp1_tx": l2_cp1_tx, "l2_cp2_env": l2_cp2_env, "l2_cp2_tx": l2_cp2_tx,
        "l2_gen_op": l2_gen_op, "l2_lid": l2_lid,
        "pred_chain_for_l2": [
            {"checkpoint": l1_cp1_env, "checkpoint_txid": l1_cp1_tx},
            {"checkpoint": l0_term_env, "checkpoint_txid": l0_term_tx},
        ],
    }


def add_draft14_conformance_cases(add: Callable[..., None]) -> None:
    # ========================================================================
    # SECTION 1: Wire, JCS, Keys, Locators, Manifest & Role Disjointness
    # ========================================================================
    # 1.1 D14-B03: NaN / Infinity / -Infinity / Arabic-Indic digits -> WIRE_JSON
    for lbl_j, raw_j in [
        ("nan", '{"a":NaN,"type":"seallink-card/1"}'),
        ("inf", '{"a":Infinity,"type":"seallink-card/1"}'),
        ("neginf", '{"a":-Infinity,"type":"seallink-card/1"}'),
        ("arabic-indic-digit", '{"seq":0\u0661,"type":"seallink-card/1"}'),
    ]:
        add(
            f"d14-b03-jcs-reject-{lbl_j}",
            ["SL-WIRE-001"],
            "raw_wire",
            {"raw_bytes_utf8": raw_j},
            "REFUSE",
            "WIRE_JSON",
            f"D14-B03: Non-RFC-8259 JSON token ({lbl_j}) MUST refuse WIRE_JSON.",
        )

    # 1.2 D14-B03: Off-curve disposer_pk on seallink-origin/1 -> WIRE_KEY (never CHAIN_SCRIPT_UNSUPPORTED!)
    of_dk = rm._base_origin_fixture()
    bad_secp_comp = next(f"02{i:064x}" for i in range(1, 200) if not sl.is_valid_compressed_pubkey(f"02{i:064x}"))
    orig_bad_disp = copy.deepcopy(of_dk["origin_bundle"]["origin"])
    orig_bad_disp["payload"]["guardian_policy"]["disposer_pk"] = bad_secp_comp
    add(
        "d14-b03-origin-off-curve-disposer-pk-wire-key",
        ["SL-WIRE-012", "SL-ORIG-001"],
        "raw_wire",
        {"expected_type": "seallink-origin/1", "object": orig_bad_disp},
        "REFUSE",
        "WIRE_KEY",
        "D14-B03: Off-curve disposer_pk in seallink-origin/1 MUST refuse WIRE_KEY (Step 9 precedence before CHAIN_SCRIPT_UNSUPPORTED).",
    )

    # 1.3 D14-H01: SetEntryMerkleProof with < 8 steps (7 steps) MUST refuse WIRE_MEMBER!
    fx_s1 = rm._base_invocation_fixture()
    now_s1 = fx_s1["chain"]["now"]
    a1_k = _kp("s1-auth-1")
    as1_pol = {"kind": "key", "pk": _kp("s1-aseal")["comp"]}
    as1_tx = _h32("s1-aseal-tx")
    fx_s1["chain"]["txs"][as1_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(as1_pol)}}}
    ah1, aps1 = rm.make_salted_auth_set(
        "id/alice",
        [{"alg": "bip340", "key": a1_k["xonly"], "label": "k1", "seal": {"script_policy": as1_pol, "txid": as1_tx, "vout": 0}}],
    )
    assert len(aps1[0]["proof"]["steps"]) == 16
    man_s1 = rm.bind_sets_manifest(
        fx_s1["chain"], "id/alice", fx_s1["_alice_owner_pol"], fx_s1["_alice_reg"],
        auth_head=ah1, extra_link={"grant": fx_s1["_keys"]["alice_gr"]["xonly"]},
    )
    man_s1_h = sl.content_addr(man_s1)
    ac1_n = _h32("s1-ac-n")
    ac1_env = sl.sign_envelope({
        "auth_alg": "bip340", "auth_pubkey": a1_k["xonly"], "expires_at": now_s1 + 60,
        "genesis": GENESIS_MAIN, "issued_at": now_s1, "name": "id/alice", "network": "main",
        "nonce": ac1_n, "service_id": "sso.example.org", "type": "seallink-auth-challenge/1",
    }, [a1_k["sk"]])
    pf_15_steps = copy.deepcopy(aps1[0])
    pf_15_steps["proof"]["steps"] = pf_15_steps["proof"]["steps"][:15]
    add(
        "d14-h01-salted-merkle-proof-under-16-steps-refuse",
        ["SL-IDEN-010", "SL-WIRE-010"],
        "auth_challenge",
        {
            "auth_proof": pf_15_steps, "chain": fx_s1["chain"], "challenge": ac1_env,
            "journal": {"auth_nonces": {ac1_n: {"expires_at": now_s1 + 60, "issued_at": now_s1, "service_id": "sso.example.org", "used": False}}, "journal_id": _h32("s1-j1")},
            "manifests": {man_s1_h: man_s1}, "service_id": "sso.example.org",
        },
        "REFUSE",
        "WIRE_MEMBER",
        "D14-H01: Depth-16 salted sparse Merkle proof with fewer than 16 steps MUST refuse WIRE_MEMBER.",
    )

    # 1.4 D14-H02 / D14-H06: Step 8b LocatorUri (forbidden http://, magnet http tracker, unknown future ar://) & SSO empty actions[]
    base_card_14 = {
        "avatar": {"bytes": 4096, "locators": ["https://cdn.example.org/a.webp"], "mime": "image/webp", "sha256": _h32("c14-av")},
        "contact": "alice@example.org", "display": "Alice 14", "kind": "person",
        "links": [{"label": "Arweave", "url": "ar://txid-example-future-scheme"}],
        "name": "id/alice", "network": "main", "relays": ["wss://relay.example.org"],
        "replaces": 0, "role": "engineer", "seq": 1, "transports": [], "type": "seallink-card/1",
    }
    add(
        "d14-h06-locator-uri-unknown-future-scheme-admit",
        ["SL-IDEN-006"],
        "raw_wire",
        {"object": base_card_14},
        "ADMIT",
        None,
        "D14-H06: Forward-compatible unknown RFC 3986 LocatorUri scheme (ar://) not on forbidden list is wire-valid.",
    )
    card_http = copy.deepcopy(base_card_14)
    card_http["avatar"]["locators"] = ["http://insecure.example.org/a.webp"]
    add(
        "d14-h06-locator-uri-forbidden-http-refuse",
        ["SL-WIRE-010"],
        "raw_wire",
        {"object": card_http},
        "REFUSE",
        "WIRE_MEMBER",
        "D14-H06: Forbidden http:// LocatorUri scheme MUST refuse WIRE_MEMBER at Step 8b.",
    )
    card_mag_http = copy.deepcopy(base_card_14)
    card_mag_http["links"] = [{"label": "Mag", "url": f"magnet:?xt=urn:btmh:1220{_h32('mag14')}&tr=http://tracker.example/announce"}]
    add(
        "d14-h06-locator-uri-magnet-http-tracker-refuse",
        ["SL-WIRE-010"],
        "raw_wire",
        {"object": card_mag_http},
        "REFUSE",
        "WIRE_MEMBER",
        "D14-H06: magnet: LocatorUri carrying cleartext http:// tracker parameter MUST refuse WIRE_MEMBER.",
    )
    man_sso_empty = {
        "network": "main", "owner": "id/sso-d14", "seq": 1,
        "service": {"actions": [], "endpoint": "https://sso.example.org/auth", "receipt_key": _kp("s1-sso-rcpt")["xonly"], "service_type": "sso"},
        "type": "seallink-manifest/1",
    }
    add(
        "d14-h06-manifest-sso-empty-actions-admit",
        ["SL-IDEN-005"],
        "raw_wire",
        {"expected_type": "seallink-manifest/1", "object": man_sso_empty},
        "ADMIT",
        None,
        "D14-H06: seallink-manifest/1 with service_type='sso' and actions=[] (minItems: 0) admits cleanly.",
    )

    # 1.5 D14-H03: X25519 low-order u-coordinate in transport-binding statement -> WIRE_KEY
    st_x25519_lo = sl.sign_envelope({
        "genesis": GENESIS_MAIN,
        "issuer": {"name": "id/alice", "owner_policy": fx_s1["_alice_owner_pol"], "registration": fx_s1["_alice_reg"]},
        "network": "main", "not_after": now_s1 + 600, "not_before": now_s1, "seq": 1,
        "statement_kind": "transport-binding",
        "subject": {"endpoint": "ssh://alice.example.org", "key_alg": "x25519", "key_hex": "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", "transport": "ssh"},
        "type": "seallink-statement/1",
    }, [fx_s1["_keys"]["alice_gr"]["sk"]])
    add(
        "d14-h03-x25519-low-order-transport-binding-refuse",
        ["SL-WIRE-012"],
        "raw_wire",
        {"expected_type": "seallink-statement/1", "object": st_x25519_lo},
        "REFUSE",
        "WIRE_KEY",
        "D14-H03: RFC 7748 low-order X25519 pubkey in transport-binding statement MUST refuse WIRE_KEY.",
    )

    # 1.6 SL-IDEN-003 (kills L2338 in resolve_role_policy & L2690 in resolve_manifest!)
    # (a) Hash-pin 1-of-2 link.grant = {"p": H(1-of-2)} whose key collides with nostr.names._ -> NAME_VALUE_INVALID at L2338!
    ch_rp_nostr = copy.deepcopy(fx_s1["chain"])
    coll_gr_k = _kp("s1-coll-gr-nostr")
    coll_gr_k2 = _kp("s1-coll-gr-extra")
    coll_gr_pol = {"m": 1, "pks": sorted([coll_gr_k["xonly"], coll_gr_k2["xonly"]])}
    coll_gr_h = sl.sha256(sl.jcs_encode(coll_gr_pol)).hex()
    ch_rp_nostr["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx_s1["_alice_reg"], fx_s1["_alice_owner_pol"],
        {"link": {"grant": {"p": coll_gr_h}}, "nostr": {"names": {"_": coll_gr_k["xonly"]}}},
        first_height=748000, update_height=749000,
    )
    st_coll_rp = sl.sign_envelope({
        "body_sha256": _h32("s1-coll-rp-b"), "genesis": GENESIS_MAIN,
        "issuer": {"name": "id/alice", "owner_policy": fx_s1["_alice_owner_pol"], "registration": fx_s1["_alice_reg"]},
        "network": "main", "not_after": now_s1 + 600, "not_before": now_s1, "seq": 1,
        "statement_kind": "profile-section", "subject": {"section_kind": "org.seallink.profile/bio"},
        "type": "seallink-statement/1",
    }, [coll_gr_k["sk"]], policy_pks=coll_gr_pol["pks"], m=1)
    add(
        "d14-h04-hash-pin-role-policy-collides-nostr-refuse",
        ["SL-IDEN-003"],
        "statement",
        {"chain": ch_rp_nostr, "statement": st_coll_rp},
        "REFUSE",
        "NAME_VALUE_INVALID",
        "D14-H04 / SL-IDEN-003: Hash-pinned 1-of-2 link.grant resolving to key colliding with nostr.names._ MUST refuse NAME_VALUE_INVALID.",
    )
    # (b) resolve_manifest detects 1-of-2 manifest.role_policies colliding with owner_policy (kills L2690!)
    ch_man_coll = copy.deepcopy(fx_s1["chain"])
    own_xonly = fx_s1["_alice_owner_pol"]["pk"][2:]
    not_coll_pol = {"m": 1, "pks": sorted([own_xonly, _kp("s1-coll-not-extra")["xonly"]])}
    man_coll_own = {
        "network": "main", "owner": "id/alice",
        "role_policies": {"notary": not_coll_pol},
        "seq": 1, "type": "seallink-manifest/1",
    }
    man_coll_own_h = sl.content_addr(man_coll_own)
    not_hash_own = sl.sha256(sl.jcs_encode(not_coll_pol)).hex()
    ch_man_coll["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx_s1["_alice_reg"], fx_s1["_alice_owner_pol"],
        {"link": {"grant": fx_s1["_keys"]["alice_gr"]["xonly"], "notary": {"p": not_hash_own}}, "m": {"h": man_coll_own_h, "s": 1}},
        first_height=748000, update_height=749000,
    )
    add(
        "d14-h04-manifest-role-policy-collides-owner-refuse",
        ["SL-IDEN-003"],
        "multi_step_journal",
        {
            "journal": {"journal_id": _h32("s1-mcoll-j")},
            "steps": [{
                "chain": ch_man_coll, "expected_owner_policy": fx_s1["_alice_owner_pol"],
                "expected_registration": fx_s1["_alice_reg"], "kind": "manifest", "label": "man-coll-owner",
                "manifests": {man_coll_own_h: man_coll_own}, "name": "id/alice",
                "want_refusal": "NAME_VALUE_INVALID", "want_verdict": "REFUSE",
            }],
        },
        "ADMIT",
        None,
        "D14-H04 / SL-IDEN-003: resolve_manifest MUST refuse NAME_VALUE_INVALID when manifest.role_policies reuses owner_policy pubkey.",
    )

    # 1.7 D14-M03 / D14-B09 (kills L2162 idx_o > 0 & L2189 int(uh_conf) <= at_height!)
    # (a) OP_NAME_FIRSTUPDATE (idx_o == 0) commits link.origin, followed by a non-owner-authored update (different owner_policy!).
    # If idx_o > 0 mutates to >= 0, updates[0 - 1] wraps to updates[-1] (different owner!) and falsely drops link.origin!
    ch_idx0 = copy.deepcopy(fx_s1["chain"])
    o0_k = _kp("s1-idx0-own")
    o0_pol = {"kind": "key", "pk": o0_k["comp"]}
    o0_other_pol = {"kind": "key", "pk": _kp("s1-idx0-other")["comp"]}
    o0_reg = {"txid": _h32("s1-idx0-reg"), "vout": 0}
    o0_gr = _kp("s1-idx0-gr")
    ch_idx0["names"]["id/idx0-test"] = sv.make_name_history(
        "id/idx0-test", o0_reg, o0_pol,
        {"link": {"grant": o0_gr["xonly"], "origin": _h32("s1-real-oid")}},
        first_height=748000, update_height=749000,
        extra_updates=[{
            "confirmed_height": 749500, "owner_policy": o0_other_pol, "sighash_bytes": [0x81],
            "txid": _h32("s1-idx0-nonauth"), "value": {"link": {"grant": o0_gr["xonly"], "origin": _h32("s1-fake-oid")}},
        }],
    )
    # Keep idx_o==0 carrying link.origin, idx_o==1 non-owner-authored with fake origin, and idx_o==2 owner-authored by o0_other_pol WITHOUT link.origin!
    # So require_writer=True passes, non-owner fake origin is ignored, AND updates[0-1]==updates[-1] has o0_other_pol != o0_pol (killing idx_o > 0 -> >= 0)!
    u0_idx0 = ch_idx0["names"]["id/idx0-test"]["updates"][0]
    u1_nonauth = {
        **ch_idx0["names"]["id/idx0-test"]["updates"][2],
        "prev_input": {"sighash_bytes": [0x81], "txid": o0_reg["txid"], "vout": 0, "witness_policy": o0_other_pol},
    }
    u2_clean = bd13._mk_upd(
        "id/idx0-test", o0_other_pol, sl.jcs_encode({"link": {"grant": o0_gr["xonly"]}}),
        _h32("s1-idx0-u2-clean"), 749600, u1_nonauth["txid"], o0_other_pol, prev_vout=0,
    )
    ch_idx0["names"]["id/idx0-test"]["updates"] = [u0_idx0, u1_nonauth, u2_clean]
    st_idx0 = sl.sign_envelope({
        "body_sha256": _h32("s1-idx0-sb"), "genesis": GENESIS_MAIN,
        "issuer": {"name": "id/idx0-test", "owner_policy": o0_other_pol, "registration": o0_reg},
        "network": "main", "not_after": now_s1 + 600, "not_before": now_s1, "seq": 1,
        "statement_kind": "profile-section", "subject": {"section_kind": "org.seallink.profile/bio"},
        "type": "seallink-statement/1",
    }, [o0_gr["sk"]])
    # Missing origin_bundle MUST refuse ORIGIN_UNVERIFIED (proves idx_o == 0 real origin WAS detected, AND non-owner fake origin was ignored!)
    add(
        "d14-m03-firstupdate-origin-detected-nonauth-ignored",
        ["SL-ORIG-002", "SL-LDGR-010"],
        "statement",
        {"chain": ch_idx0, "statement": st_idx0},
        "REFUSE",
        "ORIGIN_UNVERIFIED",
        "D14-M03: OP_NAME_FIRSTUPDATE (idx_o==0) link.origin is always recorded while non-owner-authored follow-up link.origin is ignored.",
    )
    # (b) frame_bad (2 SLNK OP_RETURNs in one owner-authored update at h=750000): at_height=749999 ADMIT vs at_height=750000 CHAIN_FRAME_INVALID (kills L2189 <= -> <!)
    fb_k = _kp("s1-fb-own")
    fb_cr = _kp("s1-fb-cred")
    fb_pol = {"kind": "key", "pk": fb_k["comp"]}
    fb_reg = {"txid": _h32("s1-fb-reg"), "vout": 0}
    fb_val = {"link": {"cred": fb_cr["xonly"]}}
    fb_cred_p = {
        "claims": {"ok": True}, "credential_kind": "org.seallink.test/d14", "genesis": GENESIS_MAIN,
        "issued_at": 1795219000,
        "issuer": {"name": "id/fb-iss", "owner_policy": fb_pol, "registration": fb_reg, "role_policy": {"m": 1, "pks": [fb_cr["xonly"]]}},
        "lifecycle": "eternal", "network": "main", "not_before_height": 749500,
        "subject": {"key": _kp("s1-fb-subj")["xonly"], "mode": "key"}, "type": "seallink-credential/1",
    }
    fb_cred_env = sl.sign_envelope(fb_cred_p, [fb_cr["sk"]])
    fb_atx_before = _h32("s1-fb-atx-749999")
    fb_atx_exact = _h32("s1-fb-atx-750000")
    ch_fb = copy.deepcopy(fx_s1["chain"])
    u_fb_bad = {
        "confirmed_height": 750000,
        "sighash_bytes": [0x01], "txid": _h32("s1-fb-u-750000"), "value": fb_val,
    }
    ch_fb["names"]["id/fb-iss"] = sv.make_name_history(
        "id/fb-iss", fb_reg, fb_pol, fb_val, first_height=748000, update_height=749000, extra_updates=[u_fb_bad],
    )
    ch_fb["names"]["id/fb-iss"]["updates"][-1]["opreturns"] = [
        {"script_pubkey_hex": sl.encode_opreturn(0x10, _h32("fb-1")).hex(), "value_sat": 0, "vout": 1},
        {"script_pubkey_hex": sl.encode_opreturn(0x10, _h32("fb-2")).hex(), "value_sat": 0, "vout": 2},
    ]
    ch_fb["txs"][fb_atx_before] = {"confirmed_height": 749999, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(fb_cred_env)).hex(), "outputs": {}}
    ch_fb["txs"][fb_atx_exact] = {"confirmed_height": 750000, "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(fb_cred_env)).hex(), "outputs": {}}
    add(
        "d14-b09-frame-bad-forward-only-before-h-admit",
        ["SL-LDGR-010"],
        "credential",
        {"anchor_txid": fb_atx_before, "chain": ch_fb, "credential": fb_cred_env},
        "ADMIT",
        None,
        "D14-B09: Duplicate SLNK frame (frame_bad) at h=750000 is strictly forward-only and preserves historical eternal credential at h=749999.",
    )
    add(
        "d14-b09-frame-bad-forward-only-at-exact-h-refuse",
        ["SL-LDGR-010"],
        "credential",
        {"anchor_txid": fb_atx_exact, "chain": ch_fb, "credential": fb_cred_env},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B09: Duplicate SLNK frame (frame_bad) at exact h=750000 == at_height MUST refuse CHAIN_FRAME_INVALID.",
    )

    # ========================================================================
    # SECTION 2: FencedJournal Per-Set Rollback, Durable Closures, Auth, Cmd & Statement
    # ========================================================================
    fx_s2 = rm._base_invocation_fixture()
    now_s2 = fx_s2["chain"]["now"]
    d_l0 = _kp("s2-dev-l0")
    d_l1 = _kp("s2-dev-l1")
    d_l2_np = _kp("s2-dev-l2-nopres")
    d_l2_ok = _kp("s2-dev-l2-ok")
    d_p256_sk = sl.deterministic_p256_privkey("s2-dev-p256")
    d_p256_pk = sl.p256_compressed_pubkey(d_p256_sk)
    s2_seal_pol = {"kind": "key", "pk": _kp("s2-dseal")["comp"]}
    s2_seal_tx = _h32("s2-dseal-tx")
    s2_seal_sp_tx = _h32("s2-dseal-sp-tx")
    s2_st_seal_tx = _h32("s2-st-seal-tx")
    fx_s2["chain"]["txs"][s2_seal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(s2_seal_pol)}}}
    fx_s2["chain"]["txs"][s2_seal_sp_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(s2_seal_pol), "spent_by_txid": _h32("s2-dseal-spend")}}}
    fx_s2["chain"]["txs"][_h32("s2-dseal-spend")] = {"confirmed_height": 749950, "inputs": [sv.make_segwit_input(s2_seal_sp_tx, 0)], "outputs": {}}
    fx_s2["chain"]["txs"][s2_st_seal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(s2_seal_pol), "spent_by_txid": _h32("s2-st-spend")}}}
    fx_s2["chain"]["txs"][_h32("s2-st-spend")] = {"confirmed_height": 749955, "inputs": [sv.make_segwit_input(s2_st_seal_tx, 0)], "outputs": {}}

    dh_s2, dps_s2 = rm.make_salted_device_set(
        "id/alice",
        [
            {"alg": "bip340", "ceiling": 0, "key": d_l0["xonly"], "label": "l0", "presence": False, "seal": {"script_policy": s2_seal_pol, "txid": s2_seal_tx, "vout": 0}},
            {"alg": "bip340", "ceiling": 1, "key": d_l1["xonly"], "label": "l1", "presence": False, "seal": {"script_policy": s2_seal_pol, "txid": s2_seal_tx, "vout": 0}},
            {"alg": "bip340", "ceiling": 2, "key": d_l2_np["xonly"], "label": "l2-np", "presence": False, "seal": {"script_policy": s2_seal_pol, "txid": s2_seal_tx, "vout": 0}},
            {"alg": "bip340", "ceiling": 2, "key": d_l2_ok["xonly"], "label": "l2-ok", "presence": True, "seal": {"script_policy": s2_seal_pol, "txid": s2_seal_tx, "vout": 0}},
            {"alg": "bip340", "ceiling": 2, "key": _kp("s2-dev-rev")["xonly"], "label": "l2-rev", "presence": True, "seal": {"script_policy": s2_seal_pol, "txid": s2_seal_sp_tx, "vout": 0}},
        ],
        seq=2,
    )
    dh_s2_alt, _ = rm.make_salted_device_set(
        "id/alice",
        [{"alg": "bip340", "ceiling": 2, "key": d_l2_ok["xonly"], "label": "l2-alt", "presence": True, "seal": {"script_policy": s2_seal_pol, "txid": s2_seal_tx, "vout": 0}}],
        seq=2,
    )
    dh_s2_seq1, _ = rm.make_salted_device_set(
        "id/alice",
        [{"alg": "bip340", "ceiling": 2, "key": d_l2_ok["xonly"], "label": "l2-s1", "presence": True, "seal": {"script_policy": s2_seal_pol, "txid": s2_seal_tx, "vout": 0}}],
        seq=1,
    )
    dh_s2_seq3, _ = rm.make_salted_device_set(
        "id/alice",
        [{"alg": "bip340", "ceiling": 2, "key": d_l2_ok["xonly"], "label": "l2-s3", "presence": True, "seal": {"script_policy": s2_seal_pol, "txid": s2_seal_tx, "vout": 0}}],
        seq=3,
    )
    ah_s2, aps_s2 = rm.make_salted_auth_set(
        "id/alice",
        [{"alg": "bip340", "key": _kp("s2-auth-1")["xonly"], "label": "a1", "seal": {"script_policy": s2_seal_pol, "txid": s2_seal_tx, "vout": 0}}],
        seq=1,
    )
    man_s2 = rm.bind_sets_manifest(
        fx_s2["chain"], "id/alice", fx_s2["_alice_owner_pol"], fx_s2["_alice_reg"],
        auth_head=ah_s2, device_head=dh_s2, seq=1, extra_link={"grant": fx_s2["_keys"]["alice_gr"]["xonly"]},
    )
    man_s2_h = sl.content_addr(man_s2)

    # 2.1 SL-IDEN-008 per-set monotonic sequence & removed_sets non-resurrection across replay_restart (kills L2722, L2723, L2725, L2726!)
    man_p1 = copy.deepcopy(man_s2)  # seq=1, devices seq=2 hash=H_A
    man_p2_same = {**copy.deepcopy(man_s2), "seq": 2}  # seq=2, devices seq=2 hash=H_A (same -> ADMIT! kills L2722 < -> <=!)
    man_p3_low = {**copy.deepcopy(man_s2), "seq": 3, "sets": {"devices": {"seq": 1, "sha256": sl.content_addr(dh_s2_seq1)}}}  # devices seq=1 < 2 -> ROLLBACK (kills L2723!)
    man_p3_diff = {**copy.deepcopy(man_s2), "seq": 3, "sets": {"devices": {"seq": 2, "sha256": sl.content_addr(dh_s2_alt)}}}  # devices seq=2 diff hash -> ROLLBACK
    man_p3_rem = {"network": "main", "owner": "id/alice", "seq": 3, "type": "seallink-manifest/1"}  # removes devices (rem_seq=2!)
    man_p4_res_eq = {**copy.deepcopy(man_s2), "seq": 4, "sets": {"devices": {"seq": 2, "sha256": sl.content_addr(dh_s2_alt)}}}  # reintroduces at seq==2 == rem_seq -> ROLLBACK (kills L2725 <= -> < & L2726!)
    man_p4_res_ok = {**copy.deepcopy(man_s2), "seq": 4, "sets": {"devices": {"seq": 3, "sha256": sl.content_addr(dh_s2_seq3)}}}  # reintroduces at seq==3 > rem_seq -> ADMIT!

    mh_p1 = sl.content_addr(man_p1)
    mh_p2 = sl.content_addr(man_p2_same)
    mh_p3l = sl.content_addr(man_p3_low)
    mh_p3d = sl.content_addr(man_p3_diff)
    mh_p3r = sl.content_addr(man_p3_rem)
    mh_p4e = sl.content_addr(man_p4_res_eq)
    mh_p4o = sl.content_addr(man_p4_res_ok)

    def _ch_man_chain(extras: list[tuple[str, int, str]]) -> dict[str, Any]:
        ch_m = copy.deepcopy(fx_s2["chain"])
        ch_m["names"]["id/alice"] = sv.make_name_history(
            "id/alice", fx_s2["_alice_reg"], fx_s2["_alice_owner_pol"],
            {"link": {"grant": fx_s2["_keys"]["alice_gr"]["xonly"]}, "m": {"h": mh_p1, "s": 1}},
            first_height=748000, update_height=749001,
            extra_updates=[
                {"confirmed_height": 749001 + i + 1, "txid": _h32(f"s2-mh-{tag}"), "value": {"link": {"grant": fx_s2["_keys"]["alice_gr"]["xonly"]}, "m": {"h": mh_v, "s": s_v}}}
                for i, (tag, s_v, mh_v) in enumerate(extras)
            ],
        )
        return ch_m

    ch_p1 = _ch_man_chain([])
    ch_p2 = _ch_man_chain([("p2", 2, mh_p2)])
    ch_p3l = _ch_man_chain([("p2", 2, mh_p2), ("p3l", 3, mh_p3l)])
    ch_p3d = _ch_man_chain([("p2", 2, mh_p2), ("p3d", 3, mh_p3d)])
    ch_p3r = _ch_man_chain([("p2", 2, mh_p2), ("p3r", 3, mh_p3r)])
    ch_p4e = _ch_man_chain([("p2", 2, mh_p2), ("p3r", 3, mh_p3r), ("p4e", 4, mh_p4e)])
    ch_p4o = _ch_man_chain([("p2", 2, mh_p2), ("p3r", 3, mh_p3r), ("p4o", 4, mh_p4o)])
    add(
        "d14-b11-manifest-per-set-rollback-and-removed-sets-replay",
        ["SL-IDEN-008"],
        "multi_step_journal",
        {
            "journal": {"journal_id": _h32("s2-perset-j")},
            "steps": [
                {"chain": ch_p1, "expected_owner_policy": fx_s2["_alice_owner_pol"], "expected_registration": fx_s2["_alice_reg"], "kind": "manifest", "label": "p1-admit", "manifests": {mh_p1: man_p1}, "name": "id/alice", "want_refusal": None, "want_verdict": "ADMIT"},
                {"kind": "replay_restart", "label": "restart-1"},
                {"chain": ch_p2, "expected_owner_policy": fx_s2["_alice_owner_pol"], "expected_registration": fx_s2["_alice_reg"], "kind": "manifest", "label": "p2-same-set-seq-admit", "manifests": {mh_p2: man_p2_same}, "name": "id/alice", "want_refusal": None, "want_verdict": "ADMIT"},
                {"chain": ch_p3l, "expected_owner_policy": fx_s2["_alice_owner_pol"], "expected_registration": fx_s2["_alice_reg"], "kind": "manifest", "label": "p3-set-seq-rollback", "manifests": {mh_p3l: man_p3_low}, "name": "id/alice", "want_refusal": "MANIFEST_ROLLBACK", "want_verdict": "REFUSE"},
                {"chain": ch_p3d, "expected_owner_policy": fx_s2["_alice_owner_pol"], "expected_registration": fx_s2["_alice_reg"], "kind": "manifest", "label": "p3-set-same-seq-diff-hash", "manifests": {mh_p3d: man_p3_diff}, "name": "id/alice", "want_refusal": "MANIFEST_ROLLBACK", "want_verdict": "REFUSE"},
                {"chain": ch_p3r, "expected_owner_policy": fx_s2["_alice_owner_pol"], "expected_registration": fx_s2["_alice_reg"], "kind": "manifest", "label": "p3-remove-devices", "manifests": {mh_p3r: man_p3_rem}, "name": "id/alice", "want_refusal": None, "want_verdict": "ADMIT"},
                {"kind": "replay_restart", "label": "restart-2"},
                {"chain": ch_p4e, "expected_owner_policy": fx_s2["_alice_owner_pol"], "expected_registration": fx_s2["_alice_reg"], "kind": "manifest", "label": "p4-resurrect-at-rem-seq-refuse", "manifests": {mh_p4e: man_p4_res_eq}, "name": "id/alice", "want_refusal": "MANIFEST_ROLLBACK", "want_verdict": "REFUSE"},
                {"chain": ch_p4o, "expected_owner_policy": fx_s2["_alice_owner_pol"], "expected_registration": fx_s2["_alice_reg"], "kind": "manifest", "label": "p4-reintroduce-gt-rem-seq-admit", "manifests": {mh_p4o: man_p4_res_ok}, "name": "id/alice", "want_refusal": None, "want_verdict": "ADMIT"},
            ],
        },
        "ADMIT",
        None,
        "D14-B11 / SL-IDEN-008: Per-set monotonic seq and removed_sets non-resurrection persist across replay_restart.",
    )

    # 2.2 Durable SEAL_SPENT closure on sets.devices surviving mempool eviction (kills L2659!)
    d_rev_k = _kp("s2-dev-rev")
    oc_rev = sl.sign_envelope({
        "arguments": {"scope": "all"}, "command": "keyholder-halt", "exp": now_s2 + 300,
        "genesis": GENESIS_MAIN, "iat": now_s2, "level": 2, "network": "main",
        "nonce": _h32("s2-oc-rev-1"), "owner": "id/alice", "target_executor": "id/station-a",
        "type": "seallink-owner-command/1",
    }, [d_rev_k["sk"]])
    ch_s2_evicted = copy.deepcopy(fx_s2["chain"])
    ch_s2_evicted["txs"][s2_seal_sp_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(s2_seal_pol)}}}
    add(
        "d14-b11-salted-device-seal-closure-survives-eviction",
        ["SL-IDEN-011", "SL-LDGR-011"],
        "multi_step_journal",
        {
            "journal": {"journal_id": _h32("s2-dseal-cl-j")},
            "steps": [
                {"chain": fx_s2["chain"], "command": oc_rev, "device_proof": dps_s2[4], "expect_closures_delta": 1, "is_foreign_service": False, "kind": "owner_command", "label": "observe-spent-seal", "owner_manifest": man_s2, "want_refusal": "SEAL_SPENT", "want_verdict": "REFUSE"},
                {"kind": "replay_restart", "label": "restart-after-seal-closure"},
                {"chain": ch_s2_evicted, "command": oc_rev, "device_proof": dps_s2[4], "expect_closures_delta": 0, "is_foreign_service": False, "kind": "owner_command", "label": "evicted-still-refuses-seal-spent", "owner_manifest": man_s2, "want_refusal": "SEAL_SPENT", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "D14-B11: Durable SEAL_SPENT closure on salted sets.devices entry persists across restart and mempool eviction.",
    )

    # 2.3 auth_upgrade OP_NAME_FIRSTUPDATE depth >= operator_min_depth (kills L2957 & L2958!) + TTL > 120 + durable nonce replay
    a2_k = _kp("s2-auth-1")
    au_p = {
        "account_id": "acct-d14-1", "audience": "https://app.example.org/oidc", "auth_alg": "bip340",
        "auth_pubkey": a2_k["xonly"], "channel_binding": _h32("s2-au-cb"),
        "expires_at": now_s2 + 60, "firstupdate_txid": fx_s2["_alice_reg"]["txid"], "genesis": GENESIS_MAIN,
        "issued_at": now_s2, "name": "id/alice", "network": "main", "nonce": _h32("s2-au-n1"),
        "service_id": "sso.example.org", "type": "seallink-auth-upgrade/1",
    }
    au_env = sl.sign_envelope(au_p, [a2_k["sk"]])
    # Make FIRSTUPDATE height = tip_height - 4 (depth 5 < operator_min_depth=6 -> REFUSE) vs tip_height - 5 (depth 6 == 6 -> ADMIT!)
    ch_au_d5 = copy.deepcopy(fx_s2["chain"])
    ch_au_d5["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx_s2["_alice_reg"], fx_s2["_alice_owner_pol"],
        {"link": {"grant": fx_s2["_keys"]["alice_gr"]["xonly"]}, "m": {"h": man_s2_h, "s": 1}},
        first_height=ch_au_d5["tip_height"] - 4, update_height=ch_au_d5["tip_height"] - 2,
    )
    ch_au_d6 = copy.deepcopy(fx_s2["chain"])
    ch_au_d6["names"]["id/alice"] = sv.make_name_history(
        "id/alice", fx_s2["_alice_reg"], fx_s2["_alice_owner_pol"],
        {"link": {"grant": fx_s2["_keys"]["alice_gr"]["xonly"]}, "m": {"h": man_s2_h, "s": 1}},
        first_height=ch_au_d6["tip_height"] - 5, update_height=ch_au_d6["tip_height"] - 2,
    )
    add(
        "d14-b11-auth-upgrade-firstupdate-depth-insufficient-refuse",
        ["SL-IDEN-010"],
        "auth_upgrade",
        {
            "auth_proof": aps_s2[0], "chain": ch_au_d5, "expected_account_id": "acct-d14-1",
            "expected_audience": "https://app.example.org/oidc", "expected_channel_binding": _h32("s2-au-cb"),
            "expected_provisional_auth_pubkey": a2_k["xonly"], "expected_service_id": "sso.example.org",
            "manifests": {man_s2_h: man_s2}, "operator_min_depth": 6, "upgrade": au_env,
        },
        "REFUSE",
        "CHAIN_DEPTH_INSUFFICIENT",
        "D14-B11: auth_upgrade with OP_NAME_FIRSTUPDATE depth 5 < operator_min_depth 6 MUST refuse CHAIN_DEPTH_INSUFFICIENT.",
    )
    add(
        "d14-b11-auth-upgrade-firstupdate-exact-depth-and-nonce-replay",
        ["SL-IDEN-010"],
        "multi_step_journal",
        {
            "journal": {"journal_id": _h32("s2-au-j")},
            "operator_min_depth": 6,
            "steps": [
                {
                    "auth_proof": aps_s2[0], "chain": ch_au_d6, "expect_entries_delta": 1,
                    "expected_account_id": "acct-d14-1", "expected_audience": "https://app.example.org/oidc",
                    "expected_channel_binding": _h32("s2-au-cb"), "expected_provisional_auth_pubkey": a2_k["xonly"],
                    "expected_service_id": "sso.example.org", "kind": "auth_upgrade", "label": "au-exact-depth-6-admit",
                    "manifests": {man_s2_h: man_s2}, "upgrade": au_env, "want_refusal": None, "want_verdict": "ADMIT",
                },
                {"kind": "replay_restart", "label": "au-restart"},
                {
                    "auth_proof": aps_s2[0], "chain": ch_au_d6, "expect_entries_delta": 0,
                    "expected_account_id": "acct-d14-1", "expected_audience": "https://app.example.org/oidc",
                    "expected_channel_binding": _h32("s2-au-cb"), "expected_provisional_auth_pubkey": a2_k["xonly"],
                    "expected_service_id": "sso.example.org", "kind": "auth_upgrade", "label": "au-nonce-replay-refuse",
                    "manifests": {man_s2_h: man_s2}, "upgrade": au_env, "want_refusal": "AUTH_CHALLENGE_INVALID", "want_verdict": "REFUSE",
                },
            ],
        },
        "ADMIT",
        None,
        "D14-B11: auth_upgrade at exact OP_NAME_FIRSTUPDATE depth == operator_min_depth (6 == 6) admits, persists nonce across restart, and refuses replay with INVOKE_REPLAY.",
    )
    au_ttl_bad = sl.sign_envelope({**au_p, "expires_at": now_s2 + 121, "nonce": _h32("s2-au-ttl")}, [a2_k["sk"]])
    add(
        "d14-b11-auth-upgrade-ttl-over-120s-refuse",
        ["SL-IDEN-010"],
        "auth_upgrade",
        {
            "auth_proof": aps_s2[0], "chain": ch_au_d6, "expected_account_id": "acct-d14-1",
            "expected_audience": "https://app.example.org/oidc", "expected_channel_binding": _h32("s2-au-cb"),
            "expected_provisional_auth_pubkey": a2_k["xonly"],
            "expected_service_id": "sso.example.org", "manifests": {man_s2_h: man_s2}, "upgrade": au_ttl_bad,
        },
        "REFUSE",
        "AUTH_CHALLENGE_EXPIRED",
        "D14-B11: auth_upgrade with TTL 121s > 120s MUST refuse AUTH_CHALLENGE_EXPIRED.",
    )

    # 2.4 owner_command expected_target_executor mismatch (kills L3035!) + durable nonce replay across replay_restart (kills L3044!) + L2 presence on all commands
    oc_ok = sl.sign_envelope({
        "arguments": {"scope": "all"}, "command": "keyholder-halt", "exp": now_s2 + 300,
        "genesis": GENESIS_MAIN, "iat": now_s2, "level": 2, "network": "main",
        "nonce": _h32("s2-oc-n1"), "owner": "id/alice", "target_executor": "id/station-a",
        "type": "seallink-owner-command/1",
    }, [d_l2_ok["sk"]])
    add(
        "d14-b11-owner-command-wrong-target-executor-refuse",
        ["SL-IDEN-011"],
        "owner_command",
        {"chain": fx_s2["chain"], "command": oc_ok, "device_proof": dps_s2[3], "expected_target_executor": "id/station-other", "is_foreign_service": False, "owner_manifest": man_s2},
        "REFUSE",
        "DEVICE_UNAUTHORIZED",
        "D14-B11: owner_command with target_executor != expected_target_executor MUST refuse DEVICE_UNAUTHORIZED.",
    )
    oc_l2_np = sl.sign_envelope({**oc_ok["payload"], "nonce": _h32("s2-oc-np")}, [d_l2_np["sk"]])
    add(
        "d14-b11-owner-command-l2-missing-presence-refuse",
        ["SL-IDEN-011"],
        "owner_command",
        {"chain": fx_s2["chain"], "command": oc_l2_np, "device_proof": dps_s2[2], "expected_target_executor": "id/station-a", "is_foreign_service": False, "owner_manifest": man_s2},
        "REFUSE",
        "DEVICE_UNAUTHORIZED",
        "D14-B11: Level-2 owner_command signed by device with presence=False MUST refuse DEVICE_UNAUTHORIZED.",
    )
    add(
        "d14-b11-owner-command-durable-nonce-replay-across-restart",
        ["SL-IDEN-011"],
        "multi_step_journal",
        {
            "journal": {"journal_id": _h32("s2-oc-rep-j")},
            "steps": [
                {"chain": fx_s2["chain"], "command": oc_ok, "device_proof": dps_s2[3], "expect_entries_delta": 1, "expected_target_executor": "id/station-a", "is_foreign_service": False, "kind": "owner_command", "label": "oc-first-admit", "owner_manifest": man_s2, "want_refusal": None, "want_verdict": "ADMIT"},
                {"kind": "replay_restart", "label": "oc-restart"},
                {"chain": fx_s2["chain"], "command": oc_ok, "device_proof": dps_s2[3], "expect_entries_delta": 0, "expected_target_executor": "id/station-a", "is_foreign_service": False, "kind": "owner_command", "label": "oc-replay-refuse", "owner_manifest": man_s2, "want_refusal": "INVOKE_REPLAY", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "D14-B11: owner_command durably records nonce in FencedJournal and refuses replay with INVOKE_REPLAY across replay_restart.",
    )

    # 2.5 D14-B05: cert_entry_proof issuer mismatch & private statement with locators -> WIRE_MEMBER
    st_bob = sl.sign_envelope({
        "body_sha256": _h32("s2-cs-bob"), "genesis": GENESIS_MAIN,
        "issuer": {"name": "id/bob", "owner_policy": fx_s2["_alice_owner_pol"], "registration": fx_s2["_alice_reg"]},
        "network": "main", "not_after": now_s2 + 600, "not_before": now_s2, "seq": 1,
        "statement_kind": "profile-section", "subject": {"section_kind": "org.seallink.profile/bio"},
        "type": "seallink-statement/1",
    }, [fx_s2["_keys"]["alice_gr"]["sk"]])
    cs_head_bad, cs_proofs_bad = rm.make_salted_cert_set("id/alice", [st_bob])
    man_cs_bad = {**copy.deepcopy(man_s2), "sets": {"certs": {"seq": 1, "sha256": sl.content_addr(cs_head_bad)}}}
    add(
        "d14-b05-certset-head-issuer-mismatch-refuse",
        ["SL-IDEN-005"],
        "cert_entry_proof",
        {"cert_proof": cs_proofs_bad[0], "owner_manifest": man_cs_bad, "statement": st_bob},
        "REFUSE",
        "MANIFEST_MISMATCH",
        "D14-B05: verify_cert_entry_proof MUST refuse MANIFEST_MISMATCH when a statement's issuer.name disagrees with head.owner.",
    )
    st_priv_loc = sl.sign_envelope({
        "body_sha256": _h32("s2-priv-loc"), "genesis": GENESIS_MAIN,
        "issuer": {"name": "id/alice", "owner_policy": fx_s2["_alice_owner_pol"], "registration": fx_s2["_alice_reg"]},
        "locators": ["https://cdn.example.org/leak.bin"], "network": "main",
        "not_after": now_s2 + 600, "not_before": now_s2, "seq": 1,
        "statement_kind": "profile-section", "subject": {"section_kind": "org.seallink.profile/bio"},
        "type": "seallink-statement/1", "visibility": "private",
    }, [fx_s2["_keys"]["alice_gr"]["sk"]])
    add(
        "d14-b05-private-statement-with-locators-refuse",
        ["SL-WIRE-010"],
        "raw_wire",
        {"expected_type": "seallink-statement/1", "object": st_priv_loc},
        "REFUSE",
        "WIRE_MEMBER",
        "D14-B05: seallink-statement/1 with visibility='private' MUST forbid public locators[] (WIRE_MEMBER).",
    )

    # 2.6 D14-B06: verify_statement full statement_kind / ceiling / presence / alg / receipt_key / durable seal matrix
    # (kills L7985, L8019, L8020, L8021, L8025, L8040!)
    st_base_iss = {"name": "id/alice", "owner_policy": fx_s2["_alice_owner_pol"], "registration": fx_s2["_alice_reg"]}
    st_root_rot = sl.sign_envelope({
        "genesis": GENESIS_MAIN, "issuer": st_base_iss, "network": "main",
        "not_after": now_s2 + 600, "not_before": now_s2, "seq": 1, "statement_kind": "root-rotate",
        "subject": {"host_id": "id/station-a", "new_role_policy": {"m": 1, "pks": [_kp("s2-nr-k")["xonly"]]}}, "type": "seallink-statement/1",
    }, [d_l2_ok["sk"]])
    add(
        "d14-b06-statement-privileged-root-rotate-device-refuse",
        ["SL-IDEN-011"],
        "statement",
        {"chain": fx_s2["chain"], "device_proof": dps_s2[3], "owner_manifest": man_s2, "statement": st_root_rot},
        "REFUSE",
        "DEVICE_UNAUTHORIZED",
        "D14-B06: Privileged statement_kind='root-rotate' MUST refuse device-key authorization (DEVICE_UNAUTHORIZED).",
    )
    st_cfg_p = {
        "body_sha256": _h32("s2-cfg"), "genesis": GENESIS_MAIN, "issuer": st_base_iss, "network": "main",
        "not_after": now_s2 + 600, "not_before": now_s2, "seq": 1, "statement_kind": "config-section",
        "subject": {"host_id": "id/station-a", "section": "net"}, "type": "seallink-statement/1",
    }
    add(
        "d14-b06-statement-config-section-foreign-service-refuse",
        ["SL-IDEN-011"],
        "statement",
        {"chain": fx_s2["chain"], "device_proof": dps_s2[3], "is_foreign_service": True, "owner_manifest": man_s2, "statement": sl.sign_envelope(st_cfg_p, [d_l2_ok["sk"]])},
        "REFUSE",
        "DEVICE_UNAUTHORIZED",
        "D14-B06: Device-signed config-section statement MUST be refused by foreign services (is_foreign_service=True).",
    )
    add(
        "d14-b06-statement-config-section-l1-ceiling-refuse",
        ["SL-IDEN-011"],
        "statement",
        {"chain": fx_s2["chain"], "device_proof": dps_s2[1], "owner_manifest": man_s2, "statement": sl.sign_envelope(st_cfg_p, [d_l1["sk"]])},
        "REFUSE",
        "DEVICE_UNAUTHORIZED",
        "D14-B06: config-section statement signed by L1 device (ceiling < 2) MUST refuse DEVICE_UNAUTHORIZED.",
    )
    add(
        "d14-b06-statement-config-section-l2-presence-admit",
        ["SL-IDEN-011"],
        "statement",
        {"chain": fx_s2["chain"], "device_proof": dps_s2[3], "owner_manifest": man_s2, "statement": sl.sign_envelope(st_cfg_p, [d_l2_ok["sk"]])},
        "ADMIT",
        None,
        "D14-B06: config-section statement signed by L2 presence=True device on owner's own host admits.",
    )
    st_prof_p = {
        "body_sha256": _h32("s2-prof"), "genesis": GENESIS_MAIN, "issuer": st_base_iss, "network": "main",
        "not_after": now_s2 + 600, "not_before": now_s2, "seq": 1, "statement_kind": "profile-section",
        "subject": {"section_kind": "org.seallink.profile/bio"}, "type": "seallink-statement/1",
    }
    add(
        "d14-b06-statement-profile-l0-escalation-refuse",
        ["SL-IDEN-011"],
        "statement",
        {"chain": fx_s2["chain"], "device_proof": dps_s2[0], "owner_manifest": man_s2, "statement": sl.sign_envelope(st_prof_p, [d_l0["sk"]])},
        "REFUSE",
        "DEVICE_UNAUTHORIZED",
        "D14-B06: Read-only L0 device (ceiling == 0) MUST NOT sign profile-section statements (DEVICE_UNAUTHORIZED).",
    )
    add(
        "d14-b06-statement-profile-l1-exact-ceiling-admit",
        ["SL-IDEN-011"],
        "statement",
        {"chain": fx_s2["chain"], "device_proof": dps_s2[1], "owner_manifest": man_s2, "statement": sl.sign_envelope(st_prof_p, [d_l1["sk"]])},
        "ADMIT",
        None,
        "D14-B06: L1 device (exact ceiling == 1) admits on profile-section statement.",
    )
    add(
        "d14-b06-statement-non-device-p256-alg-bypass-refuse",
        ["SL-IDEN-011"],
        "statement",
        {"chain": fx_s2["chain"], "statement": sl.sign_envelope(st_prof_p, [d_p256_sk], alg="p256")},
        "REFUSE",
        "DEVICE_UNAUTHORIZED",
        "D14-B06: Statement omitting device_proof yet carrying non-BIP-340 device alg ('p256') MUST refuse DEVICE_UNAUTHORIZED.",
    )
    st_with_seal = sl.sign_envelope({
        **st_prof_p, "seal": {"script_policy": s2_seal_pol, "txid": s2_st_seal_tx, "vout": 0},
    }, [fx_s2["_keys"]["alice_gr"]["sk"]])
    ch_s2_st_evict = copy.deepcopy(fx_s2["chain"])
    ch_s2_st_evict["txs"][s2_st_seal_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(s2_seal_pol)}}}
    add(
        "d14-b11-statement-seal-closure-survives-eviction",
        ["SL-LDGR-011"],
        "multi_step_journal",
        {
            "journal": {"journal_id": _h32("s2-stseal-j")},
            "steps": [
                {"chain": fx_s2["chain"], "expect_closures_delta": 1, "kind": "statement", "label": "st-seal-spent", "statement": st_with_seal, "want_refusal": "SEAL_SPENT", "want_verdict": "REFUSE"},
                {"kind": "replay_restart", "label": "st-seal-restart"},
                {"chain": ch_s2_st_evict, "expect_closures_delta": 0, "kind": "statement", "label": "st-seal-evicted-still-closed", "statement": st_with_seal, "want_refusal": "SEAL_SPENT", "want_verdict": "REFUSE"},
            ],
        },
        "ADMIT",
        None,
        "D14-B11: Durable SEAL_SPENT closure on seallink-statement/1 optional seal persists across restart and mempool eviction.",
    )

    # ========================================================================
    # SECTION 3: Origin, 0x0c Recovery, 0x13 Rebind, Ward Assent, Termination & Slot Re-appointment
    # ========================================================================
    # 3.1 Profile W P2WPKH 2-element witness non-SIGHASH_ALL DER violation (kills L3332 >= 2 -> > 2!)
    rb_pw = bd11._build_autonomous_origin_rebind_fixture("d14-pw-len2", h_act=None, tip_h=749900)
    b_pw_pol = {"kind": "key", "pk": _kp("s3-pw-new")["comp"]}
    b_pw = {
        "binding_mode": "recovery", "genesis": GENESIS_MAIN, "name": "id/d14-pw-rec", "network": "main",
        "next_recovery_policy": rb_pw["_rec_pol"], "next_recovery_vout": 0, "origin_id": rb_pw["_oid"],
        "owner_policy": b_pw_pol, "registration": {"txid": _h32("s3-pw-reg"), "vout": 0},
        "seq": 2, "supersedes_binding_id": rb_pw["_b1_id"], "type": "seallink-name-binding/1",
    }
    rtx_pw = _h32("s3-pw-rtx")
    rb_pw["chain"]["txs"][rb_pw["_rec_seal_tx"]]["outputs"]["0"]["spent_by_txid"] = rtx_pw
    rb_pw["chain"]["txs"][rtx_pw] = {
        "confirmed_height": 749610,
        "inputs": [sv.make_segwit_input(rb_pw["_rec_seal_tx"], 0, sighash=0x81)],  # exact len(wit)==2, sighash 0x81!
        "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(b_pw)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(rb_pw["_rec_pol"])}},
    }
    rb_pw["chain"]["names"]["id/d14-pw-rec"] = sv.make_name_history(
        "id/d14-pw-rec", b_pw["registration"], b_pw_pol, {"link": {"origin": rb_pw["_oid"]}},
        first_height=749600, update_height=749605,
    )
    rb_pw["origin_bundle"]["recovery_bindings"] = [b_pw]
    # Remove voluntary 0x13 so only 0x0c runs -> Profile W violation MUST burn recovery!
    rb_pw["chain"]["names"][rb_pw["_b1"]["name"]]["updates"] = rb_pw["chain"]["names"][rb_pw["_b1"]["name"]]["updates"][:2]
    rb_pw["origin_bundle"].pop("voluntary_rebind_bindings", None)
    add(
        "d14-b10-profile-w-p2wpkh-len2-non-sighash-all-burns-recovery",
        ["SL-ORIG-011", "SL-LDGR-008"],
        "origin_status",
        {
            "chain": rb_pw["chain"], "expect_active_name": rb_pw["_b1"]["name"],
            "expect_recovery_burned": True, "origin_bundle": rb_pw["origin_bundle"],
            "trusted_origin_issuer_pins": rb_pw["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "D14-B10: 0x0c spend from P2WPKH recovery_seal with len(witness)==2 non-SIGHASH_ALL (0x81) DER sig violates Profile W and sets recovery_burned.",
    )

    # 3.2 _try_open_0x0c: exact cfu_h == h_r ADMIT vs cfu_h == h_r + 1 burned (kills L4097 > -> >=!) + missing cand_nrec -> ORIGIN_STATUS_INCOMPLETE
    rb_0c_eq = copy.deepcopy(rb_pw)
    rb_0c_eq["chain"]["txs"][rtx_pw]["inputs"] = [sv.make_segwit_input(rb_0c_eq["_rec_seal_tx"], 0, sighash=0x01)]
    rb_0c_eq["chain"]["names"]["id/d14-pw-rec"] = sv.make_name_history(
        "id/d14-pw-rec", b_pw["registration"], b_pw_pol, {"link": {"origin": rb_0c_eq["_oid"]}},
        first_height=749610, update_height=749610,  # exact cfu_h == h_r == 749610!
    )
    add(
        "d14-b10-0x0c-candidate-firstupdate-exact-hr-admit",
        ["SL-ORIG-011"],
        "origin_status",
        {
            "chain": rb_0c_eq["chain"], "expect_active_name": "id/d14-pw-rec",
            "expect_recovery_burned": False, "origin_bundle": rb_0c_eq["origin_bundle"],
            "trusted_origin_issuer_pins": rb_0c_eq["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "D14-B10: 0x0c recovery candidate whose OP_NAME_FIRSTUPDATE is at exact height h_r admits cleanly.",
    )
    rb_0c_gt = copy.deepcopy(rb_0c_eq)
    rb_0c_gt["chain"]["names"]["id/d14-pw-rec"] = sv.make_name_history(
        "id/d14-pw-rec", b_pw["registration"], b_pw_pol, {"link": {"origin": rb_0c_gt["_oid"]}},
        first_height=749611, update_height=749611,  # cfu_h == h_r + 1 -> burned!
    )
    add(
        "d14-b10-0x0c-candidate-firstupdate-after-hr-burned",
        ["SL-ORIG-011"],
        "origin_status",
        {
            "chain": rb_0c_gt["chain"], "expect_active_name": rb_0c_gt["_b1"]["name"],
            "expect_recovery_burned": True, "origin_bundle": rb_0c_gt["origin_bundle"],
            "trusted_origin_issuer_pins": rb_0c_gt["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "D14-B10: 0x0c recovery candidate registered AFTER h_r (cfu_h == h_r + 1) burns recovery.",
    )
    rb_0c_miss = copy.deepcopy(rb_0c_eq)
    del rb_0c_miss["chain"]["names"]["id/d14-pw-rec"]
    add(
        "d14-b10-0x0c-candidate-name-history-missing-incomplete",
        ["SL-ORIG-011"],
        "origin_status",
        {
            "chain": rb_0c_miss["chain"], "origin_bundle": rb_0c_miss["origin_bundle"],
            "trusted_origin_issuer_pins": rb_0c_miss["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "D14-B10: 0x0c recovery candidate missing on-chain name history MUST refuse ORIGIN_STATUS_INCOMPLETE.",
    )

    # 3.3 Emancipation pre_trigger_pks exact boundaries on cap_confirmed_height (kills L4194!) & opened_majority (kills L4196!)
    # Both MUST promote a pre-trigger 0x0c recovery (B_1 -> B_2 while still a ward!) so _promote_pending_rec scans B_2.updates[]!
    # (a) Exact cap_confirmed_height == cuh: pre-trigger 0x0c promotes B_2 (owned by ec_g2_pol) at 749244 < cap_h=749600;
    #     then capacity/1 confirms at 749600 naming ec_adult_pol, and B_2 transfers to ec_adult_pol at EXACT cuh == 749600 + self-update at 749605!
    of_ec = rm._base_origin_fixture()
    ec_g2_pol = {"kind": "key", "pk": _kp("s3-ec-g2")["comp"]}
    ec_adult_pol = {"kind": "key", "pk": _kp("s3-ec-adult")["comp"]}
    ec_cap_h = 749600
    ec_cap_tx = _h32("s3-ec-cap-0x09")
    ec_st_seal = of_ec["origin_bundle"]["origin"]["payload"]["status_seal"]
    ec_cap_obj = sl.sign_envelope({
        "basis_sha256": _h32("s3-ec-basis"), "genesis": GENESIS_MAIN,
        "issued_at": of_ec["chain"]["now"] - 500,
        "issuer": of_ec["origin_bundle"]["origin"]["payload"]["issuer"],
        "network": "main", "next_status_policy": ec_st_seal["script_policy"],
        "next_status_vout": 0, "origin_id": of_ec["_origin_id"],
        "status_prev_outpoint": {"txid": ec_st_seal["txid"], "vout": ec_st_seal["vout"]},
        "subject_new_owner_policy": ec_adult_pol, "type": "seallink-capacity/1",
    }, [of_ec["_keys"]["reg_cred"]["sk"]])
    of_ec["chain"]["txs"][ec_st_seal["txid"]]["outputs"]["0"]["spent_by_txid"] = ec_cap_tx
    of_ec["chain"]["txs"][ec_cap_tx] = {
        "confirmed_height": ec_cap_h, "inputs": [sv.make_segwit_input(ec_st_seal["txid"], 0)],
        "opreturn_hex": sl.encode_opreturn(0x09, sl.content_addr(ec_cap_obj)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(ec_st_seal["script_policy"])}},
    }
    of_ec["origin_bundle"]["capacity_record"] = ec_cap_obj
    ec_rec_b2 = {
        "binding_mode": "recovery", "genesis": GENESIS_MAIN, "name": "id/child-ec-b2", "network": "main",
        "next_recovery_policy": of_ec["_rec_pol"], "next_recovery_vout": 0, "origin_id": of_ec["_origin_id"],
        "owner_policy": ec_g2_pol, "registration": {"txid": _h32("s3-ec-b2-reg"), "vout": 0},
        "seq": 2, "supersedes_binding_id": sl.object_id(of_ec["origin_bundle"]["name_binding"]),
        "type": "seallink-name-binding/1",
    }
    ec_rtx = _h32("s3-ec-0x0c")
    of_ec["chain"]["txs"][of_ec["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = ec_rtx
    of_ec["chain"]["txs"][ec_rtx] = {
        "confirmed_height": 749100, "inputs": [sv.make_segwit_input(of_ec["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]["txid"], 0)],
        "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(ec_rec_b2)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(of_ec["_rec_pol"])}},
    }
    of_ec["chain"]["names"]["id/child-ec-b2"] = sv.make_name_history(
        "id/child-ec-b2", ec_rec_b2["registration"], ec_g2_pol, {"link": {"origin": of_ec["_origin_id"]}},
        first_height=749090, update_height=749095,
        extra_updates=[
            {"confirmed_height": ec_cap_h, "owner_policy": ec_adult_pol, "sighash_bytes": [0x01], "txid": _h32("s3-ec-ho"), "value": {"link": {"origin": of_ec["_origin_id"]}}},
            {"confirmed_height": ec_cap_h + 5, "owner_policy": ec_adult_pol, "sighash_bytes": [0x01], "txid": _h32("s3-ec-self"), "value": {"link": {"origin": of_ec["_origin_id"]}}},
        ],
    )
    for u_ec in of_ec["chain"]["names"]["id/child-ec-b2"]["updates"]:
        u_ec["block_time"] = of_ec["_maj_unix"] - 10000
    of_ec["origin_bundle"]["recovery_bindings"] = [ec_rec_b2]
    rm.sync_chain_tip(of_ec["chain"], height=750100)
    add(
        "d14-b10-emancipation-cap-exact-height-boundary-admit",
        ["SL-ORIG-011", "SL-ORIG-014"],
        "origin_status",
        {
            "chain": of_ec["chain"], "expect_active_name": "id/child-ec-b2",
            "origin_bundle": of_ec["origin_bundle"], "trusted_origin_issuer_pins": of_ec["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "D14-B10: On a pre-trigger recovered B_2, handover to adult_pol at exact cap_confirmed_height is NOT added to pre_trigger_pks (emancipates to ADMIT_AUTONOMOUS).",
    )
    # (b) Exact opened_majority == cu_bt (kills L4196 < -> <=!):
    #     Pre-trigger 0x0c promotes B_2 (ec_g2_pol) at 749244 (bt < em_maj); B_2 rotates to em_adult_pol at EXACT cu_bt == em_maj;
    #     then post-majority 0x0c promotes B_3 (em_adult_pol) at 749764 (bt > em_maj) + self-update -> ADMIT_AUTONOMOUS!
    of_em = rm._base_origin_fixture()
    em_g2_pol = {"kind": "key", "pk": _kp("s3-em-g2")["comp"]}
    em_adult_pol = {"kind": "key", "pk": _kp("s3-em-adult")["comp"]}
    em_maj = of_em["_maj_unix"]
    em_b2 = {
        "binding_mode": "recovery", "genesis": GENESIS_MAIN, "name": "id/child-em-b2", "network": "main",
        "next_recovery_policy": of_em["_rec_pol"], "next_recovery_vout": 0, "origin_id": of_em["_origin_id"],
        "owner_policy": em_g2_pol, "registration": {"txid": _h32("s3-em-b2-reg"), "vout": 0},
        "seq": 2, "supersedes_binding_id": sl.object_id(of_em["origin_bundle"]["name_binding"]),
        "type": "seallink-name-binding/1",
    }
    em_b3 = {
        "binding_mode": "recovery", "genesis": GENESIS_MAIN, "name": "id/child-em-b3", "network": "main",
        "next_recovery_policy": of_em["_rec_pol"], "next_recovery_vout": 0, "origin_id": of_em["_origin_id"],
        "owner_policy": em_adult_pol, "registration": {"txid": _h32("s3-em-b3-reg"), "vout": 0},
        "seq": 3, "supersedes_binding_id": sl.object_id(em_b2),
        "type": "seallink-name-binding/1",
    }
    em_rtx1 = _h32("s3-em-0x0c-1")
    em_rtx2 = _h32("s3-em-0x0c-2")
    of_em["chain"]["txs"][of_em["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]["txid"]]["outputs"]["0"]["spent_by_txid"] = em_rtx1
    of_em["chain"]["txs"][em_rtx1] = {
        "confirmed_height": 749100, "inputs": [sv.make_segwit_input(of_em["origin_bundle"]["origin"]["payload"]["name_recovery"]["recovery_seal"]["txid"], 0)],
        "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(em_b2)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(of_em["_rec_pol"]), "spent_by_txid": em_rtx2}},
    }
    of_em["chain"]["txs"][em_rtx2] = {
        "confirmed_height": 749620, "inputs": [sv.make_segwit_input(em_rtx1, 0)],
        "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(em_b3)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(of_em["_rec_pol"])}},
    }
    of_em["chain"]["names"]["id/child-em-b2"] = sv.make_name_history(
        "id/child-em-b2", em_b2["registration"], em_g2_pol, {"link": {"origin": of_em["_origin_id"]}},
        first_height=749090, update_height=749095,
        extra_updates=[{"confirmed_height": 749610, "owner_policy": em_adult_pol, "sighash_bytes": [0x01], "txid": _h32("s3-em-b2-maj"), "value": {"link": {"origin": of_em["_origin_id"]}}}],
    )
    of_em["chain"]["names"]["id/child-em-b2"]["updates"][0]["block_time"] = em_maj - 10000
    of_em["chain"]["names"]["id/child-em-b2"]["updates"][1]["block_time"] = em_maj - 9000
    of_em["chain"]["names"]["id/child-em-b2"]["updates"][2]["block_time"] = em_maj  # exact cu_bt == opened_majority!
    of_em["chain"]["names"]["id/child-em-b3"] = sv.make_name_history(
        "id/child-em-b3", em_b3["registration"], em_adult_pol, {"link": {"origin": of_em["_origin_id"]}},
        first_height=749615, update_height=749765,
    )
    of_em["chain"]["names"]["id/child-em-b3"]["updates"][0]["block_time"] = em_maj + 50
    of_em["chain"]["names"]["id/child-em-b3"]["updates"][1]["block_time"] = em_maj + 200
    of_em["chain"]["block_times"] = {"749100": em_maj - 8000, "749244": em_maj - 7000, "749620": em_maj + 50, "749764": em_maj + 100}
    of_em["origin_bundle"]["recovery_bindings"] = [em_b2, em_b3]
    of_em["chain"]["tip_median_time_past"] = em_maj + 3600
    of_em["chain"]["credible_utc_interval"] = [em_maj + 3500, em_maj + 3700]
    of_em["chain"]["now"] = em_maj + 3600
    rm.sync_chain_tip(of_em["chain"], height=750100)
    add(
        "d14-b10-emancipation-majority-exact-time-boundary-admit",
        ["SL-ORIG-011", "SL-ORIG-014"],
        "origin_status",
        {
            "chain": of_em["chain"], "expect_active_name": "id/child-em-b3",
            "origin_bundle": of_em["origin_bundle"], "trusted_origin_issuer_pins": of_em["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "D14-B10: On a pre-trigger recovered B_2, rotation to adult_pol at exact block_time == opened_majority is NOT added to pre_trigger_pks (B_3 emancipates to ADMIT_AUTONOMOUS).",
    )

    # 3.4 _get_indexed_events exact first_error_height boundary (kills L4271 int(u["confirmed_height"]) < int(feh_b)!)
    # Put a malformed SLNK frame at exact confirmed_height == first_error_height == 749600 on active B_1:
    # With < feh_b: bad_hs=[] -> falls through to _binding_history_ok_until -> ORIGIN_STATUS_INCOMPLETE!
    # If < mutates to <=: bad_hs=[749600] -> wrongly returns CHAIN_FRAME_INVALID!
    rb_feh2 = bd11._build_autonomous_origin_rebind_fixture("d14-feh-0x10", h_offer=749450, h_13=749500, h_act=None, tip_h=749900)
    rb_feh2["chain"]["names"][rb_feh2["_b1"]["name"]]["updates"] = rb_feh2["chain"]["names"][rb_feh2["_b1"]["name"]]["updates"][:2]
    rb_feh2["origin_bundle"].pop("voluntary_rebind_bindings", None)
    b1_f_prev = rb_feh2["chain"]["names"][rb_feh2["_b1"]["name"]]["updates"][-1]
    bad_outer_slnk = (bytes([0x6A, 0x05]) + b"SLNK" + bytes([0x13, 0x05, 0x01, 0x02])).hex()
    rb_feh2["chain"]["names"][rb_feh2["_b1"]["name"]]["updates"].append(
        bd13._mk_upd(rb_feh2["_b1"]["name"], rb_feh2["_b1_pol"], b"{}", _h32("s3-feh-bad-slnk"), 749600, b1_f_prev["txid"], rb_feh2["_b1_pol"], prev_vout=b1_f_prev["vout"], opreturn_hex=bad_outer_slnk)
    )
    rb_feh2["chain"]["names"][rb_feh2["_b1"]["name"]]["history_truncated"] = True
    rb_feh2["chain"]["names"][rb_feh2["_b1"]["name"]]["first_error_height"] = 749600
    add(
        "d14-b09-indexed-events-excludes-exact-first-error-height",
        ["SL-ORIG-011"],
        "origin_status",
        {
            "chain": rb_feh2["chain"], "origin_bundle": rb_feh2["origin_bundle"],
            "trusted_origin_issuer_pins": rb_feh2["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "D14-B09: Updates at exact confirmed_height == first_error_height on truncated B_1 history are excluded (returns ORIGIN_STATUS_INCOMPLETE, not CHAIN_FRAME_INVALID).",
    )

    # 3.5 D14-B09: Second 0x13 during unknown_preimage -> immediate stall; dual_party_delayed 0x0c rescue; min_d_u == 35000 vs 35001 (kills L4598!)
    rb_decoy = bd11._build_autonomous_origin_rebind_fixture("d14-decoy", h_offer=749450, h_13=749500, h_act=None, tip_h=749550)
    rb_decoy["origin_bundle"].pop("voluntary_rebind_bindings", None)
    b1_dn = rb_decoy["_b1"]["name"]
    b1_dprev = rb_decoy["chain"]["names"][b1_dn]["updates"][-1]
    # Emit a second 0x13 at 749510 (well before 749500 + 144 = 749644!) -> MUST immediately enter unknown_rebind_stalled!
    rb_decoy["chain"]["names"][b1_dn]["updates"].append(
        bd13._mk_upd(b1_dn, rb_decoy["_b1_pol"], b"{}", _h32("s3-decoy-13b"), 749510, b1_dprev["txid"], rb_decoy["_b1_pol"], prev_vout=b1_dprev["vout"], opreturn_hex=sl.encode_opreturn(0x13, _h32("s3-decoy-cid2")).hex())
    )
    add(
        "d14-b09-second-0x13-during-unknown-preimage-stalls-immediately",
        ["SL-ORIG-017"],
        "origin_status",
        {"chain": rb_decoy["chain"], "origin_bundle": rb_decoy["origin_bundle"], "trusted_origin_issuer_pins": rb_decoy["trusted_origin_issuer_pins"]},
        "REFUSE",
        "ORIGIN_STATUS_INCOMPLETE",
        "D14-B09: A second 0x13 during unknown_preimage immediately enters unknown_rebind_stalled (refusing ORIGIN_STATUS_INCOMPLETE even before h_13 + min_d).",
    )
    # Rescue out of unknown_rebind_stalled via dual_party_delayed 0x0c (supersedes == id(B_1))!
    rb_resc = copy.deepcopy(rb_decoy)
    rm.sync_chain_tip(rb_resc["chain"], height=749900)
    b3_resc_pol = {"kind": "key", "pk": _kp("s3-resc-b3")["comp"]}
    b3_resc = {
        "binding_mode": "recovery", "genesis": GENESIS_MAIN, "name": "id/d14-resc-b3", "network": "main",
        "next_recovery_policy": rb_resc["_rec_pol"], "next_recovery_vout": 0, "origin_id": rb_resc["_oid"],
        "owner_policy": b3_resc_pol, "registration": {"txid": _h32("s3-resc-reg"), "vout": 0},
        "seq": 2, "supersedes_binding_id": rb_resc["_b1_id"], "type": "seallink-name-binding/1",
    }
    rtx_resc = _h32("s3-resc-0x0c")
    rb_resc["chain"]["txs"][rb_resc["_rec_seal_tx"]]["outputs"]["0"]["spent_by_txid"] = rtx_resc
    rb_resc["chain"]["txs"][rtx_resc] = {
        "confirmed_height": 749660, "inputs": [sv.make_segwit_input(rb_resc["_rec_seal_tx"], 0)],
        "opreturn_hex": sl.encode_opreturn(0x0C, sl.object_id(b3_resc)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(rb_resc["_rec_pol"])}},
    }
    rb_resc["chain"]["names"]["id/d14-resc-b3"] = sv.make_name_history(
        "id/d14-resc-b3", b3_resc["registration"], b3_resc_pol, {"link": {"origin": rb_resc["_oid"]}},
        first_height=749650, update_height=749655,
    )
    rb_resc["origin_bundle"]["recovery_bindings"] = [b3_resc]
    add(
        "d14-b09-dual-party-0x0c-rescues-unknown-rebind-stalled",
        ["SL-ORIG-017", "SL-ORIG-011"],
        "origin_status",
        {
            "chain": rb_resc["chain"], "expect_active_name": "id/d14-resc-b3",
            "origin_bundle": rb_resc["origin_bundle"], "trusted_origin_issuer_pins": rb_resc["trusted_origin_issuer_pins"],
        },
        "ADMIT_AUTONOMOUS",
        None,
        "D14-B09: dual_party_delayed 0x0c (supersedes == id(B_1)) cleanly rescues out of unknown_rebind_stalled and promotes B_3.",
    )
    # min_d_u == 35000 (accepted into unknown_preimage -> stalls at h_13 + 35000!) vs min_d_u == 35001 (rejected immediately!)
    for d_blk, lbl_d, want_v_d, want_c_d, extra_d in [
        (35000, "exact-35000-stalls", "REFUSE", "ORIGIN_STATUS_INCOMPLETE", {}),
        (35001, "over-35000-rejected", "ADMIT_AUTONOMOUS", None, {"expect_rebind_outcome": "rejected"}),
    ]:
        rb_md = bd11._build_autonomous_origin_rebind_fixture(
            f"d14-mind-{d_blk}", rec_delay_blocks=d_blk, delay_blocks=144,
            h_offer=749450, h_13=749500, h_act=None, tip_h=749500 + 35010,
        )
        rb_md["origin_bundle"].pop("voluntary_rebind_bindings", None)
        b1_nm_md = rb_md["_b1"]["name"]
        b1_us = rb_md["chain"]["names"][b1_nm_md]["updates"]
        b1_us.append(bd13._mk_upd(b1_nm_md, rb_md["_b1_pol"], sl.jcs_encode({"link": {"origin": rb_md["_oid"]}}), _h32(f"s3-md-ren-{d_blk}"), 775000, b1_us[-1]["txid"], rb_md["_b1_pol"], prev_vout=b1_us[-1]["vout"]))
        add(
            f"d14-m05-unknown-preimage-delay-{lbl_d}",
            ["SL-ORIG-017"],
            "origin_status",
            {"chain": rb_md["chain"], "origin_bundle": rb_md["origin_bundle"], "trusted_origin_issuer_pins": rb_md["trusted_origin_issuer_pins"], **extra_d},
            want_v_d,
            want_c_d,
            f"D14-M05: Unknown 0x13 preimage with delay_blocks={d_blk} ({lbl_d}).",
        )

    # Helper to activate slot 2 (id/parent-b) on _base_origin_fixture() so contract_assent min=2 quorum is met!
    def _activate_slot2(of_fx: dict[str, Any], tag: str) -> None:
        wop = of_fx["origin_bundle"]["origin"]["payload"]
        woid = of_fx["_origin_id"]
        g2_own_x, g2_seal_x = rm._kp("o-g2-own"), _kp(f"s3-g2s-{tag}")
        g2_pin_x = {"name": "id/parent-b", "owner_policy": {"kind": "key", "pk": g2_own_x["comp"]}, "registration": {"txid": rm._h32("g2-reg"), "vout": 0}}
        act_pol_2x = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(of_fx["_keys"]["disp"]["comp"], g2_seal_x["comp"])}
        g2_rec_px = {
            "active_policy": act_pol_2x, "active_vout": 0, "activation_mode": "initial", "genesis": GENESIS_MAIN,
            "guardian": g2_pin_x, "issuer": wop["issuer"], "network": "main", "origin_id": woid,
            "prev_outpoint": {"txid": rm._h32("os2-vac"), "vout": 0}, "revision": 1, "slot": 2,
            "term": {"ceiling_height": 1750000, "mode": "calendar", "not_after_unix": of_fx["_maj_unix"]},
            "type": "seallink-guardian/1",
        }
        g2_rec_x = sl.sign_envelope(g2_rec_px, [of_fx["_keys"]["reg_cred"]["sk"]])
        g2_ass_x = sl.sign_envelope({
            "expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main",
            "nonce": _h32(f"s3-g2a-{tag}"), "party_id": "slot-2", "party_name": "id/parent-b", "party_role": "guardian",
            "target_id": sl.object_id(g2_rec_px), "target_type": "seallink-guardian/1", "type": "seallink-assent/1",
        }, [of_fx["_keys"]["g2_gr"]["sk"]])
        g2_tx_x = _h32(f"s3-g2-0x12-{tag}")
        of_fx["chain"]["names"]["id/parent-b"] = sv.make_name_history("id/parent-b", g2_pin_x["registration"], g2_pin_x["owner_policy"], {"link": {"grant": of_fx["_keys"]["g2_gr"]["xonly"]}}, first_height=748000, update_height=748600)
        of_fx["chain"]["txs"][rm._h32("os2-vac")]["outputs"]["0"]["spent_by_txid"] = g2_tx_x
        of_fx["chain"]["txs"][g2_tx_x] = {"confirmed_height": 749020, "opreturn_hex": sl.encode_opreturn(0x12, sl.content_addr(g2_rec_x)).hex(), "outputs": {"0": {"script_pubkey_hex": _spk_hex(act_pol_2x)}}}
        of_fx["origin_bundle"]["guardian_records"].append(g2_rec_x)
        of_fx["origin_bundle"]["guardian_assents"].append(g2_ass_x)
        of_fx["origin_bundle"]["initial_guardian_disclosures"]["2"] = {"name_pin": g2_pin_x, "salt_hex": rm._h32("salt-g2")}

    # 3.6 verify_ward_approvals persisted CRED_ISSUER_CLOSED on guardian link.grant at exact cutoff_height (kills L5351 & L5352!)
    of_gcl = rm._base_origin_fixture()
    _activate_slot2(of_gcl, "gcl")
    g1_pin_cl = of_gcl["origin_bundle"]["guardian_records"][0]["payload"]["guardian"]
    g1_pol_cl = {"m": 1, "pks": [of_gcl["_keys"]["g1_gr"]["xonly"]]}
    h_cl_cut = 750000
    g1_cl_subj = {
        "cutoff_height": h_cl_cut, "name": g1_pin_cl["name"],
        "policy_sha256": sl.sha256(sl.jcs_encode(g1_pol_cl)).hex(),
        "registration": g1_pin_cl["registration"], "role": "grant", "subject_kind": "role",
    }
    j_gcl = sv.FencedJournal(_h32("s3-gcl-j"))
    j_gcl.record_closure(g1_cl_subj, "CRED_ISSUER_CLOSED", observed_at=of_gcl["chain"]["now"], observed_height=of_gcl["chain"]["tip_height"])
    wa_gcl = sl.sign_guardian_envelope(
        {
            "expires_at": 1795400000, "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": of_gcl["_origin_id"], "revision": 1, "ward_name": "id/child-leo"},
            "issued_at": 1795220000, "network": "main", "nonce": _h32("s3-gcl-an"),
            "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward",
            "target_id": sl.object_id(of_gcl["contract"]), "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [
            {"guardian_name": "id/parent-a", "revision": 1, "signers": [of_gcl["_keys"]["g1_gr"]["sk"]], "slot": 1},
            {"guardian_name": "id/parent-b", "revision": 1, "signers": [of_gcl["_keys"]["g2_gr"]["sk"]], "slot": 2},
        ],
    )
    wa_gcl_atx = _h32("s3-gcl-0x01")
    of_gcl["chain"]["txs"][wa_gcl_atx] = {"confirmed_height": h_cl_cut - 1, "opreturn_hex": sl.encode_opreturn(0x01, sl.content_addr(wa_gcl)).hex(), "outputs": {}}
    add(
        "d14-h08-ward-guardian-persisted-closure-exact-cutoff-refuse",
        ["SL-ORIG-006", "SL-CONT-009"],
        "assent",
        {
            "anchor_height": h_cl_cut, "anchor_time": of_gcl["chain"]["now"],
            "assent": wa_gcl, "assent_anchor_txid": wa_gcl_atx, "chain": of_gcl["chain"],
            "contract": of_gcl["contract"], "journal": {"closures": j_gcl.closures, "journal_id": j_gcl.journal_id},
            "origin_bundle": of_gcl["origin_bundle"], "trusted_origin_issuer_pins": of_gcl["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "CRED_ISSUER_CLOSED",
        "D14-H08: Persisted CRED_ISSUER_CLOSED closure on guardian link.grant refuses at exact eval_h == cutoff_height.",
    )
    add(
        "d14-h08-ward-guardian-persisted-closure-before-cutoff-admit",
        ["SL-ORIG-006", "SL-CONT-009"],
        "assent",
        {
            "anchor_height": h_cl_cut - 1, "anchor_time": of_gcl["chain"]["now"],
            "assent": wa_gcl, "assent_anchor_txid": wa_gcl_atx, "chain": of_gcl["chain"],
            "contract": of_gcl["contract"], "journal": {"closures": j_gcl.closures, "journal_id": j_gcl.journal_id},
            "origin_bundle": of_gcl["origin_bundle"], "trusted_origin_issuer_pins": of_gcl["trusted_origin_issuer_pins"],
        },
        "ADMIT",
        None,
        "D14-H08: Persisted CRED_ISSUER_CLOSED closure on guardian link.grant admits historical assent strictly before cutoff_height (eval_h == cutoff_height - 1).",
    )

    # 3.7 verify_assent party_name != wb["name"] on State-4 adult (kills L5469!) & D14-H08 historical ward assent backdating protection (kills L5517!)
    # (a) Emancipated autonomous origin signing contract assent with wrong party_name -> CONTRACT_ASSENT_INVALID!
    rb_s4a = bd11._build_autonomous_origin_rebind_fixture("d14-s4a", h_act=749780, tip_h=749950)
    b2_s4a = rb_s4a["_b2"]
    b2_s4a_gr = _kp("s3-s4a-gr")
    b2_s4a_u = rb_s4a["chain"]["names"][b2_s4a["name"]]["updates"][-1]
    rb_s4a["chain"]["names"][b2_s4a["name"]]["updates"].append(
        bd13._mk_upd(b2_s4a["name"], b2_s4a["owner_policy"], sl.jcs_encode({"link": {"grant": b2_s4a_gr["xonly"], "origin": rb_s4a["_oid"]}}), _h32("s3-s4a-link"), 749800, b2_s4a_u["txid"], b2_s4a["owner_policy"], prev_vout=b2_s4a_u["vout"])
    )
    c_s4a = copy.deepcopy(of_gcl["contract"])
    c_s4a["parties"] = [
        {"name_pin": {"name": b2_s4a["name"], "owner_policy": b2_s4a["owner_policy"], "registration": b2_s4a["registration"]}, "party_id": "adult-p", "role": "principal", "ward_origin_id": rb_s4a["_oid"]},
        {"party_id": "counterparty", "role": "counterparty", "signing_policy": {"m": 1, "pks": [_kp("s3-s4a-cp")["xonly"]]}},
    ]
    ass_bad_pname = sl.sign_envelope({
        "expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main",
        "nonce": _h32("s3-s4a-n"), "party_id": "adult-p", "party_name": "id/wrong-party-name", "party_role": "principal",
        "target_id": sl.object_id(c_s4a), "target_type": "seallink-contract/1", "type": "seallink-assent/1",
    }, [b2_s4a_gr["sk"]])
    add(
        "d14-b10-assent-origin-party-name-mismatch-refuse",
        ["SL-CONT-004", "SL-ORIG-002"],
        "assent",
        {
            "assent": ass_bad_pname, "chain": rb_s4a["chain"], "contract": c_s4a,
            "origin_bundle": rb_s4a["origin_bundle"], "trusted_origin_issuer_pins": rb_s4a["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "CONTRACT_ASSENT_INVALID",
        "D14-B10: Assent on origin-bound party whose party_name disagrees with effective binding name MUST refuse CONTRACT_ASSENT_INVALID.",
    )
    # Live ward assent with valid 2-of-2 guardian approvals & valid guardian_context.ward_name, ONLY party_name wrong (kills L5463!)
    wa_wrong_pn = sl.sign_guardian_envelope(
        {
            "expires_at": 1795400000, "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": of_gcl["_origin_id"], "revision": 1, "ward_name": "id/child-leo"},
            "issued_at": 1795220000, "network": "main", "nonce": _h32("s3-gcl-wpn"),
            "party_id": "student-1", "party_name": "id/wrong-ward-name", "party_role": "student_ward",
            "target_id": sl.object_id(of_gcl["contract"]), "target_type": "seallink-contract/1",
            "type": "seallink-assent/1",
        },
        [
            {"guardian_name": "id/parent-a", "revision": 1, "signers": [of_gcl["_keys"]["g1_gr"]["sk"]], "slot": 1},
            {"guardian_name": "id/parent-b", "revision": 1, "signers": [of_gcl["_keys"]["g2_gr"]["sk"]], "slot": 2},
        ],
    )
    add(
        "d14-b10-ward-assent-party-name-mismatch-refuse",
        ["SL-CONT-004", "SL-ORIG-006"],
        "assent",
        {
            "assent": wa_wrong_pn, "chain": of_gcl["chain"], "contract": of_gcl["contract"],
            "origin_bundle": of_gcl["origin_bundle"], "trusted_origin_issuer_pins": of_gcl["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "CONTRACT_ASSENT_INVALID",
        "D14-B10: Live ward assent with valid guardian approvals whose party_name != effective binding name MUST refuse CONTRACT_ASSENT_INVALID.",
    )
    # (b) D14-H08: Historical ward assent WITHOUT assent_output or 0x01/0x02 anchor -> REFUSE CONTRACT_ASSENT_INVALID (kills L5517!)
    add(
        "d14-h08-historical-ward-assent-unanchored-backdating-refuse",
        ["SL-ORIG-006", "SL-CONT-004"],
        "assent",
        {
            "anchor_height": h_cl_cut - 1, "anchor_time": of_gcl["chain"]["now"],
            "assent": wa_gcl, "chain": of_gcl["chain"], "contract": of_gcl["contract"],
            "origin_bundle": of_gcl["origin_bundle"], "trusted_origin_issuer_pins": of_gcl["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "CONTRACT_ASSENT_INVALID",
        "D14-H08: Historical ward assent lacking both contract.assent_output spend and confirmed 0x01/0x02 anchor MUST refuse CONTRACT_ASSENT_INVALID.",
    )
    # (c) D14-H08 positive: Historical ward assent bound via contract.assent_output spent by 0x07 contract_anchor_txid -> ADMIT!
    of_ao = rm._base_origin_fixture()
    _activate_slot2(of_ao, "ao")
    ao_pol = {"kind": "key", "pk": _kp("s3-ao-pol")["comp"]}
    ao_utxo_tx = _h32("s3-ao-utxo")
    ao_0x07_tx = _h32("s3-ao-0x07")
    c_ao = {**copy.deepcopy(of_ao["contract"]), "assent_output": {"script_policy": ao_pol, "txid": ao_utxo_tx, "vout": 0}}
    wa_ao = sl.sign_guardian_envelope(
        {
            "expires_at": 1795400000, "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": of_ao["_origin_id"], "revision": 1, "ward_name": "id/child-leo"},
            "issued_at": 1795220000, "network": "main", "nonce": _h32("s3-ao-an"),
            "party_id": "student-1", "party_name": "id/child-leo", "party_role": "student_ward",
            "target_id": sl.object_id(c_ao), "target_type": "seallink-contract/1", "type": "seallink-assent/1",
        },
        [
            {"guardian_name": "id/parent-a", "revision": 1, "signers": [of_ao["_keys"]["g1_gr"]["sk"]], "slot": 1},
            {"guardian_name": "id/parent-b", "revision": 1, "signers": [of_ao["_keys"]["g2_gr"]["sk"]], "slot": 2},
        ],
    )
    of_ao["chain"]["txs"][ao_utxo_tx] = {"confirmed_height": 749900, "outputs": {"0": {"script_pubkey_hex": _spk_hex(ao_pol), "spent_by_txid": ao_0x07_tx}}}
    of_ao["chain"]["txs"][ao_0x07_tx] = {
        "confirmed_height": 749999, "inputs": [sv.make_segwit_input(ao_utxo_tx, 0)],
        "opreturn_hex": sl.encode_opreturn(0x07, sl.content_addr(c_ao)).hex(), "outputs": {},
    }
    add(
        "d14-h08-historical-ward-assent-output-spent-by-0x07-admit",
        ["SL-ORIG-006", "SL-CONT-004"],
        "assent",
        {
            "anchor_height": 749999, "anchor_time": of_ao["chain"]["now"],
            "assent": wa_ao, "chain": of_ao["chain"], "contract": c_ao, "contract_anchor_txid": ao_0x07_tx,
            "origin_bundle": of_ao["origin_bundle"], "trusted_origin_issuer_pins": of_ao["trusted_origin_issuer_pins"],
        },
        "ADMIT",
        None,
        "D14-H08: Historical ward assent bound via contract.assent_output spent by confirmed 0x07 anchor tx admits cleanly.",
    )

    # 3.8 D14-H08: verify_termination ward arbiter branch banned (kills L7815!) & federation missing issuance_txid (kills L10775!)
    term_ward_arb = sl.sign_guardian_envelope(
        {
            "contract_id": sl.object_id(of_ao["contract"]), "genesis": GENESIS_MAIN,
            "guardian_context": {"event_class": "contract_assent", "origin_id": of_ao["_origin_id"], "revision": 1, "ward_name": "id/child-leo"},
            "issued_at": 1795220000, "network": "main", "reason": "arbiter-ruling", "termination_branch": "arbiter",
            "type": "seallink-termination/1",
        },
        [{"guardian_name": "id/parent-a", "revision": 1, "signers": [of_ao["_keys"]["g1_gr"]["sk"]], "slot": 1}],
    )
    add(
        "d14-h08-termination-ward-arbiter-branch-refuse",
        ["SL-ORIG-006", "SL-CONT-005"],
        "termination",
        {
            "chain": of_ao["chain"], "contract": of_ao["contract"],
            "origin_bundle": of_ao["origin_bundle"], "termination": term_ward_arb,
            "trusted_origin_issuer_pins": of_ao["trusted_origin_issuer_pins"],
        },
        "REFUSE",
        "WIRE_SIGNATURE",
        "D14-H08: Ward guardian_approvals[] MUST NOT exercise termination_branch='arbiter' (WIRE_SIGNATURE).",
    )
    gf14_p = copy.deepcopy(fx_s2["bundle"]["grants"][0]["payload"])
    gf14_p["recipient"] = {"mode": "name", "name": "id/peer-b", "owner_policy": {"kind": "key", "pk": _kp("s3-fed-pb")["comp"]}, "registration": {"txid": _h32("s3-fed-pbr"), "vout": 0}}
    gf14_env = sl.sign_envelope(gf14_p, [fx_s2["_keys"]["alice_gr"]["sk"]])
    add(
        "d14-h08-federation-missing-issuance-txid-refuse",
        ["SL-SERV-004"],
        "federation",
        {
            "chain": fx_s2["chain"], "grant": gf14_env, "journal": {"journal_id": _h32("s3-fed-noitx-j")},
            "peer_ctx": {"peer_id": "id/peer-b", "phase": "screening"},
            "policy": {"trusted_peers": ["id/peer-b"]},
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-H08: Federated screening omitting mandatory issuance_txid MUST refuse CHAIN_FRAME_INVALID.",
        module="federated-screening",
    )

    # 3.9 D14-H05: Journaled guardian slot active -> vacant (0x0f halt) -> 0x0d appoint -> 0x0e CSV activate -> active re-appointment!
    of_reapp = rm._base_origin_fixture()
    w_op_ra = of_reapp["origin_bundle"]["origin"]["payload"]
    w_oid_ra = of_reapp["_origin_id"]
    # Step 1 chain: slot 1 active (revision 1) -> ADMIT_WARD
    ch_ra_1 = copy.deepcopy(of_reapp["chain"])
    ob_ra_1 = copy.deepcopy(of_reapp["origin_bundle"])
    # Step 2 chain: slot 1 halted via 0x0f (vacant!) -> then re-appointed via 0x0d + activated via 0x0e (revision 1, new guardian id/parent-c!)
    ch_ra_2 = copy.deepcopy(of_reapp["chain"])
    ob_ra_2 = copy.deepcopy(of_reapp["origin_bundle"])
    gp_ra = w_op_ra["guardian_policy"]
    dly_ra = gp_ra["appointment_delay_blocks"]
    vac_pol_ra = gp_ra["roster_seal"]["script_policy"]
    halt_tx_ra = _h32("s3-ra-0x0f-halt")
    g1_rec1_tx = rm._h32("og1-init-0x12")
    ch_ra_2["txs"][g1_rec1_tx]["outputs"]["0"]["spent_by_txid"] = halt_tx_ra
    ch_ra_2["txs"][halt_tx_ra] = {
        "confirmed_height": 749100, "inputs": [sv.make_segwit_input(g1_rec1_tx, 0)],
        "opreturn_hex": sl.encode_opreturn(0x0F, sl.object_id(ob_ra_2["guardian_records"][0]["payload"])).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(vac_pol_ra)}},
    }
    # Step 3: 0x0d appoint + 0x0e CSV activate on slot 1 (revision 1)!
    ch_ra_3 = copy.deepcopy(ch_ra_2)
    ob_ra_3 = copy.deepcopy(ob_ra_2)
    gc_own, gc_gr, gc_seal = _kp("s3-ra-gc-own"), _kp("s3-ra-gc-gr"), _kp("s3-ra-gc-seal")
    gc_pin = {"name": "id/parent-c", "owner_policy": {"kind": "key", "pk": gc_own["comp"]}, "registration": {"txid": _h32("s3-ra-gc-reg"), "vout": 0}}
    pend_pol_ra = {"delay_blocks": dly_ra, "keys": {"challenger": gp_ra["challenger_pk"], "disposer": gp_ra["disposer_pk"], "guardian": gc_seal["comp"]}, "kind": "branch", "template": "guardian_slot_pending"}
    act_pol_ra = {"kind": "branch", "template": "either_of_2", "keys": sl.canonical_branch_pair(gp_ra["disposer_pk"], gc_seal["comp"])}
    g1_rec2_p = {
        "activation_mode": "appointed", "active_policy": act_pol_ra, "effective_delay_blocks": dly_ra,
        "genesis": GENESIS_MAIN, "guardian": gc_pin, "issuer": w_op_ra["issuer"], "network": "main",
        "origin_id": w_oid_ra, "pending_policy": pend_pol_ra, "pending_vout": 0,
        "prev_outpoint": {"txid": halt_tx_ra, "vout": 0}, "revision": 1, "slot": 1,
        "term": {"ceiling_height": 1750000, "mode": "calendar", "not_after_unix": of_reapp["_maj_unix"]},
        "type": "seallink-guardian/1",
    }
    g1_rec2 = sl.sign_envelope(g1_rec2_p, [of_reapp["_keys"]["reg_cred"]["sk"]])
    g1_ass2 = sl.sign_envelope({
        "expires_at": 1795400000, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "network": "main",
        "nonce": _h32("s3-ra-gc-ass"), "party_id": "slot-1", "party_name": "id/parent-c", "party_role": "guardian",
        "target_id": sl.object_id(g1_rec2_p), "target_type": "seallink-guardian/1", "type": "seallink-assent/1",
    }, [gc_gr["sk"]])
    app_tx_ra = _h32("s3-ra-0x0d")
    act_tx_ra = _h32("s3-ra-0x0e")
    ch_ra_3["names"]["id/parent-c"] = sv.make_name_history("id/parent-c", gc_pin["registration"], gc_pin["owner_policy"], {"link": {"grant": gc_gr["xonly"]}}, first_height=748000, update_height=749000)
    ch_ra_3["txs"][halt_tx_ra]["outputs"]["0"]["spent_by_txid"] = app_tx_ra
    ch_ra_3["txs"][app_tx_ra] = {
        "confirmed_height": 749150, "inputs": [sv.make_segwit_input(halt_tx_ra, 0)],
        "opreturn_hex": sl.encode_opreturn(0x0D, sl.content_addr(g1_rec2)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(pend_pol_ra), "spent_by_txid": act_tx_ra}},
    }
    ch_ra_3["txs"][act_tx_ra] = {
        "confirmed_height": 749150 + dly_ra,
        "inputs": [{"prev_txid": app_tx_ra, "prev_vout": 0, "script_sig_hex": "", "sequence": dly_ra, "witness": ["3044" + ("aa" * 68) + "01", "", sl.compile_script_policy(pend_pol_ra)[1].hex()]}],
        "opreturn_hex": sl.encode_opreturn(0x0E, sl.content_addr(g1_rec2)).hex(),
        "outputs": {"0": {"script_pubkey_hex": _spk_hex(act_pol_ra)}},
    }
    ob_ra_3["guardian_records"].append(g1_rec2)
    ob_ra_3["guardian_assents"].append(g1_ass2)
    add(
        "d14-h05-journaled-guardian-slot-reappointment-admit",
        ["SL-ORIG-005"],
        "multi_step_journal",
        {
            "journal": {"journal_id": _h32("s3-ra-j")},
            "trusted_origin_issuer_pins": of_reapp["trusted_origin_issuer_pins"],
            "steps": [
                {"chain": ch_ra_1, "kind": "origin_status", "label": "slot1-rev1-active", "origin_bundle": ob_ra_1, "want_refusal": None, "want_verdict": "ADMIT_WARD"},
                {"kind": "replay_restart", "label": "ra-restart-1"},
                {"chain": ch_ra_2, "kind": "origin_status", "label": "slot1-halted-vacant", "origin_bundle": ob_ra_2, "want_refusal": None, "want_verdict": "ADMIT_WARD"},
                {"kind": "replay_restart", "label": "ra-restart-2"},
                {"chain": ch_ra_3, "kind": "origin_status", "label": "slot1-rev2-reappointed-active", "origin_bundle": ob_ra_3, "want_refusal": None, "want_verdict": "ADMIT_WARD"},
            ],
        },
        "ADMIT",
        None,
        "D14-H05: Journaled guardian slot active -> vacant (0x0f) -> 0x0d -> 0x0e -> active re-appointment succeeds across replay_restart.",
    )

    # ========================================================================
    # SECTION 4: 0x14 Transparency Log Handover, P2A EOL, & Fraud Hardening
    # ========================================================================
    ho2 = _mk_handover_log_chain("d14-ho2")
    eco0 = ho2["eco0"]

    # 4.1 Valid 2-hop iterative handover L0 -> L1 -> L2 (unspent head L2.cp2) ADMIT!
    add(
        "d14-b07-log-handover-2hop-iterative-admit",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ho2["chain"], "checkpoint": ho2["l2_cp2_env"], "checkpoint_txid": ho2["l2_cp2_tx"],
            "predecessor_chain": ho2["pred_chain_for_l2"],
        },
        "ADMIT",
        None,
        "D14-B07: 2-hop iterative on-chain handover L0 -> L1 (seq=1 terminal) -> L2 (seq=2 head) admits cleanly.",
    )

    # 4.2 _authenticate_predecessor_chain cycle (kills L5902!), invalid wire pred (kills L5913!), non-terminal pred (kills L5923!)
    # (a) 257-hop handover chain (256 in predecessor_chain + 257th L0 in journal.log_heads -> exceeds 256-hop limit -> kills L5980 on BOTH refusal-return & wrong-code!)
    ch_17 = copy.deepcopy(ho2["chain"])
    ch_17["txs"][ho2["l0_term_tx"]]["outputs"] = {"1": {"script_pubkey_hex": _spk_hex(eco0["seal_pol"])}}
    prev_lid_17 = eco0["log_id"]
    prev_tx_17 = ho2["l0_term_tx"]
    dr_17 = ho2["l0_dr"]
    hops_17: list[dict[str, Any]] = []
    for h_i in range(1, 258):
        cur_tx_17 = _h32(f"d14-257hop-tx-{h_i}")
        cur_gen_17 = {"txid": prev_tx_17, "vout": 1}
        cur_lid_17 = sl.compute_log_id(
            "main", GENESIS_MAIN, "notary", eco0["iss_name"], eco0["iss_reg"], cur_gen_17,
            predecessor_log_id=prev_lid_17, predecessor_terminal_denials_root=dr_17,
        )
        is_last = (h_i == 257)
        cp_p_17: dict[str, Any] = {
            "batch_count": 0, "batch_root": sl.EMPTY_BATCH_ROOT, "checkpoints_root": sl.EMPTY_CHECKPOINTS_ROOT,
            "cumulative_entries_count": 0, "denials_delta_root": sl.EMPTY_BATCH_ROOT, "denials_root": dr_17,
            "genesis": GENESIS_MAIN, "genesis_seal_outpoint": cur_gen_17, "issuer": eco0["iss_role_pin"],
            "log_id": cur_lid_17, "network": "main", "predecessor_log_id": prev_lid_17,
            "predecessor_terminal_denials_root": dr_17, "prev_log_outpoint": cur_gen_17,
            "role": "notary", "seq": 1, "terminal": not is_last, "type": "seallink-log-checkpoint/1",
        }
        if is_last:
            cp_p_17["next_log_policy"] = eco0["seal_pol"]
            cp_p_17["next_log_vout"] = 1
        else:
            cp_p_17["handover_next_policy"] = eco0["seal_pol"]
            cp_p_17["handover_next_vout"] = 1
        cp_env_17 = sl.sign_envelope(cp_p_17, [eco0["iss_role"]["sk"]])
        ch_17["txs"][prev_tx_17]["outputs"]["1"]["spent_by_txid"] = cur_tx_17
        ch_17["txs"][cur_tx_17] = {
            "block_hash": _h32(f"d14-257hop-blk-{h_i}"), "confirmed_height": 749994 + h_i,
            "inputs": [sv.make_segwit_input(prev_tx_17, 1)],
            "opreturn_hex": sl.encode_opreturn(0x14, sl.content_addr(cp_env_17)).hex(),
            "outputs": {"1": {"script_pubkey_hex": _spk_hex(eco0["seal_pol"])}},
        }
        if is_last:
            cp17_env, cp17_tx = cp_env_17, cur_tx_17
        else:
            hops_17.append({"checkpoint": cp_env_17, "checkpoint_txid": cur_tx_17})
        prev_lid_17, prev_tx_17 = cur_lid_17, cur_tx_17
    rm.sync_chain_tip(ch_17, height=750300)
    lh_l0_17 = {
        "body": {
            "block_hash": ho2["chain"]["txs"][ho2["l0_term_tx"]]["block_hash"],
            "checkpoint_id": sl.content_addr(ho2["l0_term_env"]),
            "checkpoint_object_id": sl.object_id(ho2["l0_term_env"]["payload"]),
            "checkpoint_txid": ho2["l0_term_tx"],
            "checkpoints_root": ho2["l0_term_env"]["payload"]["checkpoints_root"],
            "confirmed_height": 749994, "denials_root": dr_17,
            "handover_next_outpoint": {"txid": ho2["l0_term_tx"], "vout": 1},
            "handover_next_policy": eco0["seal_pol"],
            "issuer_name": eco0["iss_name"], "issuer_registration": eco0["iss_reg"],
            "log_id": eco0["log_id"], "max_seq": 3, "role": "notary", "terminal": True,
        },
        "kind": "log-head",
    }
    add(
        "d14-b07-pred-chain-257-hops-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ch_17, "checkpoint": cp17_env, "checkpoint_txid": cp17_tx,
            "journal": {"initial_entries": [lh_l0_17], "journal_id": _h32("s4-257hop-j")},
            "predecessor_chain": list(reversed(hops_17)),
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B07: Handover chain exceeding 256 predecessor hops (256 presented + 257th in journal) MUST refuse CHAIN_FRAME_INVALID.",
    )
    # (b) Wire-invalid checkpoint object in predecessor_chain -> CHAIN_FRAME_INVALID (kills L5913!)
    add(
        "d14-b07-pred-chain-wire-invalid-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ho2["chain"], "checkpoint": ho2["l2_cp1_env"], "checkpoint_txid": ho2["l2_cp1_tx"],
            "predecessor_chain": [{"checkpoint": {"bad": 1}, "checkpoint_txid": ho2["l1_cp1_tx"]}],
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B07: Wire-invalid checkpoint inside predecessor_chain MUST refuse CHAIN_FRAME_INVALID.",
    )
    # (c) Handover off a VALID confirmed NON-terminal checkpoint L0.cp2 (terminal: False, vout 1 spent by L1_nt!) -> CHAIN_FRAME_INVALID (kills L5923 on BOTH refusal-return & wrong-code!)
    ch_nt = copy.deepcopy(eco0["chain_at_cp2"])
    rm.sync_chain_tip(ch_nt, height=750010)
    nt_cp1_tx = _h32("d14-nt-ho-cp1")
    nt_gen_op = {"txid": eco0["cp2_tx"], "vout": 1}
    nt_dr = eco0["cp2_env"]["payload"]["denials_root"]
    nt_lid = sl.compute_log_id("main", GENESIS_MAIN, "notary", eco0["iss_name"], eco0["iss_reg"], nt_gen_op, predecessor_log_id=eco0["log_id"], predecessor_terminal_denials_root=nt_dr)
    nt_cp1_env = sl.sign_envelope({
        "batch_count": 0, "batch_root": sl.EMPTY_BATCH_ROOT, "checkpoints_root": sl.EMPTY_CHECKPOINTS_ROOT,
        "cumulative_entries_count": 0, "denials_delta_root": sl.EMPTY_BATCH_ROOT, "denials_root": nt_dr,
        "genesis": GENESIS_MAIN, "genesis_seal_outpoint": nt_gen_op, "issuer": eco0["iss_role_pin"],
        "log_id": nt_lid, "network": "main", "next_log_policy": eco0["seal_pol"], "next_log_vout": 1,
        "predecessor_log_id": eco0["log_id"], "predecessor_terminal_denials_root": nt_dr,
        "prev_log_outpoint": nt_gen_op, "role": "notary", "seq": 1, "terminal": False,
        "type": "seallink-log-checkpoint/1",
    }, [eco0["iss_role"]["sk"]])
    ch_nt["txs"][eco0["cp2_tx"]]["outputs"] = {"1": {"script_pubkey_hex": _spk_hex(eco0["seal_pol"]), "spent_by_txid": nt_cp1_tx}}
    ch_nt["txs"][nt_cp1_tx] = {
        "block_hash": _h32("d14-nt-ho-blk"), "confirmed_height": 749999,
        "inputs": [sv.make_segwit_input(eco0["cp2_tx"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x14, sl.content_addr(nt_cp1_env)).hex(),
        "outputs": {"1": {"script_pubkey_hex": _spk_hex(eco0["seal_pol"])}},
    }
    add(
        "d14-b07-handover-from-non-terminal-checkpoint-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ch_nt, "checkpoint": nt_cp1_env, "checkpoint_txid": nt_cp1_tx,
            "predecessor_chain": [{"checkpoint": eco0["cp2_env"], "checkpoint_txid": eco0["cp2_tx"]}],
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B07: Handover attempting to branch off a valid non-terminal checkpoint (terminal=False) MUST refuse CHAIN_FRAME_INVALID.",
    )

    # 4.3 Multi-hop persisted journal ancestor walk (kills L5958 cycle, L5960 grandparent closure, L5969 missing grandparent!)
    def _mk_j_lh(lid: str, cp_env: dict[str, Any], txid: str, bh: str, ch_h: int, *, pred_lid: str | None = None, ho_vout1: bool = True, term: bool = True) -> dict[str, Any]:
        p = cp_env["payload"]
        body: dict[str, Any] = {
            "block_hash": bh, "checkpoint_id": sl.content_addr(cp_env), "checkpoint_object_id": sl.object_id(p),
            "checkpoint_txid": txid, "checkpoints_root": p["checkpoints_root"], "confirmed_height": ch_h,
            "denials_root": p["denials_root"], "issuer_name": eco0["iss_name"], "issuer_registration": eco0["iss_reg"],
            "log_id": lid, "max_seq": p["seq"], "role": "notary", "terminal": term,
        }
        if pred_lid is not None:
            body["predecessor_log_id"] = pred_lid
        if ho_vout1:
            body["handover_next_outpoint"] = {"txid": txid, "vout": 1}
            body["handover_next_policy"] = p["handover_next_policy"]
        return {"body": body, "kind": "log-head"}

    lh_l1_ok = _mk_j_lh(ho2["l1_lid"], ho2["l1_cp1_env"], ho2["l1_cp1_tx"], _h32("d14-ho2-blk-l1"), 749996, pred_lid=eco0["log_id"])
    lh_l0_ok = _mk_j_lh(eco0["log_id"], ho2["l0_term_env"], ho2["l0_term_tx"], ho2["chain"]["txs"][ho2["l0_term_tx"]]["block_hash"], 749994)
    lh_l0_cyc = _mk_j_lh(eco0["log_id"], ho2["l0_term_env"], ho2["l0_term_tx"], ho2["chain"]["txs"][ho2["l0_term_tx"]]["block_hash"], 749994, pred_lid=ho2["l1_lid"])
    # (a) Cycle in persisted journal log_heads (L1 -> L0 -> L1) -> CHAIN_FRAME_INVALID (kills L5958!)
    add(
        "d14-b07-journal-ancestor-cycle-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ho2["chain"], "checkpoint": ho2["l2_cp1_env"], "checkpoint_txid": ho2["l2_cp1_tx"],
            "journal": {"initial_entries": [lh_l0_cyc, lh_l1_ok], "journal_id": _h32("s4-j-cyc")},
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B07: Cycle in persisted journal log-head ancestor chain MUST refuse CHAIN_FRAME_INVALID.",
    )
    # (b) Grandparent L0 closed in journal.closures -> NOTARY_LOG_COMPROMISED (kills L5960!)
    j_gp_cl = sv.FencedJournal(_h32("s4-j-gpcl"))
    j_gp_cl.record_closure({"log_id": eco0["log_id"], "role": "notary", "subject_kind": "log"}, "NOTARY_LOG_COMPROMISED", observed_at=ho2["chain"]["now"], observed_height=750010)
    add(
        "d14-b07-journal-grandparent-closed-refuse",
        ["SL-CONT-012", "SL-CONT-013"],
        "log_checkpoint",
        {
            "chain": ho2["chain"], "checkpoint": ho2["l2_cp1_env"], "checkpoint_txid": ho2["l2_cp1_tx"],
            "journal": {"closures": j_gp_cl.closures, "initial_entries": [lh_l0_ok, lh_l1_ok], "journal_id": j_gp_cl.journal_id},
        },
        "REFUSE",
        "NOTARY_LOG_COMPROMISED",
        "D14-B07: Persisted log closure on grandparent predecessor L0 MUST refuse NOTARY_LOG_COMPROMISED during handover.",
    )
    # (c) Missing grandparent L0 in journal.log_heads -> CHAIN_FRAME_INVALID (kills L5969!)
    add(
        "d14-b07-journal-grandparent-missing-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ho2["chain"], "checkpoint": ho2["l2_cp1_env"], "checkpoint_txid": ho2["l2_cp1_tx"],
            "journal": {"initial_entries": [lh_l1_ok], "journal_id": _h32("s4-j-gpmiss")},
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B07: Missing grandparent L0 in persisted journal log_heads MUST refuse CHAIN_FRAME_INVALID.",
    )

    # 4.4 Maturing predecessor fails verify_log_checkpoint with CHAIN_DEPTH_INSUFFICIENT -> mapped to CHAIN_FRAME_INVALID (kills L5993!)
    ch_mat_p = copy.deepcopy(ho2["chain"])
    ch_mat_p["txs"][ho2["l1_cp1_tx"]]["confirmed_height"] = 750008  # depth 3 < operator_min_depth=6!
    add(
        "d14-b07-predecessor-insufficient-depth-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ch_mat_p, "checkpoint": ho2["l2_cp2_env"], "checkpoint_txid": ho2["l2_cp2_tx"],
            "operator_min_depth": 6, "predecessor_chain": ho2["pred_chain_for_l2"], "required_depth": 1,
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B07: Predecessor terminal checkpoint failing verification (depth insufficient) MUST refuse CHAIN_FRAME_INVALID.",
    )

    # 4.5 Revocation wipe with real log_id folding real pred_dr while setting predecessor_terminal_denials_root = denials_root = SMT_EMPTY_ROOT
    # (a) Direct seq=1 on unspent L2.cp1 (kills L5998!)
    ch_wipe1 = copy.deepcopy(ho2["chain"])
    l2_wipe_env = sl.sign_envelope({
        **ho2["l2_cp1_env"]["payload"],
        "denials_root": sl.SMT_EMPTY_ROOT,
        "predecessor_terminal_denials_root": sl.SMT_EMPTY_ROOT,
    }, [eco0["iss_role"]["sk"]])
    ch_wipe1["txs"][ho2["l2_cp1_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(l2_wipe_env)).hex()
    ch_wipe1["txs"][ho2["l2_cp1_tx"]]["outputs"]["1"].pop("spent_by_txid", None)
    ch_wipe1["txs"].pop(ho2["l2_cp2_tx"], None)
    add(
        "d14-b07-handover-seq1-empty-pred-denials-root-wipe-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ch_wipe1, "checkpoint": l2_wipe_env, "checkpoint_txid": ho2["l2_cp1_tx"],
            "predecessor_chain": ho2["pred_chain_for_l2"],
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B07: Handover seq=1 setting predecessor_terminal_denials_root=SMT_EMPTY_ROOT (while keeping real log_id) MUST refuse CHAIN_FRAME_INVALID.",
    )
    # (b) Intermediate 2-hop L1 (seq=1) wiping predecessor_terminal_denials_root = denials_root = SMT_EMPTY_ROOT while keeping real L1 log_id (unspent L2.cp1!)
    ch_wipe2 = copy.deepcopy(ho2["chain"])
    l1_wipe_env = sl.sign_envelope({
        **ho2["l1_cp1_env"]["payload"],
        "denials_root": sl.SMT_EMPTY_ROOT,
        "predecessor_terminal_denials_root": sl.SMT_EMPTY_ROOT,
    }, [eco0["iss_role"]["sk"]])
    l2_w2_lid = sl.compute_log_id(
        "main", GENESIS_MAIN, "notary", eco0["iss_name"], eco0["iss_reg"], ho2["l2_gen_op"],
        predecessor_log_id=ho2["l1_lid"], predecessor_terminal_denials_root=sl.SMT_EMPTY_ROOT,
    )
    l2_w2_env = sl.sign_envelope({
        **ho2["l2_cp1_env"]["payload"], "denials_root": sl.SMT_EMPTY_ROOT,
        "log_id": l2_w2_lid, "predecessor_terminal_denials_root": sl.SMT_EMPTY_ROOT,
    }, [eco0["iss_role"]["sk"]])
    ch_wipe2["txs"][ho2["l1_cp1_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(l1_wipe_env)).hex()
    ch_wipe2["txs"][ho2["l2_cp1_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(l2_w2_env)).hex()
    ch_wipe2["txs"][ho2["l2_cp1_tx"]]["outputs"]["1"].pop("spent_by_txid", None)
    ch_wipe2["txs"].pop(ho2["l2_cp2_tx"], None)
    add(
        "d14-b07-handover-2hop-intermediate-seq1-wipe-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ch_wipe2, "checkpoint": l2_w2_env, "checkpoint_txid": ho2["l2_cp1_tx"],
            "predecessor_chain": [
                {"checkpoint": l1_wipe_env, "checkpoint_txid": ho2["l1_cp1_tx"]},
                {"checkpoint": ho2["l0_term_env"], "checkpoint_txid": ho2["l0_term_tx"]},
            ],
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B07: 2-hop intermediate handover L1 (seq=1) wiping predecessor_terminal_denials_root MUST refuse CHAIN_FRAME_INVALID.",
    )

    # 4.6 D14-B12: 0x14 vout 0 OP_RETURN enforcement (kills L6273 & L6278!), handover missing vout 1 (kills L6429!),
    # EOL P2A + change ADMIT (kills L6439 <= -> <!) & EOL P2A + change + vout 3 REFUSE!
    ch_v0_op = copy.deepcopy(eco0["chain_at_cp1"])
    ch_v0_op["txs"][eco0["cp1_tx"]]["opreturns"] = [{"script_pubkey_hex": ch_v0_op["txs"][eco0["cp1_tx"]]["opreturn_hex"], "vout": 1}]
    add(
        "d14-b12-0x14-opreturn-at-vout1-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_v0_op, "checkpoint": eco0["cp1_env"], "checkpoint_txid": eco0["cp1_tx"], "genesis_seal": eco0["gen_seal"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B12: 0x14 SLNK OP_RETURN placed at vout != 0 MUST refuse CHAIN_FRAME_INVALID.",
    )
    ch_v0_out = copy.deepcopy(eco0["chain_at_cp1"])
    ch_v0_out["txs"][eco0["cp1_tx"]]["outputs"]["0"] = {"script_pubkey_hex": _spk_hex(eco0["seal_pol"])}
    add(
        "d14-b12-0x14-vout0-non-opreturn-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_v0_out, "checkpoint": eco0["cp1_env"], "checkpoint_txid": eco0["cp1_tx"], "genesis_seal": eco0["gen_seal"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B12: 0x14 transaction with non-OP_RETURN scriptPubKey at vout 0 MUST refuse CHAIN_FRAME_INVALID.",
    )
    # Handover terminal checkpoint missing vout 1 (or using P2A as continuation!) -> CHAIN_FRAME_INVALID (kills L6429!)
    ch_ho_nop1 = copy.deepcopy(ho2["chain"])
    ch_ho_nop1["txs"][ho2["l0_term_tx"]]["outputs"] = {"1": {"script_pubkey_hex": P2A_SPK_HEX}}
    add(
        "d14-b12-handover-terminal-p2a-vout1-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ch_ho_nop1, "checkpoint": ho2["l0_term_env"], "checkpoint_txid": ho2["l0_term_tx"],
            "prev_checkpoint": eco0["cp2_env"], "prev_checkpoint_txid": eco0["cp2_tx"],
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B12: Handover-capable terminal 0x14 checkpoint carrying P2A (51024e73) at vout 1 instead of handover_next_policy MUST refuse CHAIN_FRAME_INVALID.",
    )
    # EOL terminal 0x14 (no handover_next_policy) with vout 1 = P2A + vout 2 = change -> ADMIT (kills L6439 <= -> <!)
    ch_eol_p2a = copy.deepcopy(eco0["chain"])
    ch_eol_p2a["txs"][eco0["cp4_tx"]]["outputs"] = {
        "1": {"script_pubkey_hex": P2A_SPK_HEX},
        "2": {"script_pubkey_hex": _spk_hex({"kind": "key", "pk": _kp("s4-chg")["comp"]})},
    }
    add(
        "d14-b12-eol-terminal-p2a-plus-change-admit",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ch_eol_p2a, "checkpoint": eco0["cp4_env"], "checkpoint_txid": eco0["cp4_tx"],
            "prev_checkpoint": eco0["cp3_env"], "prev_checkpoint_txid": eco0["cp3_tx"],
        },
        "ADMIT",
        None,
        "D14-B12: Permanent EOL terminal 0x14 checkpoint with vout 1 = P2A (51024e73) + vout 2 = change admits cleanly.",
    )
    ch_eol_p2a_extra = copy.deepcopy(ch_eol_p2a)
    ch_eol_p2a_extra["txs"][eco0["cp4_tx"]]["outputs"]["3"] = {"script_pubkey_hex": _spk_hex({"kind": "key", "pk": _kp("s4-chg3")["comp"]})}
    add(
        "d14-b12-eol-terminal-p2a-vout3-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {
            "chain": ch_eol_p2a_extra, "checkpoint": eco0["cp4_env"], "checkpoint_txid": eco0["cp4_tx"],
            "prev_checkpoint": eco0["cp3_env"], "prev_checkpoint_txid": eco0["cp3_tx"],
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B12: Permanent EOL terminal 0x14 checkpoint with extra vout 3 beyond P2A + change MUST refuse CHAIN_FRAME_INVALID.",
    )
    # Maturing 0x14 with in_mempool=False -> REFUSE CHAIN_FRAME_INVALID!
    ch_mat_ev = copy.deepcopy(eco0["chain_at_cp1"])
    ch_mat_ev["txs"][eco0["cp1_tx"]]["outputs"]["1"]["spent_by_txid"] = _h32("s4-mat-unconf")
    ch_mat_ev["txs"][_h32("s4-mat-unconf")] = {"confirmed_height": None, "in_mempool": False, "inputs": [sv.make_segwit_input(eco0["cp1_tx"], 1)], "outputs": {}}
    add(
        "d14-b12-maturing-0x14-not-in-mempool-refuse",
        ["SL-CONT-012"],
        "log_checkpoint",
        {"chain": ch_mat_ev, "checkpoint": eco0["cp1_env"], "checkpoint_txid": eco0["cp1_tx"], "genesis_seal": eco0["gen_seal"]},
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B12: Maturing 0x14 continuation with confirmed_height=None and in_mempool=False MUST refuse CHAIN_FRAME_INVALID.",
    )
    # RBF-identical equivocation (differing ONLY in prev_log_outpoint) -> REFUSE CHAIN_FRAME_INVALID (NOT equivocation!)
    cp2_rbf_p = {**copy.deepcopy(eco0["cp2_env"]["payload"]), "prev_log_outpoint": {"txid": _h32("s4-rbf-prev"), "vout": 1}}
    cp2_rbf_env = sl.sign_envelope(cp2_rbf_p, [eco0["iss_role"]["sk"]])
    add(
        "d14-b12-rbf-identical-equivocation-not-fraud-refuse",
        ["SL-CONT-013"],
        "log_fraud",
        {
            "chain": eco0["chain"], "expect_zero_closures": True, "expect_zero_writes": True,
            "fraud": {
                "cp_a": eco0["cp2_env"], "cp_b": cp2_rbf_env, "fraud_mode": "equivocation",
                "genesis": GENESIS_MAIN, "genesis_seal_outpoint": eco0["gen_op"], "log_id": eco0["log_id"],
                "network": "main", "role": "notary", "type": "seallink-log-fraud/1",
            },
            "journal": {"journal_id": _h32("s4-rbf-eq-j")},
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B12: Two checkpoints differing ONLY in prev_log_outpoint (legitimate RBF fee bump) MUST NOT prove equivocation.",
    )

    # 4.7 D14-B13: verify_log_fraud hardening (kills L6591, L6611, L6782, L6789 + Mode 3d NAME_HISTORY_UNAVAILABLE zero closures!)
    # (a) cp_b with mismatched role ("release" vs fraud role "notary") -> CHAIN_FRAME_INVALID (kills L6591!)
    cp_wrong_role = sl.sign_envelope({**eco0["cp2_env"]["payload"], "role": "release"}, [eco0["iss_role"]["sk"]])
    add(
        "d14-b13-fraud-cp-role-mismatch-refuse",
        ["SL-CONT-013"],
        "log_fraud",
        {
            "chain": eco0["chain"], "expect_zero_closures": True,
            "fraud": {
                "cp_a": eco0["cp2_env"], "cp_b": cp_wrong_role, "fraud_mode": "equivocation",
                "genesis": GENESIS_MAIN, "genesis_seal_outpoint": eco0["gen_op"], "log_id": eco0["log_id"],
                "network": "main", "role": "notary", "type": "seallink-log-fraud/1",
            },
            "journal": {"journal_id": _h32("s4-fr-role-j")},
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B13: Fraud proof whose cp_b carries role != fraud.role MUST refuse CHAIN_FRAME_INVALID.",
    )
    # (b) Forged predecessor cp_a (seq=1) + forged revocation by Eve claiming L0.log_id committed in L0's checkpoints_root
    #     in revocation_omission against Alice's L2 -> CHAIN_FRAME_INVALID (kills L6609 on BOTH wrong-code & refusal-return!)
    eve14_o, eve14_r = _kp("s4-eve-o"), _kp("s4-eve-r")
    eve14_pol = {"kind": "key", "pk": eve14_o["comp"]}
    eve14_reg = {"txid": _h32("s4-eve-reg"), "vout": 0}
    eve14_pin = {"name": "id/eve-d14", "owner_policy": eve14_pol, "registration": eve14_reg, "role_policy": {"m": 1, "pks": [eve14_r["xonly"]]}}
    eve_dk = f"act:{_h32('eve-fake-act')}|*"
    eve_rev_env = sl.sign_envelope({
        "denial_key": eve_dk, "genesis": GENESIS_MAIN, "issued_at": 1795220000, "issuer": eve14_pin,
        "log_id": eco0["log_id"], "network": "main", "reason_code": "forged-rev", "role": "notary",
        "state_seq": 1, "type": "seallink-log-revocation/1",
    }, [eve14_r["sk"]])
    eve_rev_ed = sl.log_entry_digest(0x02, sl.content_addr(eve_rev_env))
    eve_broot, eve_bpfs = sl.build_merkle_tree([eve_rev_ed])
    eve_cpa_p = {
        **copy.deepcopy(eco0["cp1_env"]["payload"]),
        "batch_count": 1, "batch_root": eve_broot, "denials_delta_root": eve_broot, "issuer": eve14_pin,
    }
    eve_cpa_env = sl.sign_envelope(eve_cpa_p, [eve14_r["sk"]])
    eve_cpa_tx = _h32("s4-eve-cpa-tx")
    eve_l0_leaves = [sl.ckpt_leaf(1, sl.content_addr(eve_cpa_env)), sl.ckpt_leaf(2, sl.content_addr(eco0["cp2_env"]))]
    l0_term_eve_p = {
        **copy.deepcopy(ho2["l0_term_env"]["payload"]),
        "checkpoints_root": sl.rfc9162_mth(eve_l0_leaves).hex(),
    }
    l0_term_eve_env = sl.sign_envelope(l0_term_eve_p, [eco0["iss_role"]["sk"]])
    ch_eve_fr = copy.deepcopy(ho2["chain"])
    ch_eve_fr["names"]["id/eve-d14"] = sv.make_name_history("id/eve-d14", eve14_reg, eve14_pol, {"link": {"notary": eve14_r["xonly"]}}, first_height=748000, update_height=749000)
    ch_eve_fr["txs"][ho2["l0_term_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(l0_term_eve_env)).hex()
    ch_eve_fr["txs"][eve_cpa_tx] = {"block_hash": _h32("s4-eve-blk"), "confirmed_height": 749994, "opreturn_hex": sl.encode_opreturn(0x14, sl.content_addr(eve_cpa_env)).hex(), "outputs": {}}
    pred_chain_eve = [
        {"checkpoint": ho2["l1_cp1_env"], "checkpoint_txid": ho2["l1_cp1_tx"]},
        {"checkpoint": l0_term_eve_env, "checkpoint_txid": ho2["l0_term_tx"]},
    ]
    add(
        "d14-b13-fraud-forged-predecessor-issuer-refuse",
        ["SL-CONT-013"],
        "log_fraud",
        {
            "chain": ch_eve_fr, "expect_zero_closures": True,
            "fraud": {
                "batch_proof": eve_bpfs[eve_rev_ed],
                "checkpoints_proof": sl.rfc9162_inclusion_proof(eve_l0_leaves, 0),
                "cp_a": eve_cpa_env, "cp_a_txid": eve_cpa_tx,
                "cp_b": ho2["l2_cp1_env"], "cp_b_txid": ho2["l2_cp1_tx"], "fraud_mode": "revocation_omission",
                "genesis": GENESIS_MAIN, "genesis_seal_outpoint": ho2["l2_gen_op"], "log_id": ho2["l2_lid"],
                "network": "main", "predecessor_chain": pred_chain_eve,
                "predecessor_log_id": ho2["l1_lid"], "revocation": eve_rev_env,
                "role": "notary", "smt_proof": sl.smt_prove(eco0["kv3"], eve_dk),
                "type": "seallink-log-fraud/1",
            },
            "journal": {"journal_id": _h32("s4-eve-fr-j")},
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B13: Forged predecessor cp_a + forged revocation signed by another issuer claiming predecessor log_id MUST refuse CHAIN_FRAME_INVALID.",
    )
    # (c) Cross-handover illegal_reversion (cp_a on L0, cp_b on L2 seq=2):
    #     - rec_b_inclusion pointing to L0 (wrong log_id != L2) -> REFUSE CHAIN_FRAME_INVALID (kills L6782!)
    #     - rec_b_inclusion pointing to L2 at EXACT seq_ib == 1 (bad reinstatement inserted at L2.seq=1, persisted in L2.seq=2!) -> ADMIT (kills L6789 seq_ib >= 1 -> > 1!)
    # Build a dedicated handover chain where L2.seq=1 inserts an illegal reinstatement (state_seq=1 <= rev1.state_seq=1!) and L2.seq=2 carries it!
    ho_ir = _mk_handover_log_chain("d14-ho-ir")
    eco_ir = ho_ir["eco0"]
    bad_reinst_p = {
        "denial_key": eco_ir["denial_key"], "genesis": GENESIS_MAIN, "issued_at": 1795220000,
        "issuer": eco_ir["iss_role_pin"], "log_id": ho_ir["l2_lid"], "network": "main",
        "prev_record_id": _h32("wrong-prev-rec"),  # illegal! prev_record_id != content_addr(rev1_env)
        "reason_code": "bad-reinst", "role": "notary", "state_seq": 2,
        "type": "seallink-log-reinstatement/1",
    }
    bad_reinst_env = sl.sign_envelope(bad_reinst_p, [eco_ir["iss_role"]["sk"]])
    bad_reinst_ca = sl.content_addr(bad_reinst_env)
    bad_reinst_ed = sl.log_entry_digest(0x03, bad_reinst_ca)
    b1_ir_root, b1_ir_pfs = sl.build_merkle_tree([bad_reinst_ed])
    kv_ir_bad = {eco_ir["denial_key"]: bad_reinst_ca}
    dr_ir_bad = sl.smt_root(kv_ir_bad)
    # Put bad_reinst at L2.seq=2 (so seq_ib == 2, since handover L2.seq==1 MUST have empty denials_delta_root!) and keep it at L2.seq=2 (cp_b == L2.cp2)!
    l2_ir_cp1_env = ho_ir["l2_cp1_env"]
    l2_ir_cp1_ca = sl.content_addr(l2_ir_cp1_env)
    l2_ir_ck1 = [sl.ckpt_leaf(1, l2_ir_cp1_ca)]
    l2_ir_cp2_p = {
        **ho_ir["l2_cp2_env"]["payload"],
        "batch_count": 1, "batch_root": b1_ir_root,
        "checkpoints_root": sl.rfc9162_mth(l2_ir_ck1).hex(),
        "cumulative_entries_count": 1, "denials_delta_root": b1_ir_root,
        "denials_root": dr_ir_bad, "prev_checkpoint_id": l2_ir_cp1_ca,
    }
    l2_ir_cp2_env = sl.sign_envelope(l2_ir_cp2_p, [eco_ir["iss_role"]["sk"]])
    ch_ir = copy.deepcopy(ho_ir["chain"])
    ch_ir["txs"][ho_ir["l2_cp2_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(l2_ir_cp2_env)).hex()
    # (c1) Wrong rec_b_inclusion.checkpoint.payload.log_id (points to L0 where bad_reinst IS included in L0.cp3 batch, while cp_b is L2.cp3 seq==3!)
    #      Deleting L6774 lets _verify_state_record_inclusion_height succeed on L0.cp3 (seq_ib==3 <= seq_b==3) and falsely ADMIT!
    ch_ir_wl = copy.deepcopy(ch_ir)
    l0_wl_broot, l0_wl_bpfs = sl.build_merkle_tree([sl.log_entry_digest(0x02, sl.content_addr(eco_ir["rev1_env"])), bad_reinst_ed])
    l0_wl_cp3_p = {**ho_ir["l0_term_env"]["payload"], "batch_count": 2, "batch_root": l0_wl_broot, "denials_delta_root": l0_wl_broot}
    l0_wl_cp3_env = sl.sign_envelope(l0_wl_cp3_p, [eco_ir["iss_role"]["sk"]])
    ch_ir_wl["txs"][ho_ir["l0_term_tx"]]["opreturn_hex"] = sl.encode_opreturn(0x14, sl.content_addr(l0_wl_cp3_env)).hex()
    # Add L2.cp3 (seq=3) so seq_b == 3 >= seq_ib (3) on L0.cp3!
    l2_ir_cp3_tx = _h32("d14-ho-ir-l2-cp3")
    l2_ir_cp2_ca = sl.content_addr(l2_ir_cp2_env)
    l2_ir_ck2 = l2_ir_ck1 + [sl.ckpt_leaf(2, l2_ir_cp2_ca)]
    l2_ir_cp3_env = sl.sign_envelope({
        **l2_ir_cp2_p, "batch_count": 0, "batch_root": sl.EMPTY_BATCH_ROOT,
        "checkpoints_root": sl.rfc9162_mth(l2_ir_ck2).hex(), "denials_delta_root": sl.EMPTY_BATCH_ROOT,
        "prev_checkpoint_id": l2_ir_cp2_ca, "prev_log_outpoint": {"txid": ho_ir["l2_cp2_tx"], "vout": 1}, "seq": 3,
    }, [eco_ir["iss_role"]["sk"]])
    ch_ir_wl["txs"][ho_ir["l2_cp2_tx"]]["outputs"]["1"]["spent_by_txid"] = l2_ir_cp3_tx
    ch_ir_wl["txs"][l2_ir_cp3_tx] = {
        "block_hash": _h32("d14-ho-ir-blk-l2-3"), "confirmed_height": 750002,
        "inputs": [sv.make_segwit_input(ho_ir["l2_cp2_tx"], 1)],
        "opreturn_hex": sl.encode_opreturn(0x14, sl.content_addr(l2_ir_cp3_env)).hex(),
        "outputs": {"1": {"script_pubkey_hex": _spk_hex(eco_ir["seal_pol"])}},
    }
    pred_chain_wl = [
        {"checkpoint": ho_ir["l1_cp1_env"], "checkpoint_txid": ho_ir["l1_cp1_tx"]},
        {"checkpoint": l0_wl_cp3_env, "checkpoint_txid": ho_ir["l0_term_tx"]},
    ]
    add(
        "d14-b13-fraud-illegal-reversion-inc-b-wrong-log-id-refuse",
        ["SL-CONT-013"],
        "log_fraud",
        {
            "chain": ch_ir_wl, "expect_zero_closures": True,
            "fraud": {
                "cp_a": l0_wl_cp3_env, "cp_a_txid": ho_ir["l0_term_tx"],
                "cp_b": l2_ir_cp3_env, "cp_b_txid": l2_ir_cp3_tx,
                "fraud_mode": "illegal_reversion", "genesis": GENESIS_MAIN,
                "genesis_seal_outpoint": ho_ir["l2_gen_op"], "log_id": ho_ir["l2_lid"],
                "network": "main", "predecessor_chain": pred_chain_wl,
                "predecessor_log_id": ho_ir["l1_lid"], "rec_a": eco_ir["rev1_env"],
                "rec_b": bad_reinst_env,
                "rec_b_inclusion": {
                    "batch_proof": l0_wl_bpfs[bad_reinst_ed], "checkpoint": l0_wl_cp3_env, "checkpoint_txid": ho_ir["l0_term_tx"],
                },
                "role": "notary",
                "smt_proof_a": sl.smt_prove(eco_ir["kv3"], eco_ir["denial_key"]),
                "smt_proof_b": sl.smt_prove(kv_ir_bad, eco_ir["denial_key"]),
                "type": "seallink-log-fraud/1",
            },
            "journal": {"journal_id": _h32("s4-ir-wlid-j")},
        },
        "REFUSE",
        "CHAIN_FRAME_INVALID",
        "D14-B13: illegal_reversion rec_b_inclusion belonging to predecessor log_id != target log_id MUST refuse CHAIN_FRAME_INVALID.",
    )
    # (c2) Valid cross-handover illegal_reversion with rec_b_inclusion at exact L2.seq == 2 -> ADMIT (kills seq_ib >= 2 -> > 2!)
    add(
        "d14-b13-fraud-cross-handover-illegal-reversion-seq2-admit",
        ["SL-CONT-013"],
        "log_fraud",
        {
            "chain": ch_ir,
            "fraud": {
                "cp_a": ho_ir["l0_term_env"], "cp_a_txid": ho_ir["l0_term_tx"],
                "cp_b": l2_ir_cp2_env, "cp_b_txid": ho_ir["l2_cp2_tx"],
                "fraud_mode": "illegal_reversion", "genesis": GENESIS_MAIN,
                "genesis_seal_outpoint": ho_ir["l2_gen_op"], "log_id": ho_ir["l2_lid"],
                "network": "main", "predecessor_chain": ho_ir["pred_chain_for_l2"],
                "predecessor_log_id": ho_ir["l1_lid"], "rec_a": eco_ir["rev1_env"],
                "rec_b": bad_reinst_env,
                "rec_b_inclusion": {
                    "batch_proof": b1_ir_pfs[bad_reinst_ed], "checkpoint": l2_ir_cp2_env, "checkpoint_txid": ho_ir["l2_cp2_tx"],
                },
                "role": "notary",
                "smt_proof_a": sl.smt_prove(eco_ir["kv3"], eco_ir["denial_key"]),
                "smt_proof_b": sl.smt_prove(kv_ir_bad, eco_ir["denial_key"]),
                "type": "seallink-log-fraud/1",
            },
            "journal": {"journal_id": _h32("s4-ir-ok-j")},
        },
        "ADMIT",
        None,
        "D14-B13: Cross-handover illegal_reversion (cp_a on L0, cp_b on L2 seq=2) with rec_b_inclusion at exact L2 seq==2 proves fraud and closes L2.",
    )
    # (d) Mode 3d (invalid_checkpoint_chain) with NAME_HISTORY_UNAVAILABLE -> MUST REFUSE with ZERO closures (never close honest log!)
    ch_3d_unav = copy.deepcopy(eco0["chain"])
    ch_3d_unav["names"][eco0["iss_name"]]["history_truncated"] = True
    ch_3d_unav["names"][eco0["iss_name"]]["first_error_height"] = 749000
    add(
        "d14-b13-fraud-mode-3d-history-unavailable-zero-closures",
        ["SL-CONT-013"],
        "log_fraud",
        {
            "chain": ch_3d_unav, "expect_zero_closures": True, "expect_zero_writes": True,
            "fraud": {
                "cp_next": eco0["cp2_env"], "cp_next_txid": eco0["cp2_tx"],
                "cp_prev": eco0["cp1_env"], "cp_prev_txid": eco0["cp1_tx"],
                "fraud_mode": "invalid_checkpoint_chain", "genesis": GENESIS_MAIN,
                "genesis_seal_outpoint": eco0["gen_op"], "log_id": eco0["log_id"],
                "network": "main", "peaks": [sl.ckpt_leaf(1, sl.content_addr(eco0["cp1_env"])).hex()],
                "role": "notary", "type": "seallink-log-fraud/1",
            },
            "journal": {"journal_id": _h32("s4-3d-unav-j")},
        },
        "REFUSE",
        "NAME_HISTORY_UNAVAILABLE",
        "D14-B13: Mode 3d invalid_checkpoint_chain with NAME_HISTORY_UNAVAILABLE MUST refuse cleanly with ZERO closures.",
    )

    # ========================================================================
    # SECTION 5: D14-B08 Tier-2 SPV Full Hardening
    # ========================================================================
    t2_o1 = _kp("s5-t2-o1")
    t2_o2 = _kp("s5-t2-o2")
    t2_not = _kp("s5-t2-not")
    t2_pol1 = {"kind": "key", "pk": t2_o1["comp"]}
    t2_pol2 = {"kind": "key", "pk": t2_o2["comp"]}

    # 5.1 main network at height > 0 without trusted_checkpoint -> TICKET_PROOF_INVALID (kills L7490 on BOTH refusal-return & wrong-code!)
    # Use the real 80-byte Namecoin Mainnet Genesis header (valid mainnet PoW 0x1c007fff, nVersion=1) placed at height=1 with valid next_header_checkpoint!
    pr_m, hdr_m = bd11._build_synthetic_spv_proof(
        "d14-t2-main", t2_pol1, [t2_o1["sk"]], "id/t2-main-chk", sl.jcs_encode({"link": {"notary": t2_not["xonly"]}}).decode(),
        block_height=750010, block_time=1795220000,
    )
    nmc_main_gen_hdr = struct.pack("<I", 1) + (b"\x00" * 32) + bytes.fromhex("41c62dbd9068c89a449525e3cd5ac61b20ece28c3c38b3f35b2161f0e6d3cb0d")[::-1] + struct.pack("<III", 1303000001, 0x1C007FFF, 0xA21EA192)
    nhc_main_h1 = {
        "block_hash": GENESIS_MAIN, "epoch_start_time": 1303000001, "height": 1,
        "nbits_hex": "1c007fff", "recent_11_times": [1303000001],
    }
    add(
        "d14-b08-tier2-main-without-trusted-checkpoint-refuse",
        ["SL-ARTF-005", "SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_pol1,
            "page": {**bd13._mk_t2_page("id/t2-main-chk", [], headers=[{"header_hex": nmc_main_gen_hdr.hex(), "height": 1}], network="main", has_more=True), "next_header_checkpoint": nhc_main_h1},
            "pinned_network": "main",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "D14-B08: Tier-2 SPV page on 'main' starting at height > 0 without trusted_checkpoint MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    # 5.2 height == 0 enforces pinned_genesis (mismatch refuses -> kills L7520!; match admits!)
    hdr_h0 = bd13._mine_regtest_hdr(1, b"\x00" * 32, b"\x11" * 32, 1795220000, 0x207FFFFF)
    hdr_h0_hash = sl.dsha256(hdr_h0)[::-1].hex()
    nhc_h0 = {"block_hash": hdr_h0_hash, "epoch_start_time": 1795220000, "height": 0, "nbits_hex": "207fffff", "recent_11_times": [1795220000]}
    pg_h0 = {**bd13._mk_t2_page("id/t2-gen0", [], headers=[{"header_hex": hdr_h0.hex(), "height": 0}], has_more=True), "next_header_checkpoint": nhc_h0}
    add(
        "d14-b08-tier2-height0-wrong-pinned-genesis-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {"expected_owner_policy": t2_pol1, "page": pg_h0, "pinned_network": "regtest"},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "D14-B08: Tier-2 SPV page starting at height==0 whose block hash != pinned_genesis MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    add(
        "d14-b08-tier2-height0-matching-pinned-genesis-admit",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_pol1,
            "page": {**pg_h0, "genesis": hdr_h0_hash},
            "pinned_genesis": hdr_h0_hash, "pinned_network": "regtest",
        },
        "ADMIT",
        None,
        "D14-B08: Tier-2 SPV header-only bridging page starting at height==0 matching pinned_genesis admits cleanly.",
        module="artifact-notarization",
    )

    # 5.3 trusted_checkpoint.recent_11_times[-1] mismatch (kills L7533!) & 2-header MTP(11) enforcement
    hdr_r0 = bd13._mine_regtest_hdr(0x00010004, b"\x10" * 32, b"\x20" * 32, 1795220000, 0x207FFFFF)
    hdr_r0_le = sl.dsha256(hdr_r0)
    hdr_r0_hex = hdr_r0_le[::-1].hex()
    hdr_r1 = bd13._mine_regtest_hdr(0x00010004, hdr_r0_le, b"\x21" * 32, 1795220060, 0x207FFFFF)
    hdr_r1_hex = sl.dsha256(hdr_r1)[::-1].hex()
    tc_r0_ok = {
        "block_hash": hdr_r0_hex, "epoch_start_time": 1795200000, "height": 750010,
        "nbits_hex": "207fffff", "recent_11_times": [1795219000 + i * 100 for i in range(11)],
    }
    tc_r0_bad_last = {**tc_r0_ok, "recent_11_times": [1795219000 + i * 100 for i in range(10)] + [1795220001]}
    exp_nhc = {
        "block_hash": hdr_r1_hex, "epoch_start_time": 1795200000, "height": 750011,
        "nbits_hex": "207fffff", "recent_11_times": tc_r0_ok["recent_11_times"][1:] + [1795220060],
    }
    pg_br = {
        **bd13._mk_t2_page(
            "id/t2-bridge", [],
            headers=[{"header_hex": hdr_r0.hex(), "height": 750010}, {"header_hex": hdr_r1.hex(), "height": 750011}],
            has_more=True,
        ),
        "next_header_checkpoint": exp_nhc,
    }
    add(
        "d14-b08-tier2-tc-recent-11-times-last-mismatch-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {"expected_owner_policy": t2_pol1, "page": pg_br, "pinned_network": "regtest", "trusted_checkpoint": tc_r0_bad_last},
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "D14-B08: trusted_checkpoint.recent_11_times[-1] != headers[0].ntime MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    # 2-header page where headers[1].ntime <= median(recent_11_times) -> MTP(11) refusal!
    hdr_r1_mtp_bad = bd13._mine_regtest_hdr(0x00010004, hdr_r0_le, b"\x22" * 32, 1795219500, 0x207FFFFF)
    nhc_mtp_bad = {
        "block_hash": sl.dsha256(hdr_r1_mtp_bad)[::-1].hex(), "epoch_start_time": 1795200000, "height": 750011,
        "nbits_hex": "207fffff", "recent_11_times": tc_r0_ok["recent_11_times"][1:] + [1795219500],
    }
    add(
        "d14-b08-tier2-tc-recent-11-times-mtp11-enforced-on-header1",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_pol1,
            "page": {**bd13._mk_t2_page("id/t2-bridge", [], headers=[{"header_hex": hdr_r0.hex(), "height": 750010}, {"header_hex": hdr_r1_mtp_bad.hex(), "height": 750011}], has_more=True), "next_header_checkpoint": nhc_mtp_bad},
            "pinned_network": "regtest", "trusted_checkpoint": tc_r0_ok,
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "D14-B08: trusted_checkpoint.recent_11_times seeds MTP(11) so a 2-header page enforces ntime > MTP(11) on headers[1].",
        module="artifact-notarization",
    )

    # 5.4 next_header_checkpoint verification (matching ADMIT, tampered refuses -> kills L7587!)
    add(
        "d14-b08-tier2-bridging-next-header-checkpoint-admit",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expect_next_header_checkpoint": exp_nhc, "expected_owner_policy": t2_pol1,
            "page": pg_br,
            "pinned_network": "regtest", "trusted_checkpoint": tc_r0_ok,
        },
        "ADMIT",
        None,
        "D14-B08: Header-only bridging page with matching next_header_checkpoint admits and outputs exact next_header_checkpoint.",
        module="artifact-notarization",
    )
    add(
        "d14-b08-tier2-bridging-next-header-checkpoint-tampered-refuse",
        ["SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_pol1,
            "page": {**pg_br, "next_header_checkpoint": {**exp_nhc, "block_hash": _h32("bad-nhc")}},
            "pinned_network": "regtest", "trusted_checkpoint": tc_r0_ok,
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "D14-B08: Header-only bridging page with tampered next_header_checkpoint MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    # 5.5 Tier-1 parity: SL-IDEN-003 owner-key reuse in Tier-2 value -> TICKET_PROOF_INVALID (kills L7637!)
    pr_coll, hdr_coll = bd11._build_synthetic_spv_proof(
        "d14-t2-coll", t2_pol1, [t2_o1["sk"]], "id/t2-coll", sl.jcs_encode({"link": {"notary": t2_o1["xonly"]}}).decode(),
        block_height=750010, block_time=1795220000,
    )
    add(
        "d14-b08-tier2-owner-key-reused-as-role-refuse",
        ["SL-ARTF-005", "SL-IDEN-003"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_pol1,
            "page": bd13._mk_t2_page("id/t2-coll", [pr_coll], headers=[{"header_hex": hdr_coll.hex(), "height": 750010}]),
            "pinned_network": "regtest",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "D14-B08 / SL-IDEN-003: Tier-2 owner-authored update reusing owner_policy pubkey as link.notary MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    # 5.6 Post-FIRSTUPDATE header-only bridging page: exact expiry boundary (kills L7710 >= -> > & L7715!) + next_cursor.owner_policy mismatch (kills L7718!)
    br_cur_tx = _h32("s5-br-cur")
    # regtest name_expiry == 30: prev_h=750011 -> cursor_height=749982 gives 750011 < 749982+30=750012 (ADMIT!),
    # while cursor_height=749981 gives EXACT 750011 == 749981+30 (REFUSE!)
    add(
        "d14-b08-tier2-post-fu-bridging-before-expiry-admit",
        ["SL-ARTF-005", "SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_pol1,
            "page": bd13._mk_t2_page(
                "id/t2-bridge", [],
                headers=[{"header_hex": hdr_r0.hex(), "height": 750010}, {"header_hex": hdr_r1.hex(), "height": 750011}],
                cursor_height=749982, cursor_txid=br_cur_tx, cursor_vout=0, cursor_owner_policy=t2_pol1,
                next_cursor={"height": 749982, "owner_policy": t2_pol1, "txid": br_cur_tx, "vout": 0},
                has_more=True,
            ),
            "pinned_network": "regtest", "trusted_checkpoint": tc_r0_ok,
        },
        "ADMIT",
        None,
        "D14-B08: Post-FIRSTUPDATE header-only bridging page at prev_h == cursor_height + name_expiry - 1 (29 < 30) admits.",
        module="artifact-notarization",
    )
    add(
        "d14-b08-tier2-post-fu-bridging-exact-expiry-refuse",
        ["SL-ARTF-005", "SL-ARTF-006"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_pol1,
            "page": bd13._mk_t2_page(
                "id/t2-bridge", [],
                headers=[{"header_hex": hdr_r0.hex(), "height": 750010}, {"header_hex": hdr_r1.hex(), "height": 750011}],
                cursor_height=749981, cursor_txid=br_cur_tx, cursor_vout=0, cursor_owner_policy=t2_pol1,
                next_cursor={"height": 749981, "owner_policy": t2_pol1, "txid": br_cur_tx, "vout": 0},
                has_more=True,
            ),
            "pinned_network": "regtest", "trusted_checkpoint": tc_r0_ok,
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "D14-B08: Post-FIRSTUPDATE header-only bridging page reaching exact expiry (prev_h == cursor_height + name_expiry) MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    add(
        "d14-b08-tier2-post-fu-bridging-next-cursor-policy-mismatch-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_pol1,
            "page": bd13._mk_t2_page(
                "id/t2-bridge", [],
                headers=[{"header_hex": hdr_r0.hex(), "height": 750010}, {"header_hex": hdr_r1.hex(), "height": 750011}],
                cursor_height=749982, cursor_txid=br_cur_tx, cursor_vout=0, cursor_owner_policy=t2_pol1,
                next_cursor={"height": 749982, "owner_policy": t2_pol2, "txid": br_cur_tx, "vout": 0},
                has_more=True,
            ),
            "pinned_network": "regtest", "trusted_checkpoint": tc_r0_ok,
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "D14-B08: Post-FIRSTUPDATE header-only bridging page whose next_cursor.owner_policy mismatches cursor policy MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )

    # 5.7 Terminal page final_owner_policy on trailing rotation (matching, omitted->None, wrong -> kills L7724!) & non-rotation (wrong -> kills L7731!)
    pr_tr, hdr_tr = bd11._build_synthetic_spv_proof(
        "d14-t2-tr", t2_pol1, [t2_o1["sk"]], "id/t2-tr", "{}",
        block_height=750010, block_time=1795220000, new_owner_pol=t2_pol2,
    )
    pg_tr_base = bd13._mk_t2_page("id/t2-tr", [pr_tr], headers=[{"header_hex": hdr_tr.hex(), "height": 750010}], has_more=False)
    add(
        "d14-b08-tier2-terminal-trailing-rotation-final-policy-admit",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {
            "expect_next_cursor_owner_policy": t2_pol2, "expected_owner_policy": t2_pol1,
            "page": {**pg_tr_base, "final_owner_policy": t2_pol2}, "pinned_network": "regtest",
        },
        "ADMIT",
        None,
        "D14-B08: Terminal page ending on trailing rotation with matching final_owner_policy=P2 admits and outputs P2.",
        module="artifact-notarization",
    )
    add(
        "d14-b08-tier2-terminal-trailing-rotation-omitted-final-policy-none",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {
            "expect_final_owner_policy_is_none": True, "expected_owner_policy": t2_pol1,
            "page": pg_tr_base, "pinned_network": "regtest",
        },
        "ADMIT",
        None,
        "D14-B08: Terminal page ending on trailing rotation without final_owner_policy outputs final_owner_policy=None (never stale P1).",
        module="artifact-notarization",
    )
    add(
        "d14-b08-tier2-terminal-trailing-rotation-wrong-final-policy-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_pol1,
            "page": {**pg_tr_base, "final_owner_policy": t2_pol1}, "pinned_network": "regtest",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "D14-B08: Terminal page ending on trailing rotation P1->P2 with stale final_owner_policy=P1 MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
    pg_norot = bd13._mk_t2_page("id/t2-main-chk", [pr_m], headers=[{"header_hex": hdr_m.hex(), "height": 750010}], has_more=False)
    add(
        "d14-b08-tier2-terminal-non-rotation-wrong-final-policy-refuse",
        ["SL-ARTF-005"],
        "tier2_name_history",
        {
            "expected_owner_policy": t2_pol1,
            "page": {**pg_norot, "final_owner_policy": t2_pol2}, "pinned_network": "regtest",
        },
        "REFUSE",
        "TICKET_PROOF_INVALID",
        "D14-B08: Terminal page without rotation carrying mismatched final_owner_policy=P2 MUST refuse TICKET_PROOF_INVALID.",
        module="artifact-notarization",
    )
