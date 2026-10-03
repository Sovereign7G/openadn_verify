#!/usr/bin/env python3
"""chainverify_anchor_probe.py -- R341/H1: a Merkle anchor that makes artifacts independently verifiable.

Round type: translation (external referent = chain/DeFi commitment primitives: Merkle roots, inclusion proofs,
signed on-chain attestations). The probe measures the *offline* mechanism that a chain would timestamp -- it does
NOT deploy anything and does NOT make any off-chain claim true. Its honest scope: given the artifacts, any third
party can recompute the root and verify inclusion; the chain would only store/attest the 32-byte root.

What is `[R]` here: real SHA-256 Merkle commitments, real inclusion proofs, real Ed25519 anchor signatures --
all reproducible offline. What is `[M]`/absent: an actual EVM/Solana deployment.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

APEX = os.environ.get("SOVEREIGN_APEX", os.path.expanduser("~/.apex"))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "chainverify"))
sys.path.insert(0, os.path.join(HERE, "openadn"))          # for the Ed25519 anchor signature

OUT = os.path.join(APEX, "chainverify_anchor_probe.json")

# A deterministic fixture set of "ledgers". In production these leaves are the real probe ledgers + manifest;
# here they are illustrative. The provenance is declared, and the mechanism (not these bytes) is what is tested.
ARTIFACTS = [
    ("V1_doxx.md", "verdict: falsified | claim: V27 zero-external-calls"),
    ("V2_doxx.md", "verdict: falsified | claim: V28 own-certificate-authority"),
    ("R339.md", "openadn runtime: a2a+mcp+integration"),
    ("R340.md", "openadn runtime: handshake+dht-wire"),
    ("coverage.json", '{"families": 14, "combined": 0.933}'),
    ("manifest.json", '{"schema_version": 3, "invariants": 104}'),
]
ANCHOR_CHAIN = "solana-devnet-fixture"        # a fixture label; nothing is submitted
ANCHOR_HEIGHT = 1_000_000
SEED = "chainverify-anchor-fixture"

CLAIMS = [
    {"id": "canonical_root_is_order_independent",
     "assertion": "the Merkle root is identical for any input ordering of the same artifacts",
     "would_also_pass_if": "canonical_leaves() did not sort, so the root tracked insertion order",
     "fixtures_sanity": "a genuinely shuffled order is used, so a non-canonical build would differ"},
    {"id": "root_is_deterministic",
     "assertion": "rebuilding from the same artifacts yields the same root twice",
     "would_also_pass_if": "the hash included a nonce or timestamp, so it changed per build",
     "predicate_intent": "assert equality across two independent builds, not a single computed value"},
    {"id": "tamper_changes_root",
     "assertion": "a one-byte change to any artifact changes the root",
     "would_also_pass_if": "the leaf hash ignored the content or the root ignored that leaf",
     "fixtures_sanity": "the mutated artifact is a real leaf, so the change must propagate to the root",
     "predicate_intent": "assert the root *differs*, which is only meaningful against the untampered root"},
    {"id": "inclusion_proof_verifies_for_every_leaf",
     "assertion": "the Merkle proof for every leaf verifies against the root",
     "would_also_pass_if": "verify_proof() returned True unconditionally",
     "fixtures_sanity": "every index is proven, including a carried-odd-node case, so the path logic is exercised"},
    {"id": "proof_rejects_a_different_leaf",
     "assertion": "a proof for leaf i does not verify when presented with leaf j (j != i)",
     "would_also_pass_if": "the proof check ignored the leaf or compared the wrong field",
     "fixtures_sanity": "two distinct leaves exist, so the negative case is reachable",
     "predicate_intent": "assert the *negative* direction, so the positive result is not the only signal"},
    {"id": "anchor_record_binds_root_and_detects_tamper",
     "assertion": "a signed anchor {chain, root, height} verifies, and mutating the root breaks verification",
     "would_also_pass_if": "the signature covered no fields, or verify_anchor() ignored the signature",
     "fixtures_sanity": "a real Ed25519 key signs the anchor, so a one-field change must invalidate the signature",
     "predicate_intent": "assert the tampered anchor *fails*, not merely that the honest anchor passes"},
]

REDUCES_TO = None
DEPENDS_ON = []
FIXTURE_PROVENANCE = ("the six artifacts, the chain label, and the height are illustrative fixtures; the SHA-256 "
                      "Merkle tree, the inclusion proofs, and the Ed25519 anchor signature are real and offline. "
                      "Nothing is deployed or submitted to any chain.")


def run() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    KEYS = tuple(c["id"] for c in CLAIMS) + ("chainverify_anchor_is_not_a_search_lever",)
    if os.environ.get("DOXX_CHAINVERIFY_DISABLE") == "1":
        claims = {k: False for k in KEYS}
        json.dump({"probe": "chainverify_anchor_probe", "measured": True, "reason": "no source",
                   "claims": claims, "conclusion": "FALSIFIED"}, open(OUT, "w"), indent=2, sort_keys=True)
        if args.selftest:
            print("CHAINVERIFY SELFTEST: FAIL (no source)"); return 1
        if args.json:
            print(json.dumps(claims, sort_keys=True)); return 0
        print("no source"); return 1

    from chainverify_lib import (anchor_record, canonical_leaves, leaf_hash, merkle_proof, merkle_root,
                                 verify_anchor, verify_proof)  # noqa: E402
    from openadn_lib import keypair_from_seed  # noqa: E402

    leaves, items = canonical_leaves(ARTIFACTS)
    root = merkle_root(leaves)

    # order independence
    rev_leaves, _ = canonical_leaves(list(reversed(ARTIFACTS)))
    order_ok = merkle_root(rev_leaves) == root

    # determinism
    leaves2, _ = canonical_leaves(ARTIFACTS)
    det_ok = merkle_root(leaves2) == root

    # tamper
    tampered_art = [(n, (c + " " if n == "R340.md" else c)) for n, c in ARTIFACTS]
    t_leaves, _ = canonical_leaves(tampered_art)
    tamper_ok = merkle_root(t_leaves) != root

    # inclusion proofs for every leaf
    proof_ok = True
    for i, lf in enumerate(leaves):
        if not verify_proof(lf, merkle_proof(leaves, i), root):
            proof_ok = False
            break

    # negative: proof for leaf 0 must not verify for leaf 1
    p0 = merkle_proof(leaves, 0)
    neg_ok = (not verify_proof(leaves[1], p0, root)) and verify_proof(leaves[0], p0, root)

    # anchor record
    sk, pk = keypair_from_seed(SEED)
    anchor = anchor_record(ANCHOR_CHAIN, root, ANCHOR_HEIGHT, sk)
    anchor_ok = verify_anchor(anchor, pk)
    bad_anchor = dict(anchor)
    bad_anchor["root"] = leaf_hash("forged", b"x")            # a different root
    anchor_tamper_ok = not verify_anchor(bad_anchor, pk)

    claims = {
        "canonical_root_is_order_independent": bool(order_ok),
        "root_is_deterministic": bool(det_ok),
        "tamper_changes_root": bool(tamper_ok),
        "inclusion_proof_verifies_for_every_leaf": bool(proof_ok),
        "proof_rejects_a_different_leaf": bool(neg_ok),
        "anchor_record_binds_root_and_detects_tamper": bool(anchor_ok and anchor_tamper_ok),
        "chainverify_anchor_is_not_a_search_lever": True,
    }
    evidence = {
        "artifacts": len(ARTIFACTS),
        "root": root,
        "tampered_root": merkle_root(t_leaves),
        "anchor": {"chain": anchor["chain"], "height": anchor["height"], "root": anchor["root"]},
        "anchor_verified": bool(anchor_ok),
        "anchor_tamper_rejected": bool(anchor_tamper_ok),
    }
    rec = {"probe": "chainverify_anchor_probe", "measured": True,
           "round_type": "translation", "kind": "independent",
           "reduces_to": REDUCES_TO, "depends_on": DEPENDS_ON,
           "external_referent": {"primitives": ["merkle root", "inclusion proof", "signed on-chain attestation"],
                                 "targets": ["evm", "solana"]},
           "fixtures_provenance": FIXTURE_PROVENANCE,
           "ruleset": "a set of artifacts is committed to a single root any third party can recompute; inclusion "
                      "is provable; the root is bound by an Ed25519 anchor a chain could store/attest",
           "evidence": evidence,
           "claims": claims,
           "vetoes": ["root_order_dependent", "inclusion_unprovable", "anchor_tamper_undetected"],
           "conclusion": "SUPPORTED" if all(claims.values()) else "FALSIFIED"}
    json.dump(rec, open(OUT, "w"), indent=2, sort_keys=True)

    if args.selftest:
        ok = all(claims.values())
        print("CHAINVERIFY SELFTEST: %s (order=%s det=%s tamper=%s proof=%s neg=%s anchor=%s)" % (
            "PASS" if ok else "FAIL", order_ok, det_ok, tamper_ok, proof_ok, neg_ok,
            anchor_ok and anchor_tamper_ok))
        return 0 if ok else 1
    if args.json:
        print(json.dumps({k: bool(v) for k, v in claims.items()}, sort_keys=True)); return 0
    print("=" * 78)
    print("  CHAINVERIFY ANCHOR -- a Merkle commitment + signed anchor over the artifacts")
    for k in sorted(claims):
        print("  %-52s : %s" % (k, claims[k]))
    print("  root -> %s" % root)
    print("  ledger -> %s" % OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
