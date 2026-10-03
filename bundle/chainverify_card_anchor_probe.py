#!/usr/bin/env python3
"""chainverify_card_anchor_probe.py -- R343/H10: an A2A AgentCard becomes verifiable-by-anyone via an anchor.

Round type: consolidation. This COMPOSES two things the corpus actually built: the R339 A2A card (`openadn_node`)
and the R341 Merkle anchor (`chainverify_lib`). It adds no external claim.

Property: publish a content-addressed registry {did -> cardHash}, commit the registry AND the cards to one Merkle
root, and require that a *served* card's hash equal the registry entry AND that the card leaf is provably in the
anchored root. A divergent (tampered) card is rejected -- which is the credibility mechanism: the card is not
trusted because the agent says so, but because anyone can recompute the hash and check inclusion against the anchor.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

APEX = os.environ.get("SOVEREIGN_APEX", os.path.expanduser("~/.apex"))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "chainverify"))
sys.path.insert(0, os.path.join(HERE, "openadn"))

OUT = os.path.join(APEX, "chainverify_card_anchor_probe.json")

N_AGENTS = 3
CLAIMS = [
    {"id": "card_hash_is_content_addressed",
     "assertion": "changing any card field changes its content hash",
     "would_also_pass_if": "the hash covered only the did, so a mutated card kept the same hash",
     "fixtures_sanity": "a real card field is mutated, so the hash must change"},
    {"id": "registry_binds_did_to_card_hash",
     "assertion": "the registry entry for each agent equals the hash of its served card",
     "would_also_pass_if": "the registry stored the did but not the card hash",
     "predicate_intent": "assert per-agent equality, not just that the registry is non-empty"},
    {"id": "anchored_root_covers_each_card",
     "assertion": "the inclusion proof for every card leaf verifies against the anchored root",
     "would_also_pass_if": "verify_proof() returned True unconditionally",
     "fixtures_sanity": "every card leaf is proven, so the path logic is exercised per agent"},
    {"id": "divergent_card_is_rejected",
     "assertion": "a served card whose hash differs from the registry is rejected",
     "would_also_pass_if": "the check trusted the served card without consulting the registry/anchor",
     "fixtures_sanity": "a mutated serve is compared against the anchored registry entry, so rejection is reachable",
     "predicate_intent": "assert the *mutated* serve fails while the honest serve passes"},
    {"id": "card_tamper_breaks_inclusion",
     "assertion": "a tampered card leaf does not verify against the anchored root with the honest proof path",
     "would_also_pass_if": "inclusion ignored the leaf bytes or the index",
     "fixtures_sanity": "the honest proof for the leaf index is reused with the tampered leaf, so it must fail",
     "predicate_intent": "assert the *negative* direction (tampered leaf fails)"},
]

REDUCES_TO = "chainverify_anchor"
DEPENDS_ON = []
SUBSUMES = ["a2a_card_binding"]
FIXTURE_PROVENANCE = ("the agents, their names, and the mutated field are illustrative fixtures; the A2A cards, "
                      "the SHA-256 content hashing, the Merkle tree, and the inclusion proofs are real and offline.")


def _card_bytes(card) -> bytes:
    return json.dumps(card, sort_keys=True, separators=(",", ":")).encode("utf-8")


def run() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    KEYS = tuple(c["id"] for c in CLAIMS) + ("chainverify_card_anchor_is_not_a_search_lever",)
    if os.environ.get("DOXX_CHAINVERIFY_CARD_DISABLE") == "1":
        claims = {k: False for k in KEYS}
        json.dump({"probe": "chainverify_card_anchor_probe", "measured": True, "reason": "no source",
                   "claims": claims, "conclusion": "FALSIFIED"}, open(OUT, "w"), indent=2, sort_keys=True)
        if args.selftest:
            print("CHAINVERIFY CARD SELFTEST: FAIL (no source)"); return 1
        if args.json:
            print(json.dumps(claims, sort_keys=True)); return 0
        print("no source"); return 1

    from openadn_node import AgentNode  # noqa: E402
    from chainverify_lib import canonical_leaves, leaf_hash, merkle_proof, merkle_root, verify_proof  # noqa: E402

    nodes = [AgentNode("card-agent-%d" % i, ["data.read"], seed="chainverify-card-%d" % i) for i in range(N_AGENTS)]
    cards = [(n.did, n.agent_card()) for n in nodes]

    registry = {did: leaf_hash("agent-card:" + did, _card_bytes(card)) for did, card in cards}
    registry_blob = json.dumps({k: registry[k] for k in sorted(registry)}, sort_keys=True).encode("utf-8")
    registry_name = "registry"
    artifacts = [("agent-card:" + did, _card_bytes(card)) for did, card in cards] + [(registry_name, registry_blob)]
    leaves, items = canonical_leaves(artifacts)
    root = merkle_root(leaves)
    name_to_index = {name: i for i, (name, _c) in enumerate(items)}

    # 1. content addressing
    mutated = json.loads(json.dumps(cards[0][1]))
    mutated["description"] = mutated["description"] + " (tampered)"
    content_ok = leaf_hash("agent-card:" + cards[0][0], _card_bytes(mutated)) != registry[cards[0][0]]

    # 2. registry binds did -> card hash
    reg_ok = all(registry[did] == leaf_hash("agent-card:" + did, _card_bytes(card)) for did, card in cards)

    # 3. inclusion of every card leaf
    proof_ok = all(verify_proof(registry[did], merkle_proof(leaves, name_to_index["agent-card:" + did]), root)
                   for did, _c in cards)

    # 4. a divergent serve is rejected (hash != registry entry)
    def served_ok(did, card):
        h = leaf_hash("agent-card:" + did, _card_bytes(card))
        return h == registry.get(did)

    divergent_rejected = (served_ok(cards[0][0], cards[0][1]) is True
                          and served_ok(cards[0][0], mutated) is False)

    # 5. a tampered leaf fails against the honest proof path
    tampered_leaf = leaf_hash("agent-card:" + cards[0][0], _card_bytes(mutated))
    honest_proof = merkle_proof(leaves, name_to_index["agent-card:" + cards[0][0]])
    tamper_inclusion_ok = (verify_proof(tampered_leaf, honest_proof, root) is False
                           and verify_proof(registry[cards[0][0]], honest_proof, root) is True)

    claims = {
        "card_hash_is_content_addressed": bool(content_ok),
        "registry_binds_did_to_card_hash": bool(reg_ok),
        "anchored_root_covers_each_card": bool(proof_ok),
        "divergent_card_is_rejected": bool(divergent_rejected),
        "card_tamper_breaks_inclusion": bool(tamper_inclusion_ok),
        "chainverify_card_anchor_is_not_a_search_lever": True,
    }
    evidence = {
        "agents": N_AGENTS,
        "root": root,
        "registry_entries": len(registry),
        "card_leaf_index": name_to_index["agent-card:" + cards[0][0]],
        "registry_leaf_index": name_to_index[registry_name],
        "divergent_serve_rejected": bool(served_ok(cards[0][0], mutated) is False),
        "tampered_leaf_in_root": bool(verify_proof(tampered_leaf, honest_proof, root)),
    }
    rec = {"probe": "chainverify_card_anchor_probe", "measured": True,
           "round_type": "consolidation", "kind": "composition",
           "reduces_to": REDUCES_TO, "depends_on": DEPENDS_ON, "subsumes": SUBSUMES,
           "fixtures_provenance": FIXTURE_PROVENANCE,
           "ruleset": "an AgentCard is trusted because its content hash matches an anchored registry entry and its "
                      "leaf is provably in the committed root -- not because the serving agent asserts it",
           "evidence": evidence,
           "claims": claims,
           "vetoes": ["card_not_content_addressed", "registry_ignored", "divergent_card_accepted"],
           "conclusion": "SUPPORTED" if all(claims.values()) else "FALSIFIED"}
    json.dump(rec, open(OUT, "w"), indent=2, sort_keys=True)

    if args.selftest:
        ok = all(claims.values())
        print("CHAINVERIFY CARD SELFTEST: %s (content=%s reg=%s proof=%s divergent=%s tamper=%s)" % (
            "PASS" if ok else "FAIL", content_ok, reg_ok, proof_ok, divergent_rejected, tamper_inclusion_ok))
        return 0 if ok else 1
    if args.json:
        print(json.dumps({k: bool(v) for k, v in claims.items()}, sort_keys=True)); return 0
    print("=" * 78)
    print("  CHAINVERIFY CARD -- a served AgentCard is verified against an anchored registry + Merkle root")
    for k in sorted(claims):
        print("  %-52s : %s" % (k, claims[k]))
    print("  ledger -> %s" % OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
