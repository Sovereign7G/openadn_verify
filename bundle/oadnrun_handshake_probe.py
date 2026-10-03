#!/usr/bin/env python3
"""oadnrun_handshake_probe.py -- R340/H1: a two-node `did:adn` mutual handshake over loopback (real crypto).

Round type: runtime. Two agent nodes each hold an Ed25519 key and a signed capability manifest; the initiator
proves possession of the key bound to its DID, the responder consumes a single-use challenge and returns a signed
ack, and the initiator verifies it (mutual). Replay, responder-confusion, and a tampered manifest all fail.

Keys are **seed-derived**, so DIDs, signatures, and sessions are reproducible and may be recorded in the ledger
without breaking the byte-identical check. Transport is loopback only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request

APEX = os.environ.get("SOVEREIGN_APEX", os.path.expanduser("~/.apex"))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "openadn"))

OUT = os.path.join(APEX, "oadnrun_handshake_probe.json")

CLAIMS = [
    {"id": "two_node_handshake_completes",
     "assertion": "over loopback, a valid handshake is accepted and yields a non-empty session",
     "would_also_pass_if": "the endpoint accepted any payload, or the session came from a local object not a response",
     "fixtures_sanity": "a real challenge is fetched and a real signed message is posted, so the accept branch runs",
     "predicate_intent": "assert the *received* response says accepted with a session, not that a function returned"},
    {"id": "handshake_is_mutual",
     "assertion": "the initiator verifies the responder's signed ack against the responder's manifest",
     "would_also_pass_if": "only the responder checked the initiator, so trust were one-directional",
     "fixtures_sanity": "the ack carries a real Ed25519 signature over (responder, initiator, challenge, session)",
     "predicate_intent": "assert verify_ack() succeeds on the real ack (a forged ack would be rejected)"},
    {"id": "replay_is_rejected",
     "assertion": "re-sending the identical accepted handshake is rejected as challenge_already_consumed",
     "would_also_pass_if": "the challenge were not single-use, so a captured handshake could be replayed",
     "fixtures_sanity": "the challenge was consumed by the prior successful handshake, so the replay branch is reached"},
    {"id": "wrong_responder_is_rejected",
     "assertion": "a handshake signed for a different responder DID is rejected with wrong_responder",
     "would_also_pass_if": "the responder ignored the addressed DID and accepted the signature anyway",
     "fixtures_sanity": "the message names a DID that is not the responder's, so the mismatch branch is reached"},
    {"id": "tampered_manifest_is_rejected",
     "assertion": "a handshake whose manifest has an extra capability is rejected (manifest_invalid)",
     "would_also_pass_if": "only the DID binding were checked, so a post-signing manifest edit slipped through",
     "fixtures_sanity": "the body signature is left intact while the manifest is mutated, isolating the manifest check",
     "predicate_intent": "assert the rejection reason names the manifest/signature path, not merely a generic deny"},
    {"id": "identity_is_transport_independent",
     "assertion": "the initiator's DID is unchanged across handshakes to responders on different loopback ports",
     "would_also_pass_if": "the DID incorporated the endpoint/host, so it changed per responder",
     "fixtures_sanity": "two responders on distinct ports both accept the same initiator, so the invariance is exercised"},
]

REDUCES_TO = "openadn_did_sovereignty"
DEPENDS_ON = []
SUBSUMES = []
FIXTURE_PROVENANCE = ("the seeds, names, and capabilities are illustrative fixtures; the Ed25519 keys, DIDs, "
                      "signatures, challenges, and loopback transport are real. No remote host is contacted.")


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read().decode("utf-8"))


def _post(url, obj):
    req = urllib.request.Request(url, data=json.dumps(obj).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read().decode("utf-8"))


def run() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    KEYS = tuple(c["id"] for c in CLAIMS) + ("oadnrun_handshake_is_not_a_search_lever",)
    if os.environ.get("DOXX_OADNRUN_HANDSHAKE_DISABLE") == "1":
        claims = {k: False for k in KEYS}
        json.dump({"probe": "oadnrun_handshake_probe", "measured": True, "reason": "no source",
                   "claims": claims, "conclusion": "FALSIFIED"}, open(OUT, "w"), indent=2, sort_keys=True)
        if args.selftest:
            print("OADNRUN HANDSHAKE SELFTEST: FAIL (no source)"); return 1
        if args.json:
            print(json.dumps(claims, sort_keys=True)); return 0
        print("no source"); return 1

    from openadn_node import AgentNode  # noqa: E402
    import openadn_handshake as hs  # noqa: E402

    A = AgentNode("initiator", ["compute.exec"], seed="oadnrun-handshake-initiator")
    B = AgentNode("responder", ["data.read"], seed="oadnrun-handshake-responder")
    C = AgentNode("responder-2", ["data.read"], seed="oadnrun-handshake-responder-2")
    srvB, _t, portB = B.serve_background()
    srvC, _t2, portC = C.serve_background()
    baseB = "http://127.0.0.1:%d" % portB
    baseC = "http://127.0.0.1:%d" % portC
    try:
        # 1+2: happy path + mutual ack
        chal1 = _get(baseB + "/adn/challenge")["challenge"]
        msg1 = hs.make_handshake(A, B.did, chal1)
        acc1 = _post(baseB + "/adn/handshake", msg1)
        completes = bool(acc1.get("accepted")) and bool(acc1.get("session"))
        mutual, _ack_reasons = (hs.verify_ack(A.did, B.did, chal1, acc1["ack"]) if completes else (False, []))

        # 3: replay
        rep = _post(baseB + "/adn/handshake", msg1)
        replay_ok = (rep.get("accepted") is False and "challenge_already_consumed" in rep.get("reasons", []))

        # 4: wrong responder
        chal2 = _get(baseB + "/adn/challenge")["challenge"]
        wrong = hs.make_handshake(A, "did:adn:not-the-responder", chal2)
        wrongresp = _post(baseB + "/adn/handshake", wrong)
        wrong_ok = (wrongresp.get("accepted") is False and "wrong_responder" in wrongresp.get("reasons", []))

        # 5: tampered manifest (body sig intact, manifest mutated)
        chal3 = _get(baseB + "/adn/challenge")["challenge"]
        msg3 = hs.make_handshake(A, B.did, chal3)
        tampered = json.loads(json.dumps(A.manifest))
        tampered["capabilities"] = sorted(set(tampered["capabilities"]) | {"privilege.escalate"})
        msg3["manifest"] = tampered
        tamp = _post(baseB + "/adn/handshake", msg3)
        tamper_ok = (tamp.get("accepted") is False
                     and any(r.startswith("manifest_invalid") for r in tamp.get("reasons", [])))

        # 6: transport/host independence -- a *second* node from the same key material has the same DID, and
        # both responders (different ports) accept it.  Not a self-compare: A2 is a distinct node object.
        A2 = AgentNode("initiator-copy", ["compute.exec"], seed="oadnrun-handshake-initiator")
        chalC = _get(baseC + "/adn/challenge")["challenge"]
        accC = _post(baseC + "/adn/handshake", hs.make_handshake(A, C.did, chalC))
        chalA2 = _get(baseC + "/adn/challenge")["challenge"]
        accA2 = _post(baseC + "/adn/handshake", hs.make_handshake(A2, C.did, chalA2))
        transport_ok = (A2.did == A.did and bool(accC.get("accepted")) and bool(accA2.get("accepted")))

        claims = {
            "two_node_handshake_completes": bool(completes),
            "handshake_is_mutual": bool(mutual),
            "replay_is_rejected": bool(replay_ok),
            "wrong_responder_is_rejected": bool(wrong_ok),
            "tampered_manifest_is_rejected": bool(tamper_ok),
            "identity_is_transport_independent": bool(transport_ok),
            "oadnrun_handshake_is_not_a_search_lever": True,
        }
        evidence = {
            "initiator_did": A.did,
            "responder_did": B.did,
            "session": acc1.get("session") if completes else None,
            "replay_reasons": sorted(rep.get("reasons", [])),
            "wrong_responder_reasons": sorted(wrongresp.get("reasons", [])),
            "tamper_reasons": sorted(tamp.get("reasons", [])),
            "copy_did_equals_initiator": bool(A2.did == A.did),
            "second_responder_accepted": bool(accC.get("accepted")),
            "copy_handshake_accepted": bool(accA2.get("accepted")),
        }
    finally:
        srvB.shutdown()
        srvC.shutdown()

    rec = {"probe": "oadnrun_handshake_probe", "measured": True,
           "round_type": "runtime", "kind": "composition",
           "reduces_to": REDUCES_TO, "depends_on": DEPENDS_ON, "subsumes": SUBSUMES,
           "fixtures_provenance": FIXTURE_PROVENANCE,
           "ruleset": "two nodes prove possession of the keys bound to their did:adn identities; the handshake is "
                      "mutual, replay-resistant, responder-bound, and manifest-integrity-checked",
           "evidence": evidence,
           "claims": claims,
           "vetoes": ["handshake_not_mutual", "replay_accepted", "tampered_manifest_accepted"],
           "conclusion": "SUPPORTED" if all(claims.values()) else "FALSIFIED"}
    json.dump(rec, open(OUT, "w"), indent=2, sort_keys=True)

    if args.selftest:
        ok = all(claims.values())
        print("OADNRUN HANDSHAKE SELFTEST: %s (complete=%s mutual=%s replay=%s wrongresp=%s tamper=%s transport=%s)" % (
            "PASS" if ok else "FAIL", completes, mutual, replay_ok, wrong_ok, tamper_ok, transport_ok))
        return 0 if ok else 1
    if args.json:
        print(json.dumps({k: bool(v) for k, v in claims.items()}, sort_keys=True)); return 0
    print("=" * 78)
    print("  OADNRUN HANDSHAKE -- two-node did:adn mutual authentication over loopback")
    for k in sorted(claims):
        print("  %-52s : %s" % (k, claims[k]))
    print("  ledger -> %s" % OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
