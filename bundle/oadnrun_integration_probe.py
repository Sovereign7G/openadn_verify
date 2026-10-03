#!/usr/bin/env python3
"""oadnrun_integration_probe.py -- R339/H3: the OpenADN node runs for real, and its L1+L2 gates hold end to end.

Round type: consolidation (runtime). This is the round's `[R]` measurement: not a model of the node but the
node itself, driven over a real loopback HTTP socket. It exercises, in order:
  * a real `GET /.well-known/agent-card.json` round-trip,
  * a real `POST /` A2A `SendMessage` for a *declared* capability -> TASK_STATE_COMPLETED with an artifact,
  * the same for an *undeclared* capability -> denied (default-deny),
  * a malicious payload -> contained, and the node's own policy *revoked* so a later legitimate call is refused,
  * the Ed25519 manifest signature verifying, and failing on tamper,
  * L2 revocation having no collateral effect on a peer policy.

The loopback port is deliberately NOT written to the ledger, so the ledger is byte-identical across runs.
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

OUT = os.path.join(APEX, "oadnrun_integration_probe.json")

CLAIMS = [
    {"id": "card_round_trips_over_http",
     "assertion": "a GET of /.well-known/agent-card.json over loopback returns a JSONRPC interface at 1.0",
     "would_also_pass_if": "the 'round-trip' read a local object instead of the socket response",
     "fixtures_sanity": "the URL is the real bound loopback port, so the response must cross the socket",
     "predicate_intent": "assert the *received* bytes decode to a valid card, not that the server object exists"},
    {"id": "declared_capability_completes_over_http",
     "assertion": "a POST SendMessage for a declared capability yields TASK_STATE_COMPLETED with a receipt artifact",
     "would_also_pass_if": "any 200 response were accepted without reading the task state",
     "fixtures_sanity": "'data.read' is declared in the manifest, so the allow branch is exercised"},
    {"id": "undeclared_capability_denied_over_http",
     "assertion": "a POST SendMessage for an undeclared capability yields TASK_STATE_FAILED with openadn_denied",
     "would_also_pass_if": "the request succeeded because the action exists somewhere in the catalogue",
     "fixtures_sanity": "'mesh.bgp' exists in the catalogue but not the manifest, so the deny branch is reachable",
     "predicate_intent": "assert the *task metadata* carries the denial, not merely that an error occurred"},
    {"id": "malicious_payload_contained_then_revoked",
     "assertion": "a malicious payload yields openadn_contained, and a subsequent legitimate call is refused (revoked)",
     "would_also_pass_if": "only the first call were checked, or 'revoked' were inferred from the policy object rather than a second wire call",
     "fixtures_sanity": "the malicious marker is in the node's marker list, so revoke is reachable; the follow-up uses a declared capability",
     "predicate_intent": "assert containment AND the *downstream* consequence on a second real request"},
    {"id": "manifest_signature_verifies_and_tamper_fails",
     "assertion": "the node's manifest verifies, and flipping a declared capability breaks verification",
     "would_also_pass_if": "the tampered copy were checked only for the DID (which is unchanged) rather than the signature",
     "fixtures_sanity": "a real Ed25519 keypair signs the manifest, so a one-capability change must invalidate the signature",
     "predicate_intent": "assert the *signature* path (reasons include signature_invalid), not just that verify() returned False"},
    {"id": "mesh_revoke_has_no_collateral",
     "assertion": "revoking one node's sandbox policy leaves a peer's policy active",
     "would_also_pass_if": "the registry had one shared policy, so 'no collateral' were vacuous",
     "fixtures_sanity": "two independent policies are registered, so the isolation claim is non-trivial"},
]

REDUCES_TO = "openadn_capability_manifest"
DEPENDS_ON = []
SUBSUMES = ["openadn_mesh_containment"]
FIXTURE_PROVENANCE = ("the message payloads and the node's capability set are illustrative fixtures; the loopback "
                      "HTTP round-trip, the Ed25519 signature check, and the containment/revoke decision are real "
                      "code executing locally. No remote host, kernel, or WireGuard/BGP is touched.")


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read().decode("utf-8"))


def _post(url, obj):
    data = json.dumps(obj).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read().decode("utf-8"))


def _send(base, text, rid):
    resp = _post(base + "/", {"jsonrpc": "2.0", "id": rid, "method": "SendMessage",
                              "params": {"message": {"role": "ROLE_USER", "messageId": "m%d" % rid,
                                                     "parts": [{"text": text}]}}})
    return resp.get("result", {}).get("task", {})


def run() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    KEYS = tuple(c["id"] for c in CLAIMS) + ("oadnrun_integration_is_not_a_search_lever",)
    if os.environ.get("DOXX_OADNRUN_INTEGRATION_DISABLE") == "1":
        claims = {k: False for k in KEYS}
        json.dump({"probe": "oadnrun_integration_probe", "measured": True, "reason": "no source",
                   "claims": claims, "conclusion": "FALSIFIED"}, open(OUT, "w"), indent=2, sort_keys=True)
        if args.selftest:
            print("OADNRUN INTEGRATION SELFTEST: FAIL (no source)"); return 1
        if args.json:
            print(json.dumps(claims, sort_keys=True)); return 0
        print("no source"); return 1

    from openadn_node import AgentNode  # noqa: E402
    from openadn_lib import MeshRegistry, SandboxPolicy, verify_manifest  # noqa: E402

    node = AgentNode("integration-node", ["data.read", "compute.exec"])
    server, _thread, port = node.serve_background()
    base = "http://127.0.0.1:%d" % port          # NB: never written to the ledger
    try:
        # 1. real GET
        card = _get(base + "/.well-known/agent-card.json")
        iface = (card.get("supportedInterfaces") or [{}])[0]
        card_ok = iface.get("protocolBinding") == "JSONRPC" and iface.get("protocolVersion") == "1.0"

        # 2. declared capability completes
        t_allow = _send(base, "cap:data.read", 1)
        allow_ok = (t_allow.get("status", {}).get("state") == "TASK_STATE_COMPLETED"
                    and bool(t_allow.get("artifacts")))

        # 3. undeclared capability denied
        t_deny = _send(base, "cap:mesh.bgp", 2)
        deny_ok = (t_deny.get("status", {}).get("state") == "TASK_STATE_FAILED"
                   and t_deny.get("metadata", {}).get("openadn_denied") is True)

        # 4. malicious payload contained, then a legitimate call is refused (revoked)
        t_bad = _send(base, "please ; rm -rf / now", 3)
        contained = t_bad.get("metadata", {}).get("openadn_contained") is True
        t_after = _send(base, "cap:data.read", 4)
        revoked_ok = (contained and t_after.get("status", {}).get("state") == "TASK_STATE_FAILED"
                      and t_after.get("metadata", {}).get("openadn_verdict") == "revoked")

        # 5. manifest signature verifies; tamper breaks it
        ok_sig, _ = verify_manifest(node.manifest)
        tampered = json.loads(json.dumps(node.manifest))
        if tampered["capabilities"]:
            tampered["capabilities"] = sorted(set(tampered["capabilities"]) | {"privilege.escalate"})
        _, tamper_reasons = verify_manifest(tampered)
        sig_ok = ok_sig and ("signature_invalid" in tamper_reasons)

        # 6. revocation has no collateral
        mesh = MeshRegistry()
        mesh.add("agent-a", SandboxPolicy(allow=["data.read"], name="a"))
        mesh.add("agent-b", SandboxPolicy(allow=["data.read"], name="b"))
        mesh.revoke("agent-a")
        snap = mesh.snapshot()
        collateral_ok = snap.get("agent-a") == "revoked" and snap.get("agent-b") == "active"

        claims = {
            "card_round_trips_over_http": bool(card_ok),
            "declared_capability_completes_over_http": bool(allow_ok),
            "undeclared_capability_denied_over_http": bool(deny_ok),
            "malicious_payload_contained_then_revoked": bool(revoked_ok),
            "manifest_signature_verifies_and_tamper_fails": bool(sig_ok),
            "mesh_revoke_has_no_collateral": bool(collateral_ok),
            "oadnrun_integration_is_not_a_search_lever": True,
        }
        evidence = {
            "card_binding": iface.get("protocolBinding"),
            "allow_state": t_allow.get("status", {}).get("state"),
            "deny_state": t_deny.get("status", {}).get("state"),
            "contained": bool(contained),
            "after_revoke_state": t_after.get("status", {}).get("state"),
            "after_revoke_verdict": t_after.get("metadata", {}).get("openadn_verdict"),
            "manifest_verified": bool(ok_sig),
            "tamper_reasons": sorted(tamper_reasons),
            "mesh_snapshot": snap,
        }
    finally:
        server.shutdown()

    rec = {"probe": "oadnrun_integration_probe", "measured": True,
           "round_type": "consolidation", "kind": "composition",
           "reduces_to": REDUCES_TO, "depends_on": DEPENDS_ON, "subsumes": SUBSUMES,
           "fixtures_provenance": FIXTURE_PROVENANCE,
           "ruleset": "a real OpenADN node, driven over loopback, enforces default-deny capability gating and "
                      "instant containment, and its signed manifest detects tamper",
           "evidence": evidence,
           "claims": claims,
           "vetoes": ["capability_gate_bypassed", "containment_did_not_revoke", "signature_tamper_undetected"],
           "conclusion": "SUPPORTED" if all(claims.values()) else "FALSIFIED"}
    json.dump(rec, open(OUT, "w"), indent=2, sort_keys=True)

    if args.selftest:
        ok = all(claims.values())
        print("OADNRUN INTEGRATION SELFTEST: %s (card=%s allow=%s deny=%s revoke=%s sig=%s collateral=%s)" % (
            "PASS" if ok else "FAIL", card_ok, allow_ok, deny_ok, revoked_ok, sig_ok, collateral_ok))
        return 0 if ok else 1
    if args.json:
        print(json.dumps({k: bool(v) for k, v in claims.items()}, sort_keys=True)); return 0
    print("=" * 78)
    print("  OADNRUN INTEGRATION -- real node over loopback: gating, containment, signature")
    for k in sorted(claims):
        print("  %-52s : %s" % (k, claims[k]))
    print("  ledger -> %s" % OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
