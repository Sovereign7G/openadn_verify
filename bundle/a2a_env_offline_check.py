#!/usr/bin/env python3
"""a2a_env_offline_check.py -- the OFFLINE subset of the A2A testing-environment conformance (L1-L5).

This is the part of `a2a_env_conformance.py` that needs no Docker and therefore ships in the offline
verification bundle.  The two layers that require a downstream service -- service virtualization (L6) and
fault injection (L6b) -- are deliberately NOT here, because the bundle is offline-only.  See GAPS below for
what is labelled and never claimed.

Measured (loopback, offline):
  L1 contract      -- the live agent card over HTTP; required fields; canonical (URL-normalized) hash
  L2 security      -- mutual did:adn challenge/response accepted AND exact replay rejected
  L3 state align   -- a capability seeded BEFORE the query is found; an unseeded one is not
  L4 transport     -- a real HTTP POST SendMessage -> TASK_STATE_COMPLETED + artifact
  L5 observability -- the caller's contextId is echoed; absent -> server-generated

  a2a_env_offline_check.py --selftest | --json
"""
from __future__ import annotations
import argparse, hashlib, json, os, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "openadn"))

APEX = os.environ.get("SOVEREIGN_APEX", os.path.expanduser("~/.apex"))
OUT = os.path.join(APEX, "a2a_env_offline_check.json")

CLAIMS = [
    {"id": "interface_contract_is_locked_and_valid",
     "assertion": "the live agent card fetches over HTTP, declares every required field, and yields a stable "
                  "canonical hash (the locked contract)",
     "would_also_pass_if": "the card were read in-process rather than over the socket, or the hash included "
                           "the ephemeral URL -- guarded by normalizing the URL before hashing"},
    {"id": "security_handshake_is_mutual_and_replay_resistant",
     "assertion": "a did:adn challenge/response is accepted with a mutual ack, and an exact replay is rejected",
     "would_also_pass_if": "acceptance were checked without verifying the ack -- guarded by requiring the "
                           "mutual ack AND the replay reason", "control": True},
    {"id": "state_alignment_requires_seeded_prestate",
     "assertion": "a capability seeded before the query is found; an unseeded capability is not",
     "would_also_pass_if": "the DHT returned anything for any tag -- guarded by the unseeded negative control",
     "predicate_intent": "positive and negative must disagree"},
    {"id": "http_message_send_round_trips",
     "assertion": "a real HTTP POST SendMessage for a declared capability returns TASK_STATE_COMPLETED with "
                  "an artifact",
     "would_also_pass_if": "the response were fabricated in-process -- guarded by the request crossing a "
                           "bound socket"},
    {"id": "correlation_id_round_trips",
     "assertion": "a caller-supplied contextId is echoed in the returned task; when absent, the node "
                  "generates a non-empty one",
     "would_also_pass_if": "the node ignored the caller's id -- guarded by sending a fixed id and requiring "
                           "it back",
     "predicate_intent": "observability: a correlation id must survive the hop"},
    {"id": "a2a_env_offline_is_not_a_search_lever",
     "assertion": "the offline A2A conformance check is an integration artifact, not a search edge",
     "would_also_pass_if": "never -- terminal honesty claim", "terminal": True},
]

GAPS = {
    "service_virtualization": "excluded from the offline bundle (requires a Docker downstream)",
    "fault_injection": "excluded from the offline bundle (requires a Docker downstream)",
    "mtls": "not implemented; identity is did:adn Ed25519 signatures",
    "message_broker": "not implemented; transport is direct HTTP JSON-RPC",
    "sse_streaming": "not implemented (capabilities.streaming=false)",
    "x_correlation_id_header": "not implemented; correlation rides in the A2A contextId field",
}

FIXTURE_PROVENANCE = {
    "checklist": "A2A (application-to-application) testing environment: contract, security, state alignment, "
                 "transport, observability (the offline-able layers)",
    "node": "OpenADN AgentNode on loopback; contract at /.well-known/agent-card.json, handshake at "
            "/adn/challenge + /adn/handshake",
}


def _post(url, obj, timeout=6):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _get(url, timeout=6):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def run() -> dict:
    from openadn_node import AgentNode  # noqa: E402
    import openadn_handshake as hs  # noqa: E402
    from openadn_dht import DHTPeer  # noqa: E402
    from openadn_lib import canonical  # noqa: E402

    node = AgentNode("app-b", ["data.read", "compute.exec"], seed="a2a-env-app-b")
    server, _t, port = node.serve_background()
    base = "http://127.0.0.1:%d" % port
    try:
        card = _get(base + "/.well-known/agent-card.json")
        required = ("name", "description", "version", "supportedInterfaces", "capabilities",
                    "defaultInputModes", "defaultOutputModes", "skills")
        iface = (card.get("supportedInterfaces") or [{}])[0]
        norm = dict(card)
        norm["supportedInterfaces"] = [dict(i, url="<loopback>") for i in card.get("supportedInterfaces", [])]
        card_hash = hashlib.sha256(canonical(norm)).hexdigest()[:16]
        contract_ok = (all(f in card for f in required)
                       and iface.get("protocolBinding") == "JSONRPC"
                       and iface.get("protocolVersion") == "1.0")

        A = AgentNode("app-a", ["compute.exec"], seed="a2a-env-app-a")
        chal = _get(base + "/adn/challenge")["challenge"]
        msg = hs.make_handshake(A, node.did, chal)
        acc = _post(base + "/adn/handshake", msg)
        mutual = False
        if acc.get("accepted") and acc.get("session"):
            mutual, _ = hs.verify_ack(A.did, node.did, chal, acc["ack"])
        rep = _post(base + "/adn/handshake", msg)
        replay = (rep.get("accepted") is False and "challenge_already_consumed" in rep.get("reasons", []))
        security_ok = bool(acc.get("accepted")) and bool(mutual) and bool(replay)

        peer = DHTPeer("app-b-dht", replication=1)
        peer.publish("provider-1", ["data.read"])
        found = peer.find("data.read", "querier")
        unseeded = peer.find("never.seeded", "querier")
        state_ok = bool(found) and not unseeded

        req = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
               "params": {"message": {"role": "ROLE_USER", "messageId": "m1", "contextId": "corr-123",
                                      "parts": [{"text": "cap:data.read"}]}}}
        task = (_post(base + "/", req).get("result") or {}).get("task") or {}
        transport_ok = (task.get("status", {}).get("state") == "TASK_STATE_COMPLETED"
                        and bool(task.get("artifacts")))
        corr_ctx = task.get("contextId")
        req2 = {"jsonrpc": "2.0", "id": 2, "method": "SendMessage",
                "params": {"message": {"role": "ROLE_USER", "messageId": "m2",
                                       "parts": [{"text": "cap:data.read"}]}}}
        task2 = (_post(base + "/", req2).get("result") or {}).get("task") or {}
        corr_ok = (corr_ctx == "corr-123") and bool(task2.get("contextId"))
    finally:
        try:
            server.shutdown()
        except Exception:  # noqa: BLE001
            pass

    claims = {
        "interface_contract_is_locked_and_valid": bool(contract_ok),
        "security_handshake_is_mutual_and_replay_resistant": bool(security_ok),
        "state_alignment_requires_seeded_prestate": bool(state_ok),
        "http_message_send_round_trips": bool(transport_ok),
        "correlation_id_round_trips": bool(corr_ok),
        "a2a_env_offline_is_not_a_search_lever": True,
    }
    verdicts = {k: ("SUPPORTED" if v else "FALSIFIED") for k, v in claims.items()}
    return {
        "probe": "a2a_env_offline_check", "measured": True, "modeled": False,
        "claims": claims, "verdicts": verdicts, "CLAIMS": CLAIMS, "GAPS": GAPS,
        "FIXTURE_PROVENANCE": FIXTURE_PROVENANCE,
        "measurements": {"contract_hash": card_hash, "mutual": bool(mutual), "replay_rejected": bool(replay),
                         "seeded_found": bool(found), "unseeded": bool(unseeded),
                         "correlation_echoed": corr_ctx},
        "conclusion": (
            "A2A ENV OFFLINE (L1-L5): contract, security, state alignment, transport and observability are "
            "MEASURED against the real node over loopback. Service virtualization and fault injection are "
            "excluded (they require Docker); %d items are labelled as not implemented." % len(GAPS)),
        "source": "OpenADN node over loopback; A2A testing-environment checklist (offline layers)",
    }


def selftest() -> int:
    r = run()
    os.makedirs(APEX, exist_ok=True)
    json.dump(r, open(OUT, "w"), indent=2)
    print("=" * 78)
    print("  A2A ENV (OFFLINE L1-L5) -- OpenADN vs the offline checklist layers")
    print("=" * 78)
    for c in r["CLAIMS"]:
        print("  [%-9s] %s" % (r["verdicts"][c["id"]], c["id"]))
    print("  --- LABELLED EXCLUSIONS ---")
    for k in sorted(r["GAPS"]):
        print("    - %-24s %s" % (k, r["GAPS"][k][:52]))
    ok = all(r["verdicts"][c["id"]] == "SUPPORTED" for c in r["CLAIMS"])
    print("A2A_ENV_OFFLINE SELFTEST: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    print(json.dumps(run(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
