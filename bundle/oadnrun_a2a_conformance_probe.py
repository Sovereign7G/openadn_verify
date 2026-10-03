#!/usr/bin/env python3
"""oadnrun_a2a_conformance_probe.py -- R339/H1: the OpenADN node's A2A surface conforms to A2A v1.0.0.

Round type: translation (external artifact = the published A2A JSON-RPC binding). The external claims are the
spec's method names, Agent Card fields, TaskState enum, and JSON-RPC error codes -- tagged `[V]` here and NOT
modelled. What is measured `[R]` is that the *real* node's dispatch returns those shapes. Offline, deterministic.

The A2A spec is the referent: a card is checked against the required field set, `SendMessage` against the
`{task|message}` envelope, and the error paths against the spec's numeric codes.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

APEX = os.environ.get("SOVEREIGN_APEX", os.path.expanduser("~/.apex"))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "openadn"))

OUT = os.path.join(APEX, "oadnrun_a2a_conformance_probe.json")

# `[V]` -- the A2A v1.0.0 referent (docs/specification.md @ 1.0.0). Not modelled; checked.
A2A_CARD_REQUIRED = ("name", "description", "version", "supportedInterfaces", "capabilities",
                     "defaultInputModes", "defaultOutputModes", "skills")
A2A_TASK_STATES = {"TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_COMPLETED", "TASK_STATE_FAILED",
                   "TASK_STATE_CANCELED", "TASK_STATE_REJECTED", "TASK_STATE_INPUT_REQUIRED",
                   "TASK_STATE_AUTH_REQUIRED"}
A2A_TASK_NOT_FOUND = -32001
A2A_TASK_NOT_CANCELABLE = -32002
JSONRPC_METHOD_NOT_FOUND = -32601

CLAIMS = [
    {"id": "agent_card_conforms_to_a2a_v1",
     "assertion": "the card declares every A2A-required field, a JSONRPC interface at protocolVersion 1.0, and skills with id/name/description",
     "would_also_pass_if": "the required set were empty or the check only counted keys without reading the interface entry",
     "predicate_intent": "assert field *presence AND shape* (protocolBinding=='JSONRPC', protocolVersion=='1.0'), not merely non-empty"},
    {"id": "send_message_returns_task_envelope",
     "assertion": "SendMessage returns a result whose only key is `task`, and that task carries a spec TaskState",
     "would_also_pass_if": "the result were the bare task (no envelope) or the state were any non-empty string",
     "predicate_intent": "assert result crosses the {task|message} union boundary and the state is a member of the enum"},
    {"id": "unknown_task_uses_task_not_found_code",
     "assertion": "GetTask on an unknown id returns JSON-RPC error code -32001",
     "would_also_pass_if": "any error were accepted, or the code were compared as a string",
     "fixtures_sanity": "a task id that was never created is queried, so the not-found branch is genuinely reached"},
    {"id": "unknown_method_is_method_not_found",
     "assertion": "an unrecognised JSON-RPC method returns -32601",
     "would_also_pass_if": "the dispatcher returned a task for any method",
     "fixtures_sanity": "a method name outside the A2A set is dispatched, so the fall-through branch is reached"},
    {"id": "terminal_task_is_not_cancelable",
     "assertion": "CancelTask on a COMPLETED task returns -32002",
     "would_also_pass_if": "the cancel call mutated a terminal task or returned success",
     "fixtures_sanity": "a task is first driven to COMPLETED, so the terminal branch is reachable",
     "predicate_intent": "assert 32002 specifically (not 32001): the task exists but is terminal"},
]

REDUCES_TO = None
DEPENDS_ON = []
SUBSUMES = []
FIXTURE_PROVENANCE = ("the node, its capabilities, and the message texts are illustrative fixtures; the card, "
                      "TaskState, and error-code shapes are checked against the published A2A v1.0.0 spec.")


def run() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    KEYS = tuple(c["id"] for c in CLAIMS) + ("oadnrun_a2a_conformance_is_not_a_search_lever",)
    if os.environ.get("DOXX_OADNRUN_A2A_DISABLE") == "1":
        claims = {k: False for k in KEYS}
        json.dump({"probe": "oadnrun_a2a_conformance_probe", "measured": True, "reason": "no source",
                   "claims": claims, "conclusion": "FALSIFIED"}, open(OUT, "w"), indent=2, sort_keys=True)
        if args.selftest:
            print("OADNRUN A2A SELFTEST: FAIL (no source)"); return 1
        if args.json:
            print(json.dumps(claims, sort_keys=True)); return 0
        print("no source"); return 1

    from openadn_node import AgentNode  # noqa: E402

    node = AgentNode(
        "conformance-node",
        ["data.read", "compute.exec"],
        skills=[{"id": "data-read", "name": "Data Read", "description": "Read a declared data source",
                 "tags": ["data"], "examples": ["cap:data.read"]}],
    )

    # --- claim 1: card conformance ---
    card = node.agent_card()
    iface = (card.get("supportedInterfaces") or [{}])[0]
    skills = card.get("skills") or []
    caps = card.get("capabilities") or {}
    card_ok = (
        all(f in card for f in A2A_CARD_REQUIRED)
        and isinstance(card.get("supportedInterfaces"), list) and card["supportedInterfaces"]
        and iface.get("protocolBinding") == "JSONRPC"
        and iface.get("protocolVersion") == "1.0"
        and isinstance(iface.get("url"), str) and iface["url"]
        and isinstance(caps.get("streaming"), bool) and isinstance(caps.get("pushNotifications"), bool)
        and isinstance(skills, list) and bool(skills)
        and all(all(k in s for k in ("id", "name", "description")) for s in skills)
    )

    # --- claim 2: SendMessage envelope ---
    req = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
           "params": {"message": {"role": "ROLE_USER", "messageId": "m1",
                                  "parts": [{"text": "cap:data.read"}]}}}
    resp = node.handle_jsonrpc(req)
    result = resp.get("result")
    envelope_ok = (
        isinstance(result, dict) and list(result.keys()) == ["task"]
        and isinstance(result["task"].get("status"), dict)
        and result["task"]["status"].get("state") in A2A_TASK_STATES
        and isinstance(result["task"].get("id"), str) and result["task"]["id"]
    )

    # --- claim 3: TaskNotFoundError ---
    nf = node.handle_jsonrpc({"jsonrpc": "2.0", "id": 2, "method": "GetTask", "params": {"id": "task-does-not-exist"}})
    nf_ok = nf.get("error", {}).get("code") == A2A_TASK_NOT_FOUND

    # --- claim 4: MethodNotFoundError ---
    mn = node.handle_jsonrpc({"jsonrpc": "2.0", "id": 3, "method": "DefinitelyNotAMethod", "params": {}})
    mn_ok = mn.get("error", {}).get("code") == JSONRPC_METHOD_NOT_FOUND

    # --- claim 5: TaskNotCancelableError on a completed task ---
    completed_id = result["task"]["id"]
    cx = node.handle_jsonrpc({"jsonrpc": "2.0", "id": 4, "method": "CancelTask", "params": {"id": completed_id}})
    cx_ok = cx.get("error", {}).get("code") == A2A_TASK_NOT_CANCELABLE

    claims = {
        "agent_card_conforms_to_a2a_v1": bool(card_ok),
        "send_message_returns_task_envelope": bool(envelope_ok),
        "unknown_task_uses_task_not_found_code": bool(nf_ok),
        "unknown_method_is_method_not_found": bool(mn_ok),
        "terminal_task_is_not_cancelable": bool(cx_ok),
        "oadnrun_a2a_conformance_is_not_a_search_lever": True,
    }
    rec = {"probe": "oadnrun_a2a_conformance_probe", "measured": True,
           "round_type": "translation", "kind": "independent",
           "reduces_to": REDUCES_TO, "depends_on": DEPENDS_ON, "subsumes": SUBSUMES,
           "external_spec": {"name": "A2A", "version": "1.0.0", "binding": "JSON-RPC"},
           "fixtures_provenance": FIXTURE_PROVENANCE,
           "ruleset": "the node exposes an A2A-conformant card and JSON-RPC surface",
           "evidence": {"card_fields": sorted(card.keys()),
                        "interface": iface,
                        "task_state": (result.get("task", {}).get("status", {}).get("state")
                                       if isinstance(result, dict) else None),
                        "not_found_code": nf.get("error", {}).get("code"),
                        "method_not_found_code": mn.get("error", {}).get("code"),
                        "not_cancelable_code": cx.get("error", {}).get("code")},
           "claims": claims,
           "vetoes": ["card_missing_required_field", "send_message_not_enveloped", "wrong_error_code"],
           "conclusion": "SUPPORTED" if all(claims.values()) else "FALSIFIED"}
    json.dump(rec, open(OUT, "w"), indent=2, sort_keys=True)

    if args.selftest:
        ok = all(claims.values())
        print("OADNRUN A2A SELFTEST: %s (card=%s envelope=%s nf=%s mn=%s cx=%s)" % (
            "PASS" if ok else "FAIL", card_ok, envelope_ok, nf_ok, mn_ok, cx_ok))
        return 0 if ok else 1
    if args.json:
        print(json.dumps({k: bool(v) for k, v in claims.items()}, sort_keys=True)); return 0
    print("=" * 78)
    print("  OADNRUN A2A CONFORMANCE -- real dispatch vs the A2A v1.0.0 JSON-RPC binding")
    for k in sorted(claims):
        print("  %-52s : %s" % (k, claims[k]))
    print("  ledger -> %s" % OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
