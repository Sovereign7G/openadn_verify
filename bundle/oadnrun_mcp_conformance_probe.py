#!/usr/bin/env python3
"""oadnrun_mcp_conformance_probe.py -- R339/H2: the OpenADN node's MCP surface conforms to MCP, and the
capability gate filters the tool surface.

Round type: translation (external artifact = Anthropic's Model Context Protocol, JSON-RPC transport). The MCP
method names and result shapes are the `[V]` referent and are NOT modelled. Measured `[R]`: the real node's
`initialize`/`tools/list`/`tools/call` responses and the manifest-driven filtering of the catalogue.

A2A is agent-to-agent; MCP is agent-to-tool. Here MCP is the tool edge of the same node.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

APEX = os.environ.get("SOVEREIGN_APEX", os.path.expanduser("~/.apex"))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "openadn"))

OUT = os.path.join(APEX, "oadnrun_mcp_conformance_probe.json")

JSONRPC_INVALID_PARAMS = -32602
JSONRPC_METHOD_NOT_FOUND = -32601

CLAIMS = [
    {"id": "initialize_returns_protocol_and_server_info",
     "assertion": "initialize returns a protocolVersion string, a capabilities object, and serverInfo{name,version}",
     "would_also_pass_if": "the check accepted any non-empty result without reading the nested serverInfo",
     "predicate_intent": "assert nested shape (capabilities is a dict, serverInfo has name+version), not top-level presence"},
    {"id": "tools_list_schema_is_well_formed",
     "assertion": "every listed tool has name/description and an inputSchema of type 'object'",
     "would_also_pass_if": "the list were accepted non-empty without checking each entry's schema",
     "fixtures_sanity": "the node declares at least one capability, so the list is non-empty and the loop is exercised"},
    {"id": "tools_list_is_capability_filtered",
     "assertion": "the listed tools are exactly the declared capabilities: a catalogue tool with an undeclared capability is absent",
     "would_also_pass_if": "the list exposed the whole catalogue regardless of the manifest",
     "predicate_intent": "assert an *absence* driven by the manifest, which requires the fixture to contain a catalogue tool the node does not declare"},
    {"id": "undeclared_tool_call_is_denied",
     "assertion": "calling a catalogue tool whose capability is not declared returns a result with isError=true and an explicit denial",
     "would_also_pass_if": "the call succeeded because the tool exists in the catalogue",
     "fixtures_sanity": "the called tool is in the catalogue but not in the manifest, so the gate branch is reached"},
    {"id": "unknown_tool_is_invalid_params",
     "assertion": "calling a tool not in the catalogue returns JSON-RPC -32602",
     "would_also_pass_if": "unknown and undeclared tools were treated identically",
     "predicate_intent": "assert the two denial modes are distinct: -32602 for unknown, isError for undeclared"},
]

REDUCES_TO = None
DEPENDS_ON = []
FIXTURE_PROVENANCE = ("the node's declared capability set is an illustrative fixture; the MCP method/result "
                      "shapes are checked against the MCP JSON-RPC spec and the catalogue is a fixture superset.")


def run() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    KEYS = tuple(c["id"] for c in CLAIMS) + ("oadnrun_mcp_conformance_is_not_a_search_lever",)
    if os.environ.get("DOXX_OADNRUN_MCP_DISABLE") == "1":
        claims = {k: False for k in KEYS}
        json.dump({"probe": "oadnrun_mcp_conformance_probe", "measured": True, "reason": "no source",
                   "claims": claims, "conclusion": "FALSIFIED"}, open(OUT, "w"), indent=2, sort_keys=True)
        if args.selftest:
            print("OADNRUN MCP SELFTEST: FAIL (no source)"); return 1
        if args.json:
            print(json.dumps(claims, sort_keys=True)); return 0
        print("no source"); return 1

    from openadn_node import AgentNode, TOOL_CATALOG  # noqa: E402

    declared_caps = ["data.read", "compute.exec"]
    node = AgentNode("mcp-node", declared_caps)

    # --- claim 1: initialize ---
    init = node.handle_mcp({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": "probe", "version": "0"}}}).get("result", {})
    init_ok = (
        isinstance(init.get("protocolVersion"), str) and bool(init["protocolVersion"])
        and isinstance(init.get("capabilities"), dict)
        and isinstance(init.get("serverInfo"), dict)
        and bool(init["serverInfo"].get("name")) and bool(init["serverInfo"].get("version"))
    )

    # --- claim 2: tools/list schema ---
    tools = node.handle_mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).get("result", {}).get("tools", [])
    schema_ok = (
        isinstance(tools, list) and bool(tools)
        and all(isinstance(t.get("name"), str) and bool(t["name"])
                and isinstance(t.get("description"), str) and bool(t["description"])
                and isinstance(t.get("inputSchema"), dict) and t["inputSchema"].get("type") == "object"
                for t in tools)
    )

    # --- claim 3: filtering (an undeclared catalogue tool is absent) ---
    listed_names = {t["name"] for t in tools}
    declared = set(declared_caps)
    # catalogue tools whose capability is NOT declared -> must be absent
    undeclared_catalogue = sorted(name for name, (cap, _d) in TOOL_CATALOG.items() if cap not in declared)
    listed_caps = {TOOL_CATALOG[n][0] for n in listed_names if n in TOOL_CATALOG}
    filter_ok = (
        bool(undeclared_catalogue)
        and all(name not in listed_names for name in undeclared_catalogue)
        and listed_caps <= declared
        and listed_caps == declared
    )

    # --- claim 4: undeclared tool call is denied (isError, explicit) ---
    target = undeclared_catalogue[0] if undeclared_catalogue else "net.bgp_announce"
    deny = node.handle_mcp({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": target}}).get("result", {})
    denial_text = ""
    for c in deny.get("content", []) or []:
        if isinstance(c, dict) and isinstance(c.get("text"), str):
            denial_text = c["text"]
    deny_ok = bool(deny.get("isError")) and "capability not declared" in denial_text

    # --- claim 5: unknown tool is -32602 ---
    unknown = node.handle_mcp({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "no.such.tool"}})
    unknown_ok = unknown.get("error", {}).get("code") == JSONRPC_INVALID_PARAMS

    claims = {
        "initialize_returns_protocol_and_server_info": bool(init_ok),
        "tools_list_schema_is_well_formed": bool(schema_ok),
        "tools_list_is_capability_filtered": bool(filter_ok),
        "undeclared_tool_call_is_denied": bool(deny_ok),
        "unknown_tool_is_invalid_params": bool(unknown_ok),
        "oadnrun_mcp_conformance_is_not_a_search_lever": True,
    }
    rec = {"probe": "oadnrun_mcp_conformance_probe", "measured": True,
           "round_type": "translation", "kind": "independent",
           "reduces_to": REDUCES_TO, "depends_on": DEPENDS_ON,
           "external_spec": {"name": "MCP", "transport": "JSON-RPC"},
           "fixtures_provenance": FIXTURE_PROVENANCE,
           "ruleset": "the node exposes an MCP tool surface filtered by its signed capability manifest",
           "evidence": {"declared_caps": sorted(declared),
                        "listed_tools": sorted(listed_names),
                        "undeclared_catalogue_tools": undeclared_catalogue,
                        "denial_text": denial_text,
                        "unknown_tool_code": unknown.get("error", {}).get("code")},
           "claims": claims,
           "vetoes": ["initialize_shape_wrong", "catalogue_leaked", "undeclared_tool_allowed"],
           "conclusion": "SUPPORTED" if all(claims.values()) else "FALSIFIED"}
    json.dump(rec, open(OUT, "w"), indent=2, sort_keys=True)

    if args.selftest:
        ok = all(claims.values())
        print("OADNRUN MCP SELFTEST: %s (init=%s schema=%s filter=%s deny=%s unknown=%s)" % (
            "PASS" if ok else "FAIL", init_ok, schema_ok, filter_ok, deny_ok, unknown_ok))
        return 0 if ok else 1
    if args.json:
        print(json.dumps({k: bool(v) for k, v in claims.items()}, sort_keys=True)); return 0
    print("=" * 78)
    print("  OADNRUN MCP CONFORMANCE -- real tool surface, filtered by the signed manifest")
    for k in sorted(claims):
        print("  %-52s : %s" % (k, claims[k]))
    print("  ledger -> %s" % OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
