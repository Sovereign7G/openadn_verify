#!/usr/bin/env python3
"""openadn_node.py -- an OpenADN agent node (REAL runtime).

A single agent process that exposes, over loopback HTTP:
  * `GET /.well-known/agent-card.json`  -- an A2A v1.0.0 Agent Card
  * `POST /`                            -- A2A JSON-RPC 2.0 (`SendMessage`, `GetTask`, `ListTasks`, `CancelTask`)
  * `POST /mcp`                         -- MCP JSON-RPC 2.0 (`initialize`, `tools/list`, `tools/call`)

The A2A/MCP surfaces are REAL protocol implementations (faithful to the published specs), and the
capability gate is REAL: a request for an action the signed manifest does not declare is denied, and a
malicious payload trips the L2 sandbox policy (model) which revokes the node.

What is NOT here (and must not be claimed): kernel eBPF enforcement, real WireGuard/BGP, a live DHT
transport, and real settlement. Those layers are modelled by `openadn_lib`.
"""
from __future__ import annotations

import hashlib
import json
import threading

from openadn_lib import (
    CapabilityGuard,
    CapabilityDHT,
    MeshRegistry,
    SandboxPolicy,
    SettlementEngine,
    TunnelRegistry,
    build_manifest,
    did_from_public,
    generate_keypair,
    keypair_from_seed,
)
from openadn_handshake import make_ack, session_id, verify_handshake

# A2A v1.0.0 JSON-RPC error codes (Section 5.4).
A2A_ERRORS = {
    "TaskNotFoundError": -32001,
    "TaskNotCancelableError": -32002,
    "PushNotificationNotSupportedError": -32003,
    "UnsupportedOperationError": -32004,
    "ContentTypeNotSupportedError": -32005,
    "InvalidAgentResponseError": -32006,
    "ExtendedAgentCardNotConfiguredError": -32007,
    "ExtensionSupportRequiredError": -32008,
    "VersionNotSupportedError": -32009,
}
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603

TASK_STATES = (
    "TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_COMPLETED", "TASK_STATE_FAILED",
    "TASK_STATE_CANCELED", "TASK_STATE_REJECTED", "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED",
)
TERMINAL_STATES = ("TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED")

MCP_PROTOCOL_VERSION = "2025-06-18"

# The installable capability catalogue. A node's *manifest* declares a subset; only declared capabilities
# are served. This is what makes the capability gate meaningful: the catalogue is a superset.
TOOL_CATALOG = {
    "net.wg_up": ("mesh.wireguard", "Bring up an ephemeral WireGuard tunnel to a peer"),
    "net.bgp_announce": ("mesh.bgp", "Announce an anycast route on the backbone"),
    "dht.publish": ("dht.publish", "Publish this node's capabilities to the capability DHT"),
    "compute.exec": ("compute.exec", "Execute a bounded compute task"),
    "data.read": ("data.read", "Read from a declared data source"),
    "settle.barter": ("settle.barter", "Settle a peer obligation via compute-for-compute barter"),
}

# Payload markers that the L2 sandbox policy treats as a compromise -> revoke.
MALICIOUS_MARKERS = ("; rm -rf", "DROP TABLE", "../", "__import__", "os.system", "/etc/passwd")
MAX_PART_LEN = 4096


class AgentNode:
    def __init__(self, name, capabilities, bounds=None, skills=None, nonce="n0", seed=None):
        if seed is None:
            self.sk, self.pk = generate_keypair()
        else:
            self.sk, self.pk = keypair_from_seed(seed)
        self.did = did_from_public(self.pk)
        self.name = name
        self.manifest = build_manifest(self.sk, capabilities, bounds=bounds, nonce=nonce)
        self.guard = CapabilityGuard(self.manifest)
        self.policy = SandboxPolicy(allow=self.guard.declared(), name=name)
        self.skills = list(skills or [])
        self.tasks = {}
        self._counter = 0
        self.dht = CapabilityDHT()
        self.mesh = MeshRegistry()
        self.mesh.add(self.did, self.policy)
        self.settlement = SettlementEngine(reserve=1000, committee_size=7, threshold=5)
        self.tunnels = TunnelRegistry()
        self._pending_challenges = {}    # challenge -> consumed(bool); single-use, replay-resistant

    # ---- deterministic ids (no uuid4, no wall clock -> byte-identical ledgers) ----
    def _next_id(self, prefix):
        self._counter += 1
        return "%s-%s" % (prefix, hashlib.sha256(("%s:%d" % (self.did, self._counter)).encode()).hexdigest()[:16])

    # ---- A2A agent card ----
    def agent_card(self, url="http://127.0.0.1:0/"):
        return {
            "name": self.name,
            "description": "OpenADN agent node (DID-bound, capability-gated).",
            "version": "1.0.0",
            "supportedInterfaces": [
                {"url": url, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
            ],
            "capabilities": {"streaming": False, "pushNotifications": False, "extendedAgentCard": False},
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["text/plain"],
            "skills": [dict(s) for s in self.skills],
            "securitySchemes": {
                "openadn-did": {"httpAuthSecurityScheme": {"scheme": "OpenADN-DID", "bearerFormat": "Ed25519"}},
            },
        }

    # ---- A2A operations ----
    def _new_task(self, state, context_id, action=None, text=None, extra_meta=None):
        tid = self._next_id("task")
        task = {"id": tid, "contextId": context_id, "status": {"state": state}}
        if text is not None:
            task["status"]["message"] = {"role": "ROLE_AGENT", "parts": [{"text": text}], "messageId": self._next_id("msg")}
        if extra_meta:
            task["metadata"] = extra_meta
        self.tasks[tid] = task
        return task

    def _scan_parts(self, parts):
        for p in parts or []:
            if not isinstance(p, dict):
                continue
            text = p.get("text")
            if isinstance(text, str):
                if len(text) > MAX_PART_LEN:
                    return "oversize_part", text[:64]
                for m in MALICIOUS_MARKERS:
                    if m in text:
                        return "malicious_marker:" + m, text[:64]
        return None, None

    def send_message(self, params):
        if not isinstance(params, dict) or "message" not in params:
            return None, _err(JSONRPC_INVALID_PARAMS, "Invalid parameters", "message is required")
        message = params["message"]
        if not isinstance(message, dict) or "parts" not in message:
            return None, _err(JSONRPC_INVALID_PARAMS, "Invalid parameters", "message.parts is required")
        parts = message.get("parts") or []
        if not isinstance(parts, list) or not parts:
            return None, _err(JSONRPC_INVALID_PARAMS, "Invalid parameters", "at least one part is required")
        context_id = message.get("contextId") or self._next_id("ctx")

        # L2 containment: a malicious payload revokes this node's network privileges.
        kind, snippet = self._scan_parts(parts)
        if kind is not None:
            self.policy.revoke(kind)
            task = self._new_task("TASK_STATE_FAILED", context_id, text="payload contained",
                                  extra_meta={"openadn_contained": True, "openadn_violation": kind})
            return {"task": task}, None

        text = ""
        for p in parts:
            if isinstance(p, dict) and isinstance(p.get("text"), str):
                text = p["text"]
                break

        # Command form: "cap:<capability>". Undeclared -> denied (default-deny).
        if text.startswith("cap:"):
            action = text[4:].strip()
            verdict = self.policy.evaluate(action) if action in self._catalog_caps() else "deny"
            if verdict != "allow":
                task = self._new_task("TASK_STATE_FAILED", context_id, text="capability denied",
                                      extra_meta={"openadn_denied": True, "openadn_action": action,
                                                  "openadn_verdict": verdict})
                return {"task": task}, None
            task = self._new_task("TASK_STATE_COMPLETED", context_id, text="ok",
                                  extra_meta={"openadn_action": action})
            task["artifacts"] = [{
                "artifactId": self._next_id("artifact"),
                "name": "openadn-receipt",
                "parts": [{"data": {"action": action, "did": self.did, "verdict": "allow"}}],
            }]
            return {"task": task}, None

        # Non-command message: echo, completed.
        task = self._new_task("TASK_STATE_COMPLETED", context_id, text="ack")
        return {"task": task}, None

    def _catalog_caps(self):
        return {cap for _, (cap, _d) in TOOL_CATALOG.items()}

    def get_task(self, params):
        tid = (params or {}).get("id")
        if tid not in self.tasks:
            return None, _err(A2A_ERRORS["TaskNotFoundError"], "Task not found",
                              "taskId=%s" % tid, reason="TASK_NOT_FOUND")
        return self.tasks[tid], None

    def list_tasks(self):
        tasks = [dict(self.tasks[t]) for t in sorted(self.tasks)]
        return {"tasks": tasks, "nextPageToken": ""}, None

    def cancel_task(self, params):
        tid = (params or {}).get("id")
        if tid not in self.tasks:
            return None, _err(A2A_ERRORS["TaskNotFoundError"], "Task not found", "taskId=%s" % tid,
                              reason="TASK_NOT_FOUND")
        task = self.tasks[tid]
        if task["status"]["state"] in TERMINAL_STATES:
            return None, _err(A2A_ERRORS["TaskNotCancelableError"], "Task not cancelable",
                              "task %s is in %s" % (tid, task["status"]["state"]), reason="TASK_NOT_CANCELABLE")
        task["status"]["state"] = "TASK_STATE_CANCELED"
        return task, None

    # ---- JSON-RPC dispatch (A2A + MCP) ----
    def handle_jsonrpc(self, request):
        if not isinstance(request, dict):
            return _err(JSONRPC_INVALID_REQUEST, "Invalid Request", "request must be an object")
        if request.get("jsonrpc") != "2.0" or "method" not in request:
            return _err(JSONRPC_INVALID_REQUEST, "Invalid Request", "jsonrpc=2.0 and method are required",
                        rid=request.get("id"))
        rid = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}
        a2a = {
            "SendMessage": lambda: self.send_message(params),
            "GetTask": lambda: self.get_task(params),
            "ListTasks": lambda: self.list_tasks(),
            "CancelTask": lambda: self.cancel_task(params),
        }
        if method in a2a:
            result, error = a2a[method]()
            return _ok(result, rid) if error is None else _with_id(error, rid)
        return _err(JSONRPC_METHOD_NOT_FOUND, "Method not found", method, rid=rid)

    def handle_mcp(self, request):
        if not isinstance(request, dict):
            return _err(JSONRPC_INVALID_REQUEST, "Invalid Request", "request must be an object")
        if request.get("jsonrpc") != "2.0" or "method" not in request:
            return _err(JSONRPC_INVALID_REQUEST, "Invalid Request", "jsonrpc=2.0 and method are required",
                        rid=request.get("id"))
        rid = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}
        if method == "initialize":
            return _ok({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": self.name, "version": "1.0.0"},
            }, rid)
        if method == "tools/list":
            tools = []
            for tool_name, (cap, desc) in sorted(TOOL_CATALOG.items()):
                if self.guard.allows(cap):
                    tools.append({
                        "name": tool_name,
                        "description": desc,
                        "inputSchema": {"type": "object", "properties": {"arg": {"type": "string"}},
                                        "required": []},
                    })
            return _ok({"tools": tools}, rid)
        if method == "tools/call":
            name = params.get("name")
            if name not in TOOL_CATALOG:
                return _err(JSONRPC_INVALID_PARAMS, "Invalid parameters", "unknown tool: %s" % name, rid=rid)
            cap = TOOL_CATALOG[name][0]
            if not self.guard.allows(cap):
                # Capability gate: tool exists in the catalogue but the manifest does not declare it.
                return _ok({"content": [{"type": "text", "text": "capability not declared: %s" % cap}],
                            "isError": True}, rid)
            if self.policy.evaluate(cap) != "allow":
                return _ok({"content": [{"type": "text", "text": "node revoked"}], "isError": True}, rid)
            return _ok({"content": [{"type": "text", "text": "ok: %s" % name}], "isError": False}, rid)
        return _err(JSONRPC_METHOD_NOT_FOUND, "Method not found", method, rid=rid)

    # ---- did:adn two-node handshake (L1, wire-level) ----
    def issue_challenge(self):
        chal = self._next_id("chal")
        self._pending_challenges[chal] = False
        return {"peer_did": self.did, "challenge": chal}

    def accept_handshake(self, payload):
        ok, reasons = verify_handshake(self, payload)
        if not ok:
            return {"accepted": False, "reasons": sorted(reasons)}
        initiator = payload["initiator"]
        challenge = payload["challenge"]
        sess = session_id(initiator, self.did, challenge)
        ack = make_ack(self, initiator, challenge, sess)
        return {"accepted": True, "session": sess, "ack": ack}

    # ---- HTTP adapter (loopback only) ----
    def dispatch(self, method, path, body):
        if method == "GET" and path == "/.well-known/agent-card.json":
            card = self.agent_card()
            return 200, card
        if method == "GET" and path == "/adn/challenge":
            return 200, self.issue_challenge()
        if method == "POST" and path == "/adn/handshake":
            return 200, self.accept_handshake(body)
        if method == "POST" and path == "/mcp":
            return 200, self.handle_mcp(body)
        if method == "POST" and path in ("/", "/rpc"):
            return 200, self.handle_jsonrpc(body)
        return 404, _err(JSONRPC_METHOD_NOT_FOUND, "Not found", path)

    def serve_background(self, host="127.0.0.1"):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        node = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _respond(self, status, obj):
                payload = json.dumps(obj, sort_keys=True).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                try:
                    return json.loads(raw.decode("utf-8"))
                except Exception:
                    return None

            def do_GET(self):
                status, obj = node.dispatch("GET", self.path.split("?")[0], None)
                self._respond(status, obj)

            def do_POST(self):
                status, obj = node.dispatch("POST", self.path.split("?")[0], self._body())
                self._respond(status, obj)

        server = ThreadingHTTPServer((host, 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, port


def _ok(result, rid):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _err(code, message, detail=None, rid=None, reason=None):
    data = []
    if reason is not None:
        data.append({"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": reason,
                     "domain": "openadn.local"})
    if detail is not None:
        data.append({"detail": detail})
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message, "data": data}}


def _with_id(err, rid):
    e = dict(err)
    e["id"] = rid
    return e
