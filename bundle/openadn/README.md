# OpenADN runtime (`openadn/`)

A **local reference implementation** of the OpenADN design (`../OPENADN_SPEC.md`). Real, deterministic, offline;
loopback only. See `../DIVERGENT_OPENADN_R339.md` / `_R340.md` and `../COVERAGE.md` §2d.

**Disclaimer.** Measured against a **loopback reference implementation, not a deployed network**. Verify by reading
the spec and running the code. Real layers: Ed25519 keys, DIDs, signatures, capability gate, containment decision,
JSON-RPC dispatch, DHT placement/federation, mutual handshake. **Modelled / not deployed:** kernel eBPF
enforcement, WireGuard/BGP, a global DHT transport, settlement.

## Public interfaces

### `openadn_lib.py` — identity, manifest, security models
- `generate_keypair()` / `keypair_from_seed(seed)` → `(Ed25519PrivateKey, Ed25519PublicKey)`. Seeded keys make
  DIDs/signatures reproducible (used so runtime ledgers stay byte-identical).
- `did_from_public(pk)` → `did:adn:<sha256(pubkey)[:32]>` (a function of the **key**, never the host).
- `build_manifest(sk, capabilities, bounds=, trusted_keys=, nonce=, issued_at=)` → signed manifest.
- `verify_manifest(manifest)` → `(ok: bool, reasons: list[str])` (checks DID↔key binding **and** the signature).
- `CapabilityGuard(manifest)` → `.allows(action)`, `.declared()` (default-deny).
- `SandboxPolicy(allow, name=)` → `.evaluate(action) ∈ {allow, deny, revoked}`, `.revoke(reason)`.
- `MeshRegistry` / `TunnelRegistry` — containment with no collateral; ephemeral, atomic tunnels.
- `CapabilityDHT(querier)` — in-process model: `.publish`, `.find(tag, querier)`, `.agents()`.
- `SettlementEngine(reserve, committee_size, threshold)` — driver-agnostic, S7G-quorum settlement model.
- `xor_distance(a, b)`, `sign(sk, obj)`, `verify(pk, obj, sig)`, `public_from_b64(s)`.

### `openadn_node.py` — the agent node
- `AgentNode(name, capabilities, bounds=, skills=, nonce=, seed=)` → attributes `.did`, `.manifest`, `.sk`, `.pk`.
- `agent_card(url=)` — A2A v1.0.0 Agent Card.
- `handle_jsonrpc(req)` — A2A: `SendMessage`, `GetTask`, `ListTasks`, `CancelTask` (+ spec error codes).
- `handle_mcp(req)` — MCP: `initialize`, `tools/list`, `tools/call` (manifest-filtered tool surface).
- `issue_challenge()` / `accept_handshake(payload)` — the `did:adn` handshake server side.
- `serve_background(host="127.0.0.1")` → `(server, thread, port)`; `dispatch(method, path, body)` → `(status, obj)`.
  Routes: `GET /.well-known/agent-card.json`, `GET /adn/challenge`, `POST /adn/handshake`, `POST /mcp`, `POST /`.

### `openadn_handshake.py` — two-node mutual auth
- `make_handshake(node, responder_did, challenge)` → signed message.
- `verify_handshake(responder_node, msg)` → `(ok, reasons)`; **consumes** the single-use challenge on success.
- `make_ack(node, initiator_did, challenge, session)` / `verify_ack(initiator_did, responder_did, challenge, ack)`.
- `session_id(initiator_did, responder_did, challenge)`.

### `openadn_dht.py` — sharded discovery over real peers
- `DHTPeer(node_id, replication=2)` → `.publish(agent_id, caps)`, `.find(tag, querier)`, `.local_matches(tag)`,
  `.store`, `.peers`, `.serve_background()`, `.shutdown()`.
- `DHTCluster(node_ids, replication=2)` → starts N peers and wires them; `.publish(entry, agent, caps)`,
  `.find(entry, tag, querier)`, `.local_matches(node, tag)`, `.local_size(node)`, `.shutdown()`.
- Placement is XOR-closest-`k`; a lookup federates across all peers and returns DIDs ordered by XOR distance.

### `openadn_cli.py`
`keygen` · `card [--caps]` · `serve [--caps]` · `call <url> <capability>`.

## Test it
```
SOVEREIGN_APEX=/tmp/x python3 ../oadnrun_integration_probe.py --selftest
SOVEREIGN_APEX=/tmp/x python3 ../oadnrun_handshake_probe.py  --selftest
SOVEREIGN_APEX=/tmp/x python3 ../oadnrun_dht_wire_probe.py   --selftest
```
