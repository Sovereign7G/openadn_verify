# CHANGELOG

## 1.0.0

First published release. Self-contained, offline verification of the OpenADN reference implementation.

**Contents**
- OpenADN runtime: `openadn_lib` (identity/manifest/signatures), `openadn_node` (A2A/MCP JSON-RPC),
  `openadn_dht` (Kademlia capability DHT), `openadn_handshake` (mutual `did:adn`), `openadn_recovery`
  (pre-committed succession + time-locked rotation).
- `chainverify_lib`: Merkle anchor + inclusion proofs + signed anchor.
- 11 probes, all offline: A2A conformance, MCP conformance, loopback integration, wire DHT, mutual
  handshake, recovery, chain anchor, card anchor, and three `sovereignl1` checks (closure, deterministic
  VM, internal mining).

**Guarantees**
- Three-layer verification: signature over the archive; manifest over the artifacts; probes over the claims.
- Two negative controls: `--break` (tamper detected) and `--break-claims` (vacuous verifier detected).

**Scope**
- Loopback reference implementation. Not a deployed network. No kernel eBPF, no WireGuard, no BGP, no money.
- No doxx token, no ICP, no Solana RPC, no external network, no secrets.

**Status**
- Verifiable by anyone; **not yet verified by anyone but the author**.
  Metric of record: *time-to-first-independent-verification* (published: see the release page).
