"""OpenADN -- open, S7G-governed Agentic Defined Network (R339 runtime).

Real, offline, deterministic primitives (identity, manifest, capability gate, sandbox policy model,
Kademlia DHT model, settlement model) plus a loopback agent node exposing A2A + MCP JSON-RPC surfaces.
See `../../../OPENADN_SPEC.md` (R338) for the design and `DIVERGENT_OPENADN_R339.md` for this round.
"""
from .openadn_lib import (  # noqa: F401
    CapabilityDHT,
    CapabilityGuard,
    MeshRegistry,
    SandboxPolicy,
    SettlementEngine,
    TunnelRegistry,
    build_manifest,
    did_from_public,
    generate_keypair,
    keypair_from_seed,
    verify_manifest,
)
