#!/usr/bin/env python3
"""openadn_lib.py -- OpenADN L1-L4 primitives (REAL, not modelled).

This is the first OpenADN module that implements the spec's primitives as *executable* code rather than
fixtures. Everything here is deterministic and offline; nothing touches the network, the kernel, or routing.

Scope, stated honestly:
  * L1 identity   -- REAL Ed25519 keypairs, `did:adn` derived from the public key, signed capability manifest.
  * L2 mesh       -- MODEL of an eBPF sandbox policy (allow/deny/revoke) and of an ephemeral tunnel registry.
                     The policy is real code; the *kernel enforcement* is not (that would reconfigure the host).
  * L3 routing    -- MODEL of a Kademlia capability DHT (capability/tag lookup + XOR distance). No sockets.
  * L4 settlement -- MODEL of a driver-agnostic settlement interface with S7G k-of-n approval. No money moves.

The point of this module is that the parts that *can* be real are real: keys, signatures, DID binding,
capability gating, JSON-RPC dispatch, and the eBPF policy decision function. The parts that cannot be real
offline (kernel enforcement, live routing, settlement) are explicitly modelled and flagged as such.
"""
from __future__ import annotations

import base64
import hashlib
import json

# ---------------------------------------------------------------------------------------------------
# L1 -- identity & sovereignty (REAL)
# ---------------------------------------------------------------------------------------------------

def _public_from_private(sk):
    return sk.public_key()


def generate_keypair():
    """Return (Ed25519PrivateKey, Ed25519PublicKey). Requires `cryptography`."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key()


def keypair_from_seed(seed) -> tuple:
    """Deterministic keypair from a fixed seed (32 bytes, or hashed if longer/shorter). Makes DIDs, signatures,
    and sessions reproducible across runs -- so a runtime probe's ledger can record them and stay byte-identical."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if isinstance(seed, str):
        seed = seed.encode("utf-8")
    if len(seed) != 32:
        seed = hashlib.sha256(seed).digest()
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    return sk, sk.public_key()


def _raw_public(pk) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def canonical(obj) -> bytes:
    """Deterministic JSON: sorted keys, no insignificant whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def did_from_public(pk) -> str:
    """A `did:adn` is a function of the public key ONLY -- never the host. This is the sovereignty property."""
    return "did:adn:" + hashlib.sha256(_raw_public(pk)).hexdigest()[:32]


def key_fingerprint(pk) -> str:
    return hashlib.sha256(_raw_public(pk)).hexdigest()[:16]


def public_from_b64(pub_b64: str):
    """Reconstruct an Ed25519 public key from its base64url raw form (e.g. from a manifest)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    return Ed25519PublicKey.from_public_bytes(unb64(pub_b64))


def sign(sk, obj) -> str:
    return b64(sk.sign(canonical(obj)))


def verify(pk, obj, signature: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    try:
        pk.verify(unb64(signature), canonical(obj))
        return True
    except (InvalidSignature, Exception):
        return False


# ---------------------------------------------------------------------------------------------------
# L1 -- capability & intent manifest (REAL, signed)
# ---------------------------------------------------------------------------------------------------

MANIFEST_FIELDS = ("did", "public_key", "capabilities", "bounds", "trusted_keys", "nonce", "issued_at", "sig_alg")


def _unsigned(manifest: dict) -> dict:
    """The signed body: everything except the detached signature itself."""
    return {k: v for k, v in manifest.items() if k != "signature"}


def build_manifest(sk, capabilities, bounds=None, trusted_keys=(), nonce="n0", issued_at="1970-01-01T00:00:00.000Z"):
    """Build and sign a capability manifest. `capabilities` is the *complete* set of actions the agent may take:
    an action not listed here is denied (default-deny), per OpenADN spec L1."""
    caps = sorted(set(capabilities))
    manifest = {
        "did": did_from_public(sk.public_key()),
        "public_key": b64(_raw_public(sk.public_key())),
        "capabilities": caps,
        "bounds": dict(bounds or {}),
        "trusted_keys": sorted(set(trusted_keys)),
        "nonce": nonce,
        "issued_at": issued_at,
        "sig_alg": "Ed25519",
    }
    manifest["signature"] = sign(sk, _unsigned(manifest))
    return manifest


def verify_manifest(manifest: dict):
    """Return (ok: bool, reasons: list[str]). Checks DID<->key binding AND the detached signature."""
    reasons = []
    if not isinstance(manifest, dict):
        return False, ["manifest_not_an_object"]
    for f in ("did", "public_key", "capabilities", "signature"):
        if f not in manifest:
            reasons.append("missing_field:" + f)
    if reasons:
        return False, reasons
    try:
        pub_raw = unb64(manifest["public_key"])
    except Exception:
        return False, ["public_key_not_base64url"]
    did_recomputed = "did:adn:" + hashlib.sha256(pub_raw).hexdigest()[:32]
    if did_recomputed != manifest["did"]:
        reasons.append("did_key_binding_mismatch")
    caps = manifest["capabilities"]
    if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
        reasons.append("capabilities_not_list_of_str")
    if len(caps) != len(set(caps)):
        reasons.append("capabilities_have_duplicates")
    # signature check
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        pk = Ed25519PublicKey.from_public_bytes(pub_raw)
    except Exception:
        return False, reasons + ["public_key_not_ed25519"]
    if not verify(pk, _unsigned(manifest), manifest["signature"]):
        reasons.append("signature_invalid")
    return (len(reasons) == 0), reasons


# ---------------------------------------------------------------------------------------------------
# L1 -- capability gate (REAL)
# ---------------------------------------------------------------------------------------------------

class CapabilityGuard:
    """Default-deny gate over a verified manifest. `allows(x)` is True iff x is a *declared* capability."""

    def __init__(self, manifest: dict):
        ok, reasons = verify_manifest(manifest)
        if not ok:
            raise ValueError("manifest not verifiable: %s" % ",".join(reasons))
        self.manifest = manifest
        self._caps = frozenset(manifest["capabilities"])

    def allows(self, action: str) -> bool:
        return action in self._caps

    def declared(self):
        return sorted(self._caps)


# ---------------------------------------------------------------------------------------------------
# L2 -- eBPF sandbox policy model (decision function REAL, enforcement modelled)
# ---------------------------------------------------------------------------------------------------

class SandboxPolicy:
    """Models the L2 eBPF containment decision function.

    `evaluate(action)` returns one of "allow" | "deny" | "revoked". A rogue action calls `revoke()`, after
    which *every* action is "revoked" (network privileges withdrawn). This is the decision logic an eBPF
    program would implement; we deliberately do NOT load it into the kernel.
    """

    def __init__(self, allow=(), name="policy"):
        self.name = name
        self.allow = frozenset(allow)
        self.revoked = False
        self.violations = []

    def evaluate(self, action: str) -> str:
        if self.revoked:
            return "revoked"
        return "allow" if action in self.allow else "deny"

    def revoke(self, reason="violation"):
        self.revoked = True
        self.violations.append(reason)
        return "revoked"


class MeshRegistry:
    """A set of per-agent sandbox policies. Revoking one must NOT affect the others (no collateral)."""

    def __init__(self):
        self._policies = {}

    def add(self, agent_id: str, policy: SandboxPolicy):
        self._policies[agent_id] = policy

    def revoke(self, agent_id: str, reason="violation"):
        return self._policies[agent_id].revoke(reason)

    def state(self, agent_id: str) -> str:
        return "revoked" if self._policies[agent_id].revoked else "active"

    def snapshot(self):
        return {k: ("revoked" if p.revoked else "active") for k, p in sorted(self._policies.items())}


class TunnelRegistry:
    """Models ephemeral mutual-TLS WireGuard tunnels: created per-pair on demand, torn down on completion.
    Atomic: a tunnel is always either fully up (both legs) or fully down (neither)."""

    def __init__(self):
        self._tunnels = {}

    def open(self, pair):
        key = tuple(sorted(pair))
        self._tunnels[key] = {"legs": "up", "state": "up"}
        return key

    def close(self, pair):
        key = tuple(sorted(pair))
        self._tunnels.pop(key, None)
        return key

    def state(self, pair):
        return self._tunnels.get(tuple(sorted(pair)))


# ---------------------------------------------------------------------------------------------------
# L3 -- Kademlia capability DHT model (lookup REAL, transport modelled)
# ---------------------------------------------------------------------------------------------------

def _node_id(agent_id: str) -> int:
    return int(hashlib.sha256(agent_id.encode()).hexdigest(), 16)


def xor_distance(a: str, b: str) -> int:
    return _node_id(a) ^ _node_id(b)


class CapabilityDHT:
    """Discovery is by *capability/tag*, never by IP. There is no central directory; a lookup returns the
    set of agent ids that declared the tag, ordered by XOR distance to the querier (Kademlia)."""

    def __init__(self):
        self._entries = {}          # agent_id -> sorted caps

    def publish(self, agent_id: str, capabilities):
        self._entries[agent_id] = sorted(set(capabilities))

    def find(self, tag: str, querier: str):
        hits = [a for a, caps in self._entries.items() if tag in caps]
        return sorted(hits, key=lambda a: (xor_distance(querier, a), a))

    def agents(self):
        return sorted(self._entries)


# ---------------------------------------------------------------------------------------------------
# L4 -- settlement model (interface REAL, money modelled) + S7G quorum
# ---------------------------------------------------------------------------------------------------

class SettlementEngine:
    """Driver-agnostic settlement: any of lightning/fiat/stablecoin/barter. Settlement is DECOUPLED from comms.
    A settlement is only final when approved by an S7G k-of-n quorum and backed by reserves."""

    DRIVERS = ("lightning", "fiat", "stablecoin", "barter")

    def __init__(self, reserve, committee_size, threshold):
        self.reserve = reserve
        self.committee_size = committee_size
        self.threshold = threshold
        self.ledger = []

    def settle(self, driver: str, amount: int, votes: int, request_id="s0"):
        if driver not in self.DRIVERS:
            return {"status": "rejected", "reason": "unknown_driver"}
        if votes < self.threshold:
            return {"status": "rejected", "reason": "no_quorum"}
        if amount > self.reserve:
            return {"status": "rejected", "reason": "insufficient_reserve"}
        self.reserve -= amount
        rec = {"id": request_id, "driver": driver, "amount": amount, "votes": votes, "reserve_after": self.reserve}
        self.ledger.append(rec)
        return {"status": "settled", **rec}
