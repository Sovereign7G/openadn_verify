#!/usr/bin/env python3
"""chainverify_lib.py -- real Merkle commitments + a chain-agnostic anchor record (REAL, offline).

This is the mechanism that turns "verifiable in principle" into "one hash anyone can check". It does NOT deploy
anything and it does NOT make any off-chain claim true. What it does, for real and offline:

  * canonicalizes a set of artifacts (sorted by name) and hashes each into a leaf (domain-separated);
  * builds a binary Merkle tree and a root over the leaves;
  * produces and verifies a Merkle **inclusion proof** for any leaf;
  * builds a signed **anchor record** `{chain, root, height, sig}` -- the thing a chain would timestamp.

The chain layer (EVM/Solana) would only ever store/attest the 32-byte `root` and verify the Ed25519 signature.
Everything here is reproducible by a third party from the artifacts alone, which is the point.
"""
from __future__ import annotations

import hashlib


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def leaf_hash(name: str, content: bytes) -> str:
    """Domain-separated leaf hash: 0x00 || name || 0x00 || content."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return _sha(b"\x00" + name.encode("utf-8") + b"\x00" + content)


def node_hash(left_hex: str, right_hex: str) -> str:
    """Domain-separated internal node: 0x01 || left || right."""
    return _sha(b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def canonical_leaves(artifacts) -> list:
    """`artifacts` is an iterable of (name, content). Returns leaf hashes sorted by name -- so the root is
    independent of the order the artifacts were supplied in."""
    items = sorted(((n, c) for n, c in artifacts), key=lambda kv: kv[0])
    return [leaf_hash(n, c) for n, c in items], items


def merkle_root(leaf_hashes) -> str:
    if not leaf_hashes:
        return _sha(b"\x00empty")
    level = list(leaf_hashes)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(node_hash(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])          # carry the odd node up (no duplication ambiguity)
        level = nxt
    return level[0]


def merkle_proof(leaf_hashes, index: int):
    """Return [(side, sibling_hex), ...] proving leaf_hashes[index] is in the tree."""
    level = list(leaf_hashes)
    idx = index
    proof = []
    while len(level) > 1:
        if idx % 2 == 0 and idx + 1 < len(level):
            proof.append(("right", level[idx + 1]))
        elif idx % 2 == 1:
            proof.append(("left", level[idx - 1]))
        # if idx is the carried odd node, it has no sibling this level
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(node_hash(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
        idx //= 2
    return proof


def verify_proof(leaf_hex: str, proof, root_hex: str) -> bool:
    cur = leaf_hex
    for side, sib in proof:
        cur = node_hash(cur, sib) if side == "right" else node_hash(sib, cur)
    return cur == root_hex


def anchor_record(chain: str, root_hex: str, height: int, sk) -> dict:
    """The chain-agnostic anchor: what would be posted on EVM/Solana. Signed over (chain, root, height)."""
    from openadn_lib import sign
    body = {"chain": chain, "root": root_hex, "height": height}
    rec = dict(body)
    rec["sig"] = sign(sk, body)
    return rec


def verify_anchor(rec: dict, pk) -> bool:
    from openadn_lib import verify
    body = {"chain": rec.get("chain"), "root": rec.get("root"), "height": rec.get("height")}
    return verify(pk, body, rec.get("sig", ""))
