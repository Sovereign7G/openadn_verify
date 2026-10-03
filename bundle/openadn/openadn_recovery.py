#!/usr/bin/env python3
"""openadn_recovery.py -- OpenADN L1 recovery clause (REAL, offline).

H-R4.  The corpus lost 16 ICP canisters to a single lost principal (see orphan_registry.py).  That is the
concrete, measured failure mode of *fragile-autonomous* identity: an agent whose existence is bound to one
key is permanently bricked when that key is lost.  A `did:adn` that claims sovereignty must therefore carry
a **recovery clause** -- sovereignty is only credible if it is recoverable.

The primitive (all real Ed25519, deterministic, offline):

  * `build_succession(sk, successor_pub, valid_from, nonce)` -- the CURRENT key publishes a signed record
    naming a pre-committed successor key and a time (epoch seconds) from which that successor may act.
    Publishing it is cheap and can be done while the key is healthy.
  * `make_rotation(succession, successor_sk, new_kp)` -- the successor proves continuity: it signs a
    statement binding the old did -> the new did.
  * `verify_rotation(succession, rotation, now)` -- any peer accepts the rotation iff:
      1. the succession is a valid signed record from the current key, and
      2. `now >= valid_from` (the time-lock), and
      3. the rotation is signed by the *pre-committed* successor (not an arbitrary key), and
      4. the new did is the key-derived did of the new public key.

The load-bearing property: **recovery must be pre-committed.**  You cannot recover what you never delegated.
A stolen or lost key cannot mint a new successor after the fact -- the successor was fixed at publication
time.  This is exactly why the 16 orphans are unrecoverable: no succession record ever existed.
"""
from __future__ import annotations

from openadn_lib import _raw_public, b64, canonical, did_from_public, public_from_b64, sign, verify


def build_succession(sk, successor_pub, valid_from: int, nonce: str = "r0") -> dict:
    """Publish a succession record signed by the CURRENT key. `successor_pub` is pre-committed here."""
    body = {
        "did": did_from_public(sk.public_key()),
        "public_key": b64(_raw_public(sk.public_key())),
        "successor_key": b64(_raw_public(successor_pub)),
        "valid_from": int(valid_from),
        "nonce": nonce,
        "sig_alg": "Ed25519",
    }
    body["signature"] = sign(sk, body)
    return body


def verify_succession(succession: dict):
    """Return (ok, reasons). Checks the current key signed it and the did<->key binding holds."""
    reasons = []
    for f in ("did", "public_key", "successor_key", "valid_from", "nonce", "sig_alg", "signature"):
        if f not in succession:
            reasons.append("missing:" + f)
    if reasons:
        return False, reasons
    try:
        cur = public_from_b64(succession["public_key"])
    except Exception:  # noqa: BLE001
        return False, ["public_key_not_ed25519"]
    if succession["did"] != did_from_public(cur):
        reasons.append("did_key_mismatch")
    if succession["successor_key"] == succession["public_key"]:
        reasons.append("successor_is_current")
    body = {k: v for k, v in succession.items() if k != "signature"}
    if not verify(cur, body, succession["signature"]):
        reasons.append("succession_signature_invalid")
    return (not reasons), reasons


def make_rotation(succession: dict, successor_sk, new_pub) -> dict:
    """The successor proves continuity from the old did to the new key's did."""
    stmt = {
        "succession_nonce": succession["nonce"],
        "old_did": succession["did"],
        "old_public_key": succession["public_key"],
        "successor_key": succession["successor_key"],
        "new_public_key": b64(_raw_public(new_pub)),
        "new_did": did_from_public(new_pub),
    }
    stmt["signature"] = sign(successor_sk, stmt)
    return stmt


def verify_rotation(succession: dict | None, rotation: dict, now: int):
    """Return (ok, reasons, new_did). The four acceptance conditions above, in order."""
    reasons = []
    if succession is None:
        return False, ["no_succession"], None
    ok, sreasons = verify_succession(succession)
    if not ok:
        return False, ["succession_invalid:" + r for r in sreasons], None
    if now < succession["valid_from"]:
        return False, ["time_lock_not_reached"], None
    if rotation.get("old_did") != succession["did"]:
        reasons.append("old_did_mismatch")
    if rotation.get("succession_nonce") != succession["nonce"]:
        reasons.append("nonce_mismatch")
    if rotation.get("new_did") != did_from_public(_pub_from_b64(rotation.get("new_public_key"))):
        reasons.append("new_did_not_key_derived")
    if rotation.get("new_did") == succession["did"]:
        reasons.append("no_key_change")
    # the rotation MUST be signed by the pre-committed successor -- not an arbitrary key
    succ_pub = public_from_b64(succession["successor_key"])
    body = {k: v for k, v in rotation.items() if k != "signature"}
    if not verify(succ_pub, body, rotation.get("signature", "")):
        reasons.append("successor_signature_invalid")
    return (not reasons), reasons, rotation.get("new_did")


def _pub_from_b64(text):
    return public_from_b64(text)


def canonical_bytes(obj) -> bytes:
    """Exposed for callers that want the exact signed bytes (parity with openadn_lib.canonical)."""
    return canonical(obj)
