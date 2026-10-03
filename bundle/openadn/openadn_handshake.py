#!/usr/bin/env python3
"""openadn_handshake.py -- a two-node `did:adn` mutual handshake (REAL crypto, loopback transport).

Protocol (two-round, challenge-response, replay-resistant):

  1. initiator -> responder :  GET /adn/challenge
         responder returns {peer_did, challenge} where challenge is single-use.
  2. initiator -> responder :  POST /adn/handshake
         {type, initiator, responder, challenge, manifest, sig}
         sig = Ed25519 over (type, initiator, responder, challenge) under the initiator's key.
  3. responder verifies: manifest is signed and its DID == initiator; msg.responder == responder.did;
         the challenge is pending and unconsumed; sig verifies. It then consumes the challenge and replies
         {type, responder, initiator, challenge, session, manifest, sig} where sig is over
         (type, responder, initiator, challenge, session) -- giving the initiator a mutual acknowledgement.

Both sides prove possession of the key bound to their DID; neither trusts a host or an address. A replayed
handshake fails (the challenge is consumed); a message addressed to a different responder fails.
"""
from __future__ import annotations

import hashlib

from openadn_lib import public_from_b64, sign, verify, verify_manifest

HANDSHAKE_TYPE = "adn.handshake"
ACK_TYPE = "adn.ack"


def handshake_body(initiator_did, responder_did, challenge):
    return {"type": HANDSHAKE_TYPE, "initiator": initiator_did, "responder": responder_did,
            "challenge": challenge}


def make_handshake(node, responder_did, challenge):
    """Build a signed handshake message from `node` (an object with .did, .sk, .manifest)."""
    body = handshake_body(node.did, responder_did, challenge)
    msg = dict(body)
    msg["manifest"] = node.manifest
    msg["sig"] = sign(node.sk, body)
    return msg


def verify_handshake(responder_node, msg):
    """Responder side. Returns (ok, reasons). Consumes the challenge only on success."""
    reasons = []
    if not isinstance(msg, dict) or msg.get("type") != HANDSHAKE_TYPE:
        return False, ["not_a_handshake"]
    if msg.get("responder") != responder_node.did:
        reasons.append("wrong_responder")
    challenge = msg.get("challenge")
    pending = responder_node._pending_challenges
    if challenge not in pending:
        reasons.append("unknown_challenge")
    elif pending[challenge] is True:
        reasons.append("challenge_already_consumed")
    manifest = msg.get("manifest")
    ok_m, m_reasons = verify_manifest(manifest) if manifest is not None else (False, ["no_manifest"])
    if not ok_m:
        reasons.append("manifest_invalid:" + ",".join(m_reasons))
    elif manifest["did"] != msg.get("initiator"):
        reasons.append("initiator_did_not_bound_to_manifest")
    if not reasons:
        body = handshake_body(msg["initiator"], msg["responder"], challenge)
        if not verify(public_from_b64(manifest["public_key"]), body, msg.get("sig", "")):
            reasons.append("handshake_signature_invalid")
    if reasons:
        return False, reasons
    pending[challenge] = True                      # single-use: consume on success
    return True, []


def make_ack(responder_node, initiator_did, challenge, session):
    body = {"type": ACK_TYPE, "responder": responder_node.did, "initiator": initiator_did,
            "challenge": challenge, "session": session}
    msg = dict(body)
    msg["manifest"] = responder_node.manifest
    msg["sig"] = sign(responder_node.sk, body)
    return msg


def verify_ack(initiator_did, responder_did, challenge, ack):
    """Initiator side. Returns (ok, reasons)."""
    reasons = []
    if not isinstance(ack, dict) or ack.get("type") != ACK_TYPE:
        return False, ["not_an_ack"]
    if ack.get("responder") != responder_did:
        reasons.append("ack_responder_mismatch")
    if ack.get("initiator") != initiator_did:
        reasons.append("ack_initiator_mismatch")
    if ack.get("challenge") != challenge:
        reasons.append("ack_challenge_mismatch")
    manifest = ack.get("manifest")
    ok_m, m_reasons = verify_manifest(manifest) if manifest is not None else (False, ["no_manifest"])
    if not ok_m:
        reasons.append("manifest_invalid:" + ",".join(m_reasons))
    elif manifest["did"] != responder_did:
        reasons.append("ack_manifest_not_responder")
    if not reasons:
        body = {"type": ACK_TYPE, "responder": ack["responder"], "initiator": ack["initiator"],
                "challenge": ack["challenge"], "session": ack["session"]}
        if not verify(public_from_b64(manifest["public_key"]), body, ack.get("sig", "")):
            reasons.append("ack_signature_invalid")
    return (len(reasons) == 0), reasons


def session_id(initiator_did, responder_did, challenge):
    return "sess-" + hashlib.sha256(("%s|%s|%s" % (initiator_did, responder_did, challenge)).encode()).hexdigest()[:16]
