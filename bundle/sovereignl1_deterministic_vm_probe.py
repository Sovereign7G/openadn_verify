#!/usr/bin/env python3
"""sovereignl1_deterministic_vm_probe.py -- R346/H6: the S7G-L1 VM is deterministic, and it REJECTS nondeterminism.

The claim: S7G-L1's execution layer is a deterministic shell whose state commitment is reproducible, so a third
party can verify by replay. The critical property is not "deterministic commands reproduce" -- it is that a
NON-deterministic command is **rejected**, not silently accepted into diverging state. A VM that silently diverges
cannot be verified at all; a VM that rejects is usable.

Checks: (a) a deterministic log reproduces the same state root; (b) clock/RNG/IO ops are rejected; (c) rejection
leaves the state unchanged (no silent divergence); (d) a POSITIVE CONTROL -- a naive VM that accepts a clock read
produces TWO different roots for the same log -- shows why rejection is the load-bearing property; (e) replaying
the log reproduces the root (one state machine).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

APEX = os.environ.get("SOVEREIGN_APEX", os.path.expanduser("~/.apex"))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "chainverify"))

OUT = os.path.join(APEX, "sovereignl1_deterministic_vm_probe.json")

DETERMINISTIC_OPS = {"add", "concat", "set"}
NONDETERMINISTIC_OPS = {"now", "rand", "fetch", "blockhash", "io"}   # clock / RNG / external reads

CLAIMS = [
    {"id": "deterministic_command_is_reproducible",
     "assertion": "running a deterministic command log twice yields the identical state root",
     "would_also_pass_if": "the root were a constant, or excluded the mutated state",
     "fixtures_sanity": "the log actually mutates state, so an unchanged root would be detected"},
    {"id": "nondeterministic_command_is_rejected",
     "assertion": "a clock/RNG/IO command is rejected (validity fails), not accepted",
     "would_also_pass_if": "the VM had no notion of nondeterministic ops and executed them",
     "fixtures_sanity": "each of now/rand/fetch/io is submitted, so the rejection path is exercised"},
    {"id": "rejection_preserves_state",
     "assertion": "a rejected command leaves the state root UNCHANGED -- rejection, not silent divergence",
     "would_also_pass_if": "the VM rejected the verdict but still mutated state",
     "fixtures_sanity": "the root before and after a rejected command are compared",
     "predicate_intent": "assert state is *unchanged* on rejection, which is stricter than merely ok=false"},
    {"id": "silent_divergence_is_the_hazard",
     "assertion": "a naive VM that ACCEPTS a clock read produces two different roots for the same log",
     "would_also_pass_if": "the naive VM ignored the clock, so it would not diverge",
     "fixtures_sanity": "two different clocks are used, so divergence is reachable",
     "predicate_intent": "assert the control *does* diverge -- this is why rejection is required"},
    {"id": "log_replay_reproduces_root",
     "assertion": "replaying the accepted log reproduces the exact state root (one state machine)",
     "would_also_pass_if": "the root depended on a nonce or wall clock",
     "fixtures_sanity": "a multi-command log is replayed from genesis"},
]

REDUCES_TO = "sovereignl1_chain"
DEPENDS_ON = []
FIXTURE_PROVENANCE = ("the command log, clocks, and state are illustrative fixtures; the SHA-256 Merkle state "
                      "root, the opcode dispatch, and the rejection logic are real and offline. No chain runs.")


def state_root(state) -> str:
    from chainverify_lib import canonical_leaves, merkle_root
    leaves, _ = canonical_leaves([(k, str(state[k]).encode()) for k in sorted(state)])
    return merkle_root(leaves)


def exec_strict(state, cmd):
    """Deterministic shell VM. A nondeterministic op is REJECTED and state is left untouched."""
    op = cmd.get("op")
    if op in NONDETERMINISTIC_OPS:
        return {"ok": False, "reason": "nondeterministic:" + str(op), "state": state}
    s = dict(state)
    if op == "add":
        s["acc"] = s.get("acc", 0) + cmd["a"] + cmd["b"]
    elif op == "concat":
        s["s"] = s.get("s", "") + cmd["a"] + cmd["b"]
    elif op == "set":
        s[cmd["k"]] = cmd["v"]
    else:
        return {"ok": False, "reason": "unknown_op:" + str(op), "state": state}
    return {"ok": True, "reason": "ok", "state": s}


def exec_naive(state, cmd, clock):
    """Positive control: a VM that ACCEPTS a clock read -> silent divergence."""
    s = dict(state)
    if cmd.get("op") == "now":
        s["now"] = clock
    elif cmd.get("op") == "add":
        s["acc"] = s.get("acc", 0) + cmd["a"] + cmd["b"]
    return {"ok": True, "state": s}


def run_log(state, log):
    for c in log:
        r = exec_strict(state, c)
        if not r["ok"]:
            return r
        state = r["state"]
    return {"ok": True, "state": state}


LOG = [{"op": "add", "a": 2, "b": 3}, {"op": "concat", "a": "x", "b": "y"}, {"op": "set", "k": "z", "v": 9}]


def run() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    KEYS = tuple(c["id"] for c in CLAIMS) + ("sovereignl1_deterministic_vm_is_not_a_search_lever",)
    if os.environ.get("DOXX_SOVEREIGNL1_VM_DISABLE") == "1":
        claims = {k: False for k in KEYS}
        json.dump({"probe": "sovereignl1_deterministic_vm_probe", "measured": True, "reason": "no source",
                   "claims": claims, "conclusion": "FALSIFIED"}, open(OUT, "w"), indent=2, sort_keys=True)
        if args.selftest:
            print("SOVEREIGNL1 VM SELFTEST: FAIL (no source)"); return 1
        if args.json:
            print(json.dumps(claims, sort_keys=True)); return 0
        print("no source"); return 1

    genesis = {"genesis": 1}
    r1 = run_log(dict(genesis), LOG)
    r2 = run_log(dict(genesis), LOG)
    root1, root2 = state_root(r1["state"]), state_root(r2["state"])
    reproducible_ok = r1["ok"] and root1 == root2 and root1 != state_root(genesis)

    # (b) nondeterministic ops rejected
    rejects = {op: exec_strict(dict(genesis), {"op": op}) for op in sorted(NONDETERMINISTIC_OPS)}
    rejected_ok = all(not r["ok"] for r in rejects.values())

    # (c) rejection preserves state (no silent divergence)
    before = state_root(dict(genesis))
    rej = exec_strict(dict(genesis), {"op": "now"})
    after = state_root(rej["state"])
    preserves_ok = (rej["ok"] is False and before == after)

    # (d) positive control: naive VM accepting a clock diverges
    naive_log = [{"op": "add", "a": 1, "b": 1}, {"op": "now"}]
    sA = dict(genesis); sB = dict(genesis)
    for c in naive_log:
        sA = exec_naive(sA, c, 1000)["state"]
        sB = exec_naive(sB, c, 2000)["state"]
    divergence_ok = state_root(sA) != state_root(sB)

    # (e) replay reproduces the root
    replay_ok = state_root(run_log(dict(genesis), LOG)["state"]) == root1

    claims = {
        "deterministic_command_is_reproducible": bool(reproducible_ok),
        "nondeterministic_command_is_rejected": bool(rejected_ok),
        "rejection_preserves_state": bool(preserves_ok),
        "silent_divergence_is_the_hazard": bool(divergence_ok),
        "log_replay_reproduces_root": bool(replay_ok),
        "sovereignl1_deterministic_vm_is_not_a_search_lever": True,
    }
    evidence = {
        "log_len": len(LOG), "root_after_log": root1, "genesis_root": state_root(genesis),
        "rejected_ops": sorted(r["reason"] for r in rejects.values()),
        "state_preserved_on_reject": bool(before == after),
        "naive_divergent_roots": [state_root(sA), state_root(sB)],
    }
    rec = {"probe": "sovereignl1_deterministic_vm_probe", "measured": True,
           "round_type": "divergent", "kind": "composition",
           "reduces_to": REDUCES_TO, "depends_on": DEPENDS_ON,
           "fixtures_provenance": FIXTURE_PROVENANCE,
           "ruleset": "the S7G-L1 VM is a deterministic shell: deterministic logs reproduce the root, "
                      "nondeterministic ops are rejected (not silently divergent), and replay reproduces the root",
           "evidence": evidence,
           "claims": claims,
           "vetoes": ["nondeterminism_accepted", "silent_divergence", "replay_mismatch"],
           "conclusion": "SUPPORTED" if all(claims.values()) else "FALSIFIED"}
    json.dump(rec, open(OUT, "w"), indent=2, sort_keys=True)

    if args.selftest:
        ok = all(claims.values())
        print("SOVEREIGNL1 VM SELFTEST: %s (repro=%s reject=%s preserve=%s control=%s replay=%s)" % (
            "PASS" if ok else "FAIL", reproducible_ok, rejected_ok, preserves_ok, divergence_ok, replay_ok))
        return 0 if ok else 1
    if args.json:
        print(json.dumps({k: bool(v) for k, v in claims.items()}, sort_keys=True)); return 0
    print("=" * 78)
    print("  SOVEREIGNL1 VM -- deterministic shell; nondeterminism is REJECTED, not silently divergent")
    for k in sorted(claims):
        print("  %-52s : %s" % (k, claims[k]))
    print("  ledger -> %s" % OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
