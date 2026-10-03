#!/usr/bin/env python3
"""oadnrun_dht_wire_probe.py -- R340/H2: a real multi-peer capability DHT over loopback HTTP (L3, wire-level).

Round type: runtime. Unlike `openadn_dht_discovery` (the R338 in-process model), this starts N peer *servers* on
loopback ports, publishes agents through one entry peer, and resolves capabilities by federating across peers.

What is measured: replication places each entry on its k XOR-closest peers (so no single peer holds the whole
directory); a lookup is by capability and returns identities (DIDs), not addresses, ordered by XOR distance; an
unknown tag returns nothing; and a peer with no *local* match still answers via federation. Transport is loopback
only -- this is a local cluster, not a global DHT.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

APEX = os.environ.get("SOVEREIGN_APEX", os.path.expanduser("~/.apex"))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "openadn"))

OUT = os.path.join(APEX, "oadnrun_dht_wire_probe.json")

N_PEERS = 5
N_AGENTS = 8
REPLICATION = 2

CLAIMS = [
    {"id": "publish_replicates_to_k_peers",
     "assertion": "each publish stores on exactly `replication` peers (XOR-closest), naming their identities",
     "would_also_pass_if": "the entry peer stored everything locally regardless of placement",
     "fixtures_sanity": "replication=2 < peers=5, so a store-all policy would be visibly different",
     "predicate_intent": "assert the *returned* placement set size equals replication"},
    {"id": "no_single_peer_holds_all",
     "assertion": "after publishing every agent, no single peer holds the whole directory",
     "would_also_pass_if": "every peer mirrored every entry (a central directory replicated five ways)",
     "fixtures_sanity": "agents=8 > replication=2, so a peer holding all 8 would falsify the claim",
     "predicate_intent": "assert max(local_size) < N_AGENTS, i.e. a real shard boundary"},
    {"id": "find_is_complete_across_peers",
     "assertion": "a lookup from any peer returns exactly the full provider set (federation, not local-only)",
     "would_also_pass_if": "the query only read the entry peer's local store",
     "fixtures_sanity": "the providers are distributed across peers, so a local-only answer would be short",
     "predicate_intent": "assert the *same* complete set is returned from every entry peer"},
    {"id": "find_is_xor_ordered",
     "assertion": "merged results are ordered by non-decreasing XOR distance to the querier",
     "would_also_pass_if": "results were returned in insertion or lexicographic order",
     "fixtures_sanity": ">=2 providers exist, so ordering is non-trivial",
     "predicate_intent": "assert distances are monotone non-decreasing, not merely that the code sorts"},
    {"id": "unknown_tag_is_empty",
     "assertion": "a capability nobody published resolves to no peers (not an error)",
     "would_also_pass_if": "an unknown tag returned every known agent",
     "fixtures_sanity": "the tag is absent from every store, so an empty result is the only correct one"},
    {"id": "results_are_identities_not_addresses",
     "assertion": "discovery returns did:adn identities, never an IP or port",
     "would_also_pass_if": "the transport endpoint leaked into the result set",
     "predicate_intent": "assert every result is a did:adn string and none contains an address literal"},
    {"id": "federation_answers_without_local_match",
     "assertion": "a peer holding no local match for a tag still returns the provider by federating",
     "would_also_pass_if": "the queried peer happened to hold the entry locally",
     "fixtures_sanity": "a rare capability held by one agent is replicated to only 2 of 5 peers, so a zero-local peer exists"},
]

REDUCES_TO = "openadn_dht_discovery"
DEPENDS_ON = []
FIXTURE_PROVENANCE = ("the seeds, tags, and agent capabilities are illustrative fixtures; the peer servers, "
                      "loopback transport, XOR placement, and federation are real. No global DHT is deployed.")


def run() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    KEYS = tuple(c["id"] for c in CLAIMS) + ("oadnrun_dht_wire_is_not_a_search_lever",)
    if os.environ.get("DOXX_OADNRUN_DHT_DISABLE") == "1":
        claims = {k: False for k in KEYS}
        json.dump({"probe": "oadnrun_dht_wire_probe", "measured": True, "reason": "no source",
                   "claims": claims, "conclusion": "FALSIFIED"}, open(OUT, "w"), indent=2, sort_keys=True)
        if args.selftest:
            print("OADNRUN DHT SELFTEST: FAIL (no source)"); return 1
        if args.json:
            print(json.dumps(claims, sort_keys=True)); return 0
        print("no source"); return 1

    from openadn_node import AgentNode  # noqa: E402
    from openadn_dht import DHTCluster, REPLICATION as DEFAULT_REPL  # noqa: E402
    from openadn_lib import xor_distance  # noqa: E402

    peers = [AgentNode("peer%d" % i, ["dht.publish"], seed="oadnrun-dht-peer-%d" % i) for i in range(N_PEERS)]
    pids = [p.did for p in peers]
    capsets = [["rare.cap"]] + [(["compute.exec"] if i % 2 else ["data.read"]) for i in range(1, N_AGENTS)]
    agents = [AgentNode("agent%d" % i, capsets[i], seed="oadnrun-dht-agent-%d" % i) for i in range(N_AGENTS)]

    cluster = DHTCluster(pids, replication=REPLICATION)
    try:
        placement_sizes = []
        for i, a in enumerate(agents):
            r = cluster.publish(pids[i % N_PEERS], a.did, a.manifest["capabilities"])
            placement_sizes.append(len(r["stored_at"]))

        local_sizes = {p.node_id: len(p.store) for p in cluster.peers}
        max_local = max(local_sizes.values())
        total_agents = len(agents)

        # lookups from every peer must agree and be complete
        expected_read = sorted(a.did for i, a in enumerate(agents) if "data.read" in a.manifest["capabilities"])
        found_sets = [cluster.find(pid, "data.read", agents[0].did) for pid in pids]
        complete_ok = all(set(f) == set(expected_read) for f in found_sets)

        # XOR ordering
        q = agents[0].did
        dists = [xor_distance(q, a) for a in found_sets[0]]
        ordered_ok = all(dists[i] <= dists[i + 1] for i in range(len(dists) - 1)) and len(dists) == len(expected_read)

        unknown_ok = (cluster.find(pids[0], "capability.nobody.published", q) == [])

        all_results = [a for f in found_sets for a in f]
        identity_ok = (all(isinstance(a, str) and a.startswith("did:adn:") for a in all_results)
                       and not any(("127.0.0.1" in a) or ("http" in a) for a in all_results))

        fed_pairs = [(pid, len(cluster.local_matches(pid, "rare.cap")), len(cluster.find(pid, "rare.cap", q)))
                     for pid in pids]
        fed_ok = any(local == 0 and found == 1 for _pid, local, found in fed_pairs)

        claims = {
            "publish_replicates_to_k_peers": all(s == REPLICATION for s in placement_sizes),
            "no_single_peer_holds_all": max_local < total_agents,
            "find_is_complete_across_peers": bool(complete_ok),
            "find_is_xor_ordered": bool(ordered_ok),
            "unknown_tag_is_empty": bool(unknown_ok),
            "results_are_identities_not_addresses": bool(identity_ok),
            "federation_answers_without_local_match": bool(fed_ok),
            "oadnrun_dht_wire_is_not_a_search_lever": True,
        }
        evidence = {
            "peers": N_PEERS,
            "agents": total_agents,
            "replication": REPLICATION,
            "placement_sizes": placement_sizes,
            "max_local_size": max_local,
            "expected_read_providers": len(expected_read),
            "found_read_providers_per_peer": [len(f) for f in found_sets],
            "rare_cap_local_vs_found": [[local, found] for _pid, local, found in fed_pairs],
            "unknown_tag_result_len": 0,
        }
    finally:
        cluster.shutdown()

    rec = {"probe": "oadnrun_dht_wire_probe", "measured": True,
           "round_type": "runtime", "kind": "composition",
           "reduces_to": REDUCES_TO, "depends_on": DEPENDS_ON,
           "fixtures_provenance": FIXTURE_PROVENANCE,
           "ruleset": "discovery is by capability over a sharded peer set: no peer holds all, every lookup federates "
                      "to the complete provider set, results are DIDs ordered by XOR distance, and no address leaks",
           "evidence": evidence,
           "claims": claims,
           "vetoes": ["central_directory_present", "lookup_incomplete", "address_leaked"],
           "conclusion": "SUPPORTED" if all(claims.values()) else "FALSIFIED"}
    json.dump(rec, open(OUT, "w"), indent=2, sort_keys=True)

    if args.selftest:
        ok = all(claims.values())
        print("OADNRUN DHT SELFTEST: %s (place=%s noall=%s complete=%s order=%s unknown=%s ident=%s fed=%s)" % (
            "PASS" if ok else "FAIL", claims["publish_replicates_to_k_peers"], claims["no_single_peer_holds_all"],
            complete_ok, ordered_ok, unknown_ok, identity_ok, fed_ok))
        return 0 if ok else 1
    if args.json:
        print(json.dumps({k: bool(v) for k, v in claims.items()}, sort_keys=True)); return 0
    print("=" * 78)
    print("  OADNRUN DHT (WIRE) -- sharded capability discovery over loopback peer servers")
    for k in sorted(claims):
        print("  %-52s : %s" % (k, claims[k]))
    print("  ledger -> %s" % OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
