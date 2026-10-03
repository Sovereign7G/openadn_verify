#!/usr/bin/env python3
"""openadn_dht.py -- a real, multi-peer capability DHT over loopback HTTP (L3, wire-level).

This is the *wire* counterpart to `openadn_lib.CapabilityDHT` (which is in-process). Here N peer servers run on
loopback ports; each holds only the shard it is responsible for, and a lookup fans out across peers and merges.

Properties this shape is built to support (and that a probe then measures):
  * **no central directory** -- replication < peers, so no single peer holds the whole directory, and a peer
    with no local match can still answer a lookup by federating;
  * **discovery by capability, not address** -- lookups are by tag, results are identities (DIDs), never IPs;
  * **Kademlia ordering** -- merged results are ordered by XOR distance to the querier.

Transport is loopback only; there is no global transport and no gossip protocol beyond this local cluster. Do not
claim otherwise.
"""
from __future__ import annotations

import json
import threading
import urllib.request

from openadn_lib import xor_distance

REPLICATION = 2


def _post(url, obj, timeout=5):
    data = json.dumps(obj).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


class DHTPeer:
    def __init__(self, node_id, replication=REPLICATION):
        self.node_id = node_id
        self.replication = replication
        self.store = {}                 # agent_id -> sorted caps
        self.peers = []                 # [(peer_node_id, base_url), ...] excluding self
        self._server = None
        self._thread = None

    # ---- placement (XOR-closest k, self included) ----
    def responsible_peers(self, agent_id):
        candidates = [(xor_distance(agent_id, self.node_id), self.node_id, None)]
        candidates += [(xor_distance(agent_id, pid), pid, url) for pid, url in self.peers]
        candidates.sort(key=lambda x: (x[0], x[1]))
        return candidates[: self.replication]

    def publish(self, agent_id, capabilities):
        caps = sorted(set(capabilities))
        stored_at = []
        for _d, pid, url in self.responsible_peers(agent_id):
            if url is None:
                self.store[agent_id] = caps
                stored_at.append(pid)
            else:
                _post(url + "/dht/store", {"agent_id": agent_id, "capabilities": caps})
                stored_at.append(pid)
        return sorted(stored_at)

    def store_local(self, agent_id, capabilities):
        self.store[agent_id] = sorted(set(capabilities))

    def find(self, tag, querier):
        found = {a for a, c in self.store.items() if tag in c}
        for _pid, url in self.peers:
            try:
                r = _post(url + "/dht/local", {"tag": tag})
                found |= set(r.get("agents", []))
            except Exception:               # a dead peer must not break discovery
                pass
        return sorted(found, key=lambda a: (xor_distance(querier, a), a))

    def local_matches(self, tag):
        return sorted(a for a, c in self.store.items() if tag in c)

    # ---- loopback HTTP ----
    def serve_background(self, host="127.0.0.1"):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        peer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, obj):
                payload = json.dumps(obj, sort_keys=True).encode("utf-8")
                self.send_response(200)
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
                    return {}

            def do_GET(self):
                path = self.path.split("?")[0]
                if path == "/dht/state":
                    self._send({"node_id": peer.node_id, "local_size": len(peer.store),
                                "local_agents": sorted(peer.store)})
                else:
                    self._send({"error": "not_found", "path": path})

            def do_POST(self):
                path = self.path.split("?")[0]
                b = self._body()
                if path == "/dht/publish":
                    self._send({"stored_at": peer.publish(b.get("agent_id"), b.get("capabilities", []))})
                elif path == "/dht/store":
                    peer.store_local(b.get("agent_id"), b.get("capabilities", []))
                    self._send({"ok": True})
                elif path == "/dht/find":
                    self._send({"agents": peer.find(b.get("tag"), b.get("querier", peer.node_id))})
                elif path == "/dht/local":
                    self._send({"agents": peer.local_matches(b.get("tag"))})
                else:
                    self._send({"error": "not_found", "path": path})

        self._server = ThreadingHTTPServer((host, 0), Handler)
        port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self._server, self._thread, port

    def shutdown(self):
        if self._server is not None:
            self._server.shutdown()


class DHTCluster:
    """Builds N peers, starts their servers, and wires each peer's peer-list to the others."""

    def __init__(self, node_ids, replication=REPLICATION):
        self.peers = [DHTPeer(nid, replication=replication) for nid in node_ids]
        self.urls = {}
        self._servers = []
        for p in self.peers:
            srv, _t, port = p.serve_background()
            self._servers.append(srv)
            self.urls[p.node_id] = "http://127.0.0.1:%d" % port
        for p in self.peers:
            p.peers = [(q.node_id, self.urls[q.node_id]) for q in self.peers if q.node_id != p.node_id]

    def url(self, node_id):
        return self.urls[node_id]

    def publish(self, entry_node_id, agent_id, capabilities):
        return _post(self.urls[entry_node_id] + "/dht/publish",
                     {"agent_id": agent_id, "capabilities": list(capabilities)})

    def find(self, entry_node_id, tag, querier):
        return _post(self.urls[entry_node_id] + "/dht/find", {"tag": tag, "querier": querier})["agents"]

    def local_size(self, node_id):
        return len(self.peers[[p.node_id for p in self.peers].index(node_id)].store)

    def local_matches(self, node_id, tag):
        p = self.peers[[q.node_id for q in self.peers].index(node_id)]
        return p.local_matches(tag)

    def shutdown(self):
        for s in self._servers:
            s.shutdown()
