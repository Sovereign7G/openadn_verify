#!/usr/bin/env python3
"""openadn_cli.py -- minimal CLI for an OpenADN node.

  keygen                      print a fresh did:adn + public key
  card [--caps a,b,c]         print an A2A agent card for a node with those capabilities
  serve [--caps a,b,c]        run the node on 127.0.0.1:<ephemeral> (prints the URL, then blocks)
  call <url> <capability>     send a `cap:<capability>` A2A SendMessage to a running node

Loopback only. `serve` binds 127.0.0.1 and does not configure WireGuard/BGP or load eBPF.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from openadn_lib import did_from_public, generate_keypair, b64, _raw_public  # noqa: E402
from openadn_node import AgentNode  # noqa: E402


def _caps(s):
    return tuple(c.strip() for c in (s or "").split(",") if c.strip())


def cmd_keygen(args):
    sk, pk = generate_keypair()
    print(json.dumps({"did": did_from_public(pk), "public_key": b64(_raw_public(pk))}, indent=2, sort_keys=True))
    return 0


def cmd_card(args):
    node = AgentNode("openadn-node", _caps(args.caps))
    print(json.dumps(node.agent_card(), indent=2, sort_keys=True))
    return 0


def cmd_serve(args):
    node = AgentNode("openadn-node", _caps(args.caps))
    server, _thread, port = node.serve_background()
    print("listening http://127.0.0.1:%d/  did=%s" % (port, node.did), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


def cmd_call(args):
    req = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
           "params": {"message": {"role": "ROLE_USER", "messageId": "msg-1",
                                  "parts": [{"text": "cap:%s" % args.capability}]}}}
    data = json.dumps(req).encode("utf-8")
    r = urllib.request.Request(args.url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=5) as resp:
        print(resp.read().decode("utf-8"))
    return 0


def main():
    ap = argparse.ArgumentParser(prog="openadn")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen").set_defaults(fn=cmd_keygen)
    p_card = sub.add_parser("card")
    p_card.add_argument("--caps", default="data.read")
    p_card.set_defaults(fn=cmd_card)
    p_serve = sub.add_parser("serve")
    p_serve.add_argument("--caps", default="data.read")
    p_serve.set_defaults(fn=cmd_serve)
    p_call = sub.add_parser("call")
    p_call.add_argument("url")
    p_call.add_argument("capability")
    p_call.set_defaults(fn=cmd_call)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
