# WHAT_THIS_PROVES.md — plain language

## What a passing `./verify.sh` proves

* **The artifacts are tamper-evident.** The Ed25519 signature over `MANIFEST.sha256` authenticates the list
  of file hashes; the hashes authenticate every file. If anyone altered a byte, `./verify.sh` fails before
  running a single probe.
* **The probes pass their own checks.** Each of the 11 probes claims a specific property and checks it.
  A probe passes only if every claim it makes is `SUPPORTED`.
* **The runtime's invariants hold against the runtime itself.** Identity is a function of the key, not the
  host; a handshake is mutually authenticated and replay-resistant; a DHT answers a query no single peer
  could; a Merkle anchor proves inclusion; a rotation is rejected when it is time-locked, wrongly signed, or
  unprecommitted; a non-deterministic command is rejected rather than silently divergent.

## What a passing `./verify.sh` does NOT prove

* **That the design is correct.** Passing probes show the implementation is self-consistent, not that the
  design is the right one, or complete, or secure against a real adversary.
* **That any deployment will work.** This is a loopback reference implementation. It does not use the
  kernel, real WireGuard tunnels, real BGP, or real money.
* **That any claim about any external system is true.** Nothing here verifies doxx.net or any other network.
  Those claims are a separate track, and where they cannot be reached they are labelled, not asserted.
* **That anyone but the author has verified it.** This archive exists to close that gap. Until a second party
  runs `./verify.sh` and reports the result, the honest status is *verifiable, not yet verified*.

## The one sentence to remember

> Runtime invariants are measured against a **loopback reference implementation, not a deployed network.**

## The asymmetry this bundle exists to make visible

doxx.net's core claims cannot be checked by the public — they sit behind a token, a paid plan, and a
gateway host. OpenADN's claims can be checked by anyone who runs one command offline. That difference —
*verifiable* versus *not* — is the point. This bundle is only credible to the degree that it is actually run
by someone who is not its author.
