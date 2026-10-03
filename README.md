# openadn_verify 1.0.0

The verification bundle for the **S7G-L1 / OpenADN** corpus — a reference implementation of **OpenADN**, an
open protocol that gives autonomous agents their own identity, discovery, and task hand-off layer.

Run one command. Read the verdict.

```
./verify.sh
```

Expected: `PASS` lines ending in `OPENADN VERIFY: 11/11 probes pass`, and exit code `0`.
Requirements: `python3` and the `cryptography` package. No network. No account. No token. No install.

**Words you don't need to know** (each is resolved by a file in `bundle/`): `oadnrun` = the OpenADN runtime
probes (conformance, integration, discovery, identity); `chainverify` = a Merkle anchor with inclusion
proofs; `sovereignl1` = a chain design that depends on no other chain, plus its closure check; `did:adn` = a
W3C-style decentralized identifier derived from a key; **S7G-L1** = the governing design these pieces belong
to.

## What "verified" means here

Each probe passes **four checks**: its `--selftest` exits 0; its `--json` path exits 0; its ledger is
byte-identical under a changed `PYTHONHASHSEED`; and it degrades cleanly with no inputs (no traceback).
"Verified" means the checks pass — nothing more.

## What "verified" does NOT mean

* It does **not** mean the design is correct.
* It does **not** mean any deployment will work.
* It does **not** mean any claim about any external system (doxx.net or otherwise) is true.
* **Nobody outside the author has run this yet.** That is precisely why it is published.

> Runtime invariants are measured against a **loopback reference implementation, not a deployed network.**

## Confirm the verifier is not a rubber stamp

```
./verify.sh --break          # tamper a file in a throwaway copy -> the manifest check MUST fail
./verify.sh --break-claims   # break the signature verifier      -> the probes MUST fail
```

If either control reports success when it should have failed, the bundle is checking nothing.

## Three independent layers

1. **Signature verifies the archive** — detached Ed25519 (`openadn_verify-<version>.tar.gz.sig`).
2. **Archive verifies the artifacts** — `MANIFEST.sha256` + `MANIFEST.sig`; enforced by `verify.sh`.
3. **Artifacts verify the claims** — the 11 probes; run by `verify.sh`.

Verify in that order: signature first, then unpack, then `./verify.sh`.

## Release public key (Ed25519, hex)

```
ba7b971610fdac9768fb52fb866ac37dd5436d610f701e30329e363bc7504cb6
```

The same key is published **outside this archive** (on the release page / in `PUBLISH.md`) — verify against
that copy, not only the one shipped inside.

## Reporting back

If you run this, please say what happened — see `EXAMPLE_REPORT.md`. The metric of record is
*time-to-first-independent-verification* (published: see the release page and `PUBLISHED`).

## Scope

**Included:** the OpenADN runtime (identity, handshake, DHT, recovery), the Merkle `chainverify` anchor,
and the `sovereignl1` closure / determinism / internal-mining checks — everything that runs offline.
**Excluded by design:** anything requiring the doxx token, ICP, or a Solana RPC; anything requiring a
pre-installed corpus; any secret.

See `VERIFY.md` (how, and the controls) and `WHAT_THIS_PROVES.md` (what a pass does and does not mean).

## License

CC0 1.0 Universal (public-domain dedication). See `LICENSE`.
