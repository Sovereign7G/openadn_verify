# CONTRIBUTING.md

The release process should be a script you run, not a procedure you remember.

## Add a probe

1. Make sure it runs **offline**: no network, no token, no ICP, no Solana RPC, no `~/.apex` dependency, and
   it must write only to `$SOVEREIGN_APEX` (which `verify.sh` points at a temp dir).
2. It must pass the four checks: `--selftest` exit 0, `--json` exit 0, byte-identical ledger under a changed
   `PYTHONHASHSEED`, and a clean degraded run (no traceback).
3. Drop it in `bundle/` (add any helper module next to it, mirroring `openadn/` and `chainverify/`).
4. Add its stem to the `PROBES` list in `verify.sh`.
5. Regenerate and sign:

   ```sh
   ./make_release.sh --version <next>
   ```

6. Verify from a fresh unpack, including both controls:

   ```sh
   tar xzf dist/openadn_verify-<next>.tar.gz -C /tmp && cd /tmp/openadn_verify-<next>
   ./verify.sh && ./verify.sh --break && ./verify.sh --break-claims
   ```

7. Commit the source **and** the new `dist/*.tar.gz` + `dist/*.tar.gz.sig`. Bump `CHANGELOG.md`.

## Do not

* Commit `~/.apex/openadn_release_key.json` or any secret.
* Add anything requiring the doxx token, ICP, or a Solana RPC — those read external systems and belong to the
  observation tools, not this offline bundle.
* Edit a bundled file by hand and ship it without regenerating the manifest; `verify.sh` will (correctly)
  fail.

## The release key

The private key lives at `~/.apex/openadn_release_key.json` (chmod 600) and never enters the repo or the
archive. Its public half is in every release's `README.md` and `release_pubkey.txt`, and should be
cross-published outside the archive (e.g. on the release page) so a stranger has an independent anchor.

## Version strings

`README.md` at the repo root is the **rendered** copy (real version string and real public key) — it is what
the GitHub repo page and the release body show. Before a new release, bump the version string in
`README.md` (and the public key there, only if the key rotated). `make_release.py` still substitutes
`{{VERSION}}`/`{{PUBKEY}}` if present, but the shipped README is always the rendered one.
