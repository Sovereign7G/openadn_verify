# PUBLISH.md — release steps (copy-paste, no interpretation)

One repo, one tag, one release. Publishing turns the archive from a local file into an artifact a stranger
can find, verify, and report on.

## Artifact of record (`v1.0.0`)

```
archive   : dist/openadn_verify-1.0.0.tar.gz
signature : dist/openadn_verify-1.0.0.tar.gz.sig
sha256    : 86143bc1adc49b1f9974c35cc6784658e39e6a5ccf8f86e449a5a232dc774f30
pubkey    : ba7b971610fdac9768fb52fb866ac37dd5436d610f701e30329e363bc7504cb6
published : 2026-10-03
```

The private key is `~/.apex/openadn_release_key.json` (chmod 600). It is **never** committed or published.

## Quick path with the GitHub CLI (`gh`)

`gh` is installed (`/usr/bin/gh`). It is not authenticated yet, so first do the interactive login
(**you** must run this — it opens a browser / prints a device code):

```sh
gh auth login          # GitHub.com -> HTTPS -> Login with a web browser
```

Then, from the repo root:

```sh
gh repo create openadn_verify --public --source=. --remote=origin --push
git push origin openadn-verify-v1.0.0
gh release create openadn-verify-v1.0.0 \
    dist/openadn_verify-1.0.0.tar.gz dist/openadn_verify-1.0.0.tar.gz.sig \
    --title "OpenADN verification bundle v1.0.0" --notes-file README.md
```

Then do step 4 below (cross-publish the public key). This path replaces steps 1–3; use whichever you prefer.

## Steps

### 1. Commit and tag

```sh
cd openadn_verify
git add -A
git commit -m "openadn_verify v1.0.0"
git tag -a openadn-verify-v1.0.0 -m "OpenADN verification bundle v1.0.0"
```

### 2. Create the remote and push

```sh
git remote add origin <YOUR_REPO_URL>     # e.g. git@github.com:<owner>/openadn_verify.git
git push -u origin main
git push origin openadn-verify-v1.0.0
```

### 3. Create the GitHub release

* Tag: `openadn-verify-v1.0.0`
* Title: `OpenADN verification bundle v1.0.0`
* Attach: `dist/openadn_verify-1.0.0.tar.gz` **and** `dist/openadn_verify-1.0.0.tar.gz.sig`
* Release notes: **paste the contents of `README.md` verbatim** (with the public key inline). Do not link —
  the release body is the first thing a stranger sees; a link is one click they may not take.

### 4. Cross-publish the public key (do not skip)

Put the release public key some place **outside the archive** — the release body, a gist, a personal site, a
pinned post:

```
ba7b971610fdac9768fb52fb866ac37dd5436d610f701e30329e363bc7504cb6
```

A key that lives only inside the archive it signs anchors nothing. The further the cross-publish is from the
archive, the more independent the anchor: release body is the minimum; a gist is better; a personal site is
best. The point is not cryptographic strength — it is that the key should not appear to have been *born
with* the archive it signs.

### 5. Record the start time

`PUBLISHED` and the release page carry the date; `METRIC.md` carries the state. Time-to-first-independent-
verification is measured from publication.

## Publishing to a private repo

Publishing to a **private or invite-only** repo does **not start the metric**. Time-to-first-independent-
verification begins when the archive is reachable by someone outside the author's circle. A private mirror is
fine for your own use — it just does not move the metric. If the archive is not publicly reachable, the
metric is undefined, not `∞`.

## When someone reports

A report should contain the archive sha256, the pubkey used, and the verdict — see `EXAMPLE_REPORT.md`.
Record it in `METRIC.md` with the date and a link. A first independent **pass** or **fail** is the state
change; nothing else closes the gap.

## Reproducing the archive

```sh
sh make_release.sh --version 1.0.0      # rebuild; requires the release key for a byte-identical sha256
```

## Verify a downloaded archive (what a stranger runs)

```sh
# 1. archive signature (needs python3 + cryptography)
python3 - <<'PY'
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(
    "ba7b971610fdac9768fb52fb866ac37dd5436d610f701e30329e363bc7504cb6"))
sig = base64.b64decode(open("openadn_verify-1.0.0.tar.gz.sig").read().strip())
pk.verify(sig, open("openadn_verify-1.0.0.tar.gz", "rb").read())
print("ARCHIVE SIGNATURE: OK")
PY

# 2. unpack and run
tar xzf openadn_verify-1.0.0.tar.gz
cd openadn_verify-1.0.0
./verify.sh                 # expect: 11/11 probes pass, exit 0
./verify.sh --break         # expect: NEGATIVE CONTROL OK (manifest)
./verify.sh --break-claims  # expect: NEGATIVE CONTROL OK (claims)
```
