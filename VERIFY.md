# VERIFY.md — how to check this bundle, and how to check the checker

## 1. Verify the archive before unpacking

The archive ships with a detached Ed25519 signature. The release public key is in `README.md` (and in
`release_pubkey.txt` inside the archive, which the signature lets you trust).

```
# archive-level (run before unpacking; needs python3 + cryptography)
python3 - <<'PY'
import base64, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(open("release_pubkey.txt").read().strip()))
sig = base64.b64decode(open("openadn_verify-1.0.0.tar.gz.sig").read().strip())
pk.verify(sig, open("openadn_verify-1.0.0.tar.gz","rb").read())
print("ARCHIVE SIGNATURE: OK")
PY
```

If this fails, stop. Do not unpack.

## 2. Verify the artifacts inside

```
tar xzf openadn_verify-1.0.0.tar.gz
cd openadn_verify-1.0.0
./verify.sh
```

`verify.sh` runs two things in order:

* **Manifest check** (`verify_manifest.py`): verifies `MANIFEST.sig` over `MANIFEST.sha256` using
  `release_pubkey.txt`, then re-hashes every listed file. Any altered, added, or missing file is reported.
* **Probe run**: each probe's `--selftest`; a probe passes iff every claim it makes is `SUPPORTED`.

Exit code `0` means every layer passed.

## 3. Verify the checker itself (the negative controls)

A verification suite whose checks cannot fail proves nothing. Two controls demonstrate that this one can:

```
./verify.sh --break          # copies the tree, appends a byte to bundle/openadn/openadn_lib.py,
                             # and expects verify_manifest.py to FAIL. Reported as "NEGATIVE CONTROL OK".
./verify.sh --break-claims   # copies the bundle, makes openadn_lib.verify() accept every signature,
                             # and expects oadnrun_handshake_probe to FAIL.
```

You can reproduce `--break` by hand: edit any file under `bundle/`, then run `python3 verify_manifest.py`.
It must report `MISMATCH <path>` and exit non-zero. If it does not, the manifest is not checking anything.

## 4. Rebuild the archive from source (strongest form)

Do not trust the archive; rebuild it. With the source tree, `make_release.py` regenerates the archive,
manifest, and signatures deterministically.

* **With the release key:** the rebuilt archive matches byte for byte (the sha256 is reproducible).
* **Without it:** you still re-derive the entire `bundle/` content and the manifest and confirm the shipped
  files match what the source produces. Only two files are key-dependent (`README.md`, which embeds the
  public key, and `release_pubkey.txt`); every content file is reproducible by anyone.

```
python3 make_release.py --version 1.0.0 --pubkey-only   # print the public key this build expects
python3 make_release.py --version 1.0.0                 # rebuild dist/openadn_verify-1.0.0.tar.gz
```

## 5. What to do if a check fails

1. Capture the full output.
2. Do **not** trust the affected claim.
3. Report it: the failure is the finding.

## 6. What passing does not prove

See `WHAT_THIS_PROVES.md`. In one line: *runtime invariants are measured against a loopback reference
implementation, not a deployed network.*
