#!/usr/bin/env python3
"""verify_manifest.py -- Layer 1/2 of the OpenADN verification bundle.

Two independent checks, in order:

  1. SIGNATURE -- the detached Ed25519 signature (MANIFEST.sig, base64) over the exact bytes of
     MANIFEST.sha256, verified with the release public key (release_pubkey.txt, hex). This authenticates
     the manifest: if it verifies, the list of file hashes has not been altered since publication.
  2. HASHES -- every file listed in the manifest is re-hashed and compared to the recorded value. This
     authenticates the artifacts: any altered, added, or removed file is reported.

Exit 0 iff both pass. If the signature does not verify, STOP -- a bundle whose manifest is not authentic
cannot be trusted even if the hashes happen to match.

  python3 verify_manifest.py
"""
from __future__ import annotations

import base64
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(ROOT, "MANIFEST.sha256")
SIG = os.path.join(ROOT, "MANIFEST.sig")
PUB = os.path.join(ROOT, "release_pubkey.txt")


def main() -> int:
    for f in (MANIFEST, SIG, PUB):
        if not os.path.exists(f):
            print("MANIFEST: missing %s" % os.path.basename(f))
            return 1
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as e:  # noqa: BLE001
        print("MANIFEST SIGNATURE: cannot import cryptography (%s)" % e)
        return 1

    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(open(PUB).read().strip()))
        sig = base64.b64decode(open(SIG).read().strip())
        pk.verify(sig, open(MANIFEST, "rb").read())
        print("MANIFEST SIGNATURE: OK (Ed25519)")
    except InvalidSignature:
        print("MANIFEST SIGNATURE: FAIL -- manifest is not authentic, do not trust this bundle")
        return 1
    except Exception as e:  # noqa: BLE001
        print("MANIFEST SIGNATURE: FAIL (%s)" % e)
        return 1

    bad = 0
    for line in open(MANIFEST):
        line = line.rstrip("\n")
        if not line:
            continue
        h, _, path = line.partition("  ")
        fp = os.path.join(ROOT, path)
        try:
            digest = hashlib.sha256(open(fp, "rb").read()).hexdigest()
        except Exception:  # noqa: BLE001
            print("  MISSING  %s" % path)
            bad += 1
            continue
        if digest != h:
            print("  MISMATCH %s" % path)
            bad += 1
    print("MANIFEST HASHES: %s" % ("OK" if bad == 0 else "FAIL (%d file(s))" % bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
