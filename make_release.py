#!/usr/bin/env python3
"""make_release.py -- build a versioned, signed, self-contained OpenADN verification archive.

  python3 make_release.py --version 1.0.0            # build dist/openadn_verify-1.0.0.tar.gz + signatures
  python3 make_release.py --version 1.0.0 --pubkey-only   # just print the release public key

Layers produced:
  MANIFEST.sha256   per-file sha256 of everything in the build dir (except MANIFEST.{sha256,sig})
  MANIFEST.sig      Ed25519 over MANIFEST.sha256  (authenticates the artifact list)
  <archive>.tar.gz  deterministic gzip (mtime=0) of the build dir
  <archive>.tar.gz.sig  Ed25519 over the archive bytes (authenticates the archive)

The release private key lives at ~/.apex/openadn_release_key.json (chmod 600), never in the archive.
Rebuilding with the same source and key reproduces the archive byte for byte.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
APEX = os.environ.get("SOVEREIGN_APEX", os.path.expanduser("~/.apex"))
KEY_PATH = os.path.join(APEX, "openadn_release_key.json")
DIST = os.path.join(HERE, "dist")
DOCS = ["verify.sh", "verify_manifest.py", "make_release.py", "README.md", "VERIFY.md",
        "WHAT_THIS_PROVES.md", "CHANGELOG.md", "LICENSE", "EXAMPLE_REPORT.md"]


def _load_or_create_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if os.path.exists(KEY_PATH):
        seed = bytes.fromhex(json.load(open(KEY_PATH))["seed_hex"])
    else:
        os.makedirs(APEX, exist_ok=True)
        sk = Ed25519PrivateKey.generate()
        from cryptography.hazmat.primitives import serialization
        seed = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
        json.dump({"seed_hex": seed.hex()}, open(KEY_PATH, "w"))
        os.chmod(KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)
    from cryptography.hazmat.primitives import serialization
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, pk.hex()


def _copy_tree(src, dst, skip_names=("__pycache__", "dist", ".pytest_cache")):
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in skip_names]
        rel = os.path.relpath(root, src)
        target = os.path.join(dst, rel) if rel != "." else dst
        os.makedirs(target, exist_ok=True)
        for f in files:
            if f in skip_names:
                continue
            shutil.copy2(os.path.join(root, f), os.path.join(target, f))


def _manifest(build_dir):
    entries = []
    for root, dirs, files in os.walk(build_dir):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for f in sorted(files):
            if f in ("MANIFEST.sha256", "MANIFEST.sig"):
                continue
            fp = os.path.join(root, f)
            rel = os.path.relpath(fp, build_dir)
            h = hashlib.sha256(open(fp, "rb").read()).hexdigest()
            entries.append((rel, h))
    entries.sort()
    return "".join("%s  %s\n" % (h, rel) for rel, h in entries)


def _deterministic_tar(build_dir, out_path):
    parent = os.path.dirname(build_dir)
    entries = []
    for root, dirs, files in os.walk(build_dir):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for f in sorted(files):
            fp = os.path.join(root, f)
            entries.append((fp, os.path.relpath(fp, parent)))
    entries.sort(key=lambda x: x[1])
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for fp, rel in entries:
            ti = tf.gettarinfo(fp, arcname=rel)
            ti.mtime = 0
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            with open(fp, "rb") as fh:
                tf.addfile(ti, fh)
    with open(out_path, "wb") as out:
        with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz:
            gz.write(buf.getvalue())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--pubkey-only", action="store_true")
    a = ap.parse_args()

    sk, pub_hex = _load_or_create_key()
    if a.pubkey_only:
        print(pub_hex)
        return 0

    name = "openadn_verify-%s" % a.version
    build_dir = os.path.join(DIST, name)
    shutil.rmtree(build_dir, ignore_errors=True)
    os.makedirs(build_dir, exist_ok=True)

    # 1. docs + tools
    for f in DOCS:
        shutil.copy2(os.path.join(HERE, f), os.path.join(build_dir, f))
    # 2. bundle (runtime + probes)
    _copy_tree(os.path.join(HERE, "bundle"), os.path.join(build_dir, "bundle"))
    # 3. substitute placeholders in README
    rp = os.path.join(build_dir, "README.md")
    text = open(rp).read().replace("{{VERSION}}", a.version).replace("{{PUBKEY}}", pub_hex)
    open(rp, "w").write(text)
    # 4. public key file
    open(os.path.join(build_dir, "release_pubkey.txt"), "w").write(pub_hex + "\n")
    # 5. manifest + signature
    manifest = _manifest(build_dir)
    mp = os.path.join(build_dir, "MANIFEST.sha256")
    open(mp, "w").write(manifest)
    sig = base64.b64encode(sk.sign(manifest.encode())).decode()
    open(os.path.join(build_dir, "MANIFEST.sig"), "w").write(sig + "\n")
    # 6. permissions
    for exe in ("verify.sh", "verify_manifest.py"):
        p = os.path.join(build_dir, exe)
        os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    # 7. archive + archive signature
    archive = os.path.join(DIST, name + ".tar.gz")
    _deterministic_tar(build_dir, archive)
    abytes = open(archive, "rb").read()
    asha = hashlib.sha256(abytes).hexdigest()
    open(archive + ".sig", "w").write(base64.b64encode(sk.sign(abytes)).decode() + "\n")

    nfiles = manifest.count("\n")
    print("RELEASE %s" % name)
    print("  build dir : %s" % build_dir)
    print("  archive   : %s (%d bytes)" % (archive, len(abytes)))
    print("  files     : %d in manifest" % nfiles)
    print("  sha256    : %s" % asha)
    print("  pubkey    : %s" % pub_hex)
    print("  signatures: MANIFEST.sig (manifest) + %s.sig (archive)" % (name + ".tar.gz"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
