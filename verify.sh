#!/bin/sh
# OpenADN verification bundle -- verify it yourself, offline, with no account.
#
#   ./verify.sh            # 1) check the signed manifest, 2) run every probe's checks; exit 0 iff all pass
#   ./verify.sh --break    # negative control: tamper a file in a throwaway copy; the manifest check MUST fail
#   ./verify.sh --break-claims  # negative control: break the signature verifier; the claims MUST fail
#   ./verify.sh --refresh  # maintainer: re-copy probes + packages from the parent tree
#
# Requirements: python3 and the `cryptography` package. Nothing else. No network. No token. No ~/.apex.
#
# What this does NOT prove: that the design is correct, that any deployment will work, or that any claim
# about any external system (doxx.net or otherwise) is true. Runtime invariants are measured against a
# LOOPBACK reference implementation, not a deployed network. See WHAT_THIS_PROVES.md.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUNDLE="$HERE/bundle"
PARENT=$(CDPATH= cd -- "$HERE/.." && pwd)

PROBES="oadnrun_a2a_conformance_probe oadnrun_mcp_conformance_probe oadnrun_integration_probe \
oadnrun_dht_wire_probe oadnrun_handshake_probe openadn_recovery_check a2a_env_offline_check \
chainverify_anchor_probe chainverify_card_anchor_probe \
sovereignl1_chain_probe sovereignl1_deterministic_vm_probe sovereignl1_internal_mining_probe"

MODE="verify"
case "${1:-}" in
  ""|--verify)      MODE="verify" ;;
  --break)          MODE="break" ;;
  --break-claims)   MODE="break-claims" ;;
  --refresh)        MODE="refresh" ;;
  -h|--help)        sed -n '2,14p' "$0"; exit 0 ;;
  *) echo "unknown option: ${1:-}"; exit 2 ;;
esac

if [ "$MODE" = "refresh" ]; then
  mkdir -p "$BUNDLE/openadn" "$BUNDLE/chainverify"
  for p in $PROBES; do
    if [ -f "$PARENT/$p.py" ]; then cp "$PARENT/$p.py" "$BUNDLE/"; fi
  done
  for m in __init__.py openadn_lib.py openadn_node.py openadn_dht.py openadn_handshake.py \
           openadn_recovery.py openadn_cli.py README.md; do cp "$PARENT/openadn/$m" "$BUNDLE/openadn/"; done
  cp "$PARENT/chainverify/chainverify_lib.py" "$BUNDLE/chainverify/"
  echo "refreshed bundle from $PARENT"
  exit 0
fi

TMP=$(mktemp -d) || { echo "mktemp failed"; exit 2; }
trap 'rm -rf "$TMP"' EXIT INT TERM

run_one() {
  _stem="$1"; _bundle="$2"
  SOVEREIGN_APEX="$TMP" python3 "$_bundle/$_stem.py" --selftest >"$TMP/$_stem.out" 2>&1
  echo $?
}

# ---- Layer 2 control: a tampered file must fail the manifest check --------------------------------
if [ "$MODE" = "break" ]; then
  if [ ! -f "$HERE/MANIFEST.sha256" ]; then
    echo "  --break requires a released bundle (MANIFEST.sha256 is absent)."
    echo "  Build one first:  python3 make_release.py --version 1.0.0"
    exit 2
  fi
  cp -R "$HERE" "$TMP/tampered"
  victim="$TMP/tampered/bundle/openadn/openadn_lib.py"
  printf '\n# TAMPER\n' >> "$victim"
  if python3 "$TMP/tampered/verify_manifest.py" >"$TMP/tamper.out" 2>&1; then
    echo "  NEGATIVE CONTROL FAILED: a tampered file passed the manifest check"
    exit 1
  else
    echo "  NEGATIVE CONTROL OK (manifest): a tampered file is detected"
    sed -n '1,4p' "$TMP/tamper.out" | sed 's/^/        /'
    exit 0
  fi
fi

# ---- Layer 1: signed manifest (only when run from a released, unpacked archive) -------------------
if [ -f "$HERE/MANIFEST.sha256" ] && [ -f "$HERE/MANIFEST.sig" ]; then
  if python3 "$HERE/verify_manifest.py" >"$TMP/manifest.out" 2>&1; then
    sed -n '1,2p' "$TMP/manifest.out"
  else
    echo "MANIFEST CHECK FAILED -- do not trust this bundle:"; cat "$TMP/manifest.out"; exit 1
  fi
else
  echo "MANIFEST: not present (running from source; skipping Layer 1/2)"
fi

# ---- Layer 3 control: an always-accept verifier must be caught ------------------------------------
if [ "$MODE" = "break-claims" ]; then
  cp -R "$BUNDLE" "$TMP/brk"
  sed -i 's/^def verify(pk, obj, signature: str) -> bool:/&\n    return True  # BREAK INJECTED/' \
      "$TMP/brk/openadn/openadn_lib.py" 2>/dev/null || true
  if ! grep -q "BREAK INJECTED" "$TMP/brk/openadn/openadn_lib.py"; then
    echo "  NEGATIVE CONTROL ERROR: could not inject the break"; exit 2
  fi
  rc=$(run_one "oadnrun_handshake_probe" "$TMP/brk")
  if [ "$rc" -ne 0 ]; then
    echo "  NEGATIVE CONTROL OK (claims): an always-accept verifier is detected (rc=$rc)"; exit 0
  fi
  echo "  NEGATIVE CONTROL FAILED: broken verifier NOT detected -- checks are vacuous"; exit 1
fi

# ---- Layer 3: run the reference probes ------------------------------------------------------------
pass=0; fail=0
echo "OPENADN VERIFY -- loopback reference implementation"
for p in $PROBES; do
  rc=$(run_one "$p" "$BUNDLE")
  if [ "$rc" -eq 0 ]; then
    pass=$((pass + 1)); printf '  PASS  %s\n' "$p"
  else
    fail=$((fail + 1)); printf '  FAIL  %s (rc=%s)\n' "$p" "$rc"
    sed -n '1,6p' "$TMP/$p.out" | sed 's/^/        /'
  fi
done
printf 'OPENADN VERIFY: %d/%d probes pass\n' "$pass" "$((pass + fail))"
[ "$fail" -eq 0 ] && exit 0 || exit 1
