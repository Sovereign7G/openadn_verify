#!/bin/sh
# make_release.sh -- thin wrapper around make_release.py (kept so the release step is one obvious command).
#   ./make_release.sh --version 1.0.0
exec python3 "$(dirname "$0")/make_release.py" "$@"
