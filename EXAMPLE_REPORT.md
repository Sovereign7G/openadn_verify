# EXAMPLE_REPORT.md — what "reporting back" looks like

If you ran `./verify.sh`, a useful report is short. Copy the block and fill it in — a failure is more useful
than a pass, so paste the failing line verbatim.

```
date:                2026-10-05
os / python:         Ubuntu 24.04 / Python 3.12
archive:             openadn_verify-1.0.0.tar.gz
archive sha256:      <the sha256 you computed for the tarball>
pubkey used:         <the Ed25519 public key from the release page, not only from inside the archive>
archive signature:   OK
manifest signature:  OK
verify.sh:           11/11 probes pass
exit code:           0
--break:             detected tamper = yes
--break-claims:      detected vacuity = yes
verdict:             reproduced / did not reproduce
notes:               <if anything failed, the exact line>
```

A failure example (report this):

```
--break-claims:      detected vacuity = no
notes:               --break-claims printed "NEGATIVE CONTROL OK" but exited 0 with a broken verifier;
                     here is the exact output: ...
```

## If you run it and don't report

That is the modal case, and it is fine — but it means the metric **stays open**. The metric measures whether
anyone reports, not whether the verification works. A silent pass and a silent fail look identical from here.

If you want the metric to close, any report will do: a one-line "reproduced on <os>, 11/11, exit 0" is
enough. See `METRIC.md`.

## Where to report

Open an issue on the repository, or reply on the release page. Include the archive sha256 and the pubkey you
used, so the report is bound to a specific artifact.
