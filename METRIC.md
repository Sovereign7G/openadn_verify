# METRIC.md

```
time-to-first-independent-verification:  OPEN since 2026-10-03
```

**Definition.** The elapsed time from publication of a *publicly reachable* archive to the first report —
from someone other than the author — of having run `./verify.sh`.

**State.** No independent report received. Verified by the author only.

**Published.** Two releases, same key, both public:

| version | release | sha256 |
|---|---|---|
| v1.0.0 | https://github.com/Sovereign7G/openadn_verify/releases/tag/openadn-verify-v1.0.0 | `86143bc1adc49b1f9974c35cc6784658e39e6a5ccf8f86e449a5a232dc774f30` |
| v1.1.0 | https://github.com/Sovereign7G/openadn_verify/releases/tag/openadn-verify-v1.1.0 | `cbf0335e05f79791f84adf8399d6fa655c60167cb1caf124e2a2a90aa53755a9` |

Key (both versions): `ba7b971610fdac9768fb52fb866ac37dd5436d610f701e30329e363bc7504cb6`.
The clock runs from **v1.0.0's** date; a new release does **not** restart it.

**To close it.** Run `./verify.sh` on a downloaded archive; report the result (a one-line
`reproduced on <os>, 11/11, exit 0` is enough — see `EXAMPLE_REPORT.md`). Any report, pass or fail, closes
the metric. Then update this file with the date and a link to the report.

**Clock.** Starts when the archive is reachable by someone outside the author's circle. Publishing to a
private or invite-only repo does **not** start the metric.

**Why it is the metric.** Every other number in this project measures the author. This one measures whether
anyone else can check the work. The project can only make "yes" cheap; it cannot make it true.
