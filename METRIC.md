# METRIC.md

```
time-to-first-independent-verification:  OPEN since 2026-10-03
```

**Definition.** The elapsed time from publication of a *publicly reachable* archive to the first report —
from someone other than the author — of having run `./verify.sh`.

**State.** No independent report received. Verified by the author only.

**To close it.** Run `./verify.sh` on a downloaded archive; report the result (a one-line
`reproduced on <os>, 11/11, exit 0` is enough — see `EXAMPLE_REPORT.md`). Any report, pass or fail, closes
the metric. Then update this file with the date and a link to the report.

**Clock.** Starts when the archive is reachable by someone outside the author's circle. Publishing to a
private or invite-only repo does **not** start the metric.

**Why it is the metric.** Every other number in this project measures the author. This one measures whether
anyone else can check the work. The project can only make "yes" cheap; it cannot make it true.
