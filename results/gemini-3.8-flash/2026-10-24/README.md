# Gemini 3.8 Flash evaluation summaries

This is a **partial results delivery** containing summary metrics and
configuration metadata for low, medium, and high reasoning effort. The frozen
selection contains 99 CPU task/persona pairs per effort; `tb3/exam-pdf-eval`
requires an H100 and is excluded.

The full local archives contain evaluator-only evidence and have **not been
uploaded**. Their public release is pending approval. This PR alone is not a
complete evidence handoff and cannot support a claim of complete end-to-end
reproducibility. Archive identities are recorded in
[retained-evidence.json](retained-evidence.json), without pointers or download
links to unavailable payloads.

## Interpretation

The latest cumulative diagnostic contains 52 successes, 221 failures, and 24
unresolved evaluations:

| Effort | Success | Failure | Error / blocked |
| --- | ---: | ---: | ---: |
| Low | 18 | 70 | 11 |
| Medium | 17 | 79 | 3 |
| High | 17 | 72 | 10 |

These counts retain original successes and replace other outcomes with their
designated subsequent attempts. Retry selection depends on earlier outcomes;
runtime versions and budgets also differ. **This is not a single-run benchmark
score or a matched-budget comparison.** Formal full-selection success rates
remain null where errors remain. Unknown native/persona grades remain null.

[campaign-overview.csv](campaign-overview.csv) keeps the campaigns separate:

- Original selected campaign: 297 recorded outcomes, 20 successes.
- Larger-budget retries: 277 selected non-successes, 29 successes.
- SWE-Together calibration repair: two medium tasks rerun, both failures.
- Evaluation-error repair: 24 selected cases; 20 episodes ran and four were
  blocked by calibration. Three successes, 14 failures, and seven unresolved
  outcomes, including the four blocked cases.
- Seven separate classification corrections changed invalid outcomes to
  failures with zero joint credit; they added no successes.

The [attempt ledger](attempt-ledger.csv) contains 600 designated campaign
outcomes, including blocked entries. [results-by-campaign.csv](results-by-campaign.csv)
also includes the cumulative view; do not sum those rows as independent tasks.
[per-profile.csv](per-profile.csv) and `campaigns/*/*/scores.json` retain coverage,
provisional outcomes, timeout counts, and observed-grade denominators.
[unresolved-evaluations.csv](unresolved-evaluations.csv) lists the 24 current errors.
Evidence paths in the CSVs are provenance labels for the retained archives; their
targets are not part of this partial export.

## Configuration

Agent: `gcp/google/gemini-3.8-flash`, NVIDIA Chat Completions,
`max_tokens_field: max_tokens`, automatic harness output budgets.
Simulator/judge: `azure/openai/gpt-6-luna`, medium reasoning, NVIDIA Responses,
32,768-token output limit.

| Setting | Original low / medium / high | Later low / medium / high |
| --- | --- | --- |
| Interaction-time multiplier | 1 / 1 / 2 | 3 / 3 / 6 |
| Configured agent API timeout | 120 seconds | 360 seconds |
| Configured simulator/judge API timeout | 300 seconds | 900 seconds |

**High has twice the interaction time of low and medium.** Differences cannot
be attributed to reasoning effort alone. The final repair fixes SWE-Live's
legacy internal 90-second request cap and raises its reference-preflight floor
from 300 to 900 seconds. Other command, verification, action, and turn limits
were not multiplied. See [configuration.json](configuration.json).

The benchmark base commit is `842e5a6a665ade335e4d3be3c3fb8887ac5ba19a`.
The four local runtime hashes are in
[runtime-fingerprints.json](runtime-fingerprints.json). Source changes, exact
per-attempt configs, and detailed audits remain in the retained full archives.
This PR does not modify the executable benchmark or dataset.

## Git LFS and validation

`public-summary.zip` contains only the files in this public summary directory,
excluding itself and the outer manifest. It contains no raw conversations,
prompts, calibration fixtures, native reference assets, or task submissions.
Both the readable files and the ZIP are covered by `bundle_manifest.json`.

After cloning this branch, run from the repository root:

```bash
git lfs install --local
git lfs pull --include="results/gemini-3.8-flash/2026-10-24/public-summary.zip"
python results/gemini-3.8-flash/2026-10-24/verify_delivery.py
```

The verifier checks the delivered file sizes/hashes, ZIP membership and contents,
297 cumulative task/effort identities, 600 campaign ledger entries, the 24 error
records, and the explicit null formal full-selection rates. A fresh checkout
must retrieve the actual LFS ZIP for these checks to pass.
