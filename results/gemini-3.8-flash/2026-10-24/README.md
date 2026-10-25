# Gemini 3.8 Flash evaluation results and evidence

This delivery contains summary metrics, configuration metadata, and the complete
recorded evidence archives for low, medium, and high reasoning effort. The frozen
selection contains 99 CPU task/persona pairs per effort; `tb3/exam-pdf-eval`
requires an H100 and is excluded.

The full archives include transcripts, calibration and grading records, task
artifacts, native reference evidence, historical attempts, and runtime source
snapshots. Archive identities are in [evidence-archives.json](evidence-archives.json).
All recorded evidence is provided, but the 24 unresolved evaluations still prevent
a claim that every selected pair completed valid end-to-end evaluation.

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
Evidence paths in the CSVs resolve after extracting the evidence archive into
`report/`, as described below. Original absolute paths inside historical records
remain unchanged; [report/path-map.json](report/path-map.json) maps them to the
archived repositories.

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
per-attempt configs, and detailed audits are included in `report/` and the full
evidence archive.
This PR does not modify the executable benchmark or dataset.

## Git LFS and validation

Three downloadable archives are tracked with Git LFS:

- [public-summary.zip](public-summary.zip): compact metrics and metadata. Its
  exact members are listed in `bundle_manifest.json`; it excludes `artifacts/`
  and `report/`.
- [gemini38-results.zip](artifacts/gemini38-results.zip): the original 5,324,779-byte
  detailed report package, including calibration reports and provenance.
- [gemini38-evidence.tar.gz](artifacts/gemini38-evidence.tar.gz): the original
  1,989,528,968-byte full evidence archive, containing 83,242 recorded files and
  about 8.90 GB of uncompressed data. Every archived file was verified against
  its recorded SHA-256 before packaging.

The original two archives are byte-identical to their locally verified packages.
The readable files and all three archives are covered by `bundle_manifest.json`.
Historical READMEs inside the original packages describe their creation-time
state; this README describes the Git LFS delivery.

After cloning this branch, run from the repository root:

```bash
git lfs install --local
git lfs pull --include="results/gemini-3.8-flash/2026-10-24/*.zip,results/gemini-3.8-flash/2026-10-24/artifacts/*"
python results/gemini-3.8-flash/2026-10-24/verify_delivery.py
```

To extract the evidence or optionally reverify all individual archive members:

```bash
cd results/gemini-3.8-flash/2026-10-24
tar -xzf artifacts/gemini38-evidence.tar.gz -C report
python report/verify_package.py artifacts/gemini38-evidence.tar.gz
```

The verifier checks the delivered file sizes/hashes, ZIP membership and contents,
297 cumulative task/effort identities, 600 campaign ledger entries, the 24 error
records, and the explicit null formal full-selection rates. A fresh checkout
must retrieve all three actual LFS objects for these checks to pass.

The original targeted scan for known live credentials found no matches. Its
scope is recorded in [report/credential-scan.json](report/credential-scan.json).
Credentials, `.env` files, virtual environments, and Git metadata are excluded.
Synthetic task credentials and evaluator-only materials remain evidence.
Upstream assets retain their original licenses and notices.
