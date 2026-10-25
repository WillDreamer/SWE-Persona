Gemini 3.8 SWE-Persona results — upload/review package

Start with campaign-overview.csv, per-profile.csv, and unresolved-evaluations.csv.
The compact ZIP is a review report. Extract the evidence TAR.GZ beside its contents
to obtain the repositories/ paths referenced by the portable reports.

Reporting status
----------------
99 CPU task/persona pairs per effort; the H100 exam-pdf-eval pair is excluded.
Model: gcp/google/gemini-3.8-flash through NVIDIA Chat Completions.
Simulator and judge: azure/openai/gpt-6-luna, medium effort, NVIDIA Responses.
All four local runtime variants and the frozen dataset are identified by SHA-256.

Campaigns are separate:
* original-selected: 297 designated original campaign outcomes, 20 passes.
  Includes documented calibration/empty-output recovery history; see full runs.
* retry-3x: all 277 original non-successes selected, 29 passes. Two medium
  SWE-Together slots were blocked at calibration in this raw campaign report.
* together-repair: those two tasks rerun with corrected fixtures, both failures.
* error-repair: 24 selected cases; 20 episodes ran, four blocked by calibration;
  three passes, 14 failures, three other errors, four calibration errors.
* Seven explicit classification corrections: invalid -> failure, no added passes.
* cumulative-diagnostic: chronological designated-result view retaining original
  successes, later retries, and the corrections: 52 pass, 221 fail, 24 errors.
  Low: 18/70/11. Medium: 17/79/3. High: 17/72/10 (pass/fail/error).

The cumulative view uses outcome-dependent retry selection, different runtimes,
and mixed budgets. It is NOT a single-run benchmark or leaderboard score. Never
sum rows across campaigns, or present a valid-only rate as an all-task score.
Formal full-selection joint rates remain null wherever errors remain. Status
fail may include a total deadline or preserved work after API interruption;
unknown native/persona grades remain null. Full coverage, provisional outcomes,
timeout counts and observed-grade denominators are included in scores.json.

Budgets
-------
Original interaction multipliers: low 1x, medium 1x, high 2x task default.
Later attempts: low 3x, medium 3x, high 6x. Original API timeouts were agent 120s
and simulator/judge 300s; later configured values are 360s and 900s.
The error-repair runtime fixes SWE-Live propagation of these configured limits
(a legacy internal 90s cap previously remained) and changes reference preflight
floor 300s -> 900s. Other command/action/turn/verifier limits are separately
recorded and were not multiplied. High has twice the interaction time of the
other efforts; differences cannot be attributed to reasoning effort alone.
Agent output budgets follow automatic harness policy; max_tokens is used for
Gemini. Simulator/judge output limit is 32,768 tokens. Exact per-attempt configs,
effective budgets, timing, concurrency changes and host information are retained.

Evidence and reproducibility
----------------------------
README section 7 requires exact selection, runtime/API identity, simulator,
budgets, hardware, coverage and per-profile metrics. This package includes them.
The upstream README has no upload endpoint, submission schema or upload command.
No results have been uploaded. Remaining evaluation errors prevent a complete
end-to-end reproducibility claim. This package does not imply such a claim.

The evidence archive preserves regular files under all four Gemini run trees,
including earlier attempts, smoke runs, failed preparations, calibration gates,
transcripts, artifacts and verification logs. It also includes runtime source,
scripts, tests, notices, configs and a single frozen dataset copy. Archive files
are byte-identical to the recorded files. Absolute paths inside original audit
files are preserved; use path-map.json to resolve them after extraction.
The compact derived reports use portable repositories/ paths.

The small bundle is insufficient by itself to replay all evidence. Supply both
archives to a reviewer who requires detailed audit. Dependencies and Docker
images are not bundled. Install using archived requirements.lock.txt; do not
silently substitute current upstream code for a recorded runtime variant.
Tracked source diffs are supplemental; full archived source includes untracked
local scripts/tests. SHA256SUMS inside each historical checkout describes that
checkout's original release; use evidence-inventory.jsonl for archive integrity.

Packaging excludes .git directories, Python bytecode, virtual environments,
live .env/credential files, and alias symlinks (symlink targets are already
included under their real repositories). Exclusions are recorded. Benchmark
fixture credentials, if present, are synthetic task content and remain evidence.
Known live credentials from Desktop .env are scanned in plain, URL-encoded and
base64 forms without exposing values; packaging fails on a match. This is a
targeted credential check, not a guarantee of arbitrary secret detection.

Check SHA256SUMS.txt for transport integrity. verify_package.py verifies every
evidence member against evidence-inventory.jsonl without extracting the archive.
Upstream notices and task asset licenses retain their original terms.
