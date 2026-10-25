#!/usr/bin/env python3
"""Build an offline review bundle and byte-preserving evidence archive."""
import base64
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile

BASE = Path('/home/sherryj/Desktop')
OUT = Path(__file__).resolve().parent
BUNDLE = OUT / 'gemini38-results'
NAMES = ['SWE-Persona-gemini38', 'SWE-Persona-gemini38-calibration-fix',
         'SWE-Persona-gemini38-together-fix', 'SWE-Persona-gemini38-errors-fix']
REPOS = [BASE / n for n in NAMES]
REPAIR = REPOS[-1] / 'runs/error-repair'
PRIOR = REPOS[1] / 'runs/gemini38-all-nonsuccess-3x'
FIRST = REPOS[1] / 'runs/gemini38-eight-workers'
TOGETHER = REPOS[2] / 'runs/medium-together-calibration-repair'
LEVELS = ('low', 'medium', 'high')
EXPECTED = ['48a0fd116e7e1a26ba2595a2e181f8cbce2f6685ad62f01247b1b2a4eda75491',
            'ce7ad1731671b2ee2790a95784487aa794f2037f662e935f3e715b14456fa606',
            'edce00d5b9de74e1fde7ba0bd139cea6aa6d0856a129091338714f034280c814',
            '37108145a425907d25d6bdf9d6f806b3b5bb8d6c54ce59e0b016745417e44835']

def read(p): return json.loads(p.read_text())
def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(1024*1024), b''): h.update(b)
    return h.hexdigest()
def save(p, value):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(value, indent=2) + '\n')
def portable(x):
    if isinstance(x, str):
        for repo in REPOS:
            if x == str(repo) or x.startswith(str(repo) + '/'):
                # Resolve the three read-only history aliases to their real source.
                p = Path(x)
                for alias in ['gemini38-timeout-audit', 'gemini38-eight-workers', 'gemini38-all-nonsuccess-3x']:
                    prefix = REPOS[-1]/'runs'/alias
                    if p == prefix or prefix in p.parents:
                        p = REPOS[1]/'runs'/alias/p.relative_to(prefix)
                return 'repositories/' + str(p.relative_to(BASE))
        return x
    if isinstance(x, list): return [portable(v) for v in x]
    if isinstance(x, dict): return {k: portable(v) for k,v in x.items()}
    return x
def csv_write(p, rows):
    p.parent.mkdir(parents=True, exist_ok=True)
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with p.open('w', newline='') as f:
        w = csv.DictWriter(f, keys); w.writeheader(); w.writerows(rows)

def main():
    assert not (OUT/'gemini38-results.zip').exists(), 'Do not replace a completed package'
    BUNDLE.mkdir(exist_ok=True)
    assert read(REPAIR/'manifest.json')['state'] == 'finished_with_errors'
    spec = importlib.util.spec_from_file_location('score', REPOS[-1]/'scripts/score.py')
    score = importlib.util.module_from_spec(spec); spec.loader.exec_module(score)
    runtime = []
    for repo, expected in zip(REPOS, EXPECTED):
        h=hashlib.sha256(); src=repo/'src/swe_persona'
        for f in sorted(src.rglob('*')):
            if f.is_file() and '__pycache__' not in f.parts:
                h.update(str(f.relative_to(src)).encode()+b'\0'+f.read_bytes())
        assert h.hexdigest() == expected, (repo.name, 'runtime changed')
        runtime.append({'repository': repo.name, 'runtime_sha256': expected,
                        'upstream_commit': subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
                        'requirements_sha256':sha(repo/'requirements.lock.txt')})
        dest=BUNDLE/'runtime'/repo.name; dest.mkdir(parents=True,exist_ok=True)
        for name in ['README.md','release.json','requirements.lock.txt','LICENSE','pyproject.toml']:
            (dest/name).write_bytes((repo/name).read_bytes())
        diff=subprocess.check_output(['git','diff','--binary','HEAD','--','.',' :!swe-persona-lite.parquet'.strip()],cwd=repo)
        (dest/'tracked-changes.patch').write_bytes(diff)
        (dest/'git-status.txt').write_bytes(subprocess.check_output(['git','status','--short'],cwd=repo))
    dataset=REPOS[0]/'swe-persona-lite.parquet'
    assert sha(dataset)=='1fbfa744b505609e02d83f9a7d7bacb41b3f72777185f131bcdc7aeb10c460ed'

    waves=[]
    for label, root in [('original-selected',FIRST/'scored'),('retry-3x',PRIOR/'scored'),
                         ('error-repair',REPAIR/'scored'),('cumulative-diagnostic',REPAIR/'reconciled')]:
        for level in LEVELS: waves.append((label,level,root/level/'summary.json'))
    waves.append(('together-repair','medium',TOGETHER/'summary.json'))
    rows=[]; profiles=[]; records=[]; ledger=[]; final={}; path_checks=[]
    for label,level,source in waves:
        data=read(source)
        if 'selection' not in data:
            data['selection']=[{k:r.get(k) for k in ['task_id','source_benchmark','profile']} for r in data['results']]
        report=score.summarize(data)
        target=BUNDLE/'campaigns'/label/level
        portable_data=portable(data)
        if label=='cumulative-diagnostic':
            portable_data.pop('time_limit_multiplier',None)
            portable_data['reporting_status']='cumulative_diagnostic_only_not_a_benchmark_submission_score'
            portable_data['selection_policy']='Retain original successes; replace other outcomes with the designated later retry; apply seven explicit zero-credit classification corrections. Outcome-dependent inclusion and mixed runtimes/budgets prevent a single-run score claim.'
            portable_data['time_policy']='Mixed: original low/medium/high 1/1/2; later attempts 3/3/6. See each result.'
        save(target/'summary.json',portable_data);save(target/'scores.json',report)
        m=report['overall']; counts=m['status_counts']
        rows.append(dict(campaign=label,effort=level,selected=m['selected'],passes=m['joint_passes'],
                         failures=counts.get('fail',0),errors=sum(v for k,v in counts.items() if k not in ['pass','fail']),
                         **{k:v for k,v in m.items() if k not in ['selected','status_counts','joint_passes']}))
        for profile,metrics in report['by_profile'].items():
            profiles.append(dict(campaign=label,effort=level,profile=profile,
                                 **{k:v for k,v in metrics.items() if k!='status_counts'},
                                 status_counts=json.dumps(metrics['status_counts'],sort_keys=True)))
        for r in data['results']:
            evidence=r.get('evidence_directory') or r.get('run_directory')
            assert evidence and Path(evidence).is_dir(), (label,r['task_id'],'missing evidence')
            for rel in r.get('details',[]):
                path_checks.append(Path(evidence)/rel)
            record=dict(campaign=label,effort=level,task_id=r['task_id'],profile=r.get('profile'),
                        status=r['status'],native_pass=r.get('native_pass'),persona_pass=r.get('persona_pass'),
                        joint_success=r.get('joint_success',False),verification_complete=r.get('verification_complete'),
                        outcome_reason=r.get('outcome_reason'),runtime_sha256=r.get('runtime_sha256'),
                        time_limit_multiplier=r.get('time_limit',{}).get('time_limit_multiplier',r.get('time_limit_multiplier')),
                        original_interaction_seconds=r.get('time_limit',{}).get('default_sec'),
                        effective_interaction_seconds=r.get('time_limit',{}).get('effective_sec'),
                        evidence_directory=portable(evidence),
                        source_summary=portable(str(source)),source_summary_sha256=sha(source),
                        episode_started=r.get('episode_started'),score_provisional=r.get('score_provisional',False))
            records.append(record)
            if label!='cumulative-diagnostic': ledger.append(record)
            else: final[(level,r['task_id'])]=r
    assert len(final)==297
    assert Counter(r['status'] for r in final.values())=={'pass':52,'fail':221,'invalid':17,'infrastructure_error':3,'calibration_error':4}
    missing=[portable(str(p)) for p in path_checks if not p.is_file()]
    assert not missing, ('Missing result.details evidence',missing[:5])
    csv_write(BUNDLE/'campaign-overview.csv',rows)
    csv_write(BUNDLE/'per-profile.csv',profiles)
    csv_write(BUNDLE/'results-by-campaign.csv',records)
    csv_write(BUNDLE/'attempt-ledger.csv',ledger)
    csv_write(BUNDLE/'unresolved-evaluations.csv',[r for r in records if r['campaign']=='cumulative-diagnostic' and r['status'] not in ['pass','fail']])
    save(BUNDLE/'path-map.json',{str(repo):'repositories/'+repo.name for repo in REPOS})
    save(BUNDLE/'runtime-fingerprints.json',runtime)
    for name, p in [('original',FIRST),('retry-3x',PRIOR),('together-repair',TOGETHER),('error-repair',REPAIR)]:
        for f in sorted(p.glob('*.json')):
            save(BUNDLE/'provenance'/name/f.name,portable(read(f)))
        for f in sorted((p/'provenance').glob('*.json')):
            save(BUNDLE/'provenance'/name/'validation'/f.name,portable(read(f)))
        for sub in ['configs','calibration-results','score-corrections']:
            for f in sorted((p/sub).rglob('*.json')):
                save(BUNDLE/'provenance'/name/sub/f.relative_to(p/sub),portable(read(f)))
    # Include every calibration gate and its complete sibling JSON/text reports in the review bundle.
    for repo in REPOS:
        for directory, dirs, files in os.walk(repo/'runs',followlinks=False):
            dirs[:]=[d for d in dirs if d not in ['.git','__pycache__','.venv'] and not (Path(directory)/d).is_symlink()]
            if 'gate.json' not in files:continue
            for fn in files:
                f=Path(directory)/fn
                if f.is_file() and f.suffix in ['.json','.log','.txt']:
                    dest=BUNDLE/'calibration'/repo.name/f.relative_to(repo/'runs')
                    dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(f.read_bytes())
    (BUNDLE/'score.py').write_bytes((REPOS[-1]/'scripts/score.py').read_bytes())
    (BUNDLE/'build_package.py').write_bytes(Path(__file__).read_bytes())
    now=datetime.now(timezone.utc).isoformat()
    manifest={'created_at':now,'model':'gcp/google/gemini-3.8-flash',
              'agent_endpoint':'https://inference-api.nvidia.com/v1','agent_api':'chat_completions',
              'simulator_and_judge':'azure/openai/gpt-6-luna','simulator_effort':'medium','simulator_api':'responses',
              'dataset_sha256':sha(dataset),'excluded_task':'tb3/exam-pdf-eval (H100 required)',
              'selected_per_effort':99,'efforts':list(LEVELS),'formal_full_selection_score':None,
              'reporting_status':'partial-coverage multi-campaign diagnostic; not a single matched-budget leaderboard score',
              'cumulative_status_counts':dict(Counter(r['status'] for r in final.values())),
              'corrections':7,'corrections_add_successes':False,'runtime_variants':runtime,
              'source_files_preserved':True,'readme_upstream_commit':'842e5a6a665ade335e4d3be3c3fb8887ac5ba19a',
              'upstream_upload_command_or_destination':None,
              'hardware_provenance':'provenance/retry-3x/validation/host.json',
              'rate_notes':'Formal joint_success_rate remains null with unresolved errors; valid-only and observed component rates retain denominators.'}
    save(BUNDLE/'manifest.json',manifest)
    (BUNDLE/'README.txt').write_text('''Gemini 3.8 SWE-Persona results — upload/review package

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
''')
    # Compact diagnostic plot: counts, not an unqualified benchmark rate.
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,ax=plt.subplots(figsize=(8.8,4.4))
    left=[0,0,0]
    for name,vals,color in [('Success',[18,17,17],'#18794e'),('Failure',[70,79,72],'#d49b31'),('Error / blocked',[11,3,10],'#a44a55')]:
        ax.barh(LEVELS,vals,left=left,color=color,label=name)
        for i,v in enumerate(vals): ax.text(left[i]+v/2,i,str(v),ha='center',va='center',color='white',weight='bold')
        left=[a+b for a,b in zip(left,vals)]
    ax.invert_yaxis();ax.set_xlim(0,99);ax.set_xlabel('Task/persona pairs (99 per effort)')
    ax.set_title('Gemini 3.8 — cumulative diagnostic after retries',loc='left',weight='bold')
    ax.legend(loc='upper center',bbox_to_anchor=(.5,-.2),ncol=3,frameon=False)
    fig.text(.08,.02,'Mixed runtimes/budgets; outcome-dependent retries. High uses 2× interaction time.\n52 successes across attempts; not a single-run benchmark score.',fontsize=9)
    fig.subplots_adjust(bottom=.32,left=.1,right=.97,top=.87)
    for ext in ['png','pdf','svg']: fig.savefig(BUNDLE/f'cumulative-diagnostic.{ext}',dpi=160)
    plt.close(fig)
    print('Reports prepared; building and scanning evidence inventory.',flush=True)

    # Load only actual credential values, never print them or package .env.
    sys.path.insert(0,str(REPOS[1]/'.venv/lib/python3.12/site-packages'))
    from dotenv import dotenv_values
    from urllib.parse import quote
    secrets=set()
    for key,value in dotenv_values(BASE/'.env').items():
        if value and len(value)>=12 and any(x in key.upper() for x in ['KEY','TOKEN','SECRET','PASSWORD']):
            for v in [value,quote(value,safe=''),base64.b64encode(value.encode()).decode()]: secrets.add(v.encode())
    assert secrets, 'No credentials loaded for the targeted scan'
    pattern=__import__('re').compile(b'|'.join(__import__('re').escape(s) for s in secrets))
    overlap=max(map(len,secrets)); files=[]; exclusions=[]
    for repo in REPOS:
        for part in ['runs','src','scripts','tests','configs']:
            for directory,dirs,names in os.walk(repo/part,followlinks=False):
                for name in list(dirs):
                    f=Path(directory)/name
                    if name in ['.git','.venv','__pycache__'] or f.is_symlink():
                        dirs.remove(name);exclusions.append({'path':portable(str(f)),'reason':'metadata/cache/alias symlink'})
                for name in names:
                    f=Path(directory)/name
                    if f.is_symlink() or name=='.env' or name.startswith('.env.') or name.endswith(('.pyc','.pyo','.pem','.key')):
                        exclusions.append({'path':portable(str(f)),'reason':'symlink, cache or credential filename'});continue
                    if f.is_file(): files.append((f,portable(str(f))))
        for name in ['README.md','release.json','requirements.lock.txt','LICENSE','pyproject.toml','SHA256SUMS','.gitattributes','.gitignore']:
            files.append((repo/name,portable(str(repo/name))))
    files.append((dataset,'dataset/swe-persona-lite.parquet'))
    files=sorted(files,key=lambda pair:pair[1]); inventory=[];hits=[]
    for i,(f,arc) in enumerate(files):
        h=hashlib.sha256();last=b'';before=f.stat()
        with f.open('rb') as stream:
            for block in iter(lambda:stream.read(1024*1024),b''):
                h.update(block)
                if pattern.search(last+block): hits.append(arc)
                last=(last+block)[-overlap:]
        after=f.stat();assert (before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns),f'File changed: {arc}'
        inventory.append({'path':arc,'size':before.st_size,'sha256':h.hexdigest()})
        if (i+1)%10000==0: print(f'Hashed and scanned {i+1}/{len(files)} evidence files',flush=True)
    if hits:
        save(OUT/'credential-scan-blocked.json',{'matched_files':sorted(set(hits))})
        raise RuntimeError('Live credential match; archive not created. See paths-only diagnostic.')
    for f in BUNDLE.rglob('*'):
        if f.is_file(): assert not pattern.search(f.read_bytes()), 'Live credential match in derived report'
    with (BUNDLE/'evidence-inventory.jsonl').open('w') as f:
        for row in inventory:f.write(json.dumps(row)+'\n')
    save(BUNDLE/'exclusions.json',exclusions)
    save(BUNDLE/'credential-scan.json',{'scope':'known live credentials from Desktop .env; raw, URL-encoded, base64',
                                     'matched_files':0,'evidence_files_scanned':len(files),'derived_reports_scanned':True,
                                     'note':'Credential values and the .env file are not included.'})
    (BUNDLE/'verify_package.py').write_text('''import hashlib,json,sys,tarfile
from pathlib import Path
root=Path(__file__).resolve().parent
expected={r['path']:r for r in map(json.loads,(root/'evidence-inventory.jsonl').read_text().splitlines())}
seen=set()
with tarfile.open(sys.argv[1], 'r|gz') as archive:
 for member in archive:
  assert member.isfile() and member.name in expected and member.name not in seen, member.name
  assert not member.name.startswith('/') and '..' not in Path(member.name).parts
  h=hashlib.sha256(); f=archive.extractfile(member)
  for chunk in iter(lambda:f.read(1048576),b''):h.update(chunk)
  assert member.size==expected[member.name]['size'] and h.hexdigest()==expected[member.name]['sha256'], member.name
  seen.add(member.name)
assert seen==set(expected),(len(seen),len(expected))
print('Verified',len(seen),'byte-identical evidence files')
''')
    archive=OUT/'gemini38-evidence.tar.gz'
    print(f'Archiving {len(files)} files, {sum(r["size"] for r in inventory)/1e9:.2f} GB uncompressed.',flush=True)
    with archive.open('xb') as output:
        compressor=subprocess.Popen(['pigz','-4','-p','4','-n'],stdin=subprocess.PIPE,stdout=output)
        try:
            with tarfile.open(fileobj=compressor.stdin,mode='w|') as tar:
                for f,arc in files:
                    info=tar.gettarinfo(str(f),arcname=arc);info.uid=info.gid=0;info.uname=info.gname=''
                    with f.open('rb') as stream:tar.addfile(info,stream)
            compressor.stdin.close();assert compressor.wait()==0
        except BaseException:
            compressor.kill();compressor.wait();raise
    print('Evidence archive written; verifying all archived bytes.',flush=True)
    verification=subprocess.check_output([sys.executable,str(BUNDLE/'verify_package.py'),str(archive)],text=True)
    print(verification.strip(),flush=True)
    save(BUNDLE/'validation.json',{'verified_at':datetime.now(timezone.utc).isoformat(),
         'runtime_fingerprints_verified':4,'dataset_checksum_verified':True,
         'cumulative_results':297,'separate_campaign_result_entries':len(ledger),
         'result_detail_paths_verified':len(path_checks),'evidence_files_verified':len(files),
         'archive_sha256':sha(archive),'credential_matches':0,
         'formal_full_selection_rates_null':all(r['joint_success_rate'] is None for r in rows if r['campaign']=='cumulative-diagnostic')})
    with (BUNDLE/'SHA256SUMS.txt').open('w') as out:
        for f in sorted(BUNDLE.rglob('*')):
            if f.is_file() and f!=BUNDLE/'SHA256SUMS.txt':out.write(f'{sha(f)}  {f.relative_to(BUNDLE)}\n')
    zip_path=OUT/'gemini38-results.zip'
    with zipfile.ZipFile(zip_path,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive_zip:
        for f in sorted(BUNDLE.rglob('*')):
            if f.is_file():archive_zip.write(f,arcname=str(f.relative_to(OUT)))
    with zipfile.ZipFile(zip_path) as archive_zip:assert archive_zip.testzip() is None
    (OUT/'SHA256SUMS.txt').write_text(''.join(f'{sha(p)}  {p.name}\n' for p in [zip_path,archive]))
    print(json.dumps({'results_zip':str(zip_path),'results_bytes':zip_path.stat().st_size,
                      'evidence_archive':str(archive),'evidence_bytes':archive.stat().st_size,
                      'validation':'passed'}),flush=True)

if __name__=='__main__':main()
