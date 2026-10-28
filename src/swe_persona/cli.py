"""Public CLI. Routing uses runtime profiles, never source benchmark names."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import pyarrow.parquet as pq

from . import __version__
from .api import load_config, fingerprint
from .dataset import rows, load_task, materialize, write, VENDOR
from .schema import PROFILES
from .time_limit import resolve_limit, run_bounded, positive_seconds, apply_timeout_result

def runtime_hash():
    h=hashlib.sha256()
    for p in sorted(Path(__file__).parent.rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts:
            h.update(str(p.relative_to(Path(__file__).parent)).encode()+b'\0'+p.read_bytes())
    return h.hexdigest()

def worker(root,mode,output,config=None,gate=None,time_limit=None,calibration=True):
    command=[sys.executable,'-B','-m','swe_persona.worker','--root',str(root),'--mode',mode,'--output',str(output)]
    if config:command+=['--config',str(Path(config).resolve())]
    if gate:command+=['--gate-dir',str(gate)]
    if not calibration:command.append('--no-calibration')
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    if time_limit and 'internal_budget' in time_limit:
        env['SWE_PERSONA_NATIVE_VERIFICATION_SECONDS']=str(time_limit['internal_budget']['verifier_timeout_sec'])
    env['PYTHONPATH']=str(Path(__file__).parents[1])+os.pathsep+env.get('PYTHONPATH','')
    Path(output).mkdir(parents=True,exist_ok=True)
    with (Path(output)/(mode+'.log')).open('w') as log:
        try:
            if time_limit is None:
                return subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT).returncode
            receipt=run_bounded(command,env=env,log=log,seconds=time_limit['effective_sec'],
                phase_file=Path(output)/'evaluation-clock.json',
                preparation_sec=time_limit.get('preparation_sec',7200),
                verification_sec=time_limit.get('verification_sec',1800))
            write(Path(output)/'time-limit.json',dict(time_limit,**{'execution':receipt}))
            return receipt['process_exit_code']
        finally:
            if mode != 'dry-run':
                from .harbor_bridge import cleanup_empty_session_networks
                cleanup_empty_session_networks(output)

def gate_allows_execution(value):
    if value.get('profile') == 'swe-together':
        from .vendor.swe_together.swe_together_pilot.persona_runtime.calibration_policy import calibration_allowed, mode
        report = value.get('calibration') or {}
        return (value.get('worker_exit_code') == 0 and value.get('execution_allowed') is True
                and value.get('passed') is report.get('passed') and report.get('mode') == mode()
                and calibration_allowed(report))
    if value.get('passed') is True:
        return True
    if value.get('profile') != 'swe-bench-live' or value.get('worker_exit_code') != 0:
        return False
    from .swe_live import live_calibration_allowed
    return value.get('execution_allowed') is True and live_calibration_allowed(value.get('calibration') or {})


def calibrate(dataset,profile,config_path,cache):
    config=load_config(config_path,require_keys=True)
    identity={'profile':profile,'api_config_sha256':fingerprint(config),'runtime_sha256':runtime_hash()}
    if profile=='swe-together':
        from .vendor.swe_together.swe_together_pilot.persona_runtime.calibration_policy import mode
        identity['calibration_mode']=mode()
    key=hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()[:20]
    gate=Path(cache)/'calibration'/key;marker=gate/'gate.json'
    if marker.exists() and gate_allows_execution(json.loads(marker.read_text())):return gate
    selected=None
    for row in rows(dataset):
        if row['interaction']['profile_id']!=profile:continue
        if profile=='swe-bench-pro-shell' and row['persona']['persona_id']!='first_time_pr_contributor':continue
        selected=row;break
    if selected is None:raise ValueError('No calibration-compatible row for '+profile)
    gate.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='calibration-input-',dir=Path(cache)) as temp:
        root=materialize(selected,Path(temp)/'task')
        rc=worker(root,'calibrate',gate,config_path)
    report={}
    if profile=='swe-bench-pro-shell':
        reports=list(gate.glob('rubric_report.*.json'))
        passed=rc==0 and bool(reports) and all(json.loads(p.read_text()).get('gate_passed') for p in reports)
    else:
        p=gate/'calibration.json'
        report=json.loads(p.read_text()) if p.exists() else {}
        passed=rc==0 and bool(report.get('passed'))
    value=dict(identity,passed=passed,worker_exit_code=rc,execution_allowed=passed)
    if profile=='swe-together':
        from .vendor.swe_together.swe_together_pilot.persona_runtime.calibration_policy import calibration_allowed
        value.update(calibration=report,execution_allowed=rc==0 and calibration_allowed(report))
    if profile=='swe-bench-live':
        from .swe_live import live_calibration_allowed
        value.update(calibration=report,execution_allowed=rc==0 and live_calibration_allowed(report))
    write(marker,value)
    if not gate_allows_execution(value):raise RuntimeError(f'Judge calibration failed; see {gate / "calibrate.log"}')
    return gate

def shell_requirement_coverage(row, episode):
    """Compare real episode loading and grading with the immutable row."""
    expected={r['requirement_id'] for r in row['requirements']}
    required={r['requirement_id'] for r in row['requirements'] if r.get('required',True)}
    # Event-triggered optional candidates retain their frozen schedule. Once
    # disclosed, they must also have an independent final requirement check.
    disclosed=(episode.get('evolved_requirement_disclosure') or {}).get('disclosed_ids') or []
    required.update(ref.rsplit('@',1)[0] for ref in disclosed)
    loaded={r['requirement_id'] for r in episode.get('rubric_config') or []}
    checks=(episode.get('outcome') or {}).get('evolved_requirements') or []
    checked={r['requirement'].rsplit('@',1)[0] for r in checks}
    missing_loaded=sorted(expected-loaded);missing_checks=sorted(required-checked)
    states=[r.get('status') for r in checks]
    persona=False if 'not_met' in states else True if (checks and not missing_loaded and not missing_checks
        and all(v=='met' for v in states)) else None
    return {'expected_ids':sorted(expected),'required_check_ids':sorted(required),
            'loaded_ids':sorted(loaded),'checked_ids':sorted(checked),
            'missing_loaded_ids':missing_loaded,'missing_check_ids':missing_checks,
            'complete':not missing_loaded and not missing_checks,'persona_pass':persona}


def normalize_result(row,out,rc):
    profile=row['interaction']['profile_id'];native=None;persona=None;details=[]
    status='infrastructure_error'
    if profile=='swe-bench-pro-shell':
        matches=list(out.glob('*/episode.json'))
        if matches:
            p=matches[0];d=json.loads(p.read_text());details=[str(p.relative_to(out))]
            native=d.get('base_pass');persona=d.get('persona_pass')
            if d.get('episode_valid') is True:status='pass' if d.get('joint_success') else 'fail'
            else:status='invalid'
    else:
        matches=([out/'persona-result.json'] if (out/'persona-result.json').is_file() else list(out.rglob('persona-result.json')))
        if matches:
            p=matches[0];d=json.loads(p.read_text());details=[str(p.relative_to(out))]
            outcome=d.get('benchmark_outcome')
            status=outcome.get('status',outcome.get('outcome','invalid')) if isinstance(outcome,dict) else outcome or 'invalid'
            reward=d.get('original_reward');native=None if reward is None else reward==1
            checker=d.get('persona_check',d.get('checker',{})) or {}
            persona=checker.get('status')
            if persona in {'pass','fail'}:persona=persona=='pass'
            else:
                values=[v.get('status') for v in checker.get('requirements',{}).values()]
                persona=False if 'fail' in values else True if values and all(v=='pass' for v in values) else None
    if profile=='swe-bench-live' and matches:
        checks=d.get('objective_requirements') or []
        values=[x.get('verdict') for x in checks]
        persona=False if 'fail' in values else True if values and all(v=='pass' for v in values) else None
    recovery=None
    coverage=None;coverage_error=None
    if matches:
        recovery=d.get('api_recovery_assessment') or d.get('interaction_stall_assessment')
        if recovery is None and isinstance(d.get('benchmark_outcome'),dict):
            candidate=d['benchmark_outcome']
            if candidate.get('api_interrupted') or candidate.get('online_judge_unavailable'):recovery=candidate
        if d.get('supervisor_status') not in (None,'completed') or d.get('cleanup_error'):
            recovery=None
        if recovery is not None:
            status=recovery['status'];native=recovery.get('native_pass');persona=recovery.get('persona_pass')
    if profile=='swe-bench-pro-shell' and matches and 'requirements' in row:
        coverage=shell_requirement_coverage(row,d)
        base_status=((d.get('outcome') or {}).get('base_task') or {}).get('status')
        if native is None and base_status in ('pass','fail'):native=base_status=='pass'
        elif native in (0,1):native=bool(native)
        persona=coverage['persona_pass']
        if coverage['missing_loaded_ids']:
            status='invalid';coverage_error='persona_requirements_not_loaded';recovery=None
        elif recovery is not None:
            # Interrupted grading can leave unknown requirements, but cannot
            # use approval fields in place of independent requirement checks.
            from .api_recovery import assess_interrupted
            recovery=assess_interrupted(native,persona,
                artifacts_available=recovery.get('artifacts_available',False),
                progress=recovery.get('agent_progress',False),integrity=recovery.get('status')!='invalid',
                budget_exhausted=recovery.get('budget_exhausted',False))
            status=recovery['status']
        elif coverage['missing_check_ids'] or not (d.get('outcome') or {}).get('evolved_requirements'):
            status='invalid';coverage_error='persona_requirement_checks_missing'
        elif status=='pass' and (native is not True or persona is not True):
            status='fail' if native is False or persona is False else 'invalid'
    result={'task_id':row['task_id'],'source_benchmark':row['source_benchmark'],'source_subset':row['source_subset'],
            'content_sha256':row['content_sha256'],'harness_version':__version__,'profile':profile,
            'status':status,'native_pass':native,'persona_pass':persona,'joint_success':status=='pass',
            'worker_exit_code':rc,'details':details,'note':'Invalid and infrastructure errors are not task failures.'}
    if recovery is not None:
        result.update(verification_complete=recovery['verification_complete'],
                      outcome_reason=recovery.get('outcome_reason','api_interrupted'))
        assessment_name=('interaction_stall_assessment' if recovery.get('interaction_stalled') else
                         'online_judge_assessment' if recovery.get('online_judge_unavailable') else
                         'api_recovery_assessment')
        result[assessment_name]=recovery
    if coverage is not None:
        result['persona_requirement_coverage']=coverage
    if coverage_error:
        result.update(outcome_reason=coverage_error,verification_complete=False,
            note='Native diagnostics are retained; missing persona loading or checks cannot earn joint credit.')
    preflight_error=out/'preflight-error.json'
    if preflight_error.is_file():
        diagnostic=json.loads(preflight_error.read_text())
        result.update(error_category=diagnostic['error_category'],
                      episode_started=diagnostic['episode_started'],error=diagnostic['error'])
        result['details'].append('preflight-error.json')
    elif matches:
        for field in ('error','final_error','error_category','end_reason','simulator_message_recoveries',
                      'stop_reason','interaction_stalled','interaction_stall_policy'):
            if d.get(field) is not None:result[field]=d[field]
        if profile=='swe-together' and d.get('calibration'):
            result['calibration']=d['calibration']
            result['score_provisional']=d['calibration'].get('score_provisional') is True
    if (out/'run-config.json').is_file():
        calibration=json.loads((out/'run-config.json').read_text()).get('calibration')
        if calibration:
            result.setdefault('calibration',calibration)
            result['score_provisional']=calibration.get('score_provisional') is True
    write(out/'result.json',result)
    return result

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--dataset',type=Path,default=Path('swe-persona-lite.parquet'))
    sub=ap.add_subparsers(dest='command',required=True)
    sub.add_parser('list',help='List tasks and their source benchmarks')
    val=sub.add_parser('validate',help='Validate rows and optionally import every executable profile')
    val.add_argument('--dry-run',action='store_true');val.add_argument('--output',type=Path,default=Path('runs/validation'))
    prep=sub.add_parser('materialize');prep.add_argument('--task',required=True);prep.add_argument('--output',type=Path,required=True)
    cal=sub.add_parser('calibrate');cal.add_argument('--profile',choices=PROFILES,required=True)
    cal.add_argument('--config',type=Path,required=True);cal.add_argument('--cache',type=Path,default=Path.home()/'.cache/swe-persona')
    run=sub.add_parser('run');run.add_argument('--task',required=True);run.add_argument('--config',type=Path,required=True)
    run.add_argument('--output',type=Path,required=True);run.add_argument('--dry-run',action='store_true')
    run.add_argument('--cache',type=Path,default=Path.home()/'.cache/swe-persona')
    run.add_argument('--calibration',action=argparse.BooleanOptionalAction,default=True,
        help='Run or reuse judge calibration before evaluation (default: enabled); --no-calibration skips startup controls, not episode judging.')
    run.add_argument('--timeout-sec','--total-timeout-sec',dest='timeout_sec',type=positive_seconds,
        help='Agent/user interaction wall-clock seconds; default: row budget.episode_timeout_sec. Excludes preparation, native preflight and final grading; existing inner limits remain in force.')
    args=ap.parse_args()
    if args.command=='list':
        table=pq.read_table(args.dataset,columns=['task_id','source_benchmark','source_subset'])
        for row in table.to_pylist():print(json.dumps(row))
        return 0
    if args.command=='materialize':
        materialize(load_task(args.dataset,args.task),args.output);print(args.output.resolve());return 0
    if args.command=='validate':
        args.output.mkdir(parents=True,exist_ok=True);results=[];seen=set();originals=set()
        with tempfile.TemporaryDirectory(prefix='sp-validation-') as temp:
            for row in rows(args.dataset):
                if row['task_id'] in seen:raise ValueError('Duplicate task_id')
                seen.add(row['task_id']);originals.add((row['source_benchmark'],row['source']['instance_id']))
                entry={'task_id':row['task_id'],'source_benchmark':row['source_benchmark'],'profile':row['interaction']['profile_id'],'status':'pass'}
                if args.dry_run:
                    root=materialize(row,Path(temp)/str(len(results)))
                    rc=worker(root,'dry-run',args.output/row['task_id'].replace('/','__'))
                    entry.update(worker_exit_code=rc,status='pass' if rc==0 else 'fail')
                    import shutil
                    shutil.rmtree(root)
                results.append(entry)
        report={'tasks':len(results),'unique_source_instances':len(originals),'passed':sum(r['status']=='pass' for r in results),
                'model_calls':0,'containers_started':0,'scope':'Row integrity and profile dry runs only' if args.dry_run else 'Row integrity only',
                'results':results}
        write(args.output/'report.json',report);print(json.dumps({k:v for k,v in report.items() if k!='results'},indent=2))
        return 0 if report['passed']==report['tasks'] else 1
    args.cache.mkdir(parents=True,exist_ok=True)
    if args.command=='calibrate':
        print(calibrate(args.dataset,args.profile,args.config,args.cache));return 0
    row=load_task(args.dataset,args.task)
    config=load_config(args.config,require_keys=not args.dry_run)
    if args.output.exists() and any(args.output.iterdir()):raise ValueError('Run output must be a new empty directory')
    args.output.mkdir(parents=True,exist_ok=True)
    time_limit=resolve_limit(row,args.timeout_sec)
    profile=row['interaction']['profile_id']
    if profile=='swe-bench-pro-mini' and config['agent']['api']!='chat_completions':
        raise ValueError('This profile uses mini-swe-agent Chat Completions; configure agent.api=chat_completions')
    write(args.output/'run-config.json',{'task_id':row['task_id'],'content_sha256':row['content_sha256'],
          'runtime_sha256':runtime_hash(),'api_config_sha256':fingerprint(config),'models':config,'time_limit':time_limit,
          'calibration':{'enabled':args.calibration,'status':'not_run' if args.dry_run else 'pending' if args.calibration else 'skipped',
                         'passed':None,'score_provisional':False}})
    try:
        gate=calibrate(args.dataset,profile,args.config,args.cache) if args.calibration and not args.dry_run else None
    except Exception as exc:
        run_config=json.loads((args.output/'run-config.json').read_text())
        run_config['calibration'].update(status='error',execution_allowed=False)
        write(args.output/'run-config.json',run_config)
        result=normalize_result(row,args.output,2)
        result.update(status='calibration_error',error=str(exc))
        write(args.output/'result.json',result)
        print(json.dumps(result,indent=2));return 2
    if gate is not None:
        value=json.loads((gate/'gate.json').read_text())
        run_config=json.loads((args.output/'run-config.json').read_text())
        run_config['calibration']={'enabled':True,'passed':value['passed'],'execution_allowed':gate_allows_execution(value),
            'status':value.get('calibration',{}).get('status') or ('passed' if value['passed'] else 'failed'),'gate':str(gate),
            'score_provisional':value.get('calibration',{}).get('score_provisional',False)}
        write(args.output/'run-config.json',run_config)
    with tempfile.TemporaryDirectory(prefix='input-',dir=args.cache) as temp:
        root=materialize(row,Path(temp)/'task')
        restorations=[json.loads(p.read_text()) for p in root.glob('tasks/*/asset-restoration.json')]
        if restorations:write(args.output/'asset-restoration.json',{'restorations':restorations})
        rc=worker(root,'dry-run' if args.dry_run else 'run',args.output,args.config,gate,
                  None if args.dry_run else time_limit,calibration=args.calibration)
    if args.dry_run:
        print(json.dumps({'task_id':row['task_id'],'dry_run':rc==0,'log':str(args.output/'dry-run.log')}));return rc
    result=normalize_result(row,args.output,rc)
    receipt=json.loads((args.output/'time-limit.json').read_text())
    result['time_limit']=receipt
    apply_timeout_result(result,receipt['execution'])
    write(args.output/'result.json',result)
    print(json.dumps(result,indent=2))
    return 0 if result['status'] in {'pass','fail'} else 2

if __name__=='__main__':raise SystemExit(main())
