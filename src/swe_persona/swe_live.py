"""SWE-Live handoff-v2 materialization and isolated runtime integration."""
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

from .api import RoleAPI, role_name
from .dataset import write

PROFILE='swe-bench-live'
# Reference compilation and tests are infrastructure. The interaction budget is
# about 156–213 seconds and is too short for this check.
GOLD_PREFLIGHT_FLOOR_SEC=300

def gold_preflight_seconds(verifier_timeout_sec):
    return max(GOLD_PREFLIGHT_FLOOR_SEC, float(verifier_timeout_sec))

def live_episode_argv(task, row, config, episode_args):
    argv=['--task',str(task/'tests/native-task.jsonl'),'--persona',row['persona']['persona_id'],
        '--gold-dir',str(episode_args.gold_dir),'--binding-dir',str(task),'--model',config['agent']['model'],
        '--sample-seconds',str(episode_args.sample_seconds)]
    # The managed clock omits this deadline. Forwarding None becomes the string
    # "None", which the episode parser rejects before the task starts.
    if episode_args.deadline_monotonic is not None:
        argv+=['--deadline-monotonic',str(episode_args.deadline_monotonic)]
    argv+=['--output-dir',str(episode_args.output_dir)]
    return argv

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def adapter(root):return root/'runtime/project/scripts/swe_live_multilang/tb3_adapter'

def live_calibration_allowed(report):
    import runpy
    protocol=Path(__file__).parent/'vendor/swe_live/runtime/project/scripts/swe_live_multilang/tb3_adapter/protocol.py'
    return runpy.run_path(str(protocol))['calibration_allowed'](report)

def materialize_live(row,root,task):
    pp=task/'tests/persona';pp.mkdir(parents=True,exist_ok=True)
    extra=json.loads(row['interaction']['config_json'])
    native_file=task/'tests/native-task.jsonl';native=json.loads(native_file.read_text())
    if (native['instance_id']!=row['source']['instance_id'] or native['problem_statement']!=row['native_task']['instruction']
        or native['base_commit']!=row['environment']['expected_base_commit'] or native['docker_image']!=row['environment']['agent']['image']):
        raise ValueError('SWE-Live native payload and typed metadata differ')
    if (len(row['requirements'])!=1 or row['budget']['max_user_turns']!=24 or row['budget']['max_agent_queries_per_turn']!=14
        or row['budget']['max_simulator_decisions']!=64):raise ValueError('Unsupported handoff-v2 protocol limits')
    r=row['requirements'][0]
    if r['schedule']['earliest_turn']!=2 or r['schedule']['trigger_event']!='original_issue_disclosed':
        raise ValueError('Handoff-v2 must disclose at the original issue event on turn 2')
    req=dict(json.loads(r['runtime_config_json']),id=r['requirement_id'],disclosure=r['disclosure'],
             depends_on=r['depends_on'],checker=json.loads(r['checker_config_json']),
             trigger={'event':r['schedule']['trigger_event'],'earliest_turn':r['schedule']['earliest_turn']})
    persona=json.loads(row['persona']['profile_json'])
    write(pp/'persona.json',persona)
    write(pp/'interaction.json',json.loads(row['persona']['interaction_contract_json']))
    write(pp/'build-identity.json',{'protocol':extra['protocol'],'source_task_sha256':sha(native_file),
       'persona_id':row['persona']['persona_id'],'cap_seconds':row['budget']['episode_timeout_sec']})
    write(pp/'blurred_task.json',{'text':row['initial_message']})
    write(pp/'evolved_requirements.json',{'requirements':[req],'coverage':req['coverage']})
    write(pp/'binding.json',{'task_id':row['source']['instance_id'],'persona_id':persona['id'],'requirements':[req],
       'task_sha256':sha(native_file),'checker':'checker.py','source_content_sha256':row['content_sha256']})
    closed=pp/'closed_loop'
    write(closed/'rubric.json',{'requirement_id':r['requirement_id'],'disclosure':r['disclosure'],
       'criteria':json.loads(r['rubric_json']),'binding_sha256':sha(pp/'binding.json')})
    # Calibration and production consume the same versioned prompts and schema.
    import runpy
    prompts=runpy.run_path(str(adapter(root)/'protocol.py'))
    (closed/'judge_prompt.md').write_text(prompts['JUDGE_PROMPT'])
    (closed/'simulator_prompt.md').write_text(prompts['SIM_PROMPT'])
    write(closed/'response_schema.json',prompts['JUDGE_SCHEMA'])
    write(closed/'simulator_schema.json',prompts['SIM_SCHEMA'])
    (pp/'checker.py').write_bytes((adapter(root)/'protocol.py').read_bytes())
    # Fallback is restricted to the complete literal contract checked here.
    expected=prompts['requirement'](persona)
    if (req['checker']!=expected['checker'] or req['disclosure']!=expected['disclosure']
        or json.loads(r['rubric_json'])!=[{'criterion_id':'R1.contract','text':req['disclosure']}]):
        raise ValueError('SWE-Live independent checker does not cover the frozen requirement')
    policy=dict(extra['policy'],judge_policy=prompts['JUDGE_POLICY'],
        calibration_policy=prompts['CALIBRATION_POLICY'],
        api_schema_evidence_error='bounded internal recovery; unknown assessment; independent literal checker fallback')
    write(closed/'policy.json',policy)
    (closed/'README.md').write_text('Host-only requirement loop: registered eligible message IDs; '
        'two internal validation attempts; unavailable assessments remain unknown in audit. '
        'Only this complete literal handoff contract permits independent checker fallback. '
        'Independent native and persona final verification remain mandatory.\n')
    protocol_file=pp/'protocol.json'
    protocol_config=json.loads(protocol_file.read_text()) if protocol_file.exists() else {}
    write(protocol_file,dict(protocol_config,protocol=prompts['PROTOCOL'],source_protocol=extra['protocol'],
                            judge_policy=prompts['JUDGE_POLICY']))
    write(pp/'build-identity.json',{'protocol':prompts['PROTOCOL'],'source_protocol':extra['protocol'],
        'source_task_sha256':sha(native_file),'persona_id':persona['id'],'cap_seconds':row['budget']['episode_timeout_sec']})
    write(closed/'manifest.json',{'protocol':prompts['PROTOCOL'],'source_protocol':extra['protocol'],'binding_sha256':sha(pp/'binding.json'),
       'files':{p.name:sha(p) for p in sorted(closed.iterdir()) if p.is_file() and p.name!='manifest.json'}})
    lock={p.relative_to(task).as_posix():sha(p) for p in sorted(task.rglob('*')) if p.is_file()}
    write(pp/'task-lock.json',lock)
    write(root/'row.json',{k:v for k,v in row.items() if k!='assets'})
    write(root/'inventory.json',{'tasks':[{'task_id':row['source']['task_id']}]})
    write(root/'release-manifest.json',{'release':'swe-persona-0.2.0','task_id':row['task_id'],
        'content_sha256':row['content_sha256'],'profile':PROFILE})
    return root


def install_live(root,config,out):
    """Called in every child worker as well as calibration; no inherited patches assumed."""
    sys.path.insert(0,str(adapter(root)))
    import bootstrap_adapter
    import llm
    if config:
        # BudgetClient copies _client with the remaining timeout per request. Retain
        # that interface while selecting the real provider separately for every role.
        class RoutedLlm:
            def __init__(self,model=None,call_log=None,**kwargs):
                self.model=model or config['judge']['model'];self.log=call_log or llm.CallLog()
                self._client=RoleAPI(config,'judge').client
            def _api(self,role):
                from copy import deepcopy
                chosen=role_name(role);settings=deepcopy(config)
                if hasattr(self,'_request_timeout'):
                    settings[chosen]['timeout_sec']=min(settings[chosen].get('timeout_sec',120),self._request_timeout)
                return RoleAPI(settings,chosen,out/'api')
            def text(self,messages,role='unspecified',max_output_tokens=4096,**kwargs):
                return self._api(role).raw(messages,max_tokens=max_output_tokens,
                    timeout=float(self._client.timeout))['text']
            def json_obj(self,messages,schema,schema_name='payload',role='unspecified',max_output_tokens=4096,**kwargs):
                return self._api(role).json(messages,schema,schema_name,max_output_tokens,
                    timeout=float(self._client.timeout))
        llm.Llm=RoutedLlm
    import support
    from .harbor_bridge import install
    install(SimpleNamespace(Container=support.Runtime),out/'environments',workdir='/testbed',sample_labels=True)
    return support


def execute(root,row,config,out,mode,config_path=None,gate=None,episode_args=None,*,calibration_enabled=True):
    from build_task import validate
    task=root/'tasks'/row['source']['task_id']
    if mode=='dry-run':
        status=validate(task)
        # Import the exact Linux native evaluator dependencies without a container.
        upstream=root/'runtime/project/.local/SWE-bench-Live'
        sys.path[:0]=[str(upstream),str(upstream/'launch')]
        from launch.core.platforms.linux import LinuxRuntime
        from evaluation.evaluation import main as native_main
        from run import main as episode_main
        print(json.dumps(dict(task_id=row['task_id'],status='pass',profile=PROFILE,
            backend='harbor-docker',native_evaluator_import='pass',validation=status)))
        return 0
    if mode=='calibrate':
        from calibrate_judge import calibrate
        calibrate(out,config['judge']['model']);return 0
    if mode=='live-episode':
        from run import main as episode_main
        return episode_main(live_episode_argv(task, row, config, episode_args))
    # The shared CLI checks the gate unless startup calibration was disabled.
    from .cli import gate_allows_execution
    if calibration_enabled:
        if gate is None or not gate_allows_execution(json.loads((gate/'gate.json').read_text())):
            raise ValueError('An approved calibration gate or explicit SWE-Live checker fallback is required')
        write(out/'calibration-gate.json',json.loads((gate/'gate.json').read_text()))
    import docker
    from support import Manifest
    from run_fullset import get_image
    from run_study import ensure_gold
    from run_reference import gold_proof
    from whole_sample import supervise_sample
    from run_batch import clean,trial_projection
    manifest=Manifest(task/'tests/native-task.jsonl');cap=row['budget']['episode_timeout_sec']
    source={'key':row['source']['task_id'],'path':str(manifest.task_path),'sha256':manifest.task_sha256,'instance_id':manifest.task_id}
    client=docker.from_env(timeout=30)
    try:
        image,_=get_image(client,manifest)
        if ensure_gold(out,source,image.id,{'gold_seconds':gold_preflight_seconds(row['budget']['verifier_timeout_sec'])},False) is None:
            from .native_preflight import native_preflight_report
            diagnostic=native_preflight_report(out/'gold'/source['key'])
            write(out/'preflight-error.json',dict(diagnostic,
                error_category='native_reference_failure', episode_started=False,
                error='Official reference patch did not pass native preflight; inspect the recorded test failures.'))
            raise ValueError('Native gold preflight failed; no coding score')
        gold=out/'gold'/source['key'];gold_proof(gold,manifest,image.id)
    finally:client.close()
    trial=out/'trials'/source['key']/'persona'
    command=[sys.executable,'-B','-m','swe_persona.worker','--root',str(root),'--config',str(config_path.resolve()),
        '--output',str(out/'episode-runtime'),'--mode','live-episode','--gold-dir',str(gold)]
    if not calibration_enabled:command.append('--no-calibration')
    receipt=supervise_sample(command,trial,cap,cleanup=clean);trial_projection(trial,receipt)
    # Prefer the supervisor projection to any partial/late worker result.
    write(out/'persona-result.json',json.loads((trial/'persona-result.json').read_text()))
    return 0 if receipt['status'] in ('completed','timeout') else 2
