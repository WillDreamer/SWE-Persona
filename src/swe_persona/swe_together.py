"""SWE-Together v2: reconstruct typed contracts and run the host API scaffold."""
import asyncio
import copy
import hashlib
import json
from pathlib import Path
import sys
from .dataset import write

PROFILE='swe-together'
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,ensure_ascii=False).encode()).hexdigest()

def materialize_together(row,root,task):
    extra=json.loads(row['interaction']['config_json'])
    native=json.loads(row['native_task']['config_json'])
    pool=json.loads((root/'human-interactive-coding-personas.full109.v1.json').read_text())
    persona=copy.deepcopy(next(p for p in pool['personas'] if p['id']==row['persona']['persona_id']))
    initial=copy.deepcopy(persona);initial['attributes'].pop('evolved_requirements',None)
    if initial!=json.loads(row['persona']['profile_json']):raise ValueError('Typed persona differs from frozen pool')
    bound=[]
    for r in row['requirements']:
        source=dict(json.loads(r['runtime_config_json']))
        checker=json.loads(r['checker_config_json'])
        source.update(id=r['requirement_id'],statement=r['disclosure'],rubric=json.loads(r['rubric_json']),
            earliest_turn=r['schedule']['earliest_turn'],deadline_turn=r['schedule']['deadline_turn'],
            checker=checker['checker'],checker_parameters=checker['checker_parameters'])
        if source['trigger']['event']!=r['schedule']['trigger_event']:raise ValueError('Trigger mismatch')
        bound.append(source)
    persona['bound_evolved_requirements']=bound
    binding=dict(extra['binding_metadata'],task_id=row['source']['task_id'],persona=persona,
        original_instruction=row['native_task']['instruction'],original_user_context=native['user_context'],
        base_user_persona={'source':'swe-together:user_simulation_prompt.md','text':native['user_context']},
        initial_pool_persona=initial)
    if native.get('native_phase_contract'):binding['native_phase_contract']=native['native_phase_contract']
    binding['binding_sha256']=digest(binding)
    if binding['binding_sha256']!=extra['binding_sha256']:raise ValueError('Reconstructed binding changed')
    # The controller assembles the exact public opening; evaluator context stays host-side.
    attrs=initial['attributes'];parts=[]
    for k,label in [('technical_context','My context: '),('primary_goal','My goal for this task: '),('interaction_preferences','How I want us to work: '),('constraints','Constraints for this run: ')]:
        if attrs.get(k):parts.append(label+attrs[k].strip())
    opening=binding['original_instruction'].rstrip()+'\n\nBefore you start, please follow these preferences for working with me:\n'+'\n'.join(parts)
    if row['initial_message']!=opening:raise ValueError('Public opening mismatch')
    (task/'instruction.md').write_text(binding['original_instruction'])
    (task/'user_simulation_prompt.md').write_text(native['user_context'])
    write(task/'tests/persona/binding.json',binding)
    if native.get('native_phase_contract'):write(task/'task_contract.json',native['native_phase_contract'])
    write(root/'row.json',{k:v for k,v in row.items() if k!='assets'})
    return root

def execute(root,row,config,out,mode,gate=None,*,calibration_enabled=True):
    sys.path.insert(0,str(root))
    from swe_together_pilot.persona_runtime.binding import validate
    from swe_together_pilot.persona_runtime.public_run import episode
    task=root/'tasks'/row['source']['task_id'];binding=json.loads((task/'tests/persona/binding.json').read_text());validate(binding)
    if mode=='dry-run':
        from harbor.environments.docker.docker import DockerEnvironment
        from harbor.models.task.config import EnvironmentConfig
        EnvironmentConfig.model_validate(json.loads(row['environment']['agent']['harbor_config_json']))
        print(json.dumps({'task_id':row['task_id'],'profile':PROFILE,'status':'pass','backend':'harbor-docker','binding_sha256':binding['binding_sha256']}));return 0
    if mode=='calibrate':
        from swe_together_pilot.persona_runtime.calibrate import calibrate
        return 0 if asyncio.run(calibrate(config,out))['execution_allowed'] else 1
    calibration={'enabled':False,'passed':None,'status':'skipped','score_provisional':False}
    if calibration_enabled:
        from .cli import gate_allows_execution
        if gate is None or not gate_allows_execution(json.loads((gate/'gate.json').read_text())):
            raise ValueError('Approved unified calibration required')
        calibration=json.loads((gate/'calibration.json').read_text())
        from swe_together_pilot.persona_runtime.calibration_policy import calibration_allowed
        if not calibration_allowed(calibration):raise ValueError('Incomplete or inconsistent calibration report')
        if binding['binding_sha256'] not in calibration.get('binding_sha256s',[]):raise ValueError('Binding not covered by calibration')
        calibration={k:calibration[k] for k in ('passed','status','execution_allowed','score_provisional','policy','mode','controls')}
        calibration.update(enabled=True,report=str(gate/'calibration.json'))
    result=asyncio.run(episode(binding,task,config,out/'episode',row['environment']['agent']['image'],
        seconds=row['budget']['episode_timeout_sec'],max_steps=json.loads(row['interaction']['config_json'])['max_agent_steps'],
        verifier_seconds=row['budget']['verifier_timeout_sec']))
    result['calibration']=calibration
    result['score_provisional']=calibration['score_provisional']
    # Calibration is attached as a scoped control result, not global judge accuracy.
    write(out/'persona-result.json',result)
    return 0 if result['benchmark_outcome'] in {'pass','fail'} else 2
