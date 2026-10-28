"""DeepSWE staged controller over Harbor 0.23; isolated host API roles."""
import hashlib,json,os,shutil,subprocess,sys
from pathlib import Path
from .dataset import write
from .api import chat_token_options
from .output_mode import configured_mode
from .schema import safe_path
PROFILE='deep-swe'
def read(path):return json.loads(Path(path).read_text())
def materialize_deepswe(row,root,task):
    project=root/'project';tid=row['source']['task_id'];pid=row['persona']['persona_id']
    frozen=task/'tests/frozen-inputs';extra=json.loads(row['interaction']['config_json'])
    profile=read(frozen/'task-profile.json')
    if profile!=json.loads(row['native_task']['config_json'])['profile']:raise ValueError('Native profile mismatch')
    pool=read(project/'data/personas.v3.json')
    persona=next(p for p in pool['personas'] if p['id']==pid)
    if persona!=json.loads(row['persona']['profile_json']):raise ValueError('Persona mismatch')
    (project/'data/tasks').mkdir(parents=True,exist_ok=True)
    shutil.copy2(frozen/'task-profile.json',project/'data/tasks'/f'{tid}.json')
    target=project.joinpath(*safe_path(profile['contract_file']).parts);target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(frozen/'contract.md',target)
    (project/'data/bindings').mkdir(parents=True,exist_ok=True)
    shutil.copy2(frozen/'source-binding.json',project/'data/bindings'/f'{tid}--{pid}.json')
    if (frozen/'calibration').exists():shutil.copytree(frozen/'calibration',project,dirs_exist_ok=True)
    write(project/'data/staged_bindings'/f'{tid}--{pid}.json',extra['plan'])
    native=project/'.cache/tasks'/tid
    shutil.copytree(task/'tests/native-inputs',native,dirs_exist_ok=True)
    for file in (task/'tests').iterdir():
        if file.is_file():
            (native/'tests').mkdir(parents=True,exist_ok=True);shutil.copy2(file,native/'tests'/file.name)
    if profile['source'].get('lock_file'):
        shutil.copy2(native/'instruction.md',project/'data/instruction.md')
    opening=project/'frozen-opening';opening.mkdir()
    for name in ['task-blur.json','blur-receipt.json','opening-receipt.json']:shutil.copy2(frozen/name,opening/name)
    (opening/'instruction.md').write_text(row['initial_message'])
    # Bind calibration to the selected input row; source code is separately hashed.
    write(root/'release-lock.json',{'kind':'parquet_materialization','content_sha256':row['content_sha256']})
    write(root/'row.json',{k:v for k,v in row.items() if k!='assets'})
    return root

def configure_roles(config):
    # Avoid accidental fallback to credentials inherited from another benchmark.
    keys={name:os.environ.get(config[name]['api_key_env']) for name in ('agent','user_simulator','judge')}
    for key in list(os.environ):
        if key.startswith(('AGENT_','SIMULATOR_','JUDGE_','OPENAI_','AZURE_')) or key in {'DS_PERSONA_ENV_FILE','API_PROVIDER','API_BASE_URL','API_KEY','API_MODE'}:os.environ.pop(key,None)
    for name,prefix in [('agent','AGENT'),('user_simulator','SIMULATOR'),('judge','JUDGE')]:
        value=config[name];options=chat_token_options(value) if value['api']=='chat_completions' else value.get('request_options',{})
        allowed={'reasoning_effort','max_tokens_field','temperature','top_p','max_completion_tokens','max_output_tokens','max_tokens','seed','stop','extra_body'}
        if set(options)-allowed:raise ValueError('Unsupported DeepSWE request_options')
        key=keys[name]
        if not key:raise ValueError('Missing API key variable: '+value['api_key_env'])
        for field,item in {'HTTP_TIMEOUT_SECONDS':str(value.get('timeout_sec',300)),'MODEL':value['model'],'API_PROVIDER':'openai','API_BASE_URL':value['base_url'],'API_KEY':key,'API_MODE':value['api'],'REASONING_EFFORT':options.get('reasoning_effort','inherit'),'MAX_TOKENS_FIELD':value.get('max_tokens_field',value.get('request_options',{}).get('max_tokens_field','max_completion_tokens')),'REQUEST_OPTIONS_JSON':json.dumps({k:v for k,v in options.items() if k not in ('reasoning_effort','max_tokens_field')}),'STRUCTURED_OUTPUT_MODE':value.get('structured_output_mode','json_schema' if value.get('strict_json_schema',True) else 'json_object')}.items():os.environ[prefix+'_'+field]=item
        configured_mode(value)
        os.environ[prefix+'_STRUCTURED_OUTPUT_FALLBACK']=json.dumps(value.get('structured_output_fallback',True))

def prepare_image(row,root,out):
    image=row['environment']['agent']['image']
    with (out/'image.log').open('w') as log:
        if image:
            found=subprocess.run(['docker','image','inspect',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
            if not found:subprocess.run(['docker','pull',image],stdout=log,stderr=subprocess.STDOUT,check=True,timeout=1200)
        else:
            image='swe-persona-deepswe:'+row['content_sha256'][:24]
            subprocess.run(['docker','build','-t',image,str(root/'tasks'/row['source']['task_id']/'environment')],stdout=log,stderr=subprocess.STDOUT,check=True,timeout=1200)
    actual=subprocess.check_output(['docker','image','inspect',image,'--format','{{.Id}}'],text=True).strip()
    write(out/'image.json',{'requested':image,'image_id':actual,'cpu_only':True})
    return actual

def execute(root,row,config,out,mode,gate=None,*,calibration_enabled=True):
    project=root/'project';tid=row['source']['task_id'];pid=row['persona']['persona_id']
    sys.path.insert(0,str(project))
    os.environ.update(DS_TASK_ID=tid,DS_PERSONA_ID=pid,DS_PROTOCOL='staged',DS_RUNTIME='harbor',DS_CODING_BACKEND='json_act')
    from dspilot import specs
    from dspilot.prepare import verify_cache
    from dspilot.frozen_staged import basic_checks
    from dspilot.staged import adapt_episode
    from dspilot.delivery_capture import verify_opening
    ep=specs.compile_episode(tid,pid);plan=json.loads(row['interaction']['config_json'])['plan']
    basic_checks(plan,ep);verify_cache(tid)
    verify_opening(project/'frozen-opening',task_id=tid,persona_id=pid,arm='pivot',plan=plan)
    adapted=adapt_episode(ep,plan=plan)
    from dspilot.fingerprint import episode_manifest
    episode_manifest(adapted)
    actual={r['id']:r['statement'] for r in adapted.requirements}
    if actual!={r['requirement_id']:r['disclosure'] for r in row['requirements']}:raise ValueError('Typed disclosures differ from executable controller')
    if mode=='dry-run':
        from dspilot.harbor_runtime import metadata
        print(json.dumps({'status':'pass','task_id':row['task_id'],'runtime':metadata(),'requirements':len(actual),'gold_required':False}));return 0
    configure_roles(config)
    # Keep host-owned session metadata available to the outer worker after a
    # watchdog interruption. Never use agent artifacts to authorize cleanup.
    sessions=out/'environments';sessions.mkdir(parents=True,exist_ok=True)
    os.environ['DS_HARBOR_WORK_ROOT']=str(sessions.resolve())
    from dspilot import delivery_runtime as rt
    if mode=='calibrate':
        from dspilot.delivery_calibration import run
        from dspilot.api import Client
        import time
        value=run(root,out/'source-calibration',client=Client(out/'source-calibration/audit/api.jsonl',max_calls=32,deadline=time.monotonic()+900))
        write(out/'calibration.json',value)
        return 0 if value['passed'] else 2
    if calibration_enabled and (gate is None or not read(gate/'gate.json').get('passed')):
        raise ValueError('Passed runtime/API calibration required')
    image=prepare_image(row,root,out)
    work=out/'project';shutil.copytree(project,work)
    write(work/'environment-images.json',{tid:image})
    pair={'task_id':tid,'persona_id':pid,'delivery_id':tid+'--'+pid};pipeline='parquet-'+row['content_sha256'][:20]
    common=['--pipeline-id',pipeline,'--arm','pivot','--opening-directory',str(work/'frozen-opening')]
    preflight=rt.command(work,pair,'harbor','preflight',arguments=common);write(out/'preflight.json',preflight)
    rc=rt.command(work,pair,'harbor','run',arguments=common,log=out/'controller.log')
    result_path=work/'runs'/('pipeline-'+pipeline+'-pivot')/'result.json'
    if not result_path.exists():raise RuntimeError('Staged controller produced no result; inspect controller.log')
    result=read(result_path)
    from dspilot.export_tb3_results import benchmark_assessment
    official_path=result_path.parent/'official/result.json'
    assessment=benchmark_assessment(result,read(official_path) if official_path.exists() else None)
    valid=assessment['status'] in ('pass','fail')
    native=result.get('base_pass') if result.get('original_evaluation_valid') else None
    persona=result.get('persona_pass') if result.get('persona_evaluation_valid') else None
    report={'benchmark_outcome':assessment['status'],'benchmark_assessment':assessment,
        'api_recovery_assessment':result.get('api_recovery_assessment'),
        'original_reward':None if native is None else int(native),'persona_check':{'status':'pass' if persona is True else 'fail' if persona is False else 'invalid'},
        'evaluation_valid':valid,'end_reason':result.get('end_reason'),'stage':result.get('stage'),
        'error':result.get('error'),'final_error':result.get('final_error'),
        'error_category':'simulator_message_rejected' if result.get('end_reason')=='simulator_message_error' else None,
        'simulator_message_recoveries':result.get('simulator_message_recoveries',[]),
        'budget_exhausted':result.get('budget_exhausted'),'source_result':str(result_path.relative_to(out)),
        'historical_pier_equivalence':False,
        'calibration_report':str(gate/'calibration.json') if calibration_enabled else None}
    write(out/'persona-result.json',report)
    return 0 if valid else 2
