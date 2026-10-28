#!/usr/bin/env python3
"""Parallel evaluation with shared calibration and explicit per-task results."""
import argparse
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading

import pyarrow.parquet as pq


def run_command(command, log_path, interrupted):
    """Keep each CLI in its own group and allow its worker to clean up on stop."""
    with log_path.open('w') as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        while True:
            try:
                return process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                if not interrupted.is_set():
                    continue
                # The CLI's watchdog handles its separately grouped task worker.
                # Remember descendant groups in case cleanup itself hangs.
                parents = {}
                for path in Path('/proc').iterdir():
                    if not path.name.isdigit():
                        continue
                    try:
                        fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
                        parents[int(path.name)] = (int(fields[1]), int(fields[2]))
                    except (OSError, ValueError, IndexError):
                        continue
                descendants = {process.pid}
                while True:
                    expanded = descendants | {pid for pid, (ppid, _) in parents.items() if ppid in descendants}
                    if expanded == descendants:
                        break
                    descendants = expanded
                groups = {parents[pid][1] for pid in descendants if pid in parents}
                try:
                    os.killpg(process.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
                try:
                    return process.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    for group in groups:
                        try:
                            os.killpg(group, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    return process.wait(timeout=5)


def evaluate(args, selected):
    """Run at most workers tasks; calibrate each profile once before its tasks."""
    cache = (args.cache or Path.home() / '.cache/swe-persona').resolve()
    cache.mkdir(parents=True, exist_ok=True)
    prefix = [sys.executable, '-m', 'swe_persona.cli', '--dataset', str(args.dataset.resolve())]
    profiles = {row['interaction']['profile_id'] for row in selected}
    locks = {profile: threading.Lock() for profile in profiles}
    calibration = {}
    stop_launch = threading.Event()
    interrupted = threading.Event()
    interruption = []
    results = {}
    active = {}
    started = 0

    def stop(signum, _frame):
        interruption.append(signum)
        stop_launch.set()
        interrupted.set()

    def drain(signum, _frame):
        # Keep active task clocks and cleanup intact; transfer only the queue.
        stop_launch.set()

    def execute(index, row):
        out = args.output / f'{index:04d}'
        profile = row['interaction']['profile_id']
        result = None
        try:
            if stop_launch.is_set():
                return None
            if args.calibration and not args.dry_run:
                with locks[profile]:
                    if stop_launch.is_set():
                        return None
                    if profile not in calibration:
                        command = prefix + ['calibrate', '--profile', profile, '--config',
                                            str(args.config.resolve()), '--cache', str(cache)]
                        calibration[profile] = run_command(command, args.output / f'calibration-{profile}.log', interrupted)
                    if interrupted.is_set():
                        return None
                    if calibration[profile] != 0:
                        result = {'task_id': row['task_id'], 'status': 'calibration_error',
                                  'episode_started': False,
                                  'worker_exit_code': calibration[profile],
                                  'error': f'See calibration-{profile}.log'}
            if result is None:
                if stop_launch.is_set():
                    return None
                command = prefix + ['run', '--task', row['task_id'], '--config', str(args.config.resolve()),
                                    '--output', str(out.resolve()), '--cache', str(cache)]
                command.append('--calibration' if args.calibration else '--no-calibration')
                if args.dry_run:
                    command.append('--dry-run')
                if args.timeout_sec is not None:
                    command += ['--timeout-sec', str(args.timeout_sec)]
                rc = run_command(command, args.output / f'{index:04d}.driver.log', interrupted)
                result_path = out / 'result.json'
                result = json.loads(result_path.read_text()) if result_path.exists() else {
                    'task_id': row['task_id'],
                    'status': 'interrupted' if interrupted.is_set() else
                              'dry_run_pass' if args.dry_run and rc == 0 else 'infrastructure_error',
                    'worker_exit_code': rc}
        except Exception as exc:
            result = {'task_id': row['task_id'], 'status': 'infrastructure_error', 'error': str(exc)}
        result.update(source_benchmark=row['source_benchmark'], profile=profile, run_directory=out.name)
        # Calibrate failures and launch errors also have a reviewable task result.
        out.mkdir(parents=True, exist_ok=True)
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        return result

    def summary():
        ordered = [results[index] for index in sorted(results)]
        data = {'selected': len(selected), 'workers': args.workers, 'started': started,
                'calibration_enabled': args.calibration,
                'attempted': len(ordered), 'running': len(active),
                'active_tasks': [selected[index]['task_id'] for index in sorted(active.values())],
                'status_counts': dict(Counter(r['status'] for r in ordered)),
                'selection': [{'task_id': row['task_id'], 'source_benchmark': row['source_benchmark'],
                               'profile': row['interaction']['profile_id']} for row in selected],
                'results': ordered,
                'stopped': stop_launch.is_set(),
                'blocked_profiles': sorted(profile for profile, rc in list(calibration.items()) if rc != 0),
                'note': 'Errors and invalid episodes must be reported separately from pass/fail.'}
        path = args.output / 'summary.json'
        temporary = path.with_suffix('.json.tmp')
        temporary.write_text(json.dumps(data, indent=2) + '\n')
        temporary.replace(path)

    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
    if hasattr(signal,'SIGUSR1'):
        previous[signal.SIGUSR1] = signal.signal(signal.SIGUSR1,drain)
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            def fill():
                nonlocal started
                while len(active) < args.workers and started < len(selected) and not stop_launch.is_set():
                    index = started
                    active[pool.submit(execute, index, selected[index])] = index
                    started += 1
            fill()
            summary()
            while active:
                done, _ = wait(active, timeout=0.5, return_when=FIRST_COMPLETED)
                for future in done:
                    index = active.pop(future)
                    result = future.result()
                    if result is not None:
                        results[index] = result
                fill()
                if done or interrupted.is_set():
                    summary()
        summary()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    if interruption:
        return 128 + interruption[0]
    return 0 if len(results) == len(selected) and all(
        r['status'] in {'pass', 'fail', 'dry_run_pass'} for r in results.values()) else 2


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dataset', type=Path, default=Path('swe-persona-lite.parquet'))
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--workers', type=int, default=2, help='Concurrent task workers (default: 2; use 1 for sequential evaluation)')
    p.add_argument('--source-benchmark')
    p.add_argument('--profile')
    p.add_argument('--task',action='append',help='Evaluate only these task IDs; repeat for multiple tasks')
    p.add_argument('--limit', type=int)
    p.add_argument('--cpu-only', action='store_true', help='Select rows requiring no GPUs')
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--calibration', action=argparse.BooleanOptionalAction, default=True,
                   help='Run or reuse judge calibration before evaluation (default: enabled); use --no-calibration to skip startup controls')
    p.add_argument('--cache', type=Path, help='Directory for materialization and cached calibration')
    p.add_argument('--timeout-sec', '--total-timeout-sec', dest='timeout_sec', type=float,
                   help='Override agent/user interaction seconds; excludes preparation and final grading')
    args = p.parse_args()
    if args.workers < 1:
        p.error('--workers must be positive')
    if args.timeout_sec is not None and (not math.isfinite(args.timeout_sec) or args.timeout_sec <= 0):
        p.error('--timeout-sec must be finite and positive')
    if args.limit is not None and args.limit < 1:
        p.error('--limit must be positive')
    if args.output.exists() and any(args.output.iterdir()):
        p.error('--output must be new or empty')
    metadata = pq.read_table(args.dataset, columns=['task_id', 'source_benchmark', 'interaction', 'environment']).to_pylist()
    selected = [r for r in metadata if (not args.source_benchmark or r['source_benchmark'] == args.source_benchmark)
                and (not args.profile or r['interaction']['profile_id'] == args.profile)
                and (not args.task or r['task_id'] in args.task)
                and (not args.cpu_only or not r['environment']['agent']['resources']['gpus'])]
    if args.task and set(args.task)-{r['task_id'] for r in selected}:
        p.error('Some --task IDs are missing or excluded by the selection filters')
    if args.limit:
        selected = selected[:args.limit]
    if not selected:
        p.error('No matching tasks')
    args.output.mkdir(parents=True, exist_ok=True)
    return evaluate(args, selected)


if __name__ == '__main__':
    raise SystemExit(main())
