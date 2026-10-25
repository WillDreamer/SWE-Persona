#!/usr/bin/env python3
"""Summarize recorded grading; never run models or treat missing grades as passes."""
import argparse
from collections import Counter
import json
from pathlib import Path


def metrics(results, selected):
    valid = [r for r in results if r.get('status') in {'pass', 'fail'}]
    complete = [r for r in valid if isinstance(r.get('native_pass'), bool)
                and isinstance(r.get('persona_pass'), bool)
                and r.get('verification_complete') is not False]
    passes = sum(r['status'] == 'pass' for r in valid)
    provisional = [r for r in results if r.get('score_provisional') is True
                   or (r.get('calibration') or {}).get('score_provisional') is True]
    native = [r['native_pass'] for r in valid if isinstance(r.get('native_pass'), bool)]
    persona = [r['persona_pass'] for r in valid if isinstance(r.get('persona_pass'), bool)]
    return {
        'selected': selected,
        'attempted': len(results),
        'not_attempted': None if selected is None else selected - len(results),
        'status_counts': dict(Counter(r.get('status', 'unknown') for r in results)),
        'valid_evaluations': len(valid),
        'complete_native_and_persona_grading': len(complete),
        'total_timeouts': sum(r.get('outcome_reason') == 'total_timeout' for r in results),
        'joint_passes': passes,
        'joint_success_rate': passes / selected if selected and len(valid) == selected and not provisional else None,
        'joint_success_rate_valid_only': passes / len(valid) if valid and not provisional else None,
        'provisional_evaluations': len(provisional),
        'score_status': 'provisional' if provisional else 'standard',
        'provisional_joint_success_rate': passes / selected if provisional and selected and len(valid) == selected else None,
        'provisional_joint_success_rate_valid_only': passes / len(valid) if provisional and valid else None,
        'native_grades_observed': len(native),
        'native_pass_rate_observed': sum(native) / len(native) if native else None,
        'persona_grades_observed': len(persona),
        'persona_pass_rate_observed': sum(persona) / len(persona) if persona else None,
    }


def summarize(data):
    if 'results' not in data:
        data = {'selected': 1, 'selection': [data], 'results': [data]}
    results = data['results']
    selected = data['selected']
    if not isinstance(selected, int) or selected < 1 or len(results) > selected:
        raise ValueError('Invalid selection size')
    ids = [r['task_id'] for r in results]
    if len(set(ids)) != len(ids):
        raise ValueError('Duplicate task results; score one attempt per task')
    selection = data.get('selection')
    if selection is not None:
        chosen = {r['task_id'] for r in selection}
        if len(selection) != selected or len(chosen) != selected or not set(ids) <= chosen:
            raise ValueError('Results do not match the declared selection')
    report = {'overall': metrics(results, selected)}
    for field in ['source_benchmark', 'profile']:
        groups = sorted({r.get(field, 'unknown') for r in (selection or results)})
        report['by_' + field] = {
            group: metrics([r for r in results if r.get(field, 'unknown') == group],
                           sum(r.get(field, 'unknown') == group for r in selection)
                           if selection is not None else None)
            for group in groups
        }
    report['notes'] = [
        'Rates are fractions in [0, 1].',
        'joint_success_rate is null until every selected task has a valid pass/fail outcome.',
        'An enforced total timeout is a valid failure with zero joint credit; unexecuted component grades remain unknown.',
        'Errors, cancelled/skipped tasks, calibration failures and dry runs are excluded from valid-only rates and remain in status counts.',
        'Valid-only and observed-grade rates use the displayed denominators; they are not full-selection scores.',
        'Compare models only with matched selection, runtime, simulator/judge, API settings, budgets and hardware.',
        'Degraded SWE-Together calibration permits diagnostic execution only: formal joint rates remain null; provisional rates and observed component grades are retained.',
    ]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='Batch summary.json or a single result.json')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = summarize(json.loads(args.input.read_text()))
    text = json.dumps(report, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
