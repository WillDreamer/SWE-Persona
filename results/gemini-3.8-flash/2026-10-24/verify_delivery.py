"""Verify the public summary delivery; no model calls or containers."""
import csv
import hashlib
import json
from pathlib import Path
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def rows(name):
    with (HERE / name).open(newline='') as stream:
        return list(csv.DictReader(stream))


def main():
    manifest = json.loads((HERE / 'bundle_manifest.json').read_text())
    names = set()
    for entry in manifest['files']:
        relative = Path(entry['path'])
        assert not relative.is_absolute() and '..' not in relative.parts
        assert entry['path'] not in names
        names.add(entry['path'])
        path = ROOT / relative
        assert path.stat().st_size == entry['bytes'], relative
        assert digest(path) == entry['sha256'], relative
    expected = {str(path.relative_to(HERE)) for path in HERE.rglob('*')
                if path.is_file() and '__pycache__' not in path.parts
                and path.name not in {'public-summary.zip', 'bundle_manifest.json'}}
    with zipfile.ZipFile(HERE / 'public-summary.zip') as archive:
        assert set(archive.namelist()) == expected
        assert len(archive.namelist()) == len(expected)
        for name in expected:
            assert archive.read(name) == (HERE / name).read_bytes(), name
    cumulative = [r for r in rows('results-by-campaign.csv')
                  if r['campaign'] == 'cumulative-diagnostic']
    assert len(cumulative) == 297
    assert len({(r['effort'], r['task_id']) for r in cumulative}) == 297
    assert len(rows('attempt-ledger.csv')) == 600
    assert len(rows('unresolved-evaluations.csv')) == 24
    for level in ('low', 'medium', 'high'):
        path = HERE / 'campaigns/cumulative-diagnostic' / level / 'scores.json'
        metrics = json.loads(path.read_text())['overall']
        assert metrics['selected'] == 99
        assert metrics['joint_success_rate'] is None
    print(f'PASS: {len(names)} manifest files, LFS ZIP, 297 cumulative records, '
          '600 campaign outcomes, 24 unresolved evaluations')


if __name__ == '__main__':
    main()
