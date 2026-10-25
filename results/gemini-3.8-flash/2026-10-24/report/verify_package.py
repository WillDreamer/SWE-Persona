import hashlib,json,sys,tarfile
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
