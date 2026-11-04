"""Stock-peer metadata fixture and original-output checks; not collection work."""
import hashlib
import json

LIMIT = 32 << 10
PAYLOAD = b'account,amount,day\n'+b'0001,1.01,2026-10-28\n'*10000
BATCH = '11111111-2222-4333-8444-555555555555'


def files(mode):
    if mode not in ('explicit', 'implicit'):
        raise ValueError('stock metadata mode differs')
    ready = {'schema_version': 1, 'batch_id': BATCH, 'files': [
        {'name': mode+'-final.csv', 'size_bytes': len(PAYLOAD), 'sha256': hashlib.sha256(PAYLOAD).hexdigest()}]}
    return {mode+'-ready.json': json.dumps(ready, separators=(',', ':')).encode()+b'\n',
        mode+'-max.metadata': b'M'*LIMIT, mode+'-oversize.metadata': b'X'*(LIMIT+1)}


def inventory():
    return {name: {'size': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'mode': 0o400}
        for mode in ('explicit', 'implicit') for name, body in files(mode).items()}


# Only the exact disposable stock-peer fixture account owns these six names.
# Temporary names are exclusive, then each file and the parent are fsynced.
SEED = r'''
import json,os,pathlib,pwd,sys
from scripts.ftps_stock_metadata import files,inventory
directory=pathlib.Path(sys.argv[1]);account=pwd.getpwnam(sys.argv[2])
for mode in ('explicit','implicit'):
 for name,body in files(mode).items():
  target=directory/name;temporary=directory/(name+'.partial')
  if target.exists() or target.is_symlink():raise RuntimeError('source name already exists')
  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(body);stream.flush();os.fsync(fd)
   os.fchown(fd,account.pw_uid,account.pw_gid);os.fchmod(fd,0o400);os.fsync(fd)
  finally:os.close(fd)
  os.rename(temporary,target)
  parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(parent)
  finally:os.close(parent)
print(json.dumps(inventory()))
'''

OBSERVE = r'''
import hashlib,json,pathlib,stat,sys
from scripts.ftps_stock_metadata import files
directory=pathlib.Path(sys.argv[1]);result={}
for mode in ('explicit','implicit'):
 for name,expected in files(mode).items():
  path=directory/name;st=path.lstat()
  if not stat.S_ISREG(st.st_mode) or st.st_size!=len(expected) or path.read_bytes()!=expected:raise RuntimeError('original source changed')
  result[name]={'size':st.st_size,'sha256':hashlib.sha256(expected).hexdigest(),'mode':stat.S_IMODE(st.st_mode)}
print(json.dumps(result))
'''


def load(raw):
    if len(raw) > 1 << 20:
        raise ValueError('stock metadata output exceeds budget')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('stock metadata duplicate evidence key')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('stock metadata JSON number differs')
    return json.loads(raw, object_pairs_hook=unique, parse_float=invalid, parse_constant=invalid)


def same(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same(v, right[k]) for k, v in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    return left == right


def read_original(path, bound=4 << 20):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > bound:
        raise ValueError('unsafe stock metadata evidence')
    return path.read_bytes()


def validate(directory, read):
    expected = inventory()
    for command in ('seed-source-metadata', 'independent-source-metadata'):
        if not same(load(read(directory/(command+'.stdout'))), expected):
            raise ValueError('stock metadata original source inventory differs')
    native = read(directory/'native-stock-receiver.stdout', 64 << 20).decode()
    records = [load(line) for line in native.splitlines() if line.startswith('{') and 'freightctl-stock-ftps-metadata-v1' in line]
    wanted = []
    for mode in ('explicit', 'implicit'):
        ready = files(mode)[mode+'-ready.json']
        wanted.append({'kind': 'freightctl-stock-ftps-metadata-v1', 'mode': mode,
            'ready_size': len(ready), 'ready_sha256': hashlib.sha256(ready).hexdigest(),
            'maximum_size': LIMIT, 'maximum_sha256': hashlib.sha256(b'M'*LIMIT).hexdigest(),
            'empty_size': 0, 'empty_sha256': hashlib.sha256(b'').hexdigest(),
            'oversize_refused': True, 'session_usable_after_refusal': True})
    if not same(records, wanted):
        raise ValueError('stock metadata native cases missing or changed')
    return {'state': 'passed', 'modes': 2, 'cases_per_mode': 4, 'maximum_bytes': LIMIT,
        'source_files_unchanged': 6, 'full_collection_qualified': False}
