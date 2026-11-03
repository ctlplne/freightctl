"""Bounded receiver-owned kernel observations and private transfer-log custody."""
import hashlib
import os
from pathlib import Path
import stat


class FilterWitness:
    def __init__(self,proc=Path('/proc'),supervisor=None):
        self.proc=proc;self.supervisor=os.getpid() if supervisor is None else supervisor
        baseline=self.status(self.supervisor)
        self.baseline=None if baseline is None else baseline['filters']
        self.observations=0;self.maximum=0

    def status(self,pid):
        try:
            with (self.proc/str(pid)/'status').open('rb') as f:data=f.read(4097)
            if len(data)>4096:return None
            fields={line.split(b':',1)[0]:line.split(b':',1)[1].strip().split() for line in data.splitlines() if b':' in line}
            parent=int(fields[b'PPid'][0]);uid=int(fields[b'Uid'][1]);mode=int(fields[b'Seccomp'][0]);filters=int(fields[b'Seccomp_filters'][0])
            if not 0<=parent<1<<31 or not 0<=uid<1<<32 or mode not in (0,1,2) or not 0<=filters<=128:return None
            return {'parent':parent,'uid':uid,'mode':mode,'filters':filters}
        except (OSError,ValueError,KeyError,IndexError):return None

    def observe(self,receiver):
        if self.baseline is None or self.observations>=50000:return
        pending=[(self.supervisor,receiver)];visited=set();additional=0
        while pending and len(visited)<64:
            parent,pid=pending.pop()
            if pid in visited:continue
            visited.add(pid);value=self.status(pid)
            # Reused IDs or children that were reparented cannot select an
            # unrelated process for this task's observation.
            if value is None or value['parent']!=parent:continue
            if value['uid']!=0 and value['mode']==2:
                additional=max(additional,value['filters']-self.baseline)
            try:
                with (self.proc/str(pid)/'task'/str(pid)/'children').open('rb') as f:children=f.read(4097)
                if len(children)>4096:continue
                values=children.split()
                if len(values)>64:continue
                for child in values:
                    if child.isdigit() and len(child)<=10 and 0<int(child)<1<<31:pending.append((pid,int(child)))
            except OSError:continue
        if additional>0:self.observations+=1;self.maximum=max(self.maximum,additional)

    def result(self):
        return {'baseline_observed':self.baseline is not None,'native_filter_observations':self.observations,'maximum_added_filters':self.maximum}


def seal_transfer_logs(paths,uid,gid):
    """Stop receivers first; return hashes/counts and retain exact private bytes."""
    result={}
    for mode,path in paths.items():
        if mode not in ('explicit','implicit'):raise ValueError('unknown receiver log mode')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid not in (0,uid) or info.st_mode&0o077 or info.st_size>1<<20:raise ValueError('unsafe receiver transfer log')
            with os.fdopen(os.dup(fd),'rb') as source:data=source.read((1<<20)+1)
            if len(data)!=info.st_size or len(data)>1<<20:raise ValueError('receiver transfer log changed')
            os.fchown(fd,uid,gid);os.fchmod(fd,0o600)
            result[mode]={'size_bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'line_records':len(data.splitlines())}
        finally:os.close(fd)
    return result
