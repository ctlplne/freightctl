#!/usr/bin/env python3
"""Create synthetic GnuPG interoperability artifacts in one bounded offline peer."""
from pathlib import Path
from datetime import datetime,timezone
import argparse,hashlib,json,os,platform,subprocess,sys,time,uuid
os.umask(0o077)
root=Path(__file__).resolve().parents[1];os.chdir(root)
parser=argparse.ArgumentParser();parser.add_argument('--rows',type=int,default=2);parser.add_argument('--native-config',default=os.environ.get('FREIGHTCTL_GNUPG_NATIVE_CONFIG'));args=parser.parse_args()
if not 1<=args.rows<=1000000:raise SystemExit('bounded synthetic row count required')
run='pgp-fixtures-'+uuid.uuid4().hex;private=root/'.private'/run;private.mkdir(mode=0o700)
raw=root/'evidence/raw'/run;raw.mkdir(parents=True,mode=0o700)
image='freightctl-pgp-peer:2.4.9-r1'
image_id=None
peer_platform=None
if not args.native_config:
 metadata=json.loads(subprocess.check_output(['docker','image','inspect',image]))[0]
 assert metadata['Config']['Labels']['freightctl.workspace']==str(root)
 assert metadata['Config']['Labels']['freightctl.purpose']=='pgp-interoperability'
 image_id=metadata['Id'];peer_platform=metadata['Os']+'/'+metadata['Architecture']
data=b'account,amount,day\n'+b'00000001,100.01,2026-10-28\n'*args.rows
(private/'source.csv').write_bytes(data)
(private/'source.json').write_bytes(b'[{"account":"0001","amount":1.01,"day":"2026-10-28"}]\n')
(private/'source.fixed').write_bytes(b'00000001      100.012026-10-28\r\n')
import xml.etree.ElementTree as task_xml
import platform as task_platform
task_xml_root = task_xml.Element('records')
task_xml_record = task_xml.SubElement(task_xml_root, 'record')
for task_xml_name, task_xml_value in [('account', '0001'), ('amount', '100.01'), ('day', '2026-10-28')]:
 task_xml.SubElement(task_xml_record, task_xml_name).text = task_xml_value
(private/'source.xml').write_bytes(task_xml.tostring(task_xml_root, encoding='utf-8', xml_declaration=True))
(private/'xml-producer.json').write_text(json.dumps({'producer': 'Python xml.etree.ElementTree', 'python': task_platform.python_version(), 'element_tree': task_xml.VERSION})+'\n')
if os.environ.get('FREIGHTCTL_TEST_XLSX_DIR'):
 (private/'source.xlsx').write_bytes((Path(os.environ['FREIGHTCTL_TEST_XLSX_DIR'])/'shared.xlsx').read_bytes())
program=r'''#!/bin/sh
set -eu
umask 077
task_pgp_past=$(( $(date +%s)-172800 ))
task_pgp_aged=$(( $(date +%s)-3600 ))
for task_pgp_label in good other rsa expired recipient recipient-rsa;do
 mkdir -m 700 /tmp/gnupg-$task_pgp_label
 : > /tmp/gnupg-$task_pgp_label/common.conf
done
gpg_good() { gpg --homedir /tmp/gnupg-good --batch --yes --pinentry-mode loopback --passphrase '' "$@"; }
gpg_other() { gpg --homedir /tmp/gnupg-other --batch --yes --pinentry-mode loopback --passphrase '' "$@"; }
gpg_rsa() { gpg --homedir /tmp/gnupg-rsa --batch --yes --pinentry-mode loopback --passphrase '' "$@"; }
gpg --version > /work/gpg-version.txt
apk info -v > /work/packages.txt
gpg_good --faked-system-time "$task_pgp_past" --quick-generate-key 'freightctl synthetic signer' ed25519 cert,sign 0
task_pgp_good=$(gpg_good --with-colons --list-keys | awk -F: '$1=="fpr"{print $10;exit}')
gpg_good --quick-add-key "$task_pgp_good" ed25519 sign 0
gpg_good --with-colons --list-keys > /work/good-key-info.txt
task_pgp_sub=$(awk -F: '$1=="fpr"{v=$10} END{print v}' /work/good-key-info.txt)
printf '%s\n' "$task_pgp_good" > /work/good-fingerprint.txt
printf '%s\n' "$task_pgp_sub" > /work/subkey-fingerprint.txt
gpg_good --output /work/good-public.gpg --export "$task_pgp_good"
gpg_good --armor --output /work/good-public.asc --export "$task_pgp_good"
gpg_good --local-user "$task_pgp_sub!" --digest-algo SHA256 --output /work/good.sig --detach-sign /work/source.csv
gpg_good --local-user "$task_pgp_sub!" --digest-algo SHA256 --output /work/good-json.sig --detach-sign /work/source.json
gpg_good --local-user "$task_pgp_sub!" --digest-algo SHA256 --output /work/good-fixed.sig --detach-sign /work/source.fixed
gpg_good --local-user "$task_pgp_sub!" --digest-algo SHA256 --output /work/good-xml.sig --detach-sign /work/source.xml
if [ -f /work/source.xlsx ]; then gpg_good --local-user "$task_pgp_sub!" --digest-algo SHA256 --output /work/good-xlsx.sig --detach-sign /work/source.xlsx; fi
gpg_good --local-user "$task_pgp_sub!" --digest-algo SHA256 --armor --output /work/good.sig.asc --detach-sign /work/source.csv
gpg_good --faked-system-time "$task_pgp_aged" --local-user "$task_pgp_good!" --digest-algo SHA256 --output /work/aged.sig --detach-sign /work/source.csv
gpg_good --output /work/private-rejection.gpg --export-secret-keys "$task_pgp_good"
gpg_good --status-fd 1 --verify /work/good.sig /work/source.csv > /work/good-verification.txt
gpg_other --faked-system-time "$task_pgp_past" --quick-generate-key 'freightctl synthetic signer' ed25519 sign 0
task_pgp_other=$(gpg_other --with-colons --list-keys | awk -F: '$1=="fpr"{print $10;exit}')
printf '%s\n' "$task_pgp_other" > /work/other-fingerprint.txt
gpg_other --output /work/other-public.gpg --export "$task_pgp_other"
gpg_other --local-user "$task_pgp_other!" --digest-algo SHA256 --output /work/other.sig --detach-sign /work/source.csv
gpg_rsa --quick-generate-key 'freightctl synthetic RSA signer' rsa3072 sign 0
task_pgp_rsa=$(gpg_rsa --with-colons --list-keys | awk -F: '$1=="fpr"{print $10;exit}')
printf '%s\n' "$task_pgp_rsa" > /work/rsa-fingerprint.txt
gpg_rsa --output /work/rsa-public.gpg --export "$task_pgp_rsa"
gpg_rsa --local-user "$task_pgp_rsa!" --digest-algo SHA256 --output /work/rsa.sig --detach-sign /work/source.csv
gpg_rsa --local-user "$task_pgp_rsa!" --allow-weak-digest-algos --digest-algo SHA1 --output /work/weak.sig --detach-sign /work/source.csv
gpg --homedir /tmp/gnupg-expired --batch --yes --pinentry-mode loopback --passphrase '' --faked-system-time "$task_pgp_past" --quick-generate-key 'freightctl synthetic expired signer' ed25519 sign 1d
task_pgp_expired=$(gpg --homedir /tmp/gnupg-expired --with-colons --list-keys | awk -F: '$1=="fpr"{print $10;exit}')
printf '%s\n' "$task_pgp_expired" > /work/expired-fingerprint.txt
gpg --homedir /tmp/gnupg-expired --batch --output /work/expired-public.gpg --export "$task_pgp_expired"
sed 's/^:-----BEGIN/-----BEGIN/' /tmp/gnupg-good/openpgp-revocs.d/$task_pgp_good.rev | awk '/^-----BEGIN/{p=1} p{print} /^-----END/{exit}' > /tmp/revocation.asc
gpg_good --import /tmp/revocation.asc
gpg_good --output /work/revoked-public.gpg --export "$task_pgp_good"
for task_pgp_label in recipient recipient-rsa;do
 if [ "$task_pgp_label" = recipient ];then task_pgp_primary=ed25519;task_pgp_encryption=cv25519;else task_pgp_primary=rsa3072;task_pgp_encryption=rsa3072;fi
 gpg --homedir /tmp/gnupg-$task_pgp_label --batch --yes --pinentry-mode loopback --passphrase '' --quick-generate-key "freightctl synthetic $task_pgp_label" "$task_pgp_primary" cert 1d
 task_pgp_fingerprint=$(gpg --homedir /tmp/gnupg-$task_pgp_label --with-colons --list-keys | awk -F: '$1=="fpr"{print $10;exit}')
 gpg --homedir /tmp/gnupg-$task_pgp_label --batch --yes --pinentry-mode loopback --passphrase '' --quick-add-key "$task_pgp_fingerprint" "$task_pgp_encryption" encr 1d
 printf '%s\n' "$task_pgp_fingerprint" > /work/$task_pgp_label-fingerprint.txt
 gpg --homedir /tmp/gnupg-$task_pgp_label --batch --output /work/$task_pgp_label-public.gpg --export "$task_pgp_fingerprint"
 gpg --homedir /tmp/gnupg-$task_pgp_label --batch --output /work/$task_pgp_label-private.gpg --export-secret-keys "$task_pgp_fingerprint"
done
for task_pgp_label in good other rsa expired recipient recipient-rsa;do gpgconf --homedir /tmp/gnupg-$task_pgp_label --kill all;done
'''
(private/'peer.sh').write_text(program)
command=['docker','run','--rm','--label','freightctl.workspace='+str(root),'--name','freightctl-'+run,'--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=128m','--cpus=1','--pids-limit=64','--tmpfs','/tmp:rw,noexec,nosuid,size=64m','--user',str(os.getuid())+':'+str(os.getgid()),'-v',str(private)+':/work',image_id,'/bin/sh','/work/peer.sh']
if args.native_config:
 command=[sys.executable,'scripts/pgp-native-peer.py','--config',str(Path(args.native_config).resolve()),'--metrics',str(raw/'native-peer-metrics.json'),'prepare','--work',str(private)]
start=time.monotonic()
with (raw/'peer.log').open('wb') as out:result=subprocess.run(command,stdout=out,stderr=subprocess.STDOUT,timeout=120)
if result.returncode:
 print((raw/'peer.log').read_text()[-2500:]);raise SystemExit(result.returncode)
files=['source.csv','source.json','source.fixed','source.xml','xml-producer.json','good-xml.sig','good-fixed.sig','good-json.sig','good-public.gpg','good-public.asc','good.sig','good.sig.asc','aged.sig','other-public.gpg','other.sig','rsa-public.gpg','rsa.sig','weak.sig','expired-public.gpg','revoked-public.gpg','recipient-public.gpg','recipient-rsa-public.gpg','gpg-version.txt','packages.txt','good-verification.txt']
if (private/'source.xlsx').exists():files+=['source.xlsx','good-xlsx.sig']
manifest={'schema_version':1,'state':'passed','observed_at':datetime.now(timezone.utc).isoformat(),'fixture_path':str(private.relative_to(root)),'peer_image':image_id,'peer_platform':peer_platform,'host_platform':platform.system().lower()+'/'+platform.machine(),'peer_base':'alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6','command':command,'duration_seconds':round(time.monotonic()-start,3),'gpg_version':(private/'gpg-version.txt').read_text().splitlines()[0],'fingerprints':{n:(private/(n+'-fingerprint.txt')).read_text().strip().lower() for n in ('good','subkey','other','rsa','expired','recipient','recipient-rsa')},'files':[{'path':str((private/n).relative_to(root)),'sha256':hashlib.sha256((private/n).read_bytes()).hexdigest()} for n in files],'private_rejection_fixture':'protected synthetic private packet in the fixture directory; never a production key or Git artifact','inference_performed':False,'resource_limits':{'memory_bytes':128<<20,'cpus':1,'pids':64,'network':'none'},'limits':['Independent GnuPG 2.4.9 '+str(peer_platform)+' container peer on '+platform.system().lower()+'/'+platform.machine()+' host; this does not by itself qualify native application runtime.','Synthetic keys and data only. GnuPG time overrides apply to its process; the host clock is unchanged.','V4 Ed25519 primary/signing subkey and RSA3072/SHA256 peer profiles; full algorithm/peer/platform coverage remains open.']}
manifest['peer_backend']='native-macos' if args.native_config else 'docker'
if args.native_config:
 metrics=json.loads((raw/'native-peer-metrics.json').read_text());assert metrics['state']=='passed'
 manifest['peer_base']=None
 manifest['native_peer_metrics']={'reference':str((raw/'native-peer-metrics.json').relative_to(root)),'sha256':hashlib.sha256((raw/'native-peer-metrics.json').read_bytes()).hexdigest()}
 manifest['native_acquisition_manifest']={'reference':str(Path(args.native_config).resolve().relative_to(root)),'sha256':hashlib.sha256(Path(args.native_config).read_bytes()).hexdigest()}
 manifest['resource_limits']={'sampled_child_rss_budget_bytes':metrics['rss_budget_bytes'],'sampled_process_family_peak_rss_bytes':metrics['sampled_process_family_peak_rss_bytes'],'rss_sampling_seconds':metrics['rss_sampling_seconds'],'wall_seconds':120,'network':'Only task scratch Unix sockets; IP networking denied by native sandbox','cpu':'Serial peer operations; no kernel CPU quota claimed','memory':'Sampled process-group watchdog, not a kernel RSS cap; observer memory is separate.'}
 manifest['limits'][0]='Independent '+manifest['gpg_version']+' native macOS arm64 peer with protected task-owned runtime and scratch. No global installation, user keyring or Docker startup. This does not qualify a native Linux server.'
(raw/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(private/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
(root/'.private/pgp-fixture-current').write_text(str(private)+'\n')
print(str(private),flush=True)
