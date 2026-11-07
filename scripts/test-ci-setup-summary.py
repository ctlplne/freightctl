#!/usr/bin/env python3
"""First-run evidence refusal/privacy contracts; no services are started."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('setup_summary',Path(__file__).with_name('ci-setup-summary.py'))
summary=importlib.util.module_from_spec(spec);spec.loader.exec_module(summary)


class FirstRunEvidence(unittest.TestCase):
    def test_github_source_input_is_streamed_without_local_size_ceiling(self):
        path=self.root/'source.go'
        with path.open('r+b') as stream:stream.truncate((16<<20)+1)
        with path.open('rb') as stream:self.m['source_sha256']['source.go']=hashlib.file_digest(stream,'sha256').hexdigest()
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}):
            result=self.check()
        self.assertEqual(result['build_measurements']['source_bytes'],(16<<20)+1)
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}):
            with self.assertRaises(ValueError):self.check()

    def test_github_generated_binary_is_streamed_and_measured_without_local_size_ceiling(self):
        binary=self.fixture/'freightctl'
        with binary.open('r+b') as stream:stream.truncate((64<<20)+1)
        with binary.open('rb') as stream:self.m['binary_sha256']=hashlib.file_digest(stream,'sha256').hexdigest()
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}):
            result=self.check()
        self.assertEqual(result['build_measurements']['binary_bytes'],(64<<20)+1)
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}):
            with self.assertRaises(ValueError):self.check()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='freightctl-setup-summary-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.run='setup-'+'a'*32
        self.raw=self.root/'evidence/raw'/self.run;self.raw.mkdir(parents=True)
        self.fixture=self.root/'.private'/self.run;self.fixture.mkdir(parents=True,mode=0o700)
        self.path=self.raw/'manifest.json';self.commit='b'*40
        (self.root/'source.go').write_bytes(b'synthetic source');(self.fixture/'freightctl').write_bytes(b'synthetic binary')
        first={'replayed':False,'tenant_id':'a'*36,'partner_id':'b'*36,'actor_id':'c'*36,'storage_id':'d'*36,'event_id':'e'*36,'initialized_at':'2026-11-03T00:00:00Z','private_value':'SYNTHETIC_SECRET'}
        replay=dict(first,replayed=True);plan={'request':{'tenant_id':first['tenant_id'],'partner_id':first['partner_id'],'admin_id':first['actor_id'],'storage_id':first['storage_id'],'credential_sha256':summary.sha(b'synthetic token')}}
        (self.fixture/'admin.token').write_bytes(b'synthetic token');(self.fixture/'admin.token').chmod(0o600)
        for name in ('source.csv','browser-received.csv','stock-curl-first-exchange.csv','stock-curl-after-restart.csv'):(self.fixture/name).write_bytes(summary.PAYLOAD)
        (self.fixture/'setup.json').write_text(json.dumps(plan));(self.fixture/'workspace.json').write_text(json.dumps(replay))
        browser={'state':'passed','stage':'setup','browser_version':'142.0.7444.0','node':'v26.0.0','runtime_errors':[],'page_request_egress_origins':[],'inference_performed':False,'scanner_engine_started':False,'steps':[{'name':name,'passes':10} for name in summary.BROWSER]}
        (self.raw/'setup-result.json').write_text(json.dumps(browser))
        for name in ('setup-login','setup-published-files'):(self.raw/(name+'-axe.json')).write_text(json.dumps({'violations':[],'passes':10}))
        self.m={'schema_version':1,'kind':'native-first-run-browser','state':'passed','starting_commit':self.commit,'system':'Linux','architecture':'x86_64','sources_unchanged_during_run':True,'exact_fixture_database_removed':True,'inference_performed':False,'scanner_engine_started':False,'cleanup_failures':[],'failure':None,'fixture_reference':str(self.fixture.relative_to(self.root)),'database':'freightctl_'+self.run.replace('-','_'),'source_sha256':{'source.go':summary.sha(b'synthetic source')},'binary_sha256':summary.sha(b'synthetic binary'),'original_files_sha256':{},'steps':[]}
        for name in summary.COMMANDS:
            data=json.dumps(first if name=='commit-first-run' else replay).encode()
            path=self.raw/(name+'.log');path.write_bytes(data);code=1 if name in summary.REFUSALS else 0
            self.m['steps'].append({'name':name,'exit_code':code,'expected_exit_code':code,'native_output':str(path.relative_to(self.root)),'native_output_sha256':summary.sha(data)})
        self.rehash_files()

    def rehash_files(self):
        self.m['original_files_sha256']={name:summary.sha(((self.raw if name.startswith('raw/') else self.fixture)/name.split('/',1)[1]).read_bytes()) for name in summary.FILES}

    def check(self):
        self.path.write_text(json.dumps(self.m));return summary.summarize(self.root,self.path,self.commit,{'source.go'})

    def test_complete_bookkeeping_has_only_fixed_counts_and_hashes(self):
        result=self.check();self.assertEqual(result['original_commands'],13);self.assertEqual(result['browser_records'],6)
        self.assertFalse(result['whole_journey_qualified'])
        for private in ('SYNTHETIC_SECRET','synthetic token',str(self.root),self.run,'source.go'):self.assertNotIn(private,json.dumps(result))

    def test_missing_duplicate_reordered_or_failed_command_refused(self):
        original=self.m['steps'][:]
        for changed in (original[:-1],original+[original[0]],list(reversed(original)),[dict(s,exit_code=0) if s['name']=='refuse-runtime-bootstrap' else s for s in original],[dict(s,exit_code=False) if s['name']=='build' else s for s in original]):
            self.m['steps']=changed
            with self.assertRaises(ValueError):self.check()

    def test_original_output_hash_cannot_be_replaced_by_manifest_claim(self):
        (self.raw/'commit-first-run.log').write_text('{}')
        with self.assertRaises(ValueError):self.check()

    def test_missing_changed_or_truncated_source_inventory_refused(self):
        self.m['source_sha256']={}
        with self.assertRaises(ValueError):self.check()
        self.m['source_sha256']={'source.go':summary.sha(b'different')}
        with self.assertRaises(ValueError):self.check()
        self.m['source_sha256']={'source.go':summary.sha(b'synthetic source'),'invented.go':'f'*64}
        with self.assertRaises(ValueError):self.check()

    def test_changed_binary_or_symlinked_original_refused(self):
        binary=self.fixture/'freightctl';binary.write_bytes(b'changed')
        with self.assertRaises(ValueError):self.check()
        binary.unlink();other=self.root/'other';other.write_bytes(b'synthetic binary');binary.symlink_to(other)
        with self.assertRaises(ValueError):self.check()

    def test_rehashed_wrong_bytes_cannot_replace_exact_readback(self):
        (self.fixture/'stock-curl-after-restart.csv').write_bytes(b'substitute bytes');self.rehash_files()
        with self.assertRaises(ValueError):self.check()

    def test_receipt_identity_drift_cannot_be_hidden_by_new_output_hash(self):
        path=self.raw/'replay-after-ordinary-work.log';value=json.loads(path.read_bytes());value['event_id']='f'*36;data=json.dumps(value).encode();path.write_bytes(data)
        next(s for s in self.m['steps'] if s['name']=='replay-after-ordinary-work')['native_output_sha256']=summary.sha(data)
        with self.assertRaises(ValueError):self.check()

    def test_plan_credential_proof_and_file_closure_required(self):
        self.m['original_files_sha256'].pop('fixture/setup.json')
        with self.assertRaises(ValueError):self.check()
        self.rehash_files();(self.fixture/'admin.token').write_bytes(b'different token')
        with self.assertRaises(ValueError):self.check()

    def test_missing_browser_case_egress_or_runtime_error_refused(self):
        path=self.raw/'setup-result.json';original=json.loads(path.read_bytes())
        for change in ({'steps':original['steps'][:-1]},{'runtime_errors':['SYNTHETIC_SECRET']},{'page_request_egress_origins':['https://unapproved.invalid']},{'state':'failed'}):
            path.write_text(json.dumps(dict(original,**change)));self.rehash_files()
            with self.assertRaises(ValueError):self.check()

    def test_rehashed_failed_accessibility_audit_refused(self):
        (self.raw/'setup-login-axe.json').write_text(json.dumps({'violations':['SYNTHETIC_SECRET'],'passes':10}));self.rehash_files()
        with self.assertRaises(ValueError):self.check()

    def test_cleanup_scope_and_native_profile_cannot_be_omitted(self):
        original=dict(self.m)
        for name,value in (('exact_fixture_database_removed',False),('cleanup_failures',['SYNTHETIC_SECRET']),('inference_performed',True),('scanner_engine_started',True),('architecture','aarch64'),('starting_commit','c'*40),('fixture_reference','../outside')):
            self.m=dict(original,**{name:value})
            with self.assertRaises(ValueError):self.check()

    def test_python_optimization_refused_before_fixture_or_network_work(self):
        result=subprocess.run([sys.executable,'-O',str(Path(__file__).with_name('qualify-setup.py'))],cwd=self.root,capture_output=True,timeout=5)
        self.assertNotEqual(result.returncode,0);self.assertIn(b'requires assertions',result.stderr)

    def test_failed_browser_diagnostic_never_echoes_peer_or_manifest_text(self):
        data=b'SYNTHETIC_SECRET /scripts/browser-journey.mjs:1505:11\n'
        (self.raw/'native-first-run-exchange.log').write_bytes(data)
        step=next(s for s in self.m['steps'] if s['name']=='native-first-run-exchange');step['exit_code']=1;step['native_output_sha256']=summary.sha(data)
        self.path.write_text(json.dumps(self.m));result=summary.diagnostics(self.root,self.path,self.commit)
        self.assertEqual(result['browser_failure_locations'],['browser-journey.mjs:1505:11'])
        self.assertEqual(result['failed_commands'],[{'name':'native-first-run-exchange','exit_code':1}])
        self.assertNotIn('SYNTHETIC_SECRET',json.dumps(result));self.assertNotIn(str(self.root),json.dumps(result))

    def test_open_credential_permissions_cannot_qualify(self):
        (self.fixture/'admin.token').chmod(0o644)
        with self.assertRaises(ValueError):self.check()


if __name__=='__main__':unittest.main()
