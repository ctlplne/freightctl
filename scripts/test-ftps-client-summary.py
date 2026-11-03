#!/usr/bin/env python3
"""Synthetic evidence tampering contracts; these do not qualify a transport."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location("summary",Path(__file__).with_name("ci-ftps-client-summary.py"))
summary=importlib.util.module_from_spec(spec);spec.loader.exec_module(summary)


class ReceiverEvidence(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="freightctl-client-summary-")
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.directory=self.root/".private"/("ftps-client-"+"a"*32);self.directory.mkdir(parents=True)
        self.result=self.root/"result.json";self.manifest=self.directory/"manifest.json"
        (self.root/"source.go").write_bytes(b"synthetic source")
        self.m={"kind":"native-ftps-client-stock-receiver","state":"passed","starting_commit":"b"*40,"architecture":"aarch64","sources_unchanged":True,"task_user_removed":True,"task_pam_removed":True,"cleanup_failures":[],"native_pass_records":3,"source_sha256":{"source.go":self.sha(b"synthetic source")},"steps":[]}
        for name in ("inference_performed","scanner_started","postgres_started","domain_delivery_qualified","full_journeys_qualified"):self.m[name]=False
        self.files={mode+"-"+suffix:{"size":len(b),"sha256":self.sha(b)} for mode in ("explicit","implicit") for suffix,b in (("final.csv",summary.PAYLOAD),("resume.csv",summary.PAYLOAD),("empty",b""))}
        self.m["receiver_files"]=self.files
        for name in sorted(summary.REQUIRED):
            stdout=b""
            if name=="native-stock-receiver":stdout=b"--- PASS: TestNativeStockReceiver (1s)\n    --- PASS: TestNativeStockReceiver/explicit (1s)\n    --- PASS: TestNativeStockReceiver/implicit (1s)\n"
            if name=="receiver-version":stdout=b"vsftpd: version 3.0.5\n"
            if name=="independent-receiver-files":stdout=json.dumps(self.files).encode()
            self.output(name,stdout)
            if name in {"explicit-refuse-tls12","implicit-refuse-tls12"}:
                self.output(name,b"",b"tlsv1 alert protocol version: SSL alert number 70\n")
                next(s for s in self.m["steps"] if s["name"]==name)["exit_code"]=1
        (self.directory/"openssl.conf").write_bytes(summary.OPENSSL_PROFILE)
        for mode in ("explicit","implicit"):
            config={"listen_address":"127.0.0.1","ssl_enable":"YES","force_local_logins_ssl":"YES","force_local_data_ssl":"YES","require_ssl_reuse":"YES","strict_ssl_read_eof":"YES","strict_ssl_write_shutdown":"YES","ssl_tlsv1_2":"NO","ssl_tlsv1_3":"YES","seccomp_sandbox":"YES","chroot_local_user":"YES","anonymous_enable":"NO","implicit_ssl":"YES" if mode=="implicit" else "NO"}
            (self.directory/(mode+".conf")).write_text("".join(k+"="+v+"\n" for k,v in config.items()))

    @staticmethod
    def sha(b):return hashlib.sha256(b).hexdigest()

    def output(self,name,data,err=b""):
        (self.directory/(name+".stdout")).write_bytes(data);(self.directory/(name+".stderr")).write_bytes(err)
        self.m["steps"]=[s for s in self.m["steps"] if s["name"]!=name]+[{"name":name,"exit_code":0,"stdout_sha256":self.sha(data),"stderr_sha256":self.sha(err)}]

    def write(self):
        data=json.dumps(self.m).encode();self.manifest.write_bytes(data)
        self.result.write_text(json.dumps({"state":"passed","manifest_reference":str(self.manifest.relative_to(self.root)),"manifest_sha256":self.sha(data)}))

    def check(self):
        self.write();return summary.summarize(self.root,self.result,"b"*40)

    def test_complete_bookkeeping_has_bounded_public_scope(self):
        result=self.check();self.assertEqual(result["original_commands"],20)
        self.assertFalse(result["domain_delivery_qualified"])
        for private in (str(self.root),"password","source.go"):self.assertNotIn(private,json.dumps(result))
        self.assertNotIn("receiver_files",result)

    def test_missing_duplicate_or_nonzero_command_refused(self):
        original=self.m["steps"][:]
        for changed in (original[:-1],original+[original[0]], [dict(s,exit_code=1) if i==0 else s for i,s in enumerate(original)],[dict(s,exit_code=False) if i==0 else s for i,s in enumerate(original)]):
            self.m["steps"]=changed
            with self.assertRaises(ValueError):self.check()

    def test_unrecorded_output_or_source_change_refused(self):
        self.write();(self.directory/"native-stock-receiver.stdout").write_bytes(b"substitute pass")
        with self.assertRaises(ValueError):summary.summarize(self.root,self.result,"b"*40)
        self.output("native-stock-receiver",b"--- PASS: TestNativeStockReceiver (1s)\n    --- PASS: TestNativeStockReceiver/explicit (1s)\n    --- PASS: TestNativeStockReceiver/implicit (1s)\n")
        (self.root/"source.go").write_bytes(b"different source")
        with self.assertRaises(ValueError):self.check()

    def test_skipped_missing_or_duplicate_original_case_refused(self):
        good=(self.directory/"native-stock-receiver.stdout").read_bytes()
        for bad in (good.replace(b"PASS: TestNativeStockReceiver/implicit",b"SKIP: TestNativeStockReceiver/implicit"),good.splitlines()[0]+b"\n",good+good):
            self.output("native-stock-receiver",bad)
            with self.assertRaises(ValueError):self.check()

    def test_manifest_claim_cannot_replace_actual_receiver_bytes(self):
        wrong=json.loads(json.dumps(self.files));wrong["implicit-final.csv"]["sha256"]="0"*64
        self.m["receiver_files"]=wrong;self.output("independent-receiver-files",json.dumps(wrong).encode())
        with self.assertRaises(ValueError):self.check()

    def test_weaker_receiver_tls_or_cleanup_refused(self):
        path=self.directory/"explicit.conf";good=path.read_text()
        for option in ("require_ssl_reuse","strict_ssl_read_eof","strict_ssl_write_shutdown","seccomp_sandbox"):
            path.write_text(good.replace(option+"=YES",option+"=NO"))
            with self.assertRaises(ValueError):self.check()
        path.write_text(good);self.m["task_user_removed"]=False
        with self.assertRaises(ValueError):self.check()

    def test_cross_candidate_and_excess_scope_refused(self):
        self.write()
        with self.assertRaises(ValueError):summary.summarize(self.root,self.result,"c"*40)
        for name in ("inference_performed","scanner_started","postgres_started","domain_delivery_qualified","full_journeys_qualified"):
            self.m[name]=True
            with self.assertRaises(ValueError):self.check()
            self.m[name]=False

    def test_source_escape_and_manifest_digest_refused(self):
        self.m["source_sha256"]={"../outside":self.sha(b"synthetic source")}
        with self.assertRaises(ValueError):self.check()
        self.m["source_sha256"]={"source.go":self.sha(b"synthetic source")};self.write();self.manifest.write_text("{}")
        with self.assertRaises(ValueError):summary.summarize(self.root,self.result,"b"*40)

    def test_unrelated_tls_error_cannot_replace_protocol_version_refusal(self):
        self.output("explicit-refuse-tls12",b"",b"certificate validation failed\n")
        next(s for s in self.m["steps"] if s["name"]=="explicit-refuse-tls12")["exit_code"]=1
        with self.assertRaises(ValueError):self.check()

    def test_weaker_openssl_floor_cannot_be_claimed_as_tls13(self):
        (self.directory/"openssl.conf").write_bytes(summary.OPENSSL_PROFILE.replace(b"MinProtocol=TLSv1.3",b"MinProtocol=TLSv1.2"))
        with self.assertRaises(ValueError):self.check()

    def test_failed_diagnostic_never_copies_peer_or_password_text(self):
        self.output("native-stock-receiver",b"client_stock_test.go:73: stock store secret-password FTPS receiver status 522\nprivate peer prose\n")
        for s in self.m["steps"]:
            if s["name"]=="native-stock-receiver":s["exit_code"]=1
        self.write();result=summary.failure_diagnostics(self.root,self.result,"b"*40)
        result.pop("manifest_sha256")
        self.assertEqual(result,{"failed_commands":["native-stock-receiver"],"native_stages":["store"],"reply_codes":[522]})
        self.assertNotIn("private",json.dumps(result));self.assertNotIn("password",json.dumps(result))

    def test_receiver_startup_diagnostic_reveals_only_known_categories(self):
        (self.directory/"explicit-receiver.stderr").write_bytes(b"500 OOPS: unrecognised variable in config file: ssl_tlsv1_3\nsecret-password\nTraceback: receiver exited before cleanup\n")
        self.write();result=summary.failure_diagnostics(self.root,self.result,"b"*40)
        self.assertEqual(result["receiver_categories"],["explicit:supervisor-child-exit","explicit:unsupported-option:ssl_tlsv1_3"])
        self.assertNotIn("secret",json.dumps(result))
        (self.directory/"explicit-receiver.stderr").write_bytes(b"unrecognised variable in config file: private_password_name\n")
        result=summary.failure_diagnostics(self.root,self.result,"b"*40)
        self.assertEqual(result["receiver_categories"],["explicit:unsupported-option:other"])


if __name__=="__main__":unittest.main()
