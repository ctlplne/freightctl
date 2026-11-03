#!/usr/bin/env python3
"""Synthetic evidence tampering contracts; these do not qualify a transport."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import os
import shutil

spec=importlib.util.spec_from_file_location("summary",Path(__file__).with_name("ci-ftps-client-summary.py"))
summary=importlib.util.module_from_spec(spec);spec.loader.exec_module(summary)
spec=importlib.util.spec_from_file_location("qualifier",Path(__file__).with_name("qualify-ftps-client.py"))
qualifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(qualifier)
spec=importlib.util.spec_from_file_location("library_builder",Path(__file__).with_name("install-ftps-tls.py"))
library_builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(library_builder)


class ReceiverEvidence(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="freightctl-client-summary-")
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.directory=self.root/".private"/("ftps-client-"+"a"*32);self.directory.mkdir(parents=True)
        self.result=self.root/"result.json";self.manifest=self.directory/"manifest.json"
        (self.root/"source.go").write_bytes(b"synthetic source")
        self.m={"kind":"native-ftps-client-stock-receiver","state":"passed","starting_commit":"b"*40,"architecture":"aarch64","receiver_library_profile":"system","sources_unchanged":True,"task_user_removed":True,"task_pam_removed":True,"cleanup_failures":[],"probe_failures":[],"native_pass_records":3,"receiver_traced":False,"source_sha256":{"source.go":self.sha(b"synthetic source")},"steps":[]}
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
            config={"listen_address":"127.0.0.1","ssl_enable":"YES","force_local_logins_ssl":"YES","force_local_data_ssl":"YES","require_ssl_reuse":"YES","strict_ssl_read_eof":"YES","strict_ssl_write_shutdown":"YES","ssl_tlsv11":"NO","ssl_tlsv12":"NO","ssl_tlsv13":"YES","seccomp_sandbox":"YES","chroot_local_user":"YES","anonymous_enable":"NO","implicit_ssl":"YES" if mode=="implicit" else "NO"}
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

    def test_receiver_profile_cannot_silently_reenable_kernel_offload(self):
        (self.directory/"openssl.conf").write_bytes(summary.OPENSSL_PROFILE.replace(b"Options=-KTLS",b"Options=KTLS"))
        with self.assertRaises(ValueError):self.check()

    def test_failed_diagnostic_never_copies_peer_or_password_text(self):
        self.output("native-stock-receiver",b"client_stock_test.go:73: stock store secret-password FTPS receiver status 522\nprivate peer prose\n")
        for s in self.m["steps"]:
            if s["name"]=="native-stock-receiver":s["exit_code"]=1
        self.write();result=summary.failure_diagnostics(self.root,self.result,"b"*40)
        result.pop("manifest_sha256")
        self.assertEqual(result.pop("tls_probe_categories"),["explicit:version-alert","implicit:version-alert"])
        self.assertEqual(result,{"failed_commands":["native-stock-receiver"],"native_stages":["store"],"reply_codes":[522],"observed_native_pass_records":0,"receiver_library_profile":"system"})
        self.assertNotIn("private",json.dumps(result));self.assertNotIn("password",json.dumps(result))

    def test_receiver_startup_diagnostic_reveals_only_known_categories(self):
        self.output("explicit-receiver",b"",b"500 OOPS: unrecognised variable in config file: ssl_tlsv1_3\nsecret-password\nTraceback: receiver exited before cleanup\n")
        self.write();result=summary.failure_diagnostics(self.root,self.result,"b"*40)
        self.assertEqual(result["receiver_categories"],["explicit:supervisor-child-exit","explicit:unsupported-option:ssl_tlsv1_3"])
        self.assertNotIn("secret",json.dumps(result))
        self.output("explicit-receiver",b"",b"unrecognised variable in config file: private_password_name\n");self.write()
        result=summary.failure_diagnostics(self.root,self.result,"b"*40)
        self.assertEqual(result["receiver_categories"],["explicit:unsupported-option:other"])

    def test_connection_diagnostic_omits_untrusted_details_and_unknown_phases(self):
        self.output("native-stock-receiver",b"client_stock_test.go:52: stock receiver connection FTPS connection phase greeting: invalid or oversized FTPS receiver reply\nFTPS connection phase private-password: secret\n")
        self.write();result=summary.failure_diagnostics(self.root,self.result,"b"*40)
        self.assertEqual(result["connection_phases"],["greeting"])
        self.assertEqual(result["native_stages"],["receiver connection"])
        self.assertEqual(result["native_categories"],["reply"])
        for private in ("password","secret","invalid or oversized"):self.assertNotIn(private,json.dumps(result))

    def test_traced_run_cannot_qualify_untraced_stock_receiver(self):
        self.m["receiver_traced"]=True
        with self.assertRaises(ValueError):self.check()

    def test_trace_diagnostic_exposes_only_fixed_signals_and_syscalls(self):
        (self.directory/"explicit-receiver.trace").write_text('123 --- SIGSYS {si_syscall=__NR_getrandom} ---\nread(5, "private-password", 16) = 16\n123 --- SIGSYS {si_syscall=__NR_private_password} ---\nchroot("/private-path") = -1 EACCES\n')
        self.m["trace_sha256"]={"explicit":self.sha((self.directory/"explicit-receiver.trace").read_bytes())}
        self.write();result=summary.failure_diagnostics(self.root,self.result,"b"*40)
        self.assertEqual(result["trace_categories"],["explicit:SIGSYS","explicit:chroot:EACCES","explicit:syscall:getrandom","explicit:syscall:other"])
        for private in ("password","private-path"):self.assertNotIn(private,json.dumps(result))
        (self.directory/"explicit-receiver.trace").write_text('--- SIGSEGV ---\n')
        self.assertNotIn("trace_categories",summary.failure_diagnostics(self.root,self.result,"b"*40))

    def test_raw_trace_binds_numeric_signal_and_last_syscall_to_same_process(self):
        data=b'123 [ 278] getrandom(0x1234, 0x10, 0) = ?\n124 [ 56] openat(0,0,0) = 3\n123 [ 278] +++ killed by SIGSYS +++\n--- SIGSYS {si_syscall=0x116} ---\n--- SIGSYS {si_syscall=99999999} ---\n'
        (self.directory/"explicit-receiver.trace").write_bytes(data);self.m["trace_sha256"]={"explicit":self.sha(data)};self.write()
        result=summary.failure_diagnostics(self.root,self.result,"b"*40)
        self.assertEqual(result["trace_categories"],["explicit:SIGSYS","explicit:last-syscall-before-SIGSYS:278","explicit:syscall-number:278"])

    def test_socket_option_diagnostic_omits_descriptor_pointer_and_buffer(self):
        data=b'123 [54] setsockopt(0x99,0x6,0x1f,0xdeadbeef,0x4) = ?\n123 [54] +++ killed by SIGSYS +++\n124 [231] exit_group(0x2) = ?\n'
        (self.directory/"explicit-receiver.trace").write_bytes(data);self.m["trace_sha256"]={"explicit":self.sha(data)};self.write()
        result=summary.failure_diagnostics(self.root,self.result,"b"*40)
        self.assertEqual(result["trace_categories"],["explicit:SIGSYS","explicit:last-setsockopt-before-SIGSYS:level=6,option=31,size=4","explicit:last-syscall-before-SIGSYS:54","explicit:process-exit:2"])
        self.assertNotIn("deadbeef",json.dumps(result));self.assertNotIn("0x99",json.dumps(result))

    def test_passing_transfers_cannot_overrule_failed_security_probe(self):
        self.m["probe_failures"]=["explicit-refuse-tls12"]
        with self.assertRaises(ValueError):self.check()

    def test_private_umask_keeps_payload_private_and_receiver_home_traversable(self):
        previous=os.umask(0o077)
        try:estate,home,inbox,empty=qualifier.receiver_directories()
        finally:os.umask(previous)
        self.addCleanup(shutil.rmtree,estate)
        for path in (estate,home,empty):
            mode=path.stat().st_mode&0o777
            self.assertEqual(mode&0o003,0o001,"nonowner needs traversal without write")
            self.assertEqual(mode&0o022,0,"group and other identities cannot change receiver directories")
        self.assertEqual(inbox.stat().st_mode&0o077,0,"payload must stay private")

    def library_fixture(self):
        base=self.root/summary.LIBRARY_BASE;base.mkdir(parents=True)
        for name in summary.LIBRARY_FILES:
            path=base/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(b'#define OPENSSL_NO_KTLS\n' if name.endswith("configuration.h") else b'synthetic artifact;not a real library')
        directory=self.root/".private"/("ftps-library-"+"c"*32);directory.mkdir()
        lib={"kind":"native-receiver-openssl-no-ktls","state":"passed","version":"3.5.9","source_url":"https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz","source_sha256":summary.LIBRARY_SOURCE_SHA,"architecture":"aarch64","configuration":["shared","no-ktls"],"inference_performed":False,"scanner_started":False,"postgres_started":False,"upstream_skip_lines":1,"files_sha256":{n:self.sha((base/n).read_bytes()) for n in summary.LIBRARY_FILES},"original_output_reference":str(directory.relative_to(self.root)),"steps":[]}
        for name in sorted(summary.LIBRARY_STEPS):
            value=b""
            if name=="native-compiler":value=b"aarch64-linux-gnu\n"
            if name=="installed-version":value=b"OpenSSL 3.5.9\n"
            if name=="selected-upstream-tests":value=b"25-test_verify.t ok\n80-test_ssl_new.t ok\n90-test_sslapi.t ok\n# SKIP FIPS fixture\nResult: PASS\n"
            (directory/(name+".stdout")).write_bytes(value);(directory/(name+".stderr")).write_bytes(b"")
            lib["steps"].append({"name":name,"exit_code":0,"stdout_sha256":self.sha(value),"stderr_sha256":self.sha(b"")})
        self.m["receiver_library_profile"]="no-ktls";self.lib=lib;self.lib_directory=directory;self.lib_base=base
        self.library_write()
        self.output("selected-library-version",b"OpenSSL 3.5.9\n")
        self.output("selected-library-linkage","".join(n+" => "+str(base/"prefix/lib"/n)+"\n" for n in ("libssl.so.3","libcrypto.so.3")).encode())

    def library_write(self):
        raw=json.dumps(self.lib).encode();(self.lib_base/"manifest.json").write_bytes(raw);self.m["receiver_library_manifest_sha256"]=self.sha(raw)

    def library_check(self):
        self.library_write();self.write();return summary.summarize(self.root,self.result,"b"*40,"no-ktls")

    def test_complete_library_bookkeeping_retains_visible_skips_and_variant(self):
        self.library_fixture();result=self.library_check()
        self.assertEqual(result["receiver_library_profile"],"no-ktls");self.assertEqual(result["original_commands"],22)
        self.assertEqual(result["receiver_library"]["upstream_skip_lines"],1)
        self.assertNotIn(str(self.root),json.dumps(result))

    def test_library_profile_cannot_substitute_for_system_profile(self):
        self.library_fixture();self.write()
        with self.assertRaises(ValueError):summary.summarize(self.root,self.result,"b"*40)

    def test_library_source_and_compiled_feature_must_match_pinned_variant(self):
        self.library_fixture();self.lib["source_sha256"]="0"*64
        with self.assertRaises(ValueError):self.library_check()
        self.lib["source_sha256"]=summary.LIBRARY_SOURCE_SHA;self.lib["configuration"]=["shared"]
        with self.assertRaises(ValueError):self.library_check()

    def test_changed_library_binary_or_upstream_output_refused(self):
        self.library_fixture();file=self.lib_base/"prefix/lib/libssl.so.3";good=file.read_bytes();file.write_bytes(b"changed artifact")
        with self.assertRaises(ValueError):self.library_check()
        file.write_bytes(good);(self.lib_directory/"selected-upstream-tests.stdout").write_bytes(b"fabricated pass")
        with self.assertRaises(ValueError):self.library_check()

    def test_hidden_upstream_skip_or_failed_recipe_refused(self):
        self.library_fixture();self.lib["upstream_skip_lines"]=0
        with self.assertRaises(ValueError):self.library_check()
        self.lib["upstream_skip_lines"]=1
        next(s for s in self.lib["steps"] if s["name"]=="selected-upstream-tests")["exit_code"]=1
        with self.assertRaises(ValueError):self.library_check()

    def test_native_receiver_must_resolve_to_exact_selected_library(self):
        self.library_fixture();self.output("selected-library-linkage",b"libssl.so.3 => /usr/lib/libssl.so.3\n")
        with self.assertRaises(ValueError):self.library_check()


class LibraryDiagnostics(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="freightctl-library-diagnostic-");self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/"source";self.private=self.root/"private"
        self.source.mkdir();self.private.mkdir()

    def outputs(self,data):
        (self.private/"selected-upstream-tests.stdout").write_bytes(data)
        (self.private/"selected-upstream-tests.stderr").write_bytes(b"")
        return [{"name":"selected-upstream-tests","exit_code":2,"stdout_sha256":hashlib.sha256(data).hexdigest(),"stderr_sha256":hashlib.sha256(b"").hexdigest()}]

    def test_fixed_failure_metadata_never_echoes_protected_text(self):
        steps=self.outputs(b"25-test_verify.t\nnot ok 1 - SYNTHETIC_SECRET\nNo such file or directory /private/SYNTHETIC_SECRET\nversion `OPENSSL_3.5.0' not found in /private/SYNTHETIC_SECRET\n")
        result=library_builder.diagnostics(self.source,self.private,steps)
        self.assertEqual(result["not_ok_records"],1);self.assertEqual(result["recipes_seen"],["25-test_verify.t"])
        self.assertEqual(result["categories"],["library-symbol-version","missing-file"])
        self.assertNotIn("SYNTHETIC_SECRET",json.dumps(result));self.assertNotIn(str(self.root),json.dumps(result))
        self.assertTrue(all(value is False for value in result["harness_files"].values()))

    def test_changed_or_symlinked_original_cannot_supply_diagnostic(self):
        steps=self.outputs(b"No such file or directory\n");path=self.private/"selected-upstream-tests.stdout"
        path.write_bytes(b"Failed test\n")
        self.assertEqual(library_builder.diagnostics(self.source,self.private,steps)["categories"],[])
        path.unlink();outside=self.root/"outside";outside.write_bytes(b"No such file or directory\n");path.symlink_to(outside)
        self.assertEqual(library_builder.diagnostics(self.source,self.private,steps)["categories"],[])

    def test_oversized_original_is_not_read(self):
        steps=self.outputs(b"");path=self.private/"selected-upstream-tests.stdout"
        with path.open("wb") as out:out.truncate((64<<20)+1)
        self.assertEqual(library_builder.diagnostics(self.source,self.private,steps)["categories"],[])


if __name__=="__main__":unittest.main()
