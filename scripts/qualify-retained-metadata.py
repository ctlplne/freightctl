#!/usr/bin/env python3
"""Exercise a private, same-cluster metadata restore before retained-estate maintenance.

This is not a production backup system: payloads, keys, global roles, a clean host,
in-flight work and disaster-recovery timing require separate qualification.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 512 * 1024 * 1024


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def private_directory(path):
    info = path.lstat()
    if path.is_symlink() or not path.is_dir() or info.st_mode & 0o077:
        raise ValueError("evidence parent must already be a private directory")


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def save_manifest(exercise):
    path = exercise.private / "manifest.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(json.dumps(exercise.manifest, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(exercise.private)
    return path


def validate_resource(metadata, expected_id):
    if (not re.fullmatch(r"[a-f0-9]{64}", expected_id)
            or metadata["Id"] != expected_id
            or metadata["Name"] != "/freightctl-postgres-v1"
            or metadata["Config"].get("Labels", {}).get("freightctl.workspace") != str(ROOT)):
        raise ValueError("resource identity does not match this repository's retained fixture")
    host = metadata["HostConfig"]
    if host["Memory"] != 536870912 or host["NanoCpus"] != 1000000000:
        raise ValueError("retained PostgreSQL must remain bounded to 512 MiB and one CPU")
    if host["PortBindings"] != {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "25432"}]}:
        raise ValueError("retained PostgreSQL must use its exact loopback binding")
    if metadata["State"]["Running"]:
        raise ValueError("this maintenance exercise requires the fixture to start stopped")


def bounded_output():
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))


def verify_migrations(ledger):
    # Version 1 is schema.sql; numbered files deliberately start at version 2.
    directory = ROOT / "internal/store"
    paths = [directory / "schema.sql"] + sorted(directory.glob("[0-9][0-9][0-9]_*.sql"))
    if not ledger or len(ledger) > len(paths):
        raise RuntimeError("retained migration ledger is empty or newer than source")
    for index, entry in enumerate(ledger):
        if entry != {"version": index + 1, "digest": digest(paths[index])}:
            raise RuntimeError("retained migration checksum differs from source")


class Exercise:
    def __init__(self, container_id, expected_schema):
        self.cid = container_id
        self.expected_schema = expected_schema
        self.private = ROOT / ".private" / ("retained-metadata-" + uuid.uuid4().hex)
        private_directory(ROOT / ".private")
        self.private.mkdir(mode=0o700)
        sync_directory(self.private.parent)
        self.steps = []
        self.started = False
        self.restore_owned = False
        self.restore_name = "freightctl_metadata_restore_" + uuid.uuid4().hex
        self.manifest = {
            "schema_version": 1, "state": "failed",
            "starting_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip(),
            "script_sha256": digest(Path(__file__)),
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "fixture_reference": str(self.private.relative_to(ROOT)),
            "container_id": container_id,
            "restore_database": self.restore_name,
            "inference_performed": False, "scanner_engine_started": False,
            "retained_schema_migrated": False, "shared_docker_lifecycle_changed": False,
            "full_disaster_recovery_qualified": False,
        }

    def command(self, label, arguments, data=None, input_path=None, timeout=45):
        output = self.private / (label + ".stdout")
        errors = self.private / (label + ".stderr")
        began = time.monotonic()
        # Every native output stays private, including SQL diagnostics and dumps.
        with output.open("xb") as out, errors.open("xb") as err:
            stdin = input_path.open("rb") if input_path else None
            try:
                result = subprocess.run(arguments, cwd=ROOT, input=data, stdin=stdin,
                                        stdout=out, stderr=err, timeout=timeout,
                                        preexec_fn=bounded_output)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = "timeout"
            finally:
                if stdin:
                    stdin.close()
            out.flush()
            err.flush()
            os.fsync(out.fileno())
            os.fsync(err.fileno())
        sync_directory(self.private)
        self.steps.append({"name": label, "exit_code": code,
                           "seconds": round(time.monotonic() - began, 3),
                           "stdout_sha256": digest(output), "stdout_bytes": output.stat().st_size,
                           "stderr_sha256": digest(errors), "stderr_bytes": errors.stat().st_size})
        if code != 0:
            raise RuntimeError(label + " failed; inspect its protected native output")
        return output

    def sql(self, label, text, database="freightctl"):
        path = self.command(label, ["docker", "exec", "-i", self.cid, "psql", "-X", "-qAt",
                                   "--no-password", "--set=ON_ERROR_STOP=1", "--username=postgres",
                                   "--dbname=" + database], data=text.encode())
        if path.stat().st_size > 2 * 1024 * 1024:
            raise RuntimeError("metadata observation exceeded its bounded result size")
        return path.read_text().strip()

    def inspect(self, label):
        path = self.command(label, ["docker", "inspect", self.cid])
        return json.loads(path.read_text())[0]

    def clients(self, label):
        return int(self.sql(label, "SELECT count(*) FROM pg_stat_activity WHERE backend_type="
                            "'client backend' AND pid<>pg_backend_pid();"))

    def snapshot(self, label, database="freightctl", exclude_columns=None):
        # No persistent functions or helper tables are installed in the retained database.
        tables = json.loads(self.sql(label + "-tables", "SELECT json_agg(relname ORDER BY relname) "
                            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                            "WHERE n.nspname='public' AND relkind='r';", database))
        if not tables or len(tables) > 128 or any(not re.fullmatch(r"[a-z_][a-z_0-9]*", t) for t in tables):
            raise RuntimeError("unexpected retained metadata table inventory")
        unsupported = self.sql(label + "-scope", "SELECT "
                               "(SELECT count(*) FROM pg_largeobject_metadata)+"
                               "(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                               "WHERE n.nspname NOT IN ('pg_catalog','information_schema') "
                               "AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' "
                               "AND (n.nspname<>'public' OR c.relkind IN ('p','f','m')));", database)
        if unsupported != "0":
            raise RuntimeError("large objects or additional schema/storage types need a separate backup profile")
        hash_sql = "encode(sha256(convert_to(coalesce(string_agg(h,'' ORDER BY h),''),'UTF8')),'hex')"
        queries = ["BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;",
                   "SET LOCAL statement_timeout='20s'; SET LOCAL TIME ZONE 'UTC';"]
        for table in tables:
            row = "to_jsonb(t)"
            for column in (exclude_columns or {}).get(table, []):
                if not re.fullmatch(r"[a-z_][a-z_0-9]*", column):
                    raise RuntimeError("invalid explicit historical row projection")
                row += " - '" + column + "'"
            queries.append("SELECT json_build_object('table','" + table + "','rows',count(*),"
                           "'sha256'," + hash_sql + ") FROM (SELECT encode(sha256(convert_to("
                           "(" + row + ")::text,'UTF8')),'hex') h FROM public.\"" + table + "\" t) s;")
        queries.append("COMMIT;")
        rows = [json.loads(line) for line in self.sql(label + "-rows", "\n".join(queries), database).splitlines()]
        # Compare logical definitions rather than OIDs, physical page layout or pg_dump's random restrict key.
        catalog = self.sql(label + "-catalog", """
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='20s';
SELECT jsonb_build_object(
 'relations',(SELECT jsonb_agg(jsonb_build_array(c.relname,c.relkind,c.relrowsecurity,c.relforcerowsecurity,
    pg_get_userbyid(c.relowner),c.relacl,c.reloptions) ORDER BY c.relname)
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
 'columns',(SELECT jsonb_agg(jsonb_build_array(c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),
    a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname,a.attnum)
    FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
    WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped),
 'constraints',(SELECT jsonb_agg(jsonb_build_array(c.relname,k.conname,pg_get_constraintdef(k.oid))
    ORDER BY c.relname,k.conname) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
 'indexes',(SELECT jsonb_agg(jsonb_build_array(tablename,indexname,indexdef) ORDER BY tablename,indexname)
    FROM pg_indexes WHERE schemaname='public'),
 'policies',(SELECT jsonb_agg(jsonb_build_array(tablename,policyname,permissive,roles,cmd,qual,with_check)
    ORDER BY tablename,policyname) FROM pg_policies WHERE schemaname='public'),
 'triggers',(SELECT jsonb_agg(jsonb_build_array(c.relname,t.tgname,pg_get_triggerdef(t.oid)) ORDER BY c.relname,t.tgname)
    FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND NOT t.tgisinternal),
 'functions',(SELECT jsonb_agg(jsonb_build_array(p.proname,pg_get_function_identity_arguments(p.oid),
    pg_get_functiondef(p.oid),pg_get_userbyid(p.proowner),p.proacl,p.proconfig) ORDER BY p.proname,p.oid::regprocedure::text)
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'),
 'schemas',(SELECT jsonb_agg(jsonb_build_array(nspname,pg_get_userbyid(nspowner),nspacl) ORDER BY nspname)
    FROM pg_namespace WHERE nspname='public'),
 'default_grants',(SELECT jsonb_agg(jsonb_build_array(pg_get_userbyid(d.defaclrole),n.nspname,d.defaclobjtype,d.defaclacl)
    ORDER BY d.defaclrole::regrole::text,n.nspname,d.defaclobjtype) FROM pg_default_acl d
    LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace));
COMMIT;
""", database)
        authority = self.sql(label + "-authority", """
SELECT jsonb_build_object(
 'roles',(SELECT jsonb_agg(jsonb_build_array(rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,
   rolreplication,rolbypassrls,rolconnlimit,rolvaliduntil,rolpassword) ORDER BY rolname) FROM pg_authid),
 'members',(SELECT jsonb_agg(jsonb_build_array(roleid::regrole::text,member::regrole::text,grantor::regrole::text,
   admin_option,inherit_option,set_option) ORDER BY roleid::regrole::text,member::regrole::text) FROM pg_auth_members),
 'settings',(SELECT jsonb_agg(jsonb_build_array(d.datname,r.rolname,s.setconfig) ORDER BY d.datname,r.rolname)
   FROM pg_db_role_setting s LEFT JOIN pg_database d ON d.oid=s.setdatabase LEFT JOIN pg_authid r ON r.oid=s.setrole));
""", database)
        sequences = json.loads(self.sql(label + "-sequences", "SELECT coalesce(json_agg(relname ORDER BY relname),'[]') "
                                        "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                                        "WHERE n.nspname='public' AND relkind='S';", database))
        sequence_values = []
        for index, name in enumerate(sequences):
            if not re.fullmatch(r"[a-z_][a-z_0-9]*", name):
                raise RuntimeError("unexpected sequence identifier")
            sequence_values.append([name, self.sql(label + "-sequence-" + str(index),
                                                  'SELECT last_value,is_called FROM public."' + name + '";', database)])
        ledger = json.loads(self.sql(label + "-ledger", "SELECT json_agg(json_build_object('version',version,"
                                    "'digest',digest) ORDER BY version) FROM freightctl_schema;", database))
        verify_migrations(ledger)
        rls = int(self.sql(label + "-rls", "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                           "WHERE n.nspname='public' AND relkind='r' AND relrowsecurity AND relforcerowsecurity;", database))
        runtime_safe = self.sql(label + "-runtime", "SELECT count(*)=1 AND bool_and(NOT rolsuper AND NOT rolbypassrls "
                                "AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication) "
                                "FROM pg_roles WHERE rolname='freightctl_runtime';", database) == "t"
        if not runtime_safe or rls != len(tables) - 1:
            raise RuntimeError("runtime role or forced row-security boundary differs from the retained profile")
        return {"tables": rows, "catalog_sha256": hashlib.sha256(catalog.encode()).hexdigest(),
                "role_authority_sha256": hashlib.sha256(authority.encode()).hexdigest(),
                "sequences": sequence_values, "migration_ledger": ledger, "forced_rls_tables": rls,
                "runtime_role_safe": runtime_safe}

    def compare_restore(self, original, restored):
        if original == restored:
            return
        if any(original[key] != restored[key] for key in original if key != "catalog_sha256"):
            raise RuntimeError("restored metadata, permissions, roles or sequence state differs")
        original_catalog = json.loads((self.private / "original-before-catalog.stdout").read_text())
        restored_catalog = json.loads((self.private / "restored-catalog.stdout").read_text())
        if any(original_catalog[key] != restored_catalog[key] for key in original_catalog if key != "policies"):
            raise RuntimeError("restored schema or grants differ")
        old_policies, new_policies = original_catalog["policies"], restored_catalog["policies"]
        if len(old_policies) != len(new_policies):
            raise RuntimeError("restored row-security policy inventory differs")
        queries = ["BEGIN; SET LOCAL statement_timeout='20s';"]
        expected = []
        for old, new in zip(old_policies, new_policies):
            if old == new:
                continue
            table, policy = old[:2]
            if (old[:5] != new[:5] or any(not re.fullmatch(r"[a-z_][a-z_0-9]*", name) for name in (table, policy))
                    or not all(isinstance(value, str) for value in old[5:] + new[5:])):
                raise RuntimeError("restored row-security policy authority differs")
            # pg_dump emits SQL, which PostgreSQL parses again on restore. Reparse
            # the original expressions in the isolated restored database, then
            # compare its own deparse output exactly. Do not strip parentheses or
            # simplify predicates ourselves. Roll back every temporary ALTER.
            queries.append('ALTER POLICY "' + policy + '" ON public."' + table + '" USING (' + old[5]
                           + ') WITH CHECK (' + old[6] + ');')
            queries.append("SELECT jsonb_build_array(tablename,policyname,permissive,roles,cmd,qual,with_check) "
                           "FROM pg_policies WHERE schemaname='public' AND tablename='" + table
                           + "' AND policyname='" + policy + "';")
            expected.append(new)
        if not expected:
            raise RuntimeError("catalog mismatch is not a reparsed policy expression")
        queries.append("ROLLBACK;")
        actual = [json.loads(line) for line in self.sql("reparse-original-policies-with-rollback", "\n".join(queries),
                                                       self.restore_name).splitlines()]
        if actual != expected:
            raise RuntimeError("restored row-security predicates differ after PostgreSQL parsing")
        self.manifest["policy_parser_roundtrip"] = {
            "method": "original expressions reparsed by PostgreSQL in restored database; exact pg_policies comparison; transaction rolled back",
            "policies": [{"table": row[0], "name": row[1]} for row in expected],
            "original_catalog_sha256": original["catalog_sha256"],
            "restored_catalog_sha256": restored["catalog_sha256"],
            "all_other_catalog_fields_equal": True,
            "reparsed_original_predicates_equal_restored_predicates": True,
        }

    def run(self):
        before = self.inspect("inspect-before")
        validate_resource(before, self.cid)
        self.manifest["resource"] = {"name": before["Name"], "image": before["Image"],
                                     "memory_bytes": before["HostConfig"]["Memory"],
                                     "nano_cpus": before["HostConfig"]["NanoCpus"], "originally_running": False}
        # Set this before starting: a lost client response must still enter exact-resource cleanup.
        self.started = True
        self.command("start-exact-postgres", ["docker", "start", self.cid])
        for attempt in range(30):
            result = subprocess.run(["docker", "exec", self.cid, "pg_isready", "-U", "postgres", "-d", "freightctl"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if result.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("exact retained PostgreSQL did not become ready")
        if self.clients("active-clients-before"):
            raise RuntimeError("another client is using the retained resource; do not perform maintenance")
        version = self.sql("postgres-version", "SELECT version();")
        self.manifest["postgres_version"] = version
        original = self.snapshot("original-before")
        self.manifest["before"] = original
        if len(original["migration_ledger"]) != self.expected_schema:
            raise RuntimeError("retained schema differs from the explicitly selected checkpoint")
        size = int(self.sql("database-size", "SELECT pg_database_size(current_database());"))
        if size > LIMIT:
            raise RuntimeError("retained fixture exceeds the 512 MiB backup profile")
        backup = self.command("metadata-backup", ["docker", "exec", self.cid, "pg_dump", "--no-password",
                              "--username=postgres", "--dbname=freightctl", "--format=custom", "--lock-wait-timeout=10000"], timeout=60)
        self.manifest["backup"] = {"reference": str(backup.relative_to(ROOT)), "bytes": backup.stat().st_size,
                                   "sha256": digest(backup), "database_size_bytes": size,
                                   "file_mode": oct(backup.stat().st_mode & 0o777),
                                   "file_and_directory_synced": True}
        if not backup.stat().st_size or backup.stat().st_mode & 0o077:
            raise RuntimeError("metadata backup is empty or not private")
        if self.sql("refuse-existing-restore-name", "SELECT count(*) FROM pg_database WHERE datname='" + self.restore_name + "';") != "0":
            raise RuntimeError("restore database already exists; preserve it")
        self.restore_owned = True
        self.sql("create-exact-restore", "CREATE DATABASE " + self.restore_name + " TEMPLATE template0;")
        self.command("restore-exact-backup", ["docker", "exec", "-i", self.cid, "pg_restore", "--no-password",
                     "--username=postgres", "--dbname=" + self.restore_name, "--single-transaction", "--exit-on-error"],
                     input_path=backup, timeout=60)
        restored = self.snapshot("restored", self.restore_name)
        self.manifest["restored"] = restored
        self.compare_restore(original, restored)
        final = self.snapshot("original-after")
        self.manifest["after"] = final
        if final != original:
            raise RuntimeError("retained database changed during its metadata restore exercise")
        self.manifest["restored_metadata_matches"] = True
        self.manifest["retained_database_unchanged"] = True
        self.manifest["state"] = "passed"

    def cleanup(self):
        failures = []
        if self.restore_owned:
            try:
                # Never FORCE a drop or terminate another client's connections.
                self.sql("drop-exact-created-restore", "DROP DATABASE IF EXISTS " + self.restore_name + ";")
                self.manifest["exact_restore_database_removed"] = True
            except Exception as error:
                failures.append(str(error))
        if self.started:
            try:
                if self.clients("active-clients-before-stop"):
                    raise RuntimeError("other clients appeared; leave PostgreSQL running for their owner")
                self.command("stop-exact-postgres", ["docker", "stop", "--time", "15", self.cid], timeout=25)
                final = self.inspect("inspect-after")
                self.manifest["original_stopped_state_restored"] = not final["State"]["Running"]
                if final["State"]["Running"]:
                    raise RuntimeError("retained PostgreSQL did not return to its original stopped state")
            except Exception as error:
                failures.append(str(error))
        if failures:
            self.manifest["cleanup_failures"] = failures
            self.manifest["state"] = "failed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container-id", required=True, help="exact previously inspected 64-character task-owned PostgreSQL ID")
    parser.add_argument("--expected-schema", type=int, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    exercise = Exercise(args.container_id, args.expected_schema)
    try:
        exercise.run()
    except Exception as error:
        exercise.manifest["failure"] = str(error)
    finally:
        exercise.cleanup()
    exercise.manifest["steps"] = exercise.steps
    path = save_manifest(exercise)
    print(json.dumps({"state": exercise.manifest["state"], "manifest": str(path.relative_to(ROOT)),
                      "manifest_sha256": digest(path), "failure": exercise.manifest.get("failure"),
                      "cleanup_failures": exercise.manifest.get("cleanup_failures", [])}), flush=True)
    return 0 if exercise.manifest["state"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
