#!/usr/bin/env python3
"""Build and audit the exact unmodified stock DAV peer in native GitHub Actions.

No protocol outcome is established here. All outputs remain private; acquisition,
complete default source and actual binary scans must pass before the peer runs.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import traceback

import rclone_peer as peer


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    arch = peer.validate_native(os.environ, platform.system(), platform.machine(), commit)
    import resource
    os.umask(0o077)
    private = root/'.private'/('freightctl-rclone-'+peer.VERSION+'-'+arch)
    private.mkdir(mode=0o700, parents=True)
    prefix = root/'.cache'/('freightctl-rclone-'+peer.VERSION+'-'+arch)
    prefix.mkdir(mode=0o700, parents=True)
    (prefix/'bin').mkdir(mode=0o700)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('GO', 'RCLONE_'))}
    env.update(GOTOOLCHAIN=peer.GO_VERSION, GOPROXY='https://proxy.golang.org',
               GOSUMDB='sum.golang.org', GOTELEMETRY='off',
               GOCACHE=str(root/'.cache/go-build'), GOMODCACHE=str(root/'.cache/go-mod'),
               GOPATH=str(root/'.cache/go'), GOBIN=str(prefix/'bin'))
    steps = []
    started = time.time()

    def run(name, args, cwd=root, input_path=None):
        out, err = private/(name+'.stdout'), private/(name+'.stderr')
        wall_started = time.monotonic()
        cpu_before = resource.getrusage(resource.RUSAGE_CHILDREN)
        with out.open('xb') as stdout, err.open('xb') as stderr:
            if input_path is None:
                result = subprocess.run(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                        stdout=stdout, stderr=stderr, check=False)
            else:
                with input_path.open('rb') as source:
                    result = subprocess.run(args, cwd=cwd, env=env, stdin=source,
                                            stdout=stdout, stderr=stderr, check=False)
        cpu_after = resource.getrusage(resource.RUSAGE_CHILDREN)
        steps.append(dict(name=name, exit_code=result.returncode,
                          wall_seconds=time.monotonic()-wall_started,
                          child_user_cpu_seconds=cpu_after.ru_utime-cpu_before.ru_utime,
                          child_system_cpu_seconds=cpu_after.ru_stime-cpu_before.ru_stime,
                          max_completed_child_rss_kib=cpu_after.ru_maxrss,
                          stdout_sha256=digest(out), stderr_sha256=digest(err)))
        if result.returncode:
            raise RuntimeError('native-peer-command-failed')
        return out

    state = 'failed'
    try:
        native = json.loads(run('native-toolchain', ['go', 'env', '-json', 'GOHOSTOS',
                            'GOHOSTARCH', 'GOOS', 'GOARCH', 'GOVERSION']).read_bytes())
        if native != dict(GOHOSTOS='linux', GOHOSTARCH=arch, GOOS='linux', GOARCH=arch,
                          GOVERSION=peer.GO_VERSION):
            raise ValueError('native-toolchain-differs')
        module = json.loads(run('verified-module', ['go', 'mod', 'download', '-json',
                            peer.MODULE+'@'+peer.VERSION]).read_bytes())
        peer.validate_module(module)
        directory = Path(module['Dir']).resolve(strict=True)
        expected = Path(env['GOMODCACHE'])/(peer.MODULE+'@'+peer.VERSION)
        if directory != expected.resolve(strict=True):
            raise ValueError('peer-module-cache-differs')
        originals = {p: digest(directory/p) for p in ('go.mod', 'go.sum')}
        run('stock-build', ['go', 'install', '-trimpath', '-mod=readonly',
                            peer.MODULE+'@'+peer.VERSION])
        binary = prefix/'bin/rclone'
        info = json.loads(run('binary-inventory', ['go', 'version', '-m', '-json',
                                                 str(binary)]).read_bytes())
        peer.validate_binary(info, arch)
        run('complete-module-inventory', ['go', 'list', '-mod=readonly', '-m', '-json', 'all'], directory)
        run('verified-module-cache', ['go', 'mod', 'verify'], directory)
        run('scanner-install', ['go', 'install', 'golang.org/x/vuln/cmd/govulncheck@v1.9.0'])
        scanner = prefix/'bin/govulncheck'
        run('scanner-converter-contract', [sys.executable, str(root/'scripts/test-govulncheck-gate.py'),
                                         '--tool', str(scanner)])
        # JSON mode is diagnostic-only. The original pinned converter's non-JSON
        # exit status enforces findings; retain both original reports and results.
        for scope, flags, cwd in [('source', ['./...'], directory),
                                  ('binary', ['-mode=binary', str(binary)], root)]:
            report = run(scope+'-scan', [str(scanner), '-json', *flags], cwd)
            if report.stat().st_size == 0:
                raise ValueError('peer-scan-report-missing')
            run(scope+'-findings-gate', [str(scanner), '-mode=convert', '-show=version,verbose'],
                input_path=report)
        if originals != {p: digest(directory/p) for p in originals}:
            raise ValueError('upstream-peer-manifests-changed')
        run('stock-version', [str(binary), 'version'])
        state = 'accepted-for-protocol-proof'
    except Exception:
        # Command outputs and exceptions may contain private paths. Retain them
        # in the exact closed operation files, never echo raw output to Actions.
        state = 'failed'
        with (private/'failure.traceback').open('x') as target:
            target.write(traceback.format_exc())
    manifest = dict(schema_version=1, profile='stock-rclone-webdav-v1', state=state,
                    candidate=commit, architecture=arch, module=peer.MODULE, version=peer.VERSION,
                    upstream_revision=peer.REVISION, module_sum=peer.SUM, go_mod_sum=peer.MOD_SUM,
                    go_version=peer.GO_VERSION, started_unix=started, finished_unix=time.time(),
                    steps=steps, protocol_qualified=False, local_runtime_authority=False)
    manifest.update(runner_reported_cpus=os.cpu_count(),
                    runner_reported_physical_bytes=os.sysconf('SC_PHYS_PAGES')*os.sysconf('SC_PAGE_SIZE'),
                    rss_scope='Linux cumulative maximum completed-child RSS;not simultaneous process-tree memory',
                    resource_capacity_gates=False)
    if state == 'accepted-for-protocol-proof':
        manifest.update(binary=str(binary.relative_to(root)), binary_sha256=digest(binary),
                        binary_bytes=binary.stat().st_size,
                        source_module_archive_bytes=Path(module['Zip']).stat().st_size,
                        acquisition_source_sha256=digest(Path(__file__).resolve()),
                        identity_source_sha256=digest(root/'scripts/rclone_peer.py'),
                        scanner_sha256=digest(scanner), upstream_manifests=originals)
    output = private/'manifest.json'
    with output.open('x') as target:
        json.dump(manifest, target, indent=2)
        target.write('\n')
    print(json.dumps(dict(state=state, candidate=commit, architecture=arch,
                          manifest_sha256=digest(output), protocol_qualified=False,
                          runner_reported_cpus=manifest['runner_reported_cpus'],
                          runner_reported_physical_bytes=manifest['runner_reported_physical_bytes'],
                          binary_bytes=manifest.get('binary_bytes'),
                          steps=[{k: s[k] for k in ('name','exit_code','wall_seconds','child_user_cpu_seconds',
                                 'child_system_cpu_seconds','max_completed_child_rss_kib')} for s in steps])), flush=True)
    return 0 if state == 'accepted-for-protocol-proof' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError):
        raise SystemExit('Native stock peer preparation refused; no protocol qualification.')
