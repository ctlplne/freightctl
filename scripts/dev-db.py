#!/usr/bin/env python3
"""Start/reuse only this repository's isolated loopback PostgreSQL fixture."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

root = Path(__file__).resolve().parents[1]
private = root / ".private"
private.mkdir(mode=0o700, exist_ok=True)
os.chmod(private, 0o700)
for name in ("pg-admin-password", "pg-runtime-password"):
    path = private / name
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise SystemExit("Refusing insecure credential file: " + name)
container = "freightctl-postgres-v1"
identity = str(root)
inspect = subprocess.run(["docker", "container", "inspect", container], capture_output=True)
if inspect.returncode == 0:
    metadata = json.loads(inspect.stdout)[0]
    if metadata["Config"].get("Labels", {}).get("freightctl.workspace") != identity:
        raise SystemExit("Existing container identity does not belong to this task")
    if not metadata["State"]["Running"]:
        subprocess.run(["docker", "start", container], check=True, stdout=subprocess.DEVNULL)
else:
    subprocess.run([
        "docker", "run", "-d", "--name", container,
        "--label", "freightctl.workspace=" + identity,
        "--memory", "512m", "--cpus", "1",
        "-p", "127.0.0.1:25432:5432",
        "--mount", "type=volume,src=freightctl-postgres-v1,dst=/var/lib/postgresql/data",
        "--mount", "type=bind,src=" + str(private / "pg-admin-password") + ",dst=/run/secrets/pg-password,readonly",
        "-e", "POSTGRES_PASSWORD_FILE=/run/secrets/pg-password",
        "-e", "POSTGRES_DB=freightctl",
        "postgres:16.15-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea",
    ], check=True, stdout=subprocess.DEVNULL)
for attempt in range(30):
    result = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "postgres", "-d", "freightctl"], capture_output=True)
    if result.returncode == 0:
        break
    time.sleep(1)
else:
    raise SystemExit("PostgreSQL did not become ready; inspect freightctl-postgres-v1 logs")
for user, pwname, target in [("postgres", "pg-admin-password", "pg-admin.dsn"), ("freightctl_runtime", "pg-runtime-password", "pg-runtime.dsn")]:
    path = private / target
    if path.is_symlink():
        raise SystemExit("Refusing symlink credential target")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"postgres://{user}:{(private/pwname).read_text()}@127.0.0.1:25432/freightctl?sslmode=disable")
    os.chmod(path, 0o600)
print("freightctl-postgres-v1 ready on 127.0.0.1:25432; credentials in ignored .private files")
