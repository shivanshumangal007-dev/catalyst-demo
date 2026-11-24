"""Phase 5 probe: real Docker isolation + hostile fixture (never run on host)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vulnreach.sandbox.docker_runner import DockerRunner  # noqa: E402

IMAGE = os.environ.get("VR_AUDIT_IMAGE", "vulnreach:audit")
BASE = Path("/tmp/vr_docker_hostile")


def sh(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    return p.returncode, (p.stdout + p.stderr).strip()


def make_hostile() -> tuple[Path, Path, Path]:
    shutil.rmtree(BASE, ignore_errors=True)
    project = BASE / "project"
    out = BASE / "out"
    project.mkdir(parents=True)
    out.mkdir(parents=True)
    os.chmod(out, 0o777)

    (project / "lib.py").write_text(
        "def vulnerable():\n    return 1\n\ndef safe():\n    return 2\n"
    )
    (project / "main.py").write_text(
        "import os, socket, lib\n"
        "# Hostile module-level payloads: must never execute during analysis.\n"
        "open('/workspace/PWNED_MAIN', 'w').write('executed')\n"
        "os.system('touch /workspace/PWNED_OS')\n"
        "socket.create_connection(('1.1.1.1', 80), 2)\n"
        "lib.vulnerable()\n"
    )
    (project / "setup.py").write_text(
        "import os\n"
        "open('/workspace/PWNED_SETUP', 'w').write('executed')\n"
        "os.system('touch /workspace/PWNED_SETUP_OS')\n"
    )
    (project / "sitecustomize.py").write_text(
        "open('/workspace/PWNED_SITECUSTOMIZE', 'w').write('executed')\n"
    )
    (project / "conftest.py").write_text(
        "open('/workspace/PWNED_CONFTEST', 'w').write('executed')\n"
    )
    alerts = BASE / "alerts.json"
    alerts.write_text(json.dumps([
        {"package": "definitely-not-installed", "version": "1.0.0", "advisory_id": "AUDIT-1"}
    ]))
    return project, alerts, out


if __name__ == "__main__":
    project, alerts, out = make_hostile()
    print("image:", IMAGE)
    for label, cmd in [
        ("user id", ["docker", "run", "--rm", "--entrypoint", "id", IMAGE]),
        ("network none", ["docker", "run", "--rm", "--network", "none", "--entrypoint", "python",
                          IMAGE, "-c",
                          "import socket; socket.create_connection(('1.1.1.1',80),2); print('CONNECTED')"]),
        (".git in image", ["docker", "run", "--rm", "--entrypoint", "sh", IMAGE, "-c",
                           "test -d /workspace/.git && echo GIT_PRESENT || echo GIT_ABSENT"]),
        ("audit_work in image", ["docker", "run", "--rm", "--entrypoint", "sh", IMAGE, "-c",
                                 "test -e /workspace/audit_work && echo AUDIT_WORK_PRESENT || echo ABSENT"]),
    ]:
        code, output = sh(cmd)
        print(f"{label:20s} exit={code} output={output[:300]!r}")

    runner = DockerRunner(image=IMAGE, timeout=180)
    try:
        report = runner.run_isolated(project, alerts, out)
        print("run_isolated: OK; verdicts:",
              [(v["alert"]["advisory_id"], v["status"], v["confidence"]) for v in report["verdicts"]])
    except Exception as exc:
        print("run_isolated: EXCEPTION", type(exc).__name__, str(exc)[:800])

    report_path = out / "report.json"
    print("host report.json exists:", report_path.exists())
    if report_path.exists():
        data = json.loads(report_path.read_text())
        print("host report verdicts:", [(v["alert"]["advisory_id"], v["status"]) for v in data["verdicts"]])
        print("host vex exists:", (out / "report.vex.json").exists())

    markers = sorted(p.name for p in project.glob("PWNED_*")) + sorted(p.name for p in out.glob("PWNED_*"))
    print("host markers created:", markers or "none")
    for path in ("/workspace/PWNED_MAIN", "/workspace/PWNED_OS", "/workspace/PWNED_SETUP",
                 "/workspace/PWNED_SETUP_OS", "/workspace/PWNED_SITECUSTOMIZE",
                 "/workspace/PWNED_CONFTEST"):
        print(f"  container {path}:",
              sh(["docker", "run", "--rm", "--entrypoint", "sh", IMAGE, "-c",
                  f"test -e {path} && echo PRESENT || echo ABSENT"])[1])

    # Exit code 1 is how `vulnreach scan` reports a reachable verdict. Show that
    # the runner command treats it as failure (F-26) using a harmless override.
    code, output = sh(["docker", "run", "--rm", "--entrypoint", "sh", IMAGE, "-c", "exit 1"])
    print("control container exit=1 ->", code, "| DockerRunner checks result.returncode != 0")
