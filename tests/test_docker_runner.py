"""Tests for the Docker sandbox runner (subprocess mocked, no Docker required)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from vulnreach.sandbox.docker_runner import DockerRunner


def _make_runner():
    return DockerRunner(image="vulnreach:test", timeout=120, mem_limit="1g", cpus="1")


class _FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_run_isolated_uses_network_none_and_readonly_project(tmp_path):
    """The analysis run must use --network none and mount the project read-only."""
    project = tmp_path / "proj"
    project.mkdir()
    alerts = tmp_path / "alerts.json"
    alerts.write_text("[]")
    host_out = tmp_path / "out"
    report = {"verdicts": []}

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        # image inspect call
        if cmd[0:3] == ["docker", "image", "inspect"]:
            return _FakeCompleted(returncode=1)  # not found -> triggers build
        # docker build call
        if cmd[1] == "build":
            return _FakeCompleted(returncode=0)
        # docker run call -> write a fake report.json to the host out dir
        if cmd[1] == "run":
            host_out.mkdir(parents=True, exist_ok=True)
            (host_out / "report.json").write_text(__import__("json").dumps(report))
            return _FakeCompleted(returncode=0)
        return _FakeCompleted(returncode=0)

    runner = _make_runner()
    with patch("subprocess.run", side_effect=fake_run) as m:
        result = runner.run_isolated(project, alerts, host_out)

    assert result == report
    # Find the docker run command and assert isolation flags.
    run_cmd = next(c for c in calls if c[1] == "run")
    assert "--network" in run_cmd and "none" in run_cmd
    assert "--user" in run_cmd and "1000:1000" in run_cmd
    assert "--memory" in run_cmd
    assert "--cpus" in run_cmd
    # project mounted read-only
    proj_mount = next(m for m in run_cmd if m.endswith(":ro") and "proj" in m)
    assert proj_mount is not None


def test_run_isolated_raises_on_failure(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    alerts = tmp_path / "alerts.json"
    alerts.write_text("[]")

    def fake_run(cmd, **kwargs):
        if cmd[1] == "run":
            return _FakeCompleted(returncode=2, stdout="", stderr="boom")
        return _FakeCompleted(returncode=0)

    runner = _make_runner()
    with patch("subprocess.run", side_effect=fake_run):
        with pytest.raises(RuntimeError, match="isolated analysis failed"):
            runner.run_isolated(project, alerts, tmp_path / "out")


def test_docker_not_found(tmp_path, monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(RuntimeError, match="docker executable not found"):
        DockerRunner()
