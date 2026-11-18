"""Isolated Docker sandbox for VulnReach analysis.

Runs the full VulnReach analysis *inside* a Docker container so the target
project is never imported or executed on the host: analysis is static only
(``ast``-based call graph + reachability), and the project's own code is never
executed.

Execution model:

1. Build an image from the project's requirements (pinned dependency install)
   with network access.
2. Run the analysis container with the project mounted read-only and
   ``--network none`` so no network is available during analysis.
3. Run as a non-root user with CPU/memory limits and a timeout.

The container runs ``vulnreach scan`` against the mounted project, so the same
code path is used as on the host, just isolated.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


class DockerRunner:
    """Build and run VulnReach analysis inside an isolated Docker container."""

    def __init__(
        self,
        image: str = "vulnreach:latest",
        container_workdir: str = "/workspace",
        timeout: int = 600,
        mem_limit: str = "2g",
        cpus: str | float = "2",
    ) -> None:
        self.image = image
        self.container_workdir = container_workdir
        self.timeout = timeout
        self.mem_limit = mem_limit
        self.cpus = cpus

        if shutil.which("docker") is None:
            raise RuntimeError("docker executable not found on PATH")

    # ------------------------------------------------------------------ public

    def run_isolated(
        self,
        project_path: str | Path,
        alerts_path: str | Path,
        out_dir: str | Path,
    ) -> dict[str, Any]:
        """Build + run analysis in Docker; return parsed report.json.

        The project is mounted read-only at ``<workdir>/project``.  Dependencies
        are installed from the project's requirements at image-build time
        (network on); the analysis step runs with ``--network none``.
        """
        project_path = Path(project_path).resolve()
        alerts_path = Path(alerts_path).resolve()
        out_dir = Path(out_dir).resolve()

        if not project_path.exists():
            raise FileNotFoundError(f"project path not found: {project_path}")
        if not alerts_path.exists():
            raise FileNotFoundError(f"alerts file not found: {alerts_path}")

        self._ensure_image()

        host_out = out_dir
        host_out.mkdir(parents=True, exist_ok=True)

        container_project = f"{self.container_workdir}/project"
        container_alerts = f"{self.container_workdir}/alerts.json"
        container_out = f"{self.container_workdir}/out"

        run_cmd = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",  # no network during analysis
            "--user",
            "1000:1000",  # non-root user
            "--memory",
            self.mem_limit,
            "--cpus",
            str(self.cpus),
            # project mounted read-only; output dir writable
            "-v",
            f"{project_path}:{container_project}:ro",
            "-v",
            f"{alerts_path}:{container_alerts}:ro",
            "-v",
            f"{host_out}:{container_out}:rw",
            "-w",
            self.container_workdir,
            self.image,
            "vulnreach",
            "scan",
            container_project,
            "--alerts",
            container_alerts,
            "--out-dir",
            container_out,
            "--no-cache",
        ]

        result = subprocess.run(
            run_cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout + 30,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"isolated analysis failed (exit {result.returncode}):\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )

        report_path = host_out / "report.json"
        if not report_path.exists():
            raise RuntimeError("analysis container did not produce report.json")
        return json.loads(report_path.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------ image

    def _ensure_image(self) -> None:
        """Build the VulnReach image if it does not exist locally.

        Image build runs with network (default) so pinned dependencies can be
        installed from the project's requirements.
        """
        inspect = subprocess.run(
            ["docker", "image", "inspect", self.image],
            capture_output=True,
            text=True,
        )
        if inspect.returncode == 0:
            return
        dockerfile = self._locate_dockerfile()
        build_cmd = [
            "docker",
            "build",
            "-t",
            self.image,
            "-f",
            str(dockerfile),
            str(dockerfile.parent),
        ]
        result = subprocess.run(build_cmd, capture_output=True, text=True, timeout=900)
        if result.returncode != 0:
            raise RuntimeError(
                f"docker build failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
            )

    @staticmethod
    def _locate_dockerfile() -> Path:
        here = Path(__file__).resolve()
        for candidate in [
            here.parents[3] / "Dockerfile",  # <repo>/Dockerfile
            Path.cwd() / "Dockerfile",
        ]:
            if candidate.exists():
                return candidate
        raise FileNotFoundError("Dockerfile not found for building the VulnReach image")
