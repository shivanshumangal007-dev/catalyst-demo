# VulnReach tool image.
# Analysis is static-only (ast-based): the target project's code is never
# imported or executed, only parsed.
#
# NOTE: Pin the base image digest by running:
#   docker pull python:3.11-slim
#   docker inspect --format='{{join .RepoDigests ", "}}' python:3.11-slim
# and replacing the sha256 below.
FROM python@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /workspace

# Install VulnReach dependencies first (better layer caching).
COPY pyproject.toml ./pyproject.toml
RUN pip install --no-cache-dir -e . 2>/dev/null || \
    pip install --no-cache-dir networkx pydantic unidiff packaging 2>/dev/null || true

# Copy the project source.
COPY . /workspace

# Install VulnReach itself (pip install -e . so `vulnreach` entry point works).
RUN pip install --no-cache-dir -e .

# Non-root user for isolated analysis runs.
RUN useradd -m -u 1000 vulnreachuser
USER 1000:1000

ENTRYPOINT ["vulnreach"]
CMD ["--help"]
