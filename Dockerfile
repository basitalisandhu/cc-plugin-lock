# syntax=docker/dockerfile:1
#
# The cc-plugin-lock CLI as an image. Build and run with:
#   docker build -t cc-plugin-lock .
#   docker run --rm -v "$HOME/.claude/plugins:/plugins:ro" -v "$PWD:/work" cc-plugin-lock verify --root /plugins
#
# The base image is pinned by digest (python:3.12-slim, multi-arch index).
ARG PYTHON_IMAGE=python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

# Build the wheel in a throwaway stage so the build backend never reaches the runtime image.
FROM ${PYTHON_IMAGE} AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE CHANGELOG.md ./
COPY src/ src/
RUN pip wheel --no-deps --wheel-dir /wheels .

FROM ${PYTHON_IMAGE}
ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="cc-plugin-lock" \
      org.opencontainers.image.description="Lock file for Claude Code plugins: pin, verify, diff and scan marketplace plugins" \
      org.opencontainers.image.source="https://github.com/basitalisandhu/cc-plugin-lock" \
      org.opencontainers.image.url="https://github.com/basitalisandhu/cc-plugin-lock" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    pip install --no-deps /wheels/*.whl \
 && useradd --uid 1000 --user-group --no-create-home --shell /usr/sbin/nologin app
# Mount the plugins root (read-only) and a working directory for the lock file at /work.
WORKDIR /work
USER 1000:1000
ENTRYPOINT ["cc-plugin-lock"]
CMD ["--help"]
