# SPDX-License-Identifier: Apache-2.0
# Attestra: one image, three processes (aap api | aap hook | aap worker), plus jobs.
# Base images pinned by digest; gh pinned by version + sha256 (attestation verification backend for private repos).
# Built, scanned and attested by .github/workflows/release.yml; runs as an unprivileged user with a read-only root.

FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS ui
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

FROM ghcr.io/astral-sh/uv:0.13@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 AS uv

FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS backend
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app/backend
COPY backend/pyproject.toml backend/uv.lock backend/README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY backend/src ./src
COPY backend/migrations ./migrations
COPY backend/alembic.ini ./
RUN uv sync --frozen --no-dev

FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS gh
ARG GH_VERSION=2.102.0
ARG GH_SHA256_AMD64=bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386
ARG GH_SHA256_ARM64=7862c86c72f43df3a2d93ddde6f473285b4e2af61b494849846827e513ef6484
ARG TARGETARCH
ADD https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${TARGETARCH}.tar.gz /tmp/gh.tgz
RUN expected=$([ "$TARGETARCH" = "arm64" ] && echo "$GH_SHA256_ARM64" || echo "$GH_SHA256_AMD64") \
 && echo "${expected}  /tmp/gh.tgz" | sha256sum -c - \
 && tar -xzf /tmp/gh.tgz -C /tmp && mv /tmp/gh_${GH_VERSION}_linux_${TARGETARCH}/bin/gh /usr/local/bin/gh

FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin aap
COPY --from=gh /usr/local/bin/gh /usr/local/bin/gh
COPY --from=backend /app/backend /app/backend
COPY --from=ui /src/frontend/dist /app/frontend/dist
# governed configuration, catalogue and schemas are part of the release (config versions are content-addressed)
COPY catalogue /app/catalogue
COPY config /app/config
COPY schemas /app/schemas
COPY templates /app/templates
COPY pipelines /app/pipelines
ENV PATH=/app/backend/.venv/bin:$PATH AAP_REPO_ROOT=/app AAP_STATIC_DIR=/app/frontend/dist \
    PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 10001
WORKDIR /app
EXPOSE 8000 8001
HEALTHCHECK NONE
CMD ["aap", "api", "--host", "0.0.0.0", "--port", "8000"]
