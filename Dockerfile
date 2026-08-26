ARG PYTHON_IMAGE=python:3.14.7-slim-trixie@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4
ARG PYTHON_RUNTIME_IMAGE=cgr.dev/chainguard/python@sha256:6d71f8dbd199350964ce8b10d50fb9d4d8e2bd50316f3a1821dbdc6eef5252fb
ARG NODE_IMAGE=node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d

FROM ${NODE_IMAGE} AS ui-builder
WORKDIR /ui
RUN npm install --global npm@11.12.1
COPY ui/.npmrc ui/package.json ui/package-lock.json ./
RUN npm ci --ignore-scripts
COPY ui ./
RUN npm run build

FROM ${PYTHON_IMAGE} AS builder
ENV UV_COMPILE_BYTECODE=1 \
    UV_COMPILE_BYTECODE_TIMEOUT=180 \
    UV_LINK_MODE=copy
WORKDIR /app
RUN python -m pip install --no-cache-dir uv==0.12.5
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable \
    --extra connectors \
    --extra framework-observability \
    --extra postgres \
    --extra model-providers
RUN ln -sf /usr/bin/python .venv/bin/python \
    && ln -sf python .venv/bin/python3 \
    && ln -sf python .venv/bin/python3.14

FROM ${PYTHON_RUNTIME_IMAGE} AS runtime
LABEL org.opencontainers.image.source="https://github.com/mrinmoyece/aegis-framework-platform" \
      org.opencontainers.image.description="Aegis framework-first governed Layer 15"
ENV PATH="/app/.venv/bin:${PATH}" \
    AEGIS_MIGRATIONS_DIR="/app/migrations" \
    LANGGRAPH_STRICT_MSGPACK=true \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY --from=builder --chown=10001:10001 /app/.venv /app/.venv
COPY --from=ui-builder --chown=10001:10001 /ui/dist /app/ui
COPY --chown=10001:10001 migrations /app/migrations
ENV AEGIS_OPERATOR_UI_DIR=/app/ui
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
ENTRYPOINT ["aegis-framework"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
