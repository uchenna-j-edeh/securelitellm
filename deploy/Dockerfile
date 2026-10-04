# Build context: repo root  (docker build -f deploy/Dockerfile .)
# Bakes router/ + prod config into the pinned LiteLLM base image so the
# container is self-contained — no bind-mounts needed in ECS Fargate.

FROM ghcr.io/berriai/litellm@sha256:a69f5f0c56b868d2fdfce7abfb037fed947b70ede202047ffc19c14dc96ab90a

# router/ runtime deps not bundled with the base litellm image
RUN pip install --no-cache-dir "pyyaml>=6.0" "aiohttp>=3.9"

# Application code and configs
COPY router/ /workspace/router/
COPY deploy/litellm_config_prod.yaml /app/config.yaml
COPY deploy/policy.yaml /workspace/deploy/policy.yaml

ENV PYTHONPATH=/workspace

CMD ["--config", "/app/config.yaml", "--port", "4000"]
