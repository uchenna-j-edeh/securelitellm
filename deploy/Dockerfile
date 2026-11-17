# Production image: LiteLLM proxy + the SecureLiteLLM router hook.
# Build context: repo root  (docker build -f deploy/Dockerfile .)
# Bakes router/ + prod config into the pinned LiteLLM base image so the
# container is self-contained — no bind-mounts needed in ECS Fargate.
FROM ghcr.io/berriai/litellm@sha256:a69f5f0c56b868d2fdfce7abfb037fed947b70ede202047ffc19c14dc96ab90a

# Runtime dependencies are pinned to the same versions resolved in uv.lock.
# The base image already ships them and has no pip, so the build checks the
# exact versions instead of installing: it fails if a new base image drifts.
# psycopg and cryptography are used by SESSION_STORE=postgres (#169).
RUN /app/.venv/bin/python -c "from importlib.metadata import version; \
    pins = ['pyyaml==6.0.3', 'aiohttp==3.14.3', 'psycopg==3.3.3', 'cryptography==50.0.0']; \
    wrong = [p for p in pins if version(p.split('==')[0]) != p.split('==')[1]]; \
    assert not wrong, f'base image versions differ from the pins: {wrong}'"

# CA bundle for verifying the RDS server certificate (SESSION_DB_URL uses
# sslmode=verify-full). Fetched at build time because the task has no
# internet; the checksum fails the build if the file changes. When AWS
# rotates the bundle, update the checksum from
# https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
ADD --chmod=644 --checksum=sha256:90a6f1a7978a1b1b096dca6c57511ca48d3b8cf052f8e704baf358f34ea2f21b \
    https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem \
    /etc/ssl/rds/global-bundle.pem

COPY router/ /workspace/router/
COPY deploy/litellm_config_prod.yaml /app/config.yaml
# policy.yaml always; policy.demo.yaml too when it was generated on the build
# machine (dry runs, infra/variables.tf policy_file). CI never has it.
COPY deploy/policy*.yaml /workspace/deploy/
# One-off database setup, run as its own ECS task before each deploy (infra/ecs.tf).
COPY deploy/db_setup.py /workspace/deploy/db_setup.py

ENV PYTHONPATH=/workspace
ENV ROUTER_LITELLM_CONFIG=/app/config.yaml

CMD ["--config", "/app/config.yaml", "--port", "4000"]
