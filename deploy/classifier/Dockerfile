FROM python:3.11-slim

WORKDIR /app

# Install CPU-only torch first (avoids pulling the full ~2 GB GPU build)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir fastapi "uvicorn[standard]" transformers

COPY main.py .

# Production (infra/): BAKE_MODEL=true downloads the model into the image at
# build time, so the container starts with no internet access (the ECS task
# has none; infra/DESIGN.md). It is stored outside /model_cache, which is a
# volume and would discard anything written there during the build.
ARG BAKE_MODEL=false
ARG CLASSIFIER_MODEL=protectai/deberta-v3-base-prompt-injection-v2
RUN if [ "$BAKE_MODEL" = "true" ]; then \
      python -c "from transformers import pipeline; pipeline('text-classification', model='$CLASSIFIER_MODEL', model_kwargs={'cache_dir': '/opt/model'})" ; \
    fi

# Local compose: /model_cache is a named volume, so the ~180 MB model is
# downloaded on first start and survives container rebuilds. Production sets
# TRANSFORMERS_CACHE=/opt/model and HF_HUB_OFFLINE=1 instead.
VOLUME ["/model_cache"]
ENV TRANSFORMERS_CACHE=/model_cache

EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
