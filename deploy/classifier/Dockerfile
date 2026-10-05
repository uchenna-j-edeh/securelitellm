FROM python:3.11-slim

WORKDIR /app

# Install CPU-only torch first (avoids pulling the full ~2 GB GPU build)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir fastapi "uvicorn[standard]" transformers

COPY main.py .

# /model_cache is mounted as a named volume so the ~180 MB model survives
# container rebuilds.  On first start the model is downloaded here.
VOLUME ["/model_cache"]
ENV TRANSFORMERS_CACHE=/model_cache

EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
