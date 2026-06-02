FROM python:3.12-slim

LABEL maintainer="prompt-armor contributors"
LABEL description="Open-source prompt injection detector — 5 layers, F1 86.9% internal / 98.87% external, ~24ms, offline"
LABEL org.opencontainers.image.source="https://github.com/prompt-armor/prompt-armor"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Copy source
COPY . .

# Install from source with ML layers
RUN pip install --no-cache-dir -e ".[ml]" && \
    # Warm the engine: downloads L2 DeBERTa + L5 models. L3 loads the prebuilt
    # FAISS index shipped in the package (no corpus encode), so this is fast and
    # `docker run` stays warm (~24ms) instead of paying cold start per invocation.
    python -c "from prompt_armor.engine import LiteEngine; e = LiteEngine(); print(f'Layers: {e.active_layers}'); e.close()" && \
    rm -rf /root/.cache/pip

ENTRYPOINT ["prompt-armor"]
CMD ["--help"]
