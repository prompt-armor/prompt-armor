FROM python:3.12-slim

LABEL maintainer="prompt-armor contributors"
LABEL description="Open-source prompt injection detector — 5 layers, 91.7% F1, ~27ms, offline"
LABEL org.opencontainers.image.source="https://github.com/prompt-armor/prompt-armor"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Install prompt-armor with ML layers
RUN pip install --no-cache-dir "prompt-armor[ml]" && \
    # Pre-download L2 model (DeBERTa ONNX, ~83MB)
    python -c "from prompt_armor.engine import LiteEngine; e = LiteEngine(); print(f'Layers: {e.active_layers}'); e.close()" && \
    # Cleanup pip cache
    rm -rf /root/.cache/pip

ENTRYPOINT ["prompt-armor"]
CMD ["--help"]
