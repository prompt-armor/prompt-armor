FROM python:3.12-slim

LABEL maintainer="prompt-armor contributors"
LABEL description="Open-source prompt injection detector — 5 layers, 91.7% F1, ~27ms, offline"
LABEL org.opencontainers.image.source="https://github.com/prompt-armor/prompt-armor"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Copy source
COPY . .

# Install from source with ML layers
RUN pip install --no-cache-dir -e ".[ml]" && \
    # Pre-download all models (L2 DeBERTa + L3 ONNX + L5 IsolationForest)
    python -c "from prompt_armor.engine import LiteEngine; e = LiteEngine(); print(f'Layers: {e.active_layers}'); e.close()" && \
    rm -rf /root/.cache/pip

ENTRYPOINT ["prompt-armor"]
CMD ["--help"]
