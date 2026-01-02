FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    clamav \
    ffmpeg \
    mediainfo \
    binwalk \
    file \
    binutils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN freshclam || true

WORKDIR /analyzer

COPY main.py /analyzer/main.py

ENTRYPOINT ["python3", "/analyzer/main.py"]
