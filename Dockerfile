# Netcross — image Docker pour déploiement rapide (issue #170)
#
# Construction :
#   docker build -t netcross:latest .
#
# Utilisation :
#   docker run --rm -v /chemin/vers/captures:/data netcross:latest \
#     cross_capture_analyzer_cli.py /data/capture1.pcap /data/capture2.pcap
#
# L'image inclut tshark (dépendance système) et Python 3.12.

FROM python:3.12-slim AS base

# Dépendances système : tshark pour le décodage des captures
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tshark \
        ca-certificates \
        && \
    rm -rf /var/lib/apt/lists/*

# Répertoire de travail
WORKDIR /app

# Copier d'abord les fichiers de dépendances pour optimiser le cache Docker
COPY pyproject.toml uv.lock* ./

# Installer les dépendances Python
RUN pip install --no-cache-dir -e ".[dev]"

# Copier le code source
COPY src/ ./src/
COPY tests/ ./tests/
COPY install.sh ./
COPY scripts/ ./scripts/

# PYTHONPATH nécessaire car package = false (voir pyproject.toml)
ENV PYTHONPATH=/app/src

# Point d'entrée : la CLI Netcross
ENTRYPOINT ["python", "src/cross_capture_analyzer_cli.py"]
CMD ["--help"]
