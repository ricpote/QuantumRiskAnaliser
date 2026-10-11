# QuantumTrace: one image for CLI + dashboard + offline TLS lab
# ---- stage 1: build the local TLS lab, same two halves as `make lab` and the tests
#   modern/ (8443 8444 8446 8447 2525 5433): needs Go >= 1.24 for X25519MLKEM768
#   legacy/ (8445): its go.mod says `go 1.21.13`, so it is built with Go 1.21 default GODEBUG
#                   (TLS 1.0, 3DES and RSA key transport enabled); pinning Go 1.24 here keeps that working
FROM golang:1.24-bookworm AS lab
WORKDIR /src
COPY samples/extra/tls-lab/ .
RUN cd modern && CGO_ENABLED=0 go build -o /tlslab-modern . \
 && cd ../legacy && CGO_ENABLED=0 go build -o /tlslab-legacy .

# ---- stage 2: TanStack Start SSR + Nitro Node production bundle
FROM node:24-bookworm-slim AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- stage 3: Python scanner + Node server + unchanged TLS lab
FROM python:3.12-slim
COPY --from=frontend /usr/local/bin/node /usr/local/bin/node
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update && apt-get install -y --no-install-recommends tshark \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt constraints.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c constraints.txt
COPY . .
COPY --from=frontend /frontend/.output /app/frontend/.output
RUN pip install --no-cache-dir --no-deps -e .
COPY --from=lab /tlslab-modern /tlslab-legacy /usr/local/bin/
# `tlslab` starts both halves (all 7 endpoints)
RUN printf '#!/bin/sh\ntlslab-legacy &\nexec tlslab-modern\n' > /usr/local/bin/tlslab && chmod +x /usr/local/bin/tlslab

EXPOSE 8501
# default: dashboard on http://localhost:8501
#   CLI:    docker run --rm -v "$PWD:/data" quantumtrace qtrace scan /data --out /data/out
#   probe:  docker run --rm quantumtrace qtrace probe example.com
#   lab:    docker run --rm quantumtrace sh -c "tlslab >/dev/null 2>&1 & sleep 2; qtrace probe 127.0.0.1:8443 127.0.0.1:8445"
CMD ["python", "scripts/ui.py", "--production", "--lab"]
