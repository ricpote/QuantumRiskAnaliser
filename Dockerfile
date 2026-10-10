# QuantumTrace: one image for CLI + dashboard + offline TLS lab
# ---- stage 1: build the local TLS lab (Go >= 1.24 has X25519MLKEM768 in crypto/tls)
FROM golang:1.24-bookworm AS lab
WORKDIR /src
COPY samples/extra/tls-lab/ .
RUN CGO_ENABLED=0 go build -o /tlslab .

# ---- stage 2: runtime
FROM python:3.12-slim
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    GODEBUG=tlsrsakex=1,tls3des=1,tls10server=1
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update && apt-get install -y --no-install-recommends tshark \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt constraints.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c constraints.txt
COPY . .
RUN pip install --no-cache-dir --no-deps -e .
COPY --from=lab /tlslab /usr/local/bin/tlslab

EXPOSE 8501
# default: dashboard on http://localhost:8501
#   CLI:    docker run --rm -v "$PWD:/data" quantumtrace qtrace scan /data --out /data/out
#   probe:  docker run --rm quantumtrace qtrace probe example.com
#   lab:    docker run --rm quantumtrace sh -c "tlslab & sleep 1; qtrace probe 127.0.0.1:8443 127.0.0.1:8445"
CMD ["sh", "-c", "tlslab >/dev/null 2>&1 & exec python -m streamlit run app/streamlit_app.py --server.address=0.0.0.0 --server.port=8501"]
