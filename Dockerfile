FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    openssl \
    argon2 \
    netcat-traditional \
    python3 \
    postgresql-client \
    bc \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/strongbox

COPY bin/   ./bin/
COPY lib/   ./lib/

RUN chmod +x ./bin/strongbox ./bin/strongbox-verify \
    && mkdir -p /var/log/strongbox

EXPOSE 8200

ENTRYPOINT ["./bin/strongbox"]
