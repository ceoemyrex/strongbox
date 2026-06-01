FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    openssl \
    argon2 \
    ncat \
    netcat-openbsd \
    python3 \
    python3-pip \
    postgresql-client \
    bc \
    curl \
    ca-certificates \
    jq \
    gawk \
    && pip3 install argon2-cffi --break-system-packages \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/strongbox

COPY . .

RUN find /opt/strongbox -type f \( -name "*.sh" -o -name "*.py" -o -name "*.yaml" -o -name "*.yml" -o -name "*.sql" -o -path "*/bin/*" \) -exec sed -i 's/\r$//' {} \; \
    && chmod +x ./bin/strongbox ./bin/strongbox-verify ./bin/http-handler \
    && mkdir -p /var/log/strongbox /data

EXPOSE 8200

ENTRYPOINT ["./bin/strongbox"]
