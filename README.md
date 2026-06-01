# StrongBox

## Tentative Architecture
![Strongbox](./Strongbox.png)

A distributed secrets manager built from first principles.
Encryption, auth, leasing, leader election, and tamper-evident audit — all in Bash.

## Public cluster URL

> TODO: add your VPS domain/IP after provisioning

## Quick start (fresh VPS)

```bash
# 1. Clone
git clone https://github.com/YOUR_ORG/strongbox && cd strongbox

# 2. Set secrets
echo "PG_PASSWORD=$(openssl rand -hex 16)" > .env

# 3. Get TLS cert (replace with your domain)
certbot certonly --standalone -d yourdomain.com

# 4. Start the cluster
docker compose up -d

# 5. Init (one-time — save the output)
curl -s -X POST https://yourdomain.com/v1/sys/init | tee init.json

# 6. Unseal (submit K shares)
SHARE1=$(jq -r '.shares[0]' init.json)
SHARE2=$(jq -r '.shares[1]' init.json)
curl -s -X POST https://yourdomain.com/v1/sys/unseal -d "{\"share\":\"$SHARE1\"}"
curl -s -X POST https://yourdomain.com/v1/sys/unseal -d "{\"share\":\"$SHARE2\"}"

# 7. Verify unsealed
curl -s https://yourdomain.com/v1/sys/health
```

## Architecture

See `docs/architecture.png`.

## Threat model

See `docs/threat-model.md`.

## Election protocol

TODO: 200–400 word explanation of term numbers, vote rules, partition behaviour.

## API examples

TODO: curl examples for each of the 10 grading scenarios.

## Running tests

```bash
export STRONGBOX_URL=https://yourdomain.com
export STRONGBOX_ROOT_TOKEN=<root token from init>
bash test/integration/run_all.sh
```

## Repo structure

```
bin/strongbox            Main server entrypoint
bin/strongbox-verify     Audit log verifier
lib/crypto.sh            Envelope encryption
lib/auth.sh              Tokens and policy engine
lib/lease.sh             Lease lifecycle and reaper
lib/dynamic.sh           Dynamic Postgres credential engine
lib/consensus.sh         Leader election
lib/audit.sh             HMAC audit chain
lib/seal.sh              Seal/unseal state machine
lib/storage.sh           In-memory storage interface
lib/http.sh              HTTP routing
lib/shamir.py            GF(2^8) Shamir reconstruction (Python)
test/integration/        One script per grading scenario
nginx/nginx.conf         TLS termination config
compose.yaml             3-node cluster definition
config.yaml              All tuneable thresholds and TTLs
docs/threat-model.md     Trust boundaries and limitations
```
