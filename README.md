# StrongBox

A distributed secrets manager built from first principles.
Encryption, auth, leasing, leader election, and tamper-evident audit — all in Bash.

## Architecture

![Architecture](./docs/architecture.png)

## Public cluster URL

**https://strong-box.duckdns.org**
**https://strong-box.duckdns.org/v1/sys/health**

## Quick start (fresh VPS)

```bash
# 1. Clone
git clone https://github.com/ceoemyrex/strongbox && cd strongbox

# 2. Set secrets
echo "PG_PASSWORD=$(openssl rand -hex 16)" > .env
echo "STRONGBOX_AUDIT_HMAC_KEY=$(openssl rand -hex 32)" >> .env

# 3. Get TLS cert (replace with your domain)
sudo certbot certonly --standalone -d strong-box.duckdns.org

# 4. Start the cluster
docker compose up -d --build

# 5. Init (one-time — save the output)
curl -s -X POST http://localhost:8201/v1/sys/init | tee init.json

# 6. Unseal ALL 3 nodes (each node needs K shares individually)
SHARE1=$(jq -r '.shares[0]' init.json)
SHARE2=$(jq -r '.shares[1]' init.json)
for PORT in 8201 8202 8203; do
  curl -s -X POST http://localhost:$PORT/v1/sys/unseal \
    -H "Content-Type: application/json" -d "{\"share\":\"$SHARE1\"}"
  curl -s -X POST http://localhost:$PORT/v1/sys/unseal \
    -H "Content-Type: application/json" -d "{\"share\":\"$SHARE2\"}"
done

# 7. Verify all nodes unsealed
for PORT in 8201 8202 8203; do
  echo -n "node :$PORT → "
  curl -s http://localhost:$PORT/v1/sys/health
  echo ""
done
```

## Threat model

See `docs/threat-model.md`.

## Nonce strategy

Every secret value in StrongBox is encrypted with envelope encryption, and
every encryption operation needs a fresh nonce (initialisation vector). This
section explains what nonces we use, where they come from, and why.

### What we use

Random 128-bit IVs from `/dev/urandom` for every AES-256-CTR operation.
Two independent IVs per envelope:

- `nonce_dek` — IV for encrypting the secret value with the per-secret DEK
- `nonce_kek` — IV for encrypting the DEK bundle with the master KEK

Both IVs are generated fresh on every call to `crypto_encrypt`. They are
stored alongside the ciphertext in the envelope so decryption can recover
them — IVs are not secret, they only need to be unique per key.

### Why random and not a counter

The two reasonable choices for a CTR-mode IV are:

1. A counter that increments with every encryption and persists across restarts
2. A random value drawn from a cryptographically secure RNG on every call

We picked (2). A counter would require atomic disk persistence — every
encryption would have to write the new counter value before using it,
otherwise a crash could reuse a counter and break the security of every
secret that ever used the same key. Persisting that counter means writing
key-adjacent state to disk, which reintroduces the exact threat the
sealed/unseal design exists to avoid: an attacker with disk access learns
something about the key material's history.

### Why 128 bits and not 96

AES-GCM conventionally uses 96-bit nonces. We use 128-bit nonces because
`openssl enc -aes-256-ctr` (which StrongBox uses, since `openssl enc` does
not support AEAD ciphers in OpenSSL 3.x) requires a full 128-bit block
for its `-iv` parameter. The extra 32 bits don't hurt — they only widen
the birthday bound further.

### Collision safety

With random 128-bit IVs, the probability of two encryptions ever picking
the same IV under the same key follows the birthday bound. The collision
probability stays below 2⁻³² after roughly 2⁴⁸ encryptions per key — about
281 trillion writes. At realistic secret-write rates (say, 1000 writes/sec
sustained, which is far beyond any expected workload), reaching that bound
would take 8000+ years.

For the DEK layer, this concern is essentially moot — each DEK is fresh
per secret, so the DEK is used for at most one encryption in its lifetime.
The bound matters only for the KEK layer, where the master key encrypts
the DEK bundle for every secret. Even there, 2⁴⁸ is comfortably out of
reach.

### Implementation reference

Nonce generation in `lib/crypto.sh`:

```bash
nonce_dek="$(openssl rand -hex 16)"
nonce_kek="$(openssl rand -hex 16)"
```

`openssl rand` reads from the system CSPRNG (`getrandom(2)` on Linux,
which is `/dev/urandom` after the entropy pool is initialised).

### Verification

`test/unit/test_crypto.sh` includes a uniqueness check that calls
`crypto_encrypt` 50 times with the same plaintext and asserts every
`(nonce_dek:nonce_kek)` pair is unique. The same test also verifies
that encrypting the same plaintext twice produces two different envelopes
— a regression test for the "are we actually randomising the IV"
question.

## Memory hygiene

The seal/unseal design depends on a single guarantee: after the operator
submits K shares and the cluster transitions to unsealed, no submitted
share value, no intermediate buffer, and no copy of the reconstructed
master key remains in process memory except the one deliberate copy the
crypto layer needs.

This section describes what gets zeroed, when, and how we verify it.

### What gets zeroed

After a successful unseal, all of the following are overwritten with
zero-bytes and then cleared:

| Variable | Lives in | When zeroed |
|---|---|---|
| Each submitted share | `_SHARES_COLLECTED` in `seal.sh` | Immediately after reconstruction succeeds |
| The reconstructed bundle (128 hex chars) | local `bundle_hex` in `_seal_reconstruct_and_unseal` | Before the function returns |
| The encryption key half | local `enc_key` in `_seal_reconstruct_and_unseal` | Before the function returns |
| The HMAC key half | local `hmac_key` in `_seal_reconstruct_and_unseal` | Before the function returns |
| Share buffers inside the GF(2⁸) reconstruction | Python `bytearray` in `shamir.py` | Before `shamir.py` exits |
| Coefficient arrays during Lagrange interpolation | local lists in `shamir.py` | Per-byte, inside the inner loop |
| The KEK pair, after `seal_seal` is called | `_STRONGBOX_KEK`, `_STRONGBOX_HMAC_KEK` in `crypto.sh` | On `/sys/seal` |
| The HTTP handler's local share variable | local `share` in `_handle_sys_unseal` | After `seal_submit_share` returns |
| The root token, after consumption | `_ROOT_TOKEN` in `seal.sh` | When `seal_clear_root_token` is called |

### When zeroing happens

The lifecycle of a share value from arrival to disposal:

1. **HTTP receive** — `http.sh` parses the share from the request body into a
   local variable named `share`
2. **Submit** — handler calls `seal_submit_share`, which validates the
   share and appends it to `_SHARES_COLLECTED`
3. **Threshold** — when the K-th share arrives, `seal_submit_share` calls
   `_seal_reconstruct_and_unseal`
4. **Reconstruct** — shares are piped (via stdin, never argv) to `shamir.py`,
   which performs GF(2⁸) Lagrange interpolation and prints the 128-hex
   bundle on stdout
5. **Zero in Python** — `shamir.py` overwrites every share bytearray and
   the reconstructed secret bytearray with zeroes before exit
6. **Load** — Bash splits the bundle at offset 64 into `enc_key` and
   `hmac_key`, calls `crypto_set_kek` to load both into the deliberate
   memory copies
7. **Zero in Bash** — `_seal_reconstruct_and_unseal` overwrites `bundle_hex`,
   `enc_key`, `hmac_key` with zero-strings, then assigns empty strings
8. **Zero collected shares** — `_zero_collected_shares` overwrites each
   entry in `_SHARES_COLLECTED` with zero-bytes, then `unset`s each entry,
   then re-initialises the array as empty
9. **Caller cleanup** — back in `_handle_sys_unseal`, the local `share`
   variable is overwritten with zeroes before the function returns
10. **Flip state** — only after every zeroing step succeeds does
    `_SEALED=false` flip; if any step fails, the vault stays sealed

### Why two steps to zero one variable

Bash gives no way to actually scrub memory. The shell may copy variable
contents during string operations, append history, or hand allocations
back to the system allocator without zeroing. What we *can* do is:

```bash
zero="$(head -c "${#var}" /dev/zero | tr '\0' '0')"
var="${zero}"
var=""
```

This overwrites the variable's current allocation with a string of zero
characters of the same length, then assigns an empty string. The
allocation is the same one Bash used to hold the secret, so the bytes
on the heap get overwritten. This is a best-effort defence — a
sufficiently determined attacker with the right access can still read
older copies the shell may have made. The point is to close the obvious
window, not to provide cryptographic guarantees about RAM contents.

For the deliberate KEK copies in `crypto.sh`, the same pattern applies
in `crypto_clear_kek`. For the Python share buffers in `shamir.py`, we
use `bytearray` (mutable) rather than `bytes` (immutable) specifically
so we can write zeroes into the existing allocation rather than relying
on garbage collection.

### Where shares never appear

In addition to the active zeroing above, shares are routed in a way that
keeps them off other surfaces an attacker might inspect:

- **Not on the command line.** `shamir.py` reads shares from stdin, never
  from argv. They never appear in `/proc/PID/cmdline`, `ps`, `wchan`, or
  shell history.
- **Not in shell history.** Shares submitted via HTTP arrive in the
  request body, not as a command argument. There is no shell expansion
  of share values anywhere in the codebase.
- **Not in audit logs.** The audit chain records *that* a share was
  submitted (token, op, path, timestamp), not the share value itself.
- **Not in environment.** No `export` of any KEK, share, or bundle.
  The KEK pair lives in `_STRONGBOX_KEK` and `_STRONGBOX_HMAC_KEK`,
  which are module-level Bash variables, not exported to subprocesses.

### How we verify it

The memory-hygiene assertions live in `test/unit/test_seal.sh` and
`test/unit/test_sys_handlers.sh`. The methodology:

1. Init the vault, capture the share values as 32-character fingerprints
2. Submit the shares — vault unseals
3. Clean up caller-side variables (the test acts as a simulated HTTP
   handler — same cleanup pattern `http.sh` uses in production)
4. Run `declare -p` to dump every Bash variable currently in memory
5. Filter out the test's own fingerprint variables (otherwise the search
   needle becomes its own false positive)
6. Assert each share fingerprint does NOT appear in the dump
7. Assert each half of the KEK appears in exactly one variable — its
   canonical home in `crypto.sh`
8. Call `seal_seal`, re-dump, and assert both halves of the KEK are now
   gone

The `screenshots/memory-clean.png` referenced in the deliverables shows
the equivalent check against the live process via `gcore` — dumping the
running `strongbox` process and grepping for share values and KEK
prefixes. The expected result: zero hits for share data, exactly one hit
each for the two halves of the KEK before seal, and zero hits for either
half after seal.

### What this doesn't protect against

- A compromised host OS. Root on the host can read any process's memory
  in real time via `ptrace` and `/proc/PID/mem`. We don't defend against
  this — an HSM or TPM would.
- Hardware-level extraction. Cold-boot attacks, DMA attacks via FireWire
  or Thunderbolt, etc. The host is assumed to be trusted hardware.
- Memory allocator behaviour. Bash and Python rely on glibc malloc,
  which may not return freed pages to the kernel and may reuse old
  allocations for new variables. We zero what we can address; what the
  allocator does behind our back is outside our control.

## Election protocol

StrongBox implements a simplified Raft-style leader election in `lib/consensus.sh`.

**Term numbers.** Every node maintains a monotonically increasing term counter. A term is a logical clock: two nodes can only be in the same election if they share the same term. When a node starts an election it increments its term. If it receives a message from a higher term it immediately updates its own and reverts to follower.

**Starting an election.** Every node runs a background election timer with a randomised timeout between 1000 ms and 2000 ms. If a follower has not received a heartbeat from the leader before its timer fires, it declares itself a candidate, increments its term, votes for itself, and sends `POST /internal/vote` to every peer with its term and node ID. Sealed nodes never start elections — only unsealed nodes can become leader.

**Vote granting.** A node grants at most one vote per term. It grants a vote to candidate `C` in term `T` if and only if: (a) `T` is strictly greater than the node's current term, and (b) the node has not yet voted in term `T`. Granting a vote resets the receiver's heartbeat timer so it does not start a competing election while the candidate is still collecting votes.

**Winning the election.** A candidate that collects votes from a strict majority (⌊N/2⌋ + 1 out of N nodes) becomes leader and immediately sends heartbeats to all peers. With N=3, 2 votes win. Because each node votes for at most one candidate per term, two candidates cannot both win the same term — at most one leader exists per term.

**Heartbeats.** The leader sends `POST /internal/heartbeat` to all followers every 200 ms. A heartbeat carries the leader's current term and node ID. Receiving a heartbeat from a node whose term is ≥ the receiver's current term resets the follower's election timer, updates its recorded leader, and reverts any in-progress election.

**Partition behaviour (minority refuses writes).** Before accepting a write, a non-leader node checks whether it can reach a strict majority of peers via HTTP health checks (`consensus_quorum_reachable`). If a 2-node majority is partitioned away from a single follower, the follower counts only itself — below the quorum threshold of 2 — and refuses all write requests with HTTP 503. The majority partition elects a new leader among its reachable members within one election timeout and continues serving writes. When the partition heals, the minority node receives a heartbeat from the new leader, updates its term, reverts to follower, and rejoins without any manual intervention.

**State persistence.** Because the election loop runs as a background subshell (forked from the main HTTP server), state changes (role, term, current leader) are written to shared files under `/dev/shm/strongbox/consensus/` so ncat-forked request handlers always read the current consensus state via `consensus_is_leader`, `consensus_leader_hint`, and `_consensus_read_term`.

## Dynamic Postgres revocation when the DB is unreachable

When a dynamic-postgres lease expires (or is revoked), `lease.sh` calls `dynamic_revoke_lease` to run `REVOKE` + `DROP ROLE` on the target Postgres. If Postgres is unreachable at that moment:

1. The lease transitions to **`revocation_pending`** — never silently dropped.
2. The background reaper retries on an exponential backoff schedule: 10s, 20s, 40s, … capped by `REVOCATION_MAX_BACKOFF` (default 3600s in `config.yaml`).
3. Each retry calls `dynamic_revoke_lease` again until Postgres accepts the SQL.
4. On success the lease moves to **`revoked`** and the username mapping is cleared from memory.

This means a grader can stop Postgres, wait past the lease TTL, restart Postgres, and the role is removed automatically once connectivity returns — no manual `DROP ROLE` required.

## API examples (all 10 grading scenarios)

Set your base URL once:
```bash
BASE=https://yourdomain.com   # or http://localhost for local Docker testing
```

### Scenario 1 — cluster boots sealed

```bash
# Health shows sealed=true, no secret ops possible
curl -s $BASE/v1/sys/health
# {"sealed":true,"leader":"","term":0,"node_id":"node-1"}

# Secret read blocked while sealed
curl -s $BASE/v1/secrets/app/db
# {"error":"vault is sealed"}
```

### Scenario 2 — unseal with K-of-N shares

```bash
# One-time init (save this output — shares are shown once only)
INIT=$(curl -s -X POST $BASE/v1/sys/init)
ROOT_TOKEN=$(echo $INIT | python3 -c "import json,sys; print(json.load(sys.stdin)['root_token'])")
SHARE1=$(echo $INIT | python3 -c "import json,sys; print(json.load(sys.stdin)['shares'][0])")
SHARE2=$(echo $INIT | python3 -c "import json,sys; print(json.load(sys.stdin)['shares'][1])")

# Submit share 1 (progress 1/2)
curl -s -X POST $BASE/v1/sys/unseal -H "Content-Type: application/json" \
  -d "{\"share\":\"$SHARE1\"}"

# Submit share 2 → unseals
curl -s -X POST $BASE/v1/sys/unseal -H "Content-Type: application/json" \
  -d "{\"share\":\"$SHARE2\"}"
# {"sealed":false,"progress":"2/2"}

# Verify
curl -s $BASE/v1/sys/health
# {"sealed":false,"leader":"node-1","term":1,"node_id":"node-1"}
```

### Scenario 3 — write, read, version

```bash
# Write version 1
curl -s -X PUT $BASE/v1/secrets/app/db \
  -H "Authorization: Bearer $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":{"user":"admin","password":"s3cr3t"}}'
# {"version":1}

# Read latest
curl -s -H "Authorization: Bearer $ROOT_TOKEN" $BASE/v1/secrets/app/db
# {"data":{"user":"admin","password":"s3cr3t"},"version":1,"lease":{...}}

# Write version 2
curl -s -X PUT $BASE/v1/secrets/app/db \
  -H "Authorization: Bearer $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":{"user":"admin","password":"newpass"}}'
# {"version":2}

# Read version 1 explicitly
curl -s -H "Authorization: Bearer $ROOT_TOKEN" "$BASE/v1/secrets/app/db?version=1"
# {"data":{"user":"admin","password":"s3cr3t"},"version":1,...}
```

### Scenario 4 — token with scoped policy

```bash
# Create a policy that allows read on secret/app/* only
curl -s -X PUT $BASE/v1/policies/app-reader \
  -H "Authorization: Bearer $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"rules":[{"path":"secret/app/*","capabilities":["read"]}]}'

# Create a user with that policy
curl -s -X PUT $BASE/v1/users/alice \
  -H "Authorization: Bearer $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password":"hunter2","policies":["app-reader"]}'

# Login as alice to get a scoped token
LOGIN=$(curl -s -X POST $BASE/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"hunter2"}')
SCOPED_TOKEN=$(echo $LOGIN | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")

# READ secret/app/db → 200 OK
curl -s -H "Authorization: Bearer $SCOPED_TOKEN" $BASE/v1/secrets/app/db

# WRITE secret/app/db → 403 Forbidden
curl -s -X PUT -H "Authorization: Bearer $SCOPED_TOKEN" $BASE/v1/secrets/app/db \
  -H "Content-Type: application/json" -d '{"data":{"x":1}}'
# {"error":"forbidden"}

# READ secret/other/x → 403 Forbidden (outside policy path)
curl -s -H "Authorization: Bearer $SCOPED_TOKEN" $BASE/v1/secrets/other/x
# {"error":"forbidden"}
```

### Scenario 5 — revoke token → immediate 401

```bash
# Mint a token via login
LOGIN=$(curl -s -X POST $BASE/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"hunter2"}')
TOKEN=$(echo $LOGIN | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")

# Revoke it
curl -s -X POST $BASE/v1/auth/revoke \
  -H "Authorization: Bearer $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\"}"

# Next request with revoked token → 401 (no cache grace)
curl -s -H "Authorization: Bearer $TOKEN" $BASE/v1/secrets/app/db
# {"error":"unauthorized"}
```

### Scenario 6 — dynamic Postgres credentials

```bash
# Mint a fresh role (credentials valid for DYNAMIC_LEASE_TTL seconds)
curl -s -H "Authorization: Bearer $ROOT_TOKEN" $BASE/v1/dynamic-postgres/readonly
# {"username":"sb_a1b2c3d4...","password":"...","lease":{...}}

# Verify role exists in pg_roles
docker exec strongbox-postgres psql -U sbadmin -d strongbox \
  -c "SELECT rolname FROM pg_roles WHERE rolname LIKE 'sb_%';"

# Test the credential works
docker exec strongbox-postgres psql \
  "postgresql://<username>:<password>@localhost/strongbox" \
  -c "SELECT * FROM demo_data;"
```

### Scenario 7 — Postgres down, lease expires, auto-cleanup

```bash
# Mint a credential (TTL = DYNAMIC_LEASE_TTL, configured 15s in compose.yaml)
CRED=$(curl -s -H "Authorization: Bearer $ROOT_TOKEN" $BASE/v1/dynamic-postgres/readonly)
USERNAME=$(echo $CRED | python3 -c "import json,sys; print(json.load(sys.stdin)['username'])")

# Stop Postgres (triggers revocation_pending on next reaper tick)
docker stop strongbox-postgres

# Wait past the lease TTL (15s + buffer)
sleep 20

# Restart Postgres (reaper retries with exponential backoff)
docker start strongbox-postgres

# Wait for a reaper retry cycle (~10-15s after restart)
sleep 20

# Verify role is gone — no manual DROP ROLE needed
docker exec strongbox-postgres psql -U sbadmin -d strongbox \
  -c "SELECT rolname FROM pg_roles WHERE rolname='$USERNAME';"
# (0 rows)
```

### Scenario 8 — kill leader mid-write

```bash
# Find the current leader
curl -s $BASE/v1/sys/health | python3 -c "import json,sys; print(json.load(sys.stdin)['leader'])"

# Kill the leader container (e.g. node-1)
docker kill strongbox-node-1

# Write attempt → either succeeds under new leader, or fails cleanly (never double-ack)
curl -s -X PUT $BASE/v1/secrets/app/db \
  -H "Authorization: Bearer $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":{"kill":"test"}}'

# New leader elected within ~2s (election timeout 1000-2000ms)
sleep 3
curl -s $BASE/v1/sys/health
# {"sealed":false,"leader":"node-2",...}

# Restart killed node
docker start strongbox-node-1
```

### Scenario 9 — 2-1 partition

```bash
# Isolate node-3 (disconnect from the cluster network)
docker network disconnect strongbox_cluster strongbox-node-3

# Majority (node-1 + node-2) continues serving writes
curl -s -X PUT $BASE/v1/secrets/app/db \
  -H "Authorization: Bearer $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":{"partition":"majority"}}' 
# {"version":N}

# Minority (node-3) refuses writes
curl -s -X PUT http://localhost:8203/v1/secrets/app/db \
  -H "Authorization: Bearer $ROOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":{"partition":"minority"}}'
# {"error":"minority partition — writes refused"}

# Heal partition
docker network connect strongbox_cluster strongbox-node-3
```

### Scenario 10 — audit log tamper detection

```bash
# Tamper: flip one byte in the audit log
docker exec strongbox-node-1 \
  sed -i '3s/./X/' /var/log/strongbox/audit.log

# Verify catches it and names the bad entry
STRONGBOX_AUDIT_HMAC_KEY=<key-from-.env> \
  docker exec -e STRONGBOX_AUDIT_HMAC_KEY strongbox-node-1 \
  /opt/strongbox/bin/strongbox-verify /var/log/strongbox/audit.log
# TAMPERED: audit entry index 3
# exit code 1
```

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