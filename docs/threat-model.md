# StrongBox — threat model

## What we protect against

| Threat | Mitigation |
|--------|------------|
| Plaintext secrets at rest | AES-256-GCM envelope encryption; random DEK per secret wrapped by KEK |
| KEK exposure on disk | KEK lives in memory only; never written to any file or log |
| Key material in heap post-unseal | Shamir shares and reconstructed KEK zeroed immediately after unseal |
| Stolen Bearer token | Token state is server-side; revocation is synchronous — fails on next request |
| Audit log tampering | HMAC-SHA256 chain; each entry covers the previous entry's hash |
| Writes during minority partition | Minority node refuses all writes unconditionally |
| Stale DB credentials after lease expiry | Reaper enforces TTL; REVOKE + DROP ROLE executed on Postgres |
| Password exposure | Argon2id hashing; plaintext never stored or logged |
| Unauthenticated API access | All non-/sys routes require Bearer token |
| HTTP snooping from internet | TLS 1.2/1.3 terminated at Nginx; HTTP redirects to HTTPS |
| Internal cluster traffic interception | /internal/* routes blocked at Nginx; only reachable on Docker bridge |

## What we do not protect against

| Limitation | Notes |
|------------|-------|
| Compromised host OS | Root access allows reading process memory; an HSM would address this |
| In-memory durability | Full cluster restart loses all secrets (by design for this stage) |
| Audit HMAC key rotation | Chain only verifiable with current KEK; re-seal breaks historical verification |
| Network-level DDoS | No rate limiting at application layer |
| Timing side-channels | Bash string comparison is not constant-time |
| Nginx → node plaintext | Traffic on Docker bridge is unencrypted; acceptable for same-host deployment |

## Trust boundaries

```
[ Internet ]
    │  HTTPS (TLS 1.2/1.3)
    ▼
[ Nginx ]  ← /internal/* blocked here
    │  HTTP (Docker bridge, not internet-exposed)
    ▼
[ StrongBox node 1 ] ←── mTLS TODO ───→ [ Node 2 ] [ Node 3 ]
    │
    │  psql (Docker bridge)
    ▼
[ PostgreSQL ]
```

The Nginx → node segment is plaintext on the Docker bridge network.
Operators in higher-security environments should add mTLS on this segment.
Inter-node consensus traffic (/internal/*) should also use mTLS in production.

## Nonce strategy

Random 96-bit nonces from `/dev/urandom` for every AES-256-GCM operation.
Birthday bound: collision probability exceeds 2^-32 after approximately 2^48
encryptions per key. At expected secret-write rates this is safe.
A counter-based nonce would require atomic persistence across restarts,
which reintroduces the sealed/unseal replay risk we specifically avoid.
