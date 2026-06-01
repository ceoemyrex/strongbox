-- Template role used by dynamic credential issuance.
-- Dynamic users are created with LOGIN and granted this role at runtime,
-- then dropped when their lease expires or is revoked.
CREATE ROLE readonly NOLOGIN;
GRANT CONNECT ON DATABASE strongbox TO readonly;
GRANT USAGE ON SCHEMA public TO readonly;

-- Minimal table so dynamic users have something to SELECT against during tests
CREATE TABLE IF NOT EXISTS demo_data (
    id   SERIAL PRIMARY KEY,
    note TEXT NOT NULL DEFAULT 'strongbox dynamic creds test row'
);

INSERT INTO demo_data (note) VALUES ('seed row');

-- Current and future tables — ALTER DEFAULT PRIVILEGES covers tables created after init
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO readonly;
