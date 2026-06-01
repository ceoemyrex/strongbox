CREATE ROLE readonly NOLOGIN;
GRANT CONNECT ON DATABASE strongbox TO readonly;
GRANT USAGE ON SCHEMA public TO readonly;

CREATE TABLE IF NOT EXISTS demo_data (
    id   SERIAL PRIMARY KEY,
    note TEXT NOT NULL DEFAULT 'strongbox dynamic creds test row'
);

INSERT INTO demo_data (note) VALUES ('seed row');

GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO readonly;
