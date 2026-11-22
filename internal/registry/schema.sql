-- Run explicitly once as the dedicated setup owner against the intended database.
-- After initialization, grant the application role USAGE on this schema, SELECT on
-- format, and SELECT/INSERT/UPDATE on records. The runtime role must not own these
-- objects or have schema/database creation, format-write, or elevated privileges.
BEGIN;

CREATE SCHEMA tlsbeacon_registry;
REVOKE ALL ON SCHEMA tlsbeacon_registry FROM PUBLIC;

CREATE TABLE tlsbeacon_registry.format (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    version integer NOT NULL CHECK (version > 0)
);

CREATE TABLE tlsbeacon_registry.records (
    kind text NOT NULL CHECK (kind IN ('endpoint', 'trust', 'policy')),
    key text NOT NULL CHECK (key <> ''),
    value bytea NOT NULL,
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    PRIMARY KEY (kind, key)
);

INSERT INTO tlsbeacon_registry.format (singleton, version) VALUES (true, 1);

COMMIT;
