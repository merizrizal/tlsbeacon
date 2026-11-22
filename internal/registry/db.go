package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const formatVersion = 1

type Error struct {
	Code    string
	Message string
	Action  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message + " " + e.Action }

func storageError() error {
	return &Error{"storage_error", "The registry could not be accessed safely.", "Check database availability, privileges and registry format."}
}

func unknownCommit() error {
	return &Error{"commit_outcome_unknown", "The registry commit outcome is unknown.", "Read back the registry before retrying; do not blindly repeat a creation."}
}

func notFound() error {
	return &Error{"not_found", "The requested registry record does not exist.", "Check the requested identifier."}
}

func revisionConflict() error {
	return &Error{"revision_conflict", "The registry record changed during the operation.", "Read back the registry before deciding whether to retry."}
}

type DB struct {
	gate chan struct{}
	conn *pgx.Conn
}

func (db *DB) enter(ctx context.Context) error {
	select {
	case db.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return storageError()
	}
}

func (db *DB) leave() { <-db.gate }

// Open connects using a prequalified configuration and restricted application identity.
// The caller must qualify connection paths, credentials and transport; Open preserves TLS settings.
// It never creates or upgrades a registry or parses implicit environment/file configuration.
func Open(ctx context.Context, connection *pgx.ConnConfig) (*DB, error) {
	if connection == nil {
		return nil, storageError()
	}
	config := connection.Copy()
	if config.RuntimeParams == nil {
		config.RuntimeParams = make(map[string]string)
	}
	config.RuntimeParams["search_path"] = "pg_catalog"
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, storageError()
	}
	db := &DB{gate: make(chan struct{}, 1), conn: conn}
	_, err = conn.Exec(ctx, `SET search_path = pg_catalog`)
	if err == nil {
		err = db.validate(ctx)
	}
	if err != nil {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
		return nil, storageError()
	}
	return db, nil
}

func (db *DB) Close(ctx context.Context) error {
	if err := db.enter(ctx); err != nil {
		return err
	}
	defer db.leave()
	if err := db.conn.Close(ctx); err != nil {
		return storageError()
	}
	return nil
}

func roleAccessMode(serverVersion int) string {
	if serverVersion >= 160000 {
		return "SET"
	}
	return "MEMBER"
}

func (db *DB) validate(ctx context.Context) error {
	var serverVersion int
	if err := db.conn.QueryRow(ctx, `SELECT current_setting('server_version_num')::integer`).Scan(&serverVersion); err != nil || serverVersion <= 0 {
		return storageError()
	}
	var unsafe, readable, writable bool
	err := db.conn.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
			WHERE pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER')
			AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls))
		OR pg_catalog.has_database_privilege(current_user, current_database(), 'CREATE')
		OR pg_catalog.has_schema_privilege(current_user, 'tlsbeacon_registry', 'CREATE')
		OR pg_catalog.has_schema_privilege(current_user, 'public', 'CREATE')
		OR pg_catalog.has_table_privilege(current_user, 'tlsbeacon_registry.format', 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
		OR pg_catalog.has_table_privilege(current_user, 'tlsbeacon_registry.records', 'DELETE, TRUNCATE, REFERENCES, TRIGGER')
		OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE pg_catalog.pg_has_role(current_user, r.oid, $1) AND (
			pg_catalog.has_database_privilege(r.oid, current_database(), 'CREATE')
			OR pg_catalog.has_schema_privilege(r.oid, 'tlsbeacon_registry', 'CREATE')
			OR pg_catalog.has_schema_privilege(r.oid, 'public', 'CREATE')
			OR pg_catalog.has_table_privilege(r.oid, 'tlsbeacon_registry.format', 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
			OR pg_catalog.has_table_privilege(r.oid, 'tlsbeacon_registry.records', 'DELETE, TRUNCATE, REFERENCES, TRIGGER'))),
		pg_catalog.has_schema_privilege(current_user, 'tlsbeacon_registry', 'USAGE')
		AND pg_catalog.has_table_privilege(current_user, 'tlsbeacon_registry.format', 'SELECT')
		AND pg_catalog.has_table_privilege(current_user, 'tlsbeacon_registry.records', 'SELECT'),
		pg_catalog.has_table_privilege(current_user, 'tlsbeacon_registry.records', 'INSERT')
		AND pg_catalog.has_table_privilege(current_user, 'tlsbeacon_registry.records', 'UPDATE')`, roleAccessMode(serverVersion)).Scan(&unsafe, &readable, &writable)
	if err != nil || unsafe || !readable || !writable {
		return storageError()
	}
	rows, err := db.conn.Query(ctx, `SELECT singleton, version FROM tlsbeacon_registry.format`)
	if err != nil {
		return storageError()
	}
	count := 0
	valid := true
	for rows.Next() {
		var singleton bool
		var version int
		if err := rows.Scan(&singleton, &version); err != nil || !singleton || version != formatVersion {
			valid = false
		}
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil || !valid || count != 1 {
		return storageError()
	}
	var formatColumns, recordColumns, constraints bool
	err = db.conn.QueryRow(ctx, `SELECT
		(SELECT array_agg(a.attname || ':' || pg_catalog.format_type(a.atttypid, a.atttypmod) || ':' || a.attnotnull::text ORDER BY a.attnum)
		 FROM pg_catalog.pg_attribute a WHERE a.attrelid='tlsbeacon_registry.format'::regclass AND a.attnum > 0 AND NOT a.attisdropped)
		 = ARRAY['singleton:boolean:true', 'version:integer:true'],
		(SELECT array_agg(a.attname || ':' || pg_catalog.format_type(a.atttypid, a.atttypmod) || ':' || a.attnotnull::text ORDER BY a.attnum)
		 FROM pg_catalog.pg_attribute a WHERE a.attrelid='tlsbeacon_registry.records'::regclass AND a.attnum > 0 AND NOT a.attisdropped)
		 = ARRAY['kind:text:true', 'key:text:true', 'value:bytea:true', 'digest:bytea:true'],
		(SELECT count(*)=7 FROM pg_catalog.pg_constraint c
		 WHERE c.convalidated AND (
		   (c.conrelid='tlsbeacon_registry.format'::regclass AND
		     ((c.conname='format_pkey' AND pg_catalog.pg_get_constraintdef(c.oid)='PRIMARY KEY (singleton)') OR
		      (c.conname='format_singleton_check' AND pg_catalog.pg_get_constraintdef(c.oid)='CHECK (singleton)') OR
		      (c.conname='format_version_check' AND pg_catalog.pg_get_constraintdef(c.oid)='CHECK ((version > 0))'))) OR
		   (c.conrelid='tlsbeacon_registry.records'::regclass AND
		     ((c.conname='records_pkey' AND pg_catalog.pg_get_constraintdef(c.oid)='PRIMARY KEY (kind, key)') OR
		      (c.conname='records_key_check' AND pg_catalog.pg_get_constraintdef(c.oid)='CHECK ((key <> ''''::text))') OR
		      (c.conname='records_digest_check' AND pg_catalog.pg_get_constraintdef(c.oid)='CHECK ((octet_length(digest) = 32))') OR
		      (c.conname='records_kind_check' AND pg_catalog.pg_get_constraintdef(c.oid)='CHECK ((kind = ANY (ARRAY[''endpoint''::text, ''trust''::text, ''policy''::text])))')))))`).Scan(&formatColumns, &recordColumns, &constraints)
	if err != nil || !formatColumns || !recordColumns || !constraints {
		return storageError()
	}
	rows, err = db.conn.Query(ctx, `SELECT kind, key, value, digest FROM tlsbeacon_registry.records`)
	if err != nil {
		return storageError()
	}
	valid = true
	for rows.Next() {
		var kind, key string
		var value, digest []byte
		if err := rows.Scan(&kind, &key, &value, &digest); err != nil || !validKey(kind, key) || value == nil {
			valid = false
			break
		}
		sum := recordDigest(kind, key, value)
		if !bytes.Equal(digest, sum[:]) {
			valid = false
			break
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil || !valid {
		return storageError()
	}
	return nil
}

func validKey(kind, key string) bool {
	return (kind == "endpoint" || kind == "trust" || kind == "policy") && key != ""
}

func recordDigest(kind, key string, value []byte) [sha256.Size]byte {
	hash := sha256.New()
	for _, part := range [][]byte{[]byte(kind), []byte(key), value} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write(part)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

// Read returns a stored record or an explicit error; it never substitutes defaults.
func (db *DB) Read(ctx context.Context, kind, key string) ([]byte, error) {
	if err := db.enter(ctx); err != nil {
		return nil, err
	}
	defer db.leave()
	if !validKey(kind, key) {
		return nil, storageError()
	}
	var value, digest []byte
	err := db.conn.QueryRow(ctx, `SELECT value, digest FROM tlsbeacon_registry.records WHERE kind=$1 AND key=$2`, kind, key).Scan(&value, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound()
	}
	if err != nil || value == nil {
		return nil, storageError()
	}
	sum := recordDigest(kind, key, value)
	if !bytes.Equal(digest, sum[:]) {
		return nil, storageError()
	}
	return value, nil
}

// Write atomically compares and replaces one complete record, acknowledging only after commit.
// A nil expected value requires absence; a non-nil expected value must match the current bytes.
func (db *DB) Write(ctx context.Context, kind, key string, expected, value []byte) error {
	if err := db.enter(ctx); err != nil {
		return err
	}
	defer db.leave()
	if !validKey(kind, key) || value == nil {
		return storageError()
	}
	tx, err := db.conn.Begin(ctx)
	if err != nil {
		return storageError()
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()
	var previous, previousDigest []byte
	err = tx.QueryRow(ctx, `SELECT value, digest FROM tlsbeacon_registry.records WHERE kind=$1 AND key=$2 FOR UPDATE`, kind, key).Scan(&previous, &previousDigest)
	digest := recordDigest(kind, key, value)
	var storedKind, storedKey string
	var storedValue, storedDigest []byte
	written := false
	if errors.Is(err, pgx.ErrNoRows) {
		if expected != nil {
			return revisionConflict()
		}
		err = tx.QueryRow(ctx, `INSERT INTO tlsbeacon_registry.records (kind, key, value, digest) VALUES ($1, $2, $3, $4) ON CONFLICT (kind, key) DO NOTHING RETURNING kind, key, value, digest`, kind, key, value, digest[:]).Scan(&storedKind, &storedKey, &storedValue, &storedDigest)
		if errors.Is(err, pgx.ErrNoRows) {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tlsbeacon_registry.records WHERE kind=$1 AND key=$2)`, kind, key).Scan(&exists); err != nil || !exists {
				return storageError()
			}
			return revisionConflict()
		}
		written = true
	} else if err == nil {
		previousHash := recordDigest(kind, key, previous)
		if previous == nil || !bytes.Equal(previousDigest, previousHash[:]) {
			return storageError()
		}
		if expected == nil || !bytes.Equal(previous, expected) {
			return revisionConflict()
		}
		if !bytes.Equal(previous, value) {
			err = tx.QueryRow(ctx, `UPDATE tlsbeacon_registry.records SET value=$3, digest=$4 WHERE kind=$1 AND key=$2 RETURNING kind, key, value, digest`, kind, key, value, digest[:]).Scan(&storedKind, &storedKey, &storedValue, &storedDigest)
			written = true
		}
	}
	if err != nil || (written && (storedKind != kind || storedKey != key || !bytes.Equal(storedValue, value) || !bytes.Equal(storedDigest, digest[:]))) {
		return storageError()
	}
	if err := tx.Commit(ctx); err != nil {
		return classifyCommit(err)
	}
	return nil
}

func classifyCommit(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrTxCommitRollback) {
		return storageError()
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Severity == "ERROR" && !strings.HasPrefix(pgErr.Code, "08") && pgErr.Code != "40003" {
		return storageError()
	}
	return unknownCommit()
}
