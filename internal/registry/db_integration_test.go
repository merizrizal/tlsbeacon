package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fixtureInspect struct {
	ID    string `json:"Id"`
	Image string `json:"Image"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	HostConfig struct {
		NetworkMode  string         `json:"NetworkMode"`
		Privileged   bool           `json:"Privileged"`
		PortBindings map[string]any `json:"PortBindings"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports    map[string]any `json:"Ports"`
		Networks map[string]struct {
			IPAddress         string `json:"IPAddress"`
			GlobalIPv6Address string `json:"GlobalIPv6Address"`
			Gateway           string `json:"Gateway"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
}

func protectedFixture(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("TLSBEACON_REGISTRY_FIXTURE_DIR")
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || filepath.Dir(dir) != "/tmp" || strings.ContainsAny(dir, " \t\r\n") {
		t.Fatal("an absolute verified disposable fixture directory is required")
	}
	parent, err := os.Lstat("/tmp")
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSticky == 0 {
		t.Fatal("fixture parent is unsafe")
	}
	parentStat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != 0 {
		t.Fatal("fixture parent ownership is unsafe")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("fixture directory is not protected")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		t.Fatal("fixture directory is not owned by this operator")
	}
	readID := func(name string) string {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("fixture ownership evidence is missing or unsafe")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uint32(os.Geteuid()) {
			t.Fatal("fixture evidence has the wrong owner")
		}
		b, err := os.ReadFile(path)
		id := strings.TrimSpace(string(b))
		if err != nil || len(id) != 64 {
			t.Fatal("invalid fixture identity")
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Fatal("invalid fixture identity")
		}
		return id
	}
	id, volume := readID("container-id"), readID("volume-id")
	output, err := exec.Command("docker", "inspect", "--type", "container", id).Output()
	if err != nil {
		t.Fatal("cannot inspect owned fixture")
	}
	var containers []fixtureInspect
	if json.Unmarshal(output, &containers) != nil || len(containers) != 1 {
		t.Fatal("invalid fixture inspection")
	}
	c := containers[0]
	network, hasNone := c.NetworkSettings.Networks["none"]
	if c.ID != id || c.Image != "sha256:c7fedce47eff6a78cb35dad6b627f0d684107f75ab15c0870e40c093766ba452" || !c.State.Running || c.HostConfig.NetworkMode != "none" || c.HostConfig.Privileged || len(c.HostConfig.PortBindings) != 0 || len(c.NetworkSettings.Ports) != 0 || len(c.NetworkSettings.Networks) != 1 || !hasNone || network.IPAddress != "" || network.GlobalIPv6Address != "" || network.Gateway != "" || len(c.Mounts) != 2 {
		t.Fatal("fixture identity or isolation changed")
	}
	socketDir := filepath.Join(dir, "socket")
	bind, data := false, false
	for _, mount := range c.Mounts {
		bind = bind || mount.Type == "bind" && mount.Source == socketDir && mount.Destination == "/var/run/postgresql"
		data = data || mount.Type == "volume" && mount.Name == volume && mount.Destination == "/var/lib/postgresql"
	}
	if !bind || !data {
		t.Fatal("fixture mounts changed")
	}
	out, err := exec.Command("docker", "volume", "inspect", volume, "--format", "{{.Name}}").Output()
	if err != nil || strings.TrimSpace(string(out)) != volume {
		t.Fatal("fixture volume changed")
	}
	for _, item := range []struct {
		host, container string
		socket          bool
	}{
		{socketDir, "/var/run/postgresql", false},
		{filepath.Join(socketDir, ".s.PGSQL.5432"), "/var/run/postgresql/.s.PGSQL.5432", true},
	} {
		info, err := os.Lstat(item.host)
		if err != nil || (!item.socket && !info.IsDir()) || (item.socket && info.Mode()&os.ModeSocket == 0) {
			t.Fatal("fixture socket path changed")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatal("fixture socket identity unavailable")
		}
		inside, err := exec.Command("docker", "exec", id, "stat", "-c", "%d:%i", item.container).Output()
		if err != nil || strings.TrimSpace(string(inside)) != fmt.Sprintf("%d:%d", st.Dev, st.Ino) {
			t.Fatal("fixture socket path was replaced")
		}
	}
	return socketDir
}

func connectFixture(t *testing.T, socket, role, database string) *pgx.Conn {
	t.Helper()
	config, err := pgx.ParseConfig("host=" + socket + " user=" + role + " dbname=" + database + " sslmode=disable")
	if err != nil {
		t.Fatal("invalid test fixture configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("cannot connect to owned fixture")
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func newFixtureDatabase(t *testing.T, initialize bool) (string, *pgx.Conn) {
	t.Helper()
	t.Setenv("PGPASSFILE", "/dev/null")
	t.Setenv("PGSERVICEFILE", "/dev/null")
	t.Setenv("PGSERVICE", "")
	socket := protectedFixture(t)
	admin := connectFixture(t, socket, "postgres", "postgres")
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("cannot generate fixture database identity")
	}
	name := "tlsbeacon_test_" + hex.EncodeToString(nonce[:])
	quoted := pgx.Identifier{name}.Sanitize()
	ctx := context.Background()
	for _, statement := range []string{
		"CREATE DATABASE " + quoted + " OWNER tlsbeacon_setup",
		"REVOKE ALL ON DATABASE " + quoted + " FROM PUBLIC",
		"GRANT CONNECT ON DATABASE " + quoted + " TO tlsbeacon_runtime",
	} {
		protectedFixture(t)
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal("fixture database setup failed")
		}
	}
	protectedFixture(t)
	setup := connectFixture(t, socket, "tlsbeacon_setup", name)
	if initialize {
		schema, err := os.ReadFile("schema.sql")
		if err != nil {
			t.Fatal("schema fixture unavailable")
		}
		if _, err = setup.Exec(ctx, string(schema), pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Fatal("fixture schema initialization failed")
		}
		grantFixture(t, setup)
	}
	return name, setup
}

func grantFixture(t *testing.T, setup *pgx.Conn) {
	t.Helper()
	protectedFixture(t)
	for _, statement := range []string{
		"GRANT USAGE ON SCHEMA tlsbeacon_registry TO tlsbeacon_runtime",
		"GRANT SELECT ON tlsbeacon_registry.format TO tlsbeacon_runtime",
		"GRANT SELECT, INSERT, UPDATE ON tlsbeacon_registry.records TO tlsbeacon_runtime",
	} {
		protectedFixture(t)
		if _, err := setup.Exec(context.Background(), statement); err != nil {
			t.Fatal("fixture grant failed")
		}
	}
}

func fixtureConfig(t *testing.T, role, name string) *pgx.ConnConfig {
	t.Helper()
	config, err := pgx.ParseConfig("host=" + protectedFixture(t) + " user=" + role + " dbname=" + name + " sslmode=disable")
	if err != nil {
		t.Fatal("invalid fixture connection configuration")
	}
	return config
}

func fixtureConnection(t *testing.T, name string) *pgx.ConnConfig {
	t.Helper()
	return fixtureConfig(t, "tlsbeacon_runtime", name)
}

func errorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestRegistryInitializationReopenAndTransactionFailures(t *testing.T) {
	name, setup := newFixtureDatabase(t, true)
	connection := fixtureConnection(t, name)
	ctx := context.Background()
	adminConnection := fixtureConfig(t, "postgres", name)
	if _, err := Open(ctx, adminConnection); errorCode(err) != "storage_error" {
		t.Fatalf("superuser registry access was not rejected: %v", err)
	}
	connection.RuntimeParams["search_path"] = "public"
	protectedFixture(t)
	db, err := Open(ctx, connection)
	if err != nil {
		t.Fatalf("initialized registry rejected: %v", err)
	}
	var searchPath string
	protectedFixture(t)
	if err := db.conn.QueryRow(ctx, `SHOW search_path`).Scan(&searchPath); err != nil || searchPath != "pg_catalog" || connection.RuntimeParams["search_path"] != "public" {
		t.Fatal("registry search path was not constrained without mutating the caller configuration")
	}
	key := "test'); DROP SCHEMA tlsbeacon_registry CASCADE; --"
	if _, err := db.Read(ctx, "policy", key); errorCode(err) != "not_found" {
		t.Fatalf("missing policy: %v", err)
	}
	protectedFixture(t)
	if err := db.Write(ctx, "policy", key, nil, []byte("original")); err != nil {
		t.Fatalf("write: %v", err)
	}
	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		t.Fatal("schema fixture unavailable")
	}
	protectedFixture(t)
	if _, err := setup.Exec(ctx, string(schema), pgx.QueryExecModeSimpleProtocol); err == nil {
		t.Fatal("reinitialization of an existing registry succeeded")
	}
	protectedFixture(t)
	if _, err := setup.Exec(ctx, `ROLLBACK`); err != nil {
		t.Fatal("fixture setup transaction did not roll back")
	}
	protectedFixture(t)
	if value, err := db.Read(ctx, "policy", key); err != nil || string(value) != "original" {
		t.Fatal("failed reinitialization altered existing data")
	}
	protectedFixture(t)
	if err := db.Write(ctx, "endpoint", "empty", nil, []byte{}); err != nil {
		t.Fatalf("empty record write: %v", err)
	}
	protectedFixture(t)
	if value, err := db.Read(ctx, "endpoint", "empty"); err != nil || len(value) != 0 {
		t.Fatalf("empty record read: %v", err)
	}
	var before, after string
	protectedFixture(t)
	if err := db.conn.QueryRow(ctx, `SELECT xmin::text FROM tlsbeacon_registry.records WHERE kind=$1 AND key=$2`, "policy", key).Scan(&before); err != nil {
		t.Fatal("fixture row identity unavailable")
	}
	protectedFixture(t)
	if err := db.Write(ctx, "policy", key, []byte("original"), []byte("original")); err != nil {
		t.Fatalf("identical write: %v", err)
	}
	protectedFixture(t)
	if err := db.conn.QueryRow(ctx, `SELECT xmin::text FROM tlsbeacon_registry.records WHERE kind=$1 AND key=$2`, "policy", key).Scan(&after); err != nil || before != after {
		t.Fatal("identical value caused a physical row update")
	}
	if err := db.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	protectedFixture(t)
	db, err = Open(ctx, connection)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db.Close(ctx)
	value, err := db.Read(ctx, "policy", key)
	if err != nil || string(value) != "original" {
		t.Fatalf("committed data not read back: %v", err)
	}
	protectedFixture(t)
	if _, err := setup.Exec(ctx, `ALTER TABLE tlsbeacon_registry.records ADD CONSTRAINT fixture_reject CHECK (value <> decode('626164', 'hex'))`); err != nil {
		t.Fatal("fixture constraint failed")
	}
	if err := db.Write(ctx, "policy", key, []byte("original"), []byte("bad")); errorCode(err) != "storage_error" {
		t.Fatalf("write failure: %v", err)
	}
	value, err = db.Read(ctx, "policy", key)
	if err != nil || string(value) != "original" {
		t.Fatal("failed transaction changed prior data")
	}
	protectedFixture(t)
	_, err = setup.Exec(ctx, `CREATE FUNCTION tlsbeacon_registry.fixture_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.value = decode('636f6d6d69742d6661696c', 'hex') THEN RAISE EXCEPTION 'fixture failure' USING ERRCODE = '23514'; END IF; RETURN NEW; END $$;
		CREATE CONSTRAINT TRIGGER fixture_commit_failure AFTER INSERT OR UPDATE ON tlsbeacon_registry.records DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION tlsbeacon_registry.fixture_commit_failure();`, pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		t.Fatal("fixture deferred failure setup failed")
	}
	if err := db.Write(ctx, "policy", key, []byte("original"), []byte("commit-fail")); errorCode(err) != "storage_error" {
		t.Fatalf("known commit failure: %v", err)
	}
	value, err = db.Read(ctx, "policy", key)
	if err != nil || string(value) != "original" {
		t.Fatal("failed commit changed prior data")
	}
	protectedFixture(t)
	_, err = setup.Exec(ctx, `CREATE FUNCTION tlsbeacon_registry.fixture_suppress_or_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.value = convert_to('suppressed', 'UTF8') THEN RETURN NULL; ELSIF NEW.value = convert_to('rewrite', 'UTF8') THEN NEW.value := convert_to('different', 'UTF8'); END IF; RETURN NEW; END $$;
		CREATE TRIGGER fixture_suppress_or_rewrite BEFORE INSERT OR UPDATE ON tlsbeacon_registry.records FOR EACH ROW EXECUTE FUNCTION tlsbeacon_registry.fixture_suppress_or_rewrite();`, pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		t.Fatal("fixture trigger setup failed")
	}
	for _, candidate := range []string{"suppressed", "rewrite"} {
		protectedFixture(t)
		if err := db.Write(ctx, "policy", key, []byte("original"), []byte(candidate)); errorCode(err) != "storage_error" {
			t.Fatalf("suppressed or rewritten update was acknowledged: %v", err)
		}
		protectedFixture(t)
		if value, err := db.Read(ctx, "policy", key); err != nil || string(value) != "original" {
			t.Fatal("rejected trigger-altered update changed prior data")
		}
		protectedFixture(t)
		if err := db.Write(ctx, "policy", "new-"+candidate, nil, []byte(candidate)); errorCode(err) != "storage_error" {
			t.Fatalf("suppressed or rewritten insert was acknowledged: %v", err)
		}
		protectedFixture(t)
		if _, err := db.Read(ctx, "policy", "new-"+candidate); errorCode(err) != "not_found" {
			t.Fatalf("rejected trigger-altered insert persisted: %v", err)
		}
	}
	protectedFixture(t)
	if _, err := setup.Exec(ctx, `UPDATE tlsbeacon_registry.records SET value=$1 WHERE kind=$2 AND key=$3`, []byte("corrupt"), "policy", key); err != nil {
		t.Fatal("fixture corruption setup failed")
	}
	protectedFixture(t)
	value, err = db.Read(ctx, "policy", key)
	if errorCode(err) != "storage_error" || value != nil {
		t.Fatalf("corrupt record was accepted: %v", err)
	}
	protectedFixture(t)
	if _, err := Open(ctx, connection); errorCode(err) != "storage_error" {
		t.Fatalf("opening a corrupt registry succeeded: %v", err)
	}
	protectedFixture(t)
	if err := db.Write(ctx, "policy", key, []byte("original"), []byte("replacement")); errorCode(err) != "storage_error" {
		t.Fatalf("corrupt record was silently overwritten: %v", err)
	}
}

func TestRegistryDetectsRecordIdentityCorruption(t *testing.T) {
	name, setup := newFixtureDatabase(t, true)
	connection := fixtureConnection(t, name)
	ctx := context.Background()
	db, err := Open(ctx, connection)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close(ctx)
	protectedFixture(t)
	if err := db.Write(ctx, "endpoint", "original", nil, []byte("value")); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	protectedFixture(t)
	if err := db.Write(ctx, "endpoint", "kind-change", nil, []byte("value")); err != nil {
		t.Fatalf("second write: %v", err)
	}
	protectedFixture(t)
	if _, err := setup.Exec(ctx, `UPDATE tlsbeacon_registry.records SET key=$1 WHERE kind=$2 AND key=$3`, "changed", "endpoint", "original"); err != nil {
		t.Fatal("fixture key corruption setup failed")
	}
	protectedFixture(t)
	if _, err := db.Read(ctx, "endpoint", "changed"); errorCode(err) != "storage_error" {
		t.Fatalf("corrupt record key was accepted: %v", err)
	}
	protectedFixture(t)
	if _, err := Open(ctx, connection); errorCode(err) != "storage_error" {
		t.Fatalf("registry with corrupt record key opened: %v", err)
	}
	protectedFixture(t)
	if _, err := setup.Exec(ctx, `UPDATE tlsbeacon_registry.records SET kind=$1 WHERE kind=$2 AND key=$3`, "trust", "endpoint", "kind-change"); err != nil {
		t.Fatal("fixture kind corruption setup failed")
	}
	protectedFixture(t)
	if _, err := db.Read(ctx, "trust", "kind-change"); errorCode(err) != "storage_error" {
		t.Fatalf("corrupt record kind was accepted: %v", err)
	}
}

func TestConcurrentCreateReturnsConflict(t *testing.T) {
	name, _ := newFixtureDatabase(t, true)
	connection := fixtureConnection(t, name)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	protectedFixture(t)
	first, err := Open(ctx, connection)
	if err != nil {
		t.Fatalf("first connection: %v", err)
	}
	defer first.Close(context.Background())
	protectedFixture(t)
	second, err := Open(ctx, connection)
	if err != nil {
		t.Fatalf("second connection: %v", err)
	}
	defer second.Close(context.Background())
	protectedFixture(t)
	tx, err := first.conn.Begin(ctx)
	if err != nil {
		t.Fatal("fixture transaction failed")
	}
	defer tx.Rollback(context.Background())
	value := []byte("first")
	digest := recordDigest("endpoint", "concurrent", value)
	protectedFixture(t)
	if _, err := tx.Exec(ctx, `INSERT INTO tlsbeacon_registry.records (kind, key, value, digest) VALUES ($1, $2, $3, $4)`, "endpoint", "concurrent", value, digest[:]); err != nil {
		t.Fatal("fixture insert failed")
	}
	observer := connectFixture(t, protectedFixture(t), "tlsbeacon_runtime", name)
	pid := second.conn.PgConn().PID()
	result := make(chan error, 1)
	protectedFixture(t)
	go func() { result <- second.Write(ctx, "endpoint", "concurrent", nil, []byte("second")) }()
	blocked := false
	for ctx.Err() == nil {
		var wait *string
		if err := observer.QueryRow(ctx, `SELECT wait_event_type FROM pg_catalog.pg_stat_activity WHERE pid=$1`, pid).Scan(&wait); err != nil {
			t.Fatal("cannot observe fixture transaction barrier")
		}
		if wait != nil && *wait == "Lock" {
			blocked = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("concurrent create did not reach its lock barrier")
	}
	protectedFixture(t)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("fixture commit failed")
	}
	if err := <-result; errorCode(err) != "revision_conflict" {
		t.Fatalf("concurrent creation did not report conflict: %v", err)
	}
	protectedFixture(t)
	got, err := first.Read(ctx, "endpoint", "concurrent")
	if err != nil || string(got) != "first" {
		t.Fatal("concurrent create overwrote the first record")
	}
	protectedFixture(t)
	if err := first.Write(ctx, "endpoint", "concurrent", []byte("first"), []byte("new")); err != nil {
		t.Fatalf("current replacement: %v", err)
	}
	protectedFixture(t)
	if err := second.Write(ctx, "endpoint", "concurrent", []byte("first"), []byte("stale")); errorCode(err) != "revision_conflict" {
		t.Fatalf("stale replacement was not rejected: %v", err)
	}
	protectedFixture(t)
	got, err = first.Read(ctx, "endpoint", "concurrent")
	if err != nil || string(got) != "new" {
		t.Fatal("stale replacement overwrote current data")
	}
	protectedFixture(t)
	if err := first.Write(ctx, "endpoint", "absent", []byte("expected"), []byte("new")); errorCode(err) != "revision_conflict" {
		t.Fatalf("missing expected record was not rejected: %v", err)
	}
}

func TestConcurrentCallsOnOneHandle(t *testing.T) {
	name, _ := newFixtureDatabase(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := Open(ctx, fixtureConnection(t, name))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close(context.Background())
	start := make(chan struct{})
	results := make(chan error, 2)
	protectedFixture(t)
	for _, value := range []string{"first", "second"} {
		go func(value string) {
			<-start
			results <- db.Write(ctx, "endpoint", "shared", nil, []byte(value))
		}(value)
	}
	close(start)
	first, second := <-results, <-results
	if !((first == nil && errorCode(second) == "revision_conflict") || (second == nil && errorCode(first) == "revision_conflict")) {
		t.Fatalf("shared handle did not serialize creation: %v, %v", first, second)
	}
	protectedFixture(t)
	value, err := db.Read(ctx, "endpoint", "shared")
	if err != nil || (string(value) != "first" && string(value) != "second") {
		t.Fatal("shared handle returned an invalid record")
	}
}

func TestRegistryMissingUnsupportedAndDeniedPrivileges(t *testing.T) {
	ctx := context.Background()
	missing, missingSetup := newFixtureDatabase(t, false)
	if _, err := Open(ctx, fixtureConnection(t, missing)); errorCode(err) != "storage_error" {
		t.Fatalf("missing state: %v", err)
	}
	protectedFixture(t)
	var stillMissing bool
	if err := missingSetup.QueryRow(ctx, `SELECT to_regnamespace('tlsbeacon_registry') IS NULL`).Scan(&stillMissing); err != nil || !stillMissing {
		t.Fatal("opening a missing registry performed initialization")
	}
	name, setup := newFixtureDatabase(t, true)
	protectedFixture(t)
	if _, err := setup.Exec(ctx, `UPDATE tlsbeacon_registry.format SET version=999`); err != nil {
		t.Fatal("fixture version setup failed")
	}
	if _, err := Open(ctx, fixtureConnection(t, name)); errorCode(err) != "storage_error" {
		t.Fatalf("unsupported version: %v", err)
	}
	protectedFixture(t)
	var version int
	if err := setup.QueryRow(ctx, `SELECT version FROM tlsbeacon_registry.format`).Scan(&version); err != nil || version != 999 {
		t.Fatal("unsupported registry was modified")
	}
	protectedFixture(t)
	if _, err := setup.Exec(ctx, `UPDATE tlsbeacon_registry.format SET version=1; REVOKE SELECT ON tlsbeacon_registry.records FROM tlsbeacon_runtime`, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal("fixture grant setup failed")
	}
	if _, err := Open(ctx, fixtureConnection(t, name)); errorCode(err) != "storage_error" {
		t.Fatalf("denied grant: %v", err)
	}
	protectedFixture(t)
	grantFixture(t, setup)
	app := connectFixture(t, protectedFixture(t), "tlsbeacon_runtime", name)
	for _, query := range []string{`CREATE SCHEMA denied`, `CREATE TABLE tlsbeacon_registry.denied (id integer)`, `UPDATE tlsbeacon_registry.format SET version=2`} {
		protectedFixture(t)
		if _, err := app.Exec(ctx, query); err == nil {
			t.Fatal("runtime role unexpectedly performed a prohibited operation")
		}
	}
	var super, createDB, createRole, replication, bypass, createSchema bool
	err := app.QueryRow(ctx, `SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, has_schema_privilege(current_user, 'tlsbeacon_registry', 'CREATE') FROM pg_roles WHERE rolname=current_user`).Scan(&super, &createDB, &createRole, &replication, &bypass, &createSchema)
	if err != nil || super || createDB || createRole || replication || bypass || createSchema {
		t.Fatal("unsafe effective runtime privileges")
	}
	unavailable, err := pgx.ParseConfig("host=/nonexistent/tlsbeacon-fixture user=none dbname=none password=fixture-secret connect_timeout=1")
	if err != nil {
		t.Fatal("unavailable fixture configuration failed")
	}
	if _, err := Open(ctx, unavailable); errorCode(err) != "storage_error" || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatalf("unavailable database or unsafe diagnostic: %v", err)
	}
	if _, err := Open(ctx, nil); errorCode(err) != "storage_error" {
		t.Fatalf("missing database configuration: %v", err)
	}
}

func TestRegistryRejectsSetRolePrivilegeEscalation(t *testing.T) {
	ctx := context.Background()
	name, setup := newFixtureDatabase(t, true)
	admin := connectFixture(t, protectedFixture(t), "postgres", "postgres")
	role := pgx.Identifier{name}.Sanitize()
	for _, statement := range []string{
		"CREATE ROLE " + role + " LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
		"GRANT CONNECT ON DATABASE " + pgx.Identifier{name}.Sanitize() + " TO " + role,
		"GRANT tlsbeacon_setup TO " + role + " WITH INHERIT FALSE, SET TRUE",
	} {
		protectedFixture(t)
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal("fixture role setup failed")
		}
	}
	protectedFixture(t)
	for _, statement := range []string{
		"GRANT USAGE ON SCHEMA tlsbeacon_registry TO " + role,
		"GRANT SELECT ON tlsbeacon_registry.format TO " + role,
		"GRANT SELECT, INSERT, UPDATE ON tlsbeacon_registry.records TO " + role,
	} {
		if _, err := setup.Exec(ctx, statement); err != nil {
			t.Fatal("fixture role grants failed")
		}
	}
	protectedFixture(t)
	conn := connectFixture(t, protectedFixture(t), name, name)
	var create, canSet bool
	if err := conn.QueryRow(ctx, `SELECT has_schema_privilege(current_user, 'tlsbeacon_registry', 'CREATE'), pg_has_role(current_user, 'tlsbeacon_setup', 'SET')`).Scan(&create, &canSet); err != nil || create || !canSet {
		t.Fatal("fixture role escalation prerequisite was not established")
	}
	connection := fixtureConfig(t, name, name)
	if _, err := Open(ctx, connection); errorCode(err) != "storage_error" {
		t.Fatalf("SET ROLE escalation was not rejected: %v", err)
	}
}

func TestRegistryRejectsPartialAndCorruptFormat(t *testing.T) {
	ctx := context.Background()
	partial, setup := newFixtureDatabase(t, false)
	protectedFixture(t)
	if _, err := setup.Exec(ctx, `CREATE SCHEMA tlsbeacon_registry; CREATE TABLE tlsbeacon_registry.format (singleton boolean, version integer); GRANT USAGE ON SCHEMA tlsbeacon_registry TO tlsbeacon_runtime; GRANT SELECT ON tlsbeacon_registry.format TO tlsbeacon_runtime`, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal("partial fixture setup failed")
	}
	if _, err := Open(ctx, fixtureConnection(t, partial)); errorCode(err) != "storage_error" {
		t.Fatalf("partial state accepted: %v", err)
	}
	corrupt, setup := newFixtureDatabase(t, false)
	protectedFixture(t)
	if _, err := setup.Exec(ctx, `CREATE SCHEMA tlsbeacon_registry; CREATE TABLE tlsbeacon_registry.format (singleton boolean NOT NULL, version integer NOT NULL); CREATE TABLE tlsbeacon_registry.records (kind text NOT NULL, key text NOT NULL, value bytea NOT NULL); INSERT INTO tlsbeacon_registry.format VALUES (true,1)`, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal("corrupt fixture setup failed")
	}
	grantFixture(t, setup)
	if _, err := Open(ctx, fixtureConnection(t, corrupt)); errorCode(err) != "storage_error" {
		t.Fatalf("corrupt format accepted: %v", err)
	}
	empty, setup := newFixtureDatabase(t, true)
	protectedFixture(t)
	if _, err := setup.Exec(ctx, `DELETE FROM tlsbeacon_registry.format`); err != nil {
		t.Fatal("empty format fixture setup failed")
	}
	if _, err := Open(ctx, fixtureConnection(t, empty)); errorCode(err) != "storage_error" {
		t.Fatalf("empty format accepted: %v", err)
	}
}

func TestRecordDigestBindsLengthDelimitedIdentity(t *testing.T) {
	base := recordDigest("a", "bc", []byte("value"))
	for _, other := range [][32]byte{
		recordDigest("ab", "c", []byte("value")),
		recordDigest("a", "bd", []byte("value")),
		recordDigest("a", "bc", []byte("other")),
	} {
		if base == other {
			t.Fatal("record digest did not distinguish its components")
		}
	}
}

func TestRoleAccessModeByServerVersion(t *testing.T) {
	for _, test := range []struct {
		version int
		want    string
	}{{140000, "MEMBER"}, {150999, "MEMBER"}, {160000, "SET"}, {180007, "SET"}} {
		if got := roleAccessMode(test.version); got != test.want {
			t.Fatalf("server version %d: got %q, want %q", test.version, got, test.want)
		}
	}
}

func TestCanceledHandleWait(t *testing.T) {
	db := &DB{gate: make(chan struct{}, 1)}
	db.gate <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := db.Read(ctx, "policy", "key"); errorCode(err) != "storage_error" {
		t.Fatalf("canceled wait was not reported: %v", err)
	}
	db.leave()
}

func TestCommitOutcomeClassificationAndRedaction(t *testing.T) {
	for _, test := range []struct {
		err  error
		code string
	}{
		{pgx.ErrTxCommitRollback, "storage_error"},
		{&pgconn.PgError{Severity: "ERROR", Code: "23514", Message: "secret"}, "storage_error"},
		{&pgconn.PgError{Severity: "ERROR", Code: "08007", Message: "secret"}, "commit_outcome_unknown"},
		{&pgconn.PgError{Severity: "ERROR", Code: "40003", Message: "secret"}, "commit_outcome_unknown"},
		{&pgconn.PgError{Severity: "FATAL", Code: "57P01", Message: "secret"}, "commit_outcome_unknown"},
		{io.EOF, "commit_outcome_unknown"},
		{errors.New("secret connection string"), "commit_outcome_unknown"},
	} {
		err := classifyCommit(test.err)
		if errorCode(err) != test.code || strings.Contains(err.Error(), "secret") {
			t.Fatalf("incorrect or unsafe commit error: %v", err)
		}
		if test.code == "commit_outcome_unknown" && !strings.Contains(err.Error(), "Read back") {
			t.Fatal("unknown outcome lacks read-back guidance")
		}
	}
}
