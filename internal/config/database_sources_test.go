package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func clearPostgresEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range postgresEnvironmentVariables {
		value, present := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("cannot isolate PostgreSQL environment")
		}
		t.Cleanup(func() {
			if present {
				_ = os.Setenv(name, value)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
}

func qualifyDatabaseSourcesForTest(databaseURL string) error {
	_, cleanup, err := QualifyDatabaseSources(databaseURL)
	if cleanup != nil {
		cleanup()
	}
	return err
}

func TestDatabaseHasTCPHost(t *testing.T) {
	defaultHostIsTCP := !filepath.IsAbs(defaultDatabaseHost())
	for _, tc := range []struct {
		name string
		dsn  string
		want bool
	}{
		{name: "keyword TCP", dsn: "host=db.example.test sslmode=verify-full", want: true},
		{name: "keyword Unix socket", dsn: "host=/tmp sslmode=verify-full", want: false},
		{name: "keyword default empty host", dsn: "host='' sslmode=verify-full", want: defaultHostIsTCP},
		{name: "URI default empty host", dsn: "postgresql:///fixture?host=&sslmode=verify-full", want: defaultHostIsTCP},
		{name: "empty host list element", dsn: "host=/tmp, sslmode=verify-full", want: defaultHostIsTCP},
		{name: "empty and TCP host list elements", dsn: "host=,db.example.test sslmode=verify-full", want: true},
		{name: "keyword leading whitespace is TCP to pgx", dsn: "host=' /tmp' sslmode=verify-full", want: true},
		{name: "mixed hosts", dsn: "host=/tmp,db.example.test sslmode=verify-full", want: true},
		{name: "URI TCP authority", dsn: "postgresql://fixture@db.example.test/fixture?sslmode=verify-full", want: true},
		{name: "URI mixed authority", dsn: "postgresql://fixture@%2Ftmp,db.example.test/fixture?sslmode=verify-full", want: true},
		{name: "URI Unix query host", dsn: "postgresql:///fixture?host=%2Ftmp&sslmode=verify-full", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options, err := databaseURLParameters(tc.dsn)
			if err != nil {
				t.Fatalf("cannot parse fixture DSN: %v", err)
			}
			if got := databaseHasTCPHost(tc.dsn, options); got != tc.want {
				t.Fatalf("databaseHasTCPHost() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSystemRootEnvironmentSourcesAreRejectedOnlyForTCP(t *testing.T) {
	clearPostgresEnvironment(t)
	t.Setenv("SSL_CERT_FILE", "/untrusted/synthetic-root.pem")
	t.Setenv("SSL_CERT_DIR", "")

	for _, dsn := range []string{
		"host=db.example.test user=fixture dbname=fixture sslmode=verify-full sslrootcert=system",
		"postgresql://fixture@db.example.test/fixture?sslmode=verify-full&sslrootcert=system",
	} {
		if err := qualifyDatabaseSourcesForTest(dsn); err == nil {
			t.Fatalf("system-root environment source accepted for TCP DSN %q", dsn)
		} else if failure, ok := err.(*Error); !ok || failure.Code != "configuration_error" || !strings.Contains(failure.Action, "SSL_CERT_FILE") {
			t.Fatalf("unexpected TCP system-root error: %v", err)
		}
	}

	for _, dsn := range []string{
		"host=/tmp user=fixture dbname=fixture sslmode=verify-full sslrootcert=system",
		"postgresql:///fixture?host=%2Ftmp&sslmode=verify-full&sslrootcert=system",
	} {
		if err := qualifyDatabaseSourcesForTest(dsn); err != nil {
			t.Fatalf("system-root environment source rejected without TLS for DSN %q: %v", dsn, err)
		}
	}
}

func TestValidateDatabaseSourcesRejectsEnvironmentAndServiceFiles(t *testing.T) {
	clearPostgresEnvironment(t)
	if err := os.Setenv("PGSERVICE", "fixture-service"); err != nil {
		t.Fatal("cannot set environment fixture")
	}
	if err := qualifyDatabaseSourcesForTest("host=localhost user=fixture dbname=fixture"); err == nil {
		t.Fatal("PostgreSQL environment override accepted")
	} else if failure, ok := err.(*Error); !ok || failure.Code != "configuration_error" || strings.Contains(err.Error(), "fixture-service") {
		t.Fatalf("unsafe environment diagnostic: %v", err)
	}
	if err := os.Unsetenv("PGSERVICE"); err != nil {
		t.Fatal("cannot clear environment fixture")
	}

	for _, dsn := range []string{
		"service=fixture servicefile=/tmp/untrusted-service.conf host=localhost user=fixture dbname=fixture",
		"postgresql://fixture@localhost/fixture?servicefile=%2Ftmp%2Funtrusted-service.conf",
		"postgres://ignored?x@localhost/fixture?serv%69cefile=%2Ftmp%2Funtrusted-service.conf",
	} {
		if err := qualifyDatabaseSourcesForTest(dsn); err == nil {
			t.Fatalf("service indirection accepted: %q", dsn)
		} else if failure, ok := err.(*Error); !ok || failure.Code != "configuration_error" || strings.Contains(err.Error(), "untrusted-service") {
			t.Fatalf("unsafe service diagnostic: %v", err)
		}
	}
}

func TestValidateDatabaseSourcesAcceptsProtectedPasswordAndTLSFiles(t *testing.T) {
	clearPostgresEnvironment(t)
	home := protectedDir(t)
	t.Setenv("HOME", home)
	files := protectedDir(t)
	passfile := filepath.Join(files, "pass file")
	if err := os.WriteFile(passfile, []byte("localhost:5432:fixture:fixture:synthetic-password\n"), 0600); err != nil {
		t.Fatal("cannot create passfile fixture")
	}
	ca := filepath.Join(files, "root.crt")
	if err := os.WriteFile(ca, []byte("synthetic public certificate"), 0644); err != nil {
		t.Fatal("cannot create CA fixture")
	}
	cert := filepath.Join(files, "client.crt")
	if err := os.WriteFile(cert, []byte("synthetic public client certificate"), 0644); err != nil {
		t.Fatal("cannot create client certificate fixture")
	}
	key := filepath.Join(files, "client.key")
	if err := os.WriteFile(key, []byte("synthetic private key"), 0600); err != nil {
		t.Fatal("cannot create client key fixture")
	}

	dsn := "host=localhost user=fixture dbname=fixture sslmode=verify-full passfile='" + passfile + "' sslrootcert='" + ca + "' sslcert='" + cert + "' sslkey='" + key + "'"
	qualified, cleanup, err := QualifyDatabaseSources(dsn)
	if err != nil {
		t.Fatalf("protected direct connection files rejected: %v", err)
	}
	defer cleanup()
	if !strings.Contains(qualified, "/proc/self/fd/") {
		t.Fatal("direct connection files were not pinned to qualified descriptors")
	}
	uri := "postgresql://fixture:synthetic-password@localhost/fixture?sslmode=verify-full&sslrootcert=" + strings.ReplaceAll(ca, "/", "%2F")
	qualified, cleanup, err = QualifyDatabaseSources(uri)
	if err != nil {
		t.Fatalf("protected URI connection file rejected: %v", err)
	}
	cleanup()
	if !strings.Contains(qualified, "%2Fproc%2Fself%2Ffd%2F") {
		t.Fatal("URI connection files were not pinned to qualified descriptors")
	}
}

func TestValidateDatabaseSourcesRejectsInsecureFilesAndParents(t *testing.T) {
	clearPostgresEnvironment(t)
	home := protectedDir(t)
	t.Setenv("HOME", home)
	files := protectedDir(t)
	passfile := filepath.Join(files, "passfile")
	if err := os.WriteFile(passfile, []byte("synthetic password material"), 0644); err != nil {
		t.Fatal("cannot create passfile fixture")
	}
	if err := qualifyDatabaseSourcesForTest("host=localhost user=fixture dbname=fixture sslmode=disable passfile=" + passfile); err == nil {
		t.Fatal("group/world-readable passfile accepted")
	} else if failure, ok := err.(*Error); !ok || failure.Code != "permission_error" || strings.Contains(err.Error(), passfile) || strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("unsafe passfile returned an unsafe error")
	}

	if err := os.Chmod(passfile, 0600); err != nil {
		t.Fatal("cannot protect passfile fixture")
	}
	if err := os.WriteFile(filepath.Join(home, ".pgpass"), []byte("synthetic password material"), 0644); err != nil {
		t.Fatal("cannot create default passfile fixture")
	}
	if err := qualifyDatabaseSourcesForTest("host=localhost user=fixture dbname=fixture sslmode=disable"); err == nil {
		t.Fatal("insecure default passfile accepted")
	}
	if err := os.Remove(filepath.Join(home, ".pgpass")); err != nil {
		t.Fatal("cannot remove default passfile fixture")
	}

	linkParent := filepath.Join(files, "linked")
	if err := os.Symlink(files, linkParent); err != nil {
		t.Fatal("cannot create parent symlink fixture")
	}
	linkedPassfile := filepath.Join(linkParent, "passfile")
	if err := qualifyDatabaseSourcesForTest("host=localhost user=fixture dbname=fixture passfile=" + linkedPassfile); err == nil {
		t.Fatal("passfile through a parent symlink accepted")
	}
	linkedFile := filepath.Join(files, "linked-passfile")
	if err := os.Symlink(passfile, linkedFile); err != nil {
		t.Fatal("cannot create file symlink fixture")
	}
	if err := qualifyDatabaseSourcesForTest("host=localhost user=fixture dbname=fixture passfile=" + linkedFile); err == nil {
		t.Fatal("symlinked passfile accepted")
	}

	unsafeParent := filepath.Join(files, "unsafe-parent")
	if err := os.Mkdir(unsafeParent, 0700); err != nil {
		t.Fatal("cannot create parent permission fixture")
	}
	unsafeParentPassfile := filepath.Join(unsafeParent, "passfile")
	if err := os.WriteFile(unsafeParentPassfile, []byte("synthetic password material"), 0600); err != nil {
		t.Fatal("cannot create parent permission passfile")
	}
	if err := os.Chmod(unsafeParent, 0777); err != nil {
		t.Fatal("cannot make unsafe parent fixture")
	}
	if err := qualifyDatabaseSourcesForTest("host=localhost user=fixture dbname=fixture passfile=" + unsafeParentPassfile); err == nil {
		t.Fatal("passfile under a writable parent accepted")
	}
}

func TestDatabaseConnectionKeysPreserveRuntimeParametersAndBlockServices(t *testing.T) {
	for _, dsn := range []string{
		"host=localhost application_name=tlsbeacon statement_timeout=750ms",
		"postgresql://fixture@localhost/fixture?application_name=tlsbeacon&statement_timeout=750ms",
	} {
		keys, err := DatabaseConnectionKeys(dsn)
		if err != nil {
			t.Fatalf("direct connection keys rejected: %v", err)
		}
		seen := make(map[string]bool, len(keys))
		for _, key := range keys {
			seen[key] = true
		}
		for _, key := range []string{"host", "port", "database", "user", "application_name", "statement_timeout", "passfile", "sslrootcert", "sslcert", "sslkey"} {
			if !seen[key] {
				t.Fatalf("connection key %q was not retained", key)
			}
		}
	}
	for _, dsn := range []string{"service=fixture", "postgresql://localhost/fixture?servicefile=/tmp/service.conf"} {
		if _, err := DatabaseConnectionKeys(dsn); err == nil {
			t.Fatalf("service indirection allowed in connection key list: %q", dsn)
		}
	}
}

func TestDatabaseURLParametersTracksQualifiedPathOptions(t *testing.T) {
	cases := []struct {
		input string
		key   string
		value string
	}{
		{"passfile='/tmp/path with spaces' sslkey=/tmp/client.key", "passfile", "/tmp/path with spaces"},
		{"host=localhost passfile=/tmp/path\\ with\\ spaces", "passfile", "/tmp/path with spaces"},
		{"postgres://fixture:secret@localhost/db?sslrootcert=%2Ftmp%2Froot.crt&password=override", "sslrootcert", "/tmp/root.crt"},
		{"postgres://ignored?x@localhost/db?sslkey=%2Ftmp%2Fkey.pem", "sslkey", "/tmp/key.pem"},
	}
	for _, test := range cases {
		parameters, err := databaseURLParameters(test.input)
		if err != nil || parameters[test.key] != test.value {
			t.Fatalf("parameter %q from connection string was not parsed safely", test.key)
		}
	}
}

func TestPostgresURIComponentMatchesPinnedParser(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"plain", "plain"},
		{"%20encoded%20spaces%20", " encoded spaces "},
		{"  leading%20and%20trailing  ", "leading and trailing"},
		{"plus+remains+plus", "plus+remains+plus"},
	}
	for _, test := range cases {
		if got, err := decodePostgresURIComponent(test.input); err != nil || got != test.want {
			t.Fatalf("decodePostgresURIComponent(%q) = %q, %v; want %q", test.input, got, err, test.want)
		}
	}
	for _, input := range []string{"raw interior space", "%00", "%", "%GG"} {
		if _, err := decodePostgresURIComponent(input); err == nil {
			t.Fatalf("invalid URI component %q was accepted", input)
		}
	}
}
