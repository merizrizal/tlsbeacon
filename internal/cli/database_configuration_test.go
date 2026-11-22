package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/merizrizal/tlsbeacon/internal/config"
)

func clearDatabaseEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		name, value, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, "PG") {
			continue
		}
		if err := os.Unsetenv(name); err != nil {
			t.Fatal("cannot isolate PostgreSQL environment")
		}
		t.Cleanup(func() { _ = os.Setenv(name, value) })
	}
}

func protectedDatabaseTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("cannot protect database test directory")
	}
	return dir
}

func syntheticCertificate(t *testing.T, serial int64, isCA bool, usage x509.KeyUsage, extendedUsage []x509.ExtKeyUsage) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("cannot generate certificate fixture")
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              usage,
		ExtKeyUsage:           extendedUsage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal("cannot create certificate fixture")
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal("cannot encode private-key fixture")
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certificate, key
}

func TestDatabaseConfigurationErrorsRedactConnectionString(t *testing.T) {
	clearDatabaseEnvironment(t)
	t.Setenv("HOME", protectedDatabaseTestDir(t))
	_, cleanup, err := parseConfiguredDatabaseURL("host=localhost port=invalid user=fixture password=synthetic-secret sslmode=disable")
	if cleanup != nil {
		cleanup()
	}
	if err == nil || strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(err.Error(), "port=invalid") {
		t.Fatal("database configuration error exposed connection details")
	}
}

func TestParseConfiguredDatabaseURLPreservesRuntimeParameters(t *testing.T) {
	clearDatabaseEnvironment(t)
	t.Setenv("HOME", protectedDatabaseTestDir(t))
	connection, cleanup, err := parseConfiguredDatabaseURL("host=localhost port=5432 user=fixture dbname=fixture sslmode=disable statement_timeout=750ms")
	if err != nil {
		t.Fatalf("valid PostgreSQL runtime parameter rejected: %v", err)
	}
	t.Cleanup(cleanup)
	if connection.RuntimeParams["statement_timeout"] != "750ms" {
		t.Fatal("protected database configuration did not preserve its runtime parameter")
	}
}

func TestQualifiedPassfileDescriptorSurvivesPathReplacement(t *testing.T) {
	clearDatabaseEnvironment(t)
	t.Setenv("HOME", protectedDatabaseTestDir(t))
	dir := protectedDatabaseTestDir(t)
	passfile := filepath.Join(dir, "passfile")
	if err := os.WriteFile(passfile, []byte("localhost:5432:fixture:fixture:original-password\n"), 0600); err != nil {
		t.Fatal("cannot create passfile fixture")
	}

	qualifiedURL, cleanup, err := config.QualifyDatabaseSources("host=localhost port=5432 user=fixture dbname=fixture sslmode=disable passfile=" + passfile + " application_name=fixture\\")
	if err != nil {
		t.Fatalf("protected passfile could not be qualified: %v", err)
	}
	defer cleanup()
	if err := os.Rename(passfile, passfile+".original"); err != nil {
		t.Fatal("cannot replace passfile fixture")
	}
	if err := os.WriteFile(passfile, []byte("localhost:5432:fixture:fixture:replacement-password\n"), 0666); err != nil {
		t.Fatal("cannot write replacement passfile fixture")
	}
	if err := os.Chmod(passfile, 0666); err != nil {
		t.Fatal("cannot set replacement passfile mode")
	}

	connection, err := pgx.ParseConfig(qualifiedURL)
	if err != nil || connection.Password != "original-password" || connection.RuntimeParams["application_name"] != "fixture" {
		t.Fatal("pgx did not use the qualified passfile or preserve the trailing connection value")
	}
}

func TestUnqualifiedDefaultPassfileCannotAppearAfterQualification(t *testing.T) {
	clearDatabaseEnvironment(t)
	home := protectedDatabaseTestDir(t)
	t.Setenv("HOME", home)
	qualifiedURL, cleanup, err := config.QualifyDatabaseSources("host=localhost port=5432 user=fixture dbname=fixture sslmode=disable application_name=")
	if err != nil {
		t.Fatalf("database sources could not be qualified: %v", err)
	}
	defer cleanup()
	if err := os.WriteFile(filepath.Join(home, ".pgpass"), []byte("localhost:5432:fixture:fixture:replacement-password\n"), 0600); err != nil {
		t.Fatal("cannot create late passfile fixture")
	}
	connection, err := pgx.ParseConfig(qualifiedURL)
	if err != nil || connection.Password != "" {
		t.Fatal("a default passfile created after qualification was used")
	}
}

func TestQualifiedPassfileDescriptorSurvivesPathReplacementAfterTerminalEmptyValue(t *testing.T) {
	clearDatabaseEnvironment(t)
	t.Setenv("HOME", protectedDatabaseTestDir(t))
	dir := protectedDatabaseTestDir(t)
	passfile := filepath.Join(dir, "passfile")
	if err := os.WriteFile(passfile, []byte("localhost:5432:fixture:fixture:original-password\n"), 0600); err != nil {
		t.Fatal("cannot create passfile fixture")
	}

	qualifiedURL, cleanup, err := config.QualifyDatabaseSources("host=localhost port=5432 user=fixture dbname=fixture sslmode=disable passfile='" + passfile + "' application_name =")
	if err != nil {
		t.Fatalf("protected passfile could not be qualified: %v", err)
	}
	defer cleanup()
	if err := os.Rename(passfile, passfile+".original"); err != nil {
		t.Fatal("cannot replace passfile fixture")
	}
	if err := os.WriteFile(passfile, []byte("localhost:5432:fixture:fixture:replacement-password\n"), 0600); err != nil {
		t.Fatal("cannot write replacement passfile fixture")
	}

	legacyURL := strings.Replace(qualifiedURL, "application_name ='' passfile=", "application_name = passfile=", 1)
	if legacyURL == qualifiedURL {
		t.Fatal("cannot construct the historical unquoted-empty-value reproduction")
	}
	legacyKeys, err := config.DatabaseConnectionKeys(legacyURL)
	if err != nil {
		t.Fatalf("legacy connection keys could not be parsed: %v", err)
	}
	legacyConnection, err := pgx.ParseConfigWithOptions(legacyURL, pgx.ParseConfigOptions{
		ParseConfigOptions: pgconn.ParseConfigOptions{ConnStringAllowedKeys: legacyKeys},
	})
	if err != nil || legacyConnection.Password != "replacement-password" {
		t.Fatal("historical unquoted-empty-value path did not reproduce the replaced passfile")
	}

	allowedKeys, err := config.DatabaseConnectionKeys(qualifiedURL)
	if err != nil {
		t.Fatalf("qualified connection keys could not be parsed: %v", err)
	}
	connection, err := pgx.ParseConfigWithOptions(qualifiedURL, pgx.ParseConfigOptions{
		ParseConfigOptions: pgconn.ParseConfigOptions{ConnStringAllowedKeys: allowedKeys},
	})
	if err != nil || connection.Password != "original-password" || connection.RuntimeParams["application_name"] != "" {
		t.Fatal("terminal empty keyword value swallowed the qualified passfile override")
	}
}

func TestParseConfiguredDatabaseURLUsesProtectedHomeDefaults(t *testing.T) {
	clearDatabaseEnvironment(t)
	home := protectedDatabaseTestDir(t)
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".pgpass"), []byte("localhost:5432:fixture:fixture:home-password\n"), 0600); err != nil {
		t.Fatal("cannot create default passfile fixture")
	}
	postgresqlDir := filepath.Join(home, ".postgresql")
	if err := os.Mkdir(postgresqlDir, 0700); err != nil {
		t.Fatal("cannot create default TLS directory")
	}
	rootPEM, _ := syntheticCertificate(t, 3, true, x509.KeyUsageCertSign, nil)
	if err := os.WriteFile(filepath.Join(postgresqlDir, "root.crt"), rootPEM, 0644); err != nil {
		t.Fatal("cannot create default root certificate fixture")
	}

	connection, cleanup, err := parseConfiguredDatabaseURL("host=localhost port=5432 user=fixture dbname=fixture sslmode=disable")
	if err != nil {
		t.Fatalf("protected home database sources rejected: %v", err)
	}
	t.Cleanup(cleanup)
	if connection.Password != "home-password" || connection.TLSConfig != nil || len(connection.Fallbacks) != 0 {
		t.Fatal("protected home defaults were not qualified without changing the configured transport")
	}
}

func TestParseConfiguredDatabaseURLUsesProtectedPasswordAndTLSFiles(t *testing.T) {
	clearDatabaseEnvironment(t)
	t.Setenv("HOME", protectedDatabaseTestDir(t))
	files := protectedDatabaseTestDir(t)

	passfile := filepath.Join(files, "pass file")
	if err := os.WriteFile(passfile, []byte("localhost:5432:fixture:fixture:synthetic-password\n"), 0600); err != nil {
		t.Fatal("cannot create passfile fixture")
	}
	connection, cleanup, err := parseConfiguredDatabaseURL("host=localhost port=5432 user=fixture dbname=fixture sslmode=disable passfile='" + passfile + "'")
	if err != nil {
		t.Fatalf("protected direct passfile rejected: %v", err)
	}
	t.Cleanup(cleanup)
	if connection.Password != "synthetic-password" || connection.Host != "localhost" || connection.Database != "fixture" || len(connection.Fallbacks) != 0 {
		t.Fatal("protected passfile did not preserve the direct database connection settings")
	}

	rootPEM, _ := syntheticCertificate(t, 1, true, x509.KeyUsageCertSign, nil)
	clientPEM, clientKey := syntheticCertificate(t, 2, false, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	rootPath := filepath.Join(files, "root.crt")
	clientPath := filepath.Join(files, "client.crt")
	keyPath := filepath.Join(files, "client.key")
	if err := os.WriteFile(rootPath, rootPEM, 0644); err != nil {
		t.Fatal("cannot create CA fixture")
	}
	if err := os.WriteFile(clientPath, clientPEM, 0644); err != nil {
		t.Fatal("cannot create client certificate fixture")
	}
	if err := os.WriteFile(keyPath, clientKey, 0600); err != nil {
		t.Fatal("cannot create client key fixture")
	}

	uri := "postgresql://fixture:synthetic-password@db.example.test/fixture?sslmode=verify-full&sslrootcert=" + url.PathEscape(rootPath) + "&sslcert=" + url.PathEscape(clientPath) + "&sslkey=" + url.PathEscape(keyPath)
	tlsConnection, tlsCleanup, err := parseConfiguredDatabaseURL(uri)
	if err != nil {
		t.Fatalf("protected TLS source files rejected: %v", err)
	}
	t.Cleanup(tlsCleanup)
	connection = tlsConnection
	if connection.TLSConfig == nil || connection.TLSConfig.RootCAs == nil || connection.TLSConfig.InsecureSkipVerify || connection.TLSConfig.ServerName != "db.example.test" || len(connection.Fallbacks) != 0 {
		t.Fatal("verified TLS settings were not preserved")
	}
}

func TestQualifiedPassfileOverridesRemainEffective(t *testing.T) {
	clearDatabaseEnvironment(t)
	t.Setenv("HOME", protectedDatabaseTestDir(t))
	dir := protectedDatabaseTestDir(t)
	first := filepath.Join(dir, "pass ' first\\file")
	second := filepath.Join(dir, "pass second")
	for path, password := range map[string]string{first: "first-password", second: "last-password"} {
		contents := []byte("localhost:5432:fixture:fixture:" + password + "\n")
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal("cannot create protected passfile fixture")
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal("cannot protect passfile fixture")
		}
	}
	quote := func(value string) string {
		return "'" + strings.NewReplacer("\\", "\\\\", "'", "\\'").Replace(value) + "'"
	}
	cases := []struct {
		name     string
		dsn      string
		password string
	}{
		{name: "keyword terminal empty value", dsn: "host=localhost port=5432 user=fixture dbname=fixture sslmode=disable passfile=" + quote(first) + " application_name=", password: "first-password"},
		{name: "keyword duplicate last value", dsn: "host=localhost port=5432 user=fixture dbname=fixture sslmode=disable passfile=" + quote(first) + " passfile=" + quote(second), password: "last-password"},
		{name: "URI escaped key and duplicate last value", dsn: "postgresql://fixture@localhost/fixture?sslmode=disable&pass%66ile=" + url.PathEscape(first) + "&passfile=" + url.PathEscape(second) + "&application_name=last%20value", password: "last-password"},
		{name: "URI terminal empty value", dsn: "postgresql://fixture@localhost/fixture?sslmode=disable&passfile=" + url.PathEscape(second) + "&application_name=", password: "last-password"},
		{name: "URI query password overrides userinfo", dsn: "postgresql://fixture:uri-password@localhost/fixture?sslmode=disable&password=query%20password&passfile=%2Fmissing%2Fpassfile", password: "query password"},
		{name: "URI empty query password selects passfile", dsn: "postgresql://fixture:uri-password@localhost/fixture?sslmode=disable&password=&passfile=" + url.PathEscape(second), password: "last-password"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			connection, cleanup, err := parseConfiguredDatabaseURL(tc.dsn)
			if err != nil {
				t.Fatalf("protected database source was rejected: %v", err)
			}
			defer cleanup()
			if connection.Password != tc.password {
				t.Fatalf("effective pgx password = %q, want the qualified source value", connection.Password)
			}
			if tc.name == "URI escaped key and duplicate last value" && connection.RuntimeParams["application_name"] != "last value" {
				t.Fatal("URI runtime parameter was not preserved")
			}
		})
	}
}

func syntheticDatabaseServerCertificate(t *testing.T, rootPEM, rootKeyPEM []byte) []byte {
	t.Helper()
	rootBlock, _ := pem.Decode(rootPEM)
	if rootBlock == nil {
		t.Fatal("cannot decode synthetic root certificate")
	}
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatal("cannot parse synthetic root certificate")
	}
	keyBlock, _ := pem.Decode(rootKeyPEM)
	if keyBlock == nil {
		t.Fatal("cannot decode synthetic root key")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal("cannot parse synthetic root key")
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("cannot generate synthetic server key")
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(902),
		DNSNames:              []string{"db.example.test"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, publicKey, privateKey)
	if err != nil {
		t.Fatal("cannot create synthetic server certificate")
	}
	return der
}

func TestDatabaseSystemRootEnvironmentSourcesAreRejected(t *testing.T) {
	if os.Getenv("TLSBEACON_SYSTEM_ROOT_CHILD") == "1" {
		clearDatabaseEnvironment(t)
		t.Setenv("HOME", protectedDatabaseTestDir(t))
		dsn := os.Getenv("TLSBEACON_SYSTEM_ROOT_DSN")
		connection, cleanup, err := parseConfiguredDatabaseURL(dsn)
		if err != nil {
			var configurationFailure *config.Error
			if errors.As(err, &configurationFailure) && configurationFailure.Code == "configuration_error" && strings.Contains(configurationFailure.Action, "SSL_CERT_FILE") {
				return
			}
			t.Fatalf("unexpected system-root qualification error: %v", err)
		}
		defer cleanup()
		if connection.TLSConfig == nil {
			t.Fatal("pgx accepted an external root source before disabling TLS")
		}
		leafDER, err := os.ReadFile(os.Getenv("TLSBEACON_SYSTEM_ROOT_LEAF"))
		if err != nil {
			t.Fatal("cannot read synthetic server certificate")
		}
		leaf, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Fatal("cannot parse synthetic server certificate")
		}
		verify := x509.VerifyOptions{DNSName: "db.example.test", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		switch {
		case strings.Contains(dsn, "sslrootcert=system"):
			verify.Roots = connection.TLSConfig.RootCAs
		case strings.Contains(dsn, "sslmode=verify-ca"):
			if connection.TLSConfig.VerifyPeerCertificate == nil {
				t.Fatal("pgx did not configure verify-ca validation")
			}
			if err := connection.TLSConfig.VerifyPeerCertificate([][]byte{leaf.Raw}, nil); err != nil {
				t.Fatalf("environment certificate was not trusted by pgx verify-ca: %v", err)
			}
			t.Fatal("unqualified SSL_CERT_DIR source was trusted by pgx verify-ca")
		}
		if _, err := leaf.Verify(verify); err != nil {
			t.Fatalf("synthetic server certificate was not trusted through the configured system roots: %v", err)
		}
		t.Fatalf("unqualified system-root environment source became effective: dsn=%q SSL_CERT_FILE=%q SSL_CERT_DIR=%q", dsn, os.Getenv("SSL_CERT_FILE"), os.Getenv("SSL_CERT_DIR"))
	}

	rootPEM, rootKeyPEM := syntheticCertificate(t, 901, true, x509.KeyUsageCertSign, nil)
	leafDER := syntheticDatabaseServerCertificate(t, rootPEM, rootKeyPEM)
	dir := protectedDatabaseTestDir(t)
	filePath := filepath.Join(dir, "unsafe-root.pem")
	if err := os.WriteFile(filePath, rootPEM, 0666); err != nil {
		t.Fatal("cannot create synthetic environment-root fixture")
	}
	if err := os.Chmod(filePath, 0666); err != nil {
		t.Fatal("cannot set synthetic environment-root mode")
	}
	rootDir := filepath.Join(dir, "unsafe-root-dir")
	if err := os.Mkdir(rootDir, 0700); err != nil {
		t.Fatal("cannot create synthetic environment-root directory")
	}
	if err := os.WriteFile(filepath.Join(rootDir, "root.pem"), rootPEM, 0666); err != nil {
		t.Fatal("cannot create synthetic directory-root fixture")
	}
	if err := os.Chmod(filepath.Join(rootDir, "root.pem"), 0666); err != nil {
		t.Fatal("cannot set synthetic directory-root file mode")
	}
	if err := os.Chmod(rootDir, 0777); err != nil {
		t.Fatal("cannot set synthetic directory-root mode")
	}
	leafPath := filepath.Join(dir, "server.der")
	if err := os.WriteFile(leafPath, leafDER, 0600); err != nil {
		t.Fatal("cannot create synthetic server-certificate fixture")
	}

	modes := []struct {
		name string
		dsn  string
	}{
		{name: "system verify-full", dsn: "host=db.example.test user=fixture dbname=fixture sslmode=verify-full sslrootcert=system"},
		{name: "system require promotes verification", dsn: "host=db.example.test user=fixture dbname=fixture sslmode=require sslrootcert=system"},
		{name: "system roots loaded before disabled TLS", dsn: "host=db.example.test user=fixture dbname=fixture sslmode=disable sslrootcert=system"},
		{name: "implicit verify-full", dsn: "host=db.example.test user=fixture dbname=fixture sslmode=verify-full"},
		{name: "implicit verify-ca", dsn: "host=db.example.test user=fixture dbname=fixture sslmode=verify-ca"},
		{name: "URI system verify-full", dsn: "postgresql://fixture@db.example.test/fixture?sslmode=verify-full&sslrootcert=system"},
		{name: "URI implicit verify-full", dsn: "postgresql://fixture@db.example.test/fixture?sslmode=verify-full"},
		{name: "mixed TCP and Unix hosts", dsn: "host=db.example.test,/tmp user=fixture dbname=fixture sslmode=verify-full sslrootcert=system"},
		{name: "quoted leading-space socket-looking host is TCP to pgx", dsn: "host=' /tmp' user=fixture dbname=fixture sslmode=verify-full sslrootcert=system"},
	}
	for _, source := range []struct {
		name string
		file string
		dir  string
	}{
		{name: "SSL_CERT_FILE", file: filePath},
		{name: "SSL_CERT_DIR", dir: rootDir},
	} {
		for _, mode := range modes {
			t.Run(source.name+"/"+mode.name, func(t *testing.T) {
				dsn := mode.dsn
				cmd := exec.Command(os.Args[0], "-test.run=^TestDatabaseSystemRootEnvironmentSourcesAreRejected$")
				cmd.Env = make([]string, 0, len(os.Environ())+6)
				for _, entry := range os.Environ() {
					name, _, _ := strings.Cut(entry, "=")
					if strings.HasPrefix(name, "PG") || strings.HasPrefix(name, "TLSBEACON_SYSTEM_ROOT_") || name == "SSL_CERT_FILE" || name == "SSL_CERT_DIR" {
						continue
					}
					cmd.Env = append(cmd.Env, entry)
				}
				cmd.Env = append(cmd.Env,
					"TLSBEACON_SYSTEM_ROOT_CHILD=1",
					"TLSBEACON_SYSTEM_ROOT_DSN="+dsn,
					"TLSBEACON_SYSTEM_ROOT_LEAF="+leafPath,
					"SSL_CERT_FILE="+source.file,
					"SSL_CERT_DIR="+source.dir,
				)
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("external system-root source was not rejected: %v (%s)", err, output)
				}
			})
		}
	}
}

func TestDatabaseTLSPreservesExplicitAndNonSystemModes(t *testing.T) {
	clearDatabaseEnvironment(t)
	home := protectedDatabaseTestDir(t)
	t.Setenv("HOME", home)
	dir := protectedDatabaseTestDir(t)
	environmentRoot, _ := syntheticCertificate(t, 910, true, x509.KeyUsageCertSign, nil)
	explicitRoot, explicitKey := syntheticCertificate(t, 911, true, x509.KeyUsageCertSign, nil)
	leafDER := syntheticDatabaseServerCertificate(t, explicitRoot, explicitKey)
	environmentPath := filepath.Join(dir, "environment-root.pem")
	explicitPath := filepath.Join(dir, "explicit-root.pem")
	if err := os.WriteFile(environmentPath, environmentRoot, 0666); err != nil {
		t.Fatal("cannot create synthetic environment root")
	}
	if err := os.Chmod(environmentPath, 0666); err != nil {
		t.Fatal("cannot set synthetic environment-root mode")
	}
	if err := os.WriteFile(explicitPath, explicitRoot, 0644); err != nil {
		t.Fatal("cannot create protected explicit root")
	}
	if err := os.Chmod(explicitPath, 0644); err != nil {
		t.Fatal("cannot set explicit-root mode")
	}
	t.Setenv("SSL_CERT_FILE", environmentPath)
	t.Setenv("SSL_CERT_DIR", "")
	parse := func(dsn string) *pgx.ConnConfig {
		connection, cleanup, err := parseConfiguredDatabaseURL(dsn)
		if err != nil {
			t.Fatalf("database configuration was rejected: %v", err)
		}
		t.Cleanup(cleanup)
		return connection
	}

	disabled := parse("host=db.example.test user=fixture dbname=fixture sslmode=disable")
	if disabled.TLSConfig != nil {
		t.Fatal("environment root override changed disabled TLS")
	}
	required := parse("host=db.example.test user=fixture dbname=fixture sslmode=require")
	if required.TLSConfig == nil || !required.TLSConfig.InsecureSkipVerify {
		t.Fatal("environment root override changed require-mode transport semantics")
	}

	unixSystem := parse("host=/tmp user=fixture dbname=fixture sslmode=verify-full sslrootcert=system")
	if unixSystem.TLSConfig != nil {
		t.Fatal("system-root environment override was rejected although pgx skips TLS for Unix sockets")
	}
	unixURI := parse("postgresql:///fixture?host=%2Ftmp&sslmode=verify-full&sslrootcert=system")
	if unixURI.TLSConfig != nil {
		t.Fatal("URI system-root environment override was rejected although pgx skips TLS for Unix sockets")
	}

	explicit := parse("host=db.example.test user=fixture dbname=fixture sslmode=verify-full sslrootcert=" + explicitPath)
	if explicit.TLSConfig == nil || explicit.TLSConfig.RootCAs == nil || explicit.TLSConfig.InsecureSkipVerify {
		t.Fatal("protected explicit root was blocked by an unused system-root environment override")
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal("cannot parse synthetic server certificate")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: explicit.TLSConfig.RootCAs, DNSName: "db.example.test", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("protected explicit root was not used: %v", err)
	}

	postgresqlDir := filepath.Join(home, ".postgresql")
	if err := os.Mkdir(postgresqlDir, 0700); err != nil {
		t.Fatal("cannot create protected default TLS directory")
	}
	defaultRootPath := filepath.Join(postgresqlDir, "root.crt")
	if err := os.WriteFile(defaultRootPath, explicitRoot, 0644); err != nil {
		t.Fatal("cannot create protected default root")
	}
	if err := os.Chmod(defaultRootPath, 0644); err != nil {
		t.Fatal("cannot protect default root")
	}
	defaultRoot := parse("host=db.example.test user=fixture dbname=fixture sslmode=verify-full")
	if defaultRoot.TLSConfig == nil || defaultRoot.TLSConfig.RootCAs == nil || defaultRoot.TLSConfig.InsecureSkipVerify {
		t.Fatal("protected default root was blocked by the unused system-root environment override")
	}
	if leaf, err := x509.ParseCertificate(leafDER); err != nil {
		t.Fatal("cannot parse synthetic default-root server certificate")
	} else if _, err := leaf.Verify(x509.VerifyOptions{Roots: defaultRoot.TLSConfig.RootCAs, DNSName: "db.example.test", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("protected default root was not used: %v", err)
	}

	t.Setenv("SSL_CERT_FILE", "")
	system := parse("host=db.example.test user=fixture dbname=fixture sslmode=require sslrootcert=system")
	if system.TLSConfig == nil || system.TLSConfig.RootCAs == nil || system.TLSConfig.InsecureSkipVerify || system.TLSConfig.ServerName != "db.example.test" {
		t.Fatal("explicit system-root behavior was not preserved")
	}
}
