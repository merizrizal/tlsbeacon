//go:build linux

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	canaryPassword = "CANARY-pw-7f3a9c"
	canaryKey      = "CANARY_KEY_5d1e"
	canaryText     = "CANARY-text-2b8c"
)

const validJSON = `{"schema_version":1,"database":{"host":"db.lab.internal","port":5432,` +
	`"name":"tlsbeacon","user":"tlsbeacon_app","password":"` + canaryPassword + `"}}`

// fixtureDir returns a fresh owner-only directory. testing.TempDir creates its
// numbered subdirectory with mode 0777 minus the umask, which is group-writable
// under a 0002 umask; the explicit chmod makes the fixture's own path trusted,
// so each negative test fails only for the condition it names.
func fixtureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writeConfig writes body into a fresh fixture directory and sets the file mode
// exactly (chmod is not affected by the umask).
func writeConfig(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(fixtureDir(t), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireCode(t *testing.T, err error, code string) *Error {
	t.Helper()
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("error = %v (%T), want *Error", err, err)
	}
	if ce.Code != code {
		t.Fatalf("code = %q, want %q (error: %v)", ce.Code, code, err)
	}
	return ce
}

// requireMessage fails unless the diagnostic names the specific condition.
func requireMessage(t *testing.T, err error, substr string) {
	t.Helper()
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("error %v is not *Error", err)
	}
	if !strings.Contains(ce.Message, substr) {
		t.Fatalf("message %q does not name %q", ce.Message, substr)
	}
}

// requireNoLeak fails if any canary appears in any diagnostic text.
func requireNoLeak(t *testing.T, err error, canaries ...string) {
	t.Helper()
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("error %v is not *Error", err)
	}
	text := err.Error() + "\n" + ce.Message + "\n" + ce.Action
	for _, c := range canaries {
		if strings.Contains(text, c) {
			t.Fatalf("diagnostic leaks %q: %q", c, text)
		}
	}
}

func TestLoadValidConfiguration(t *testing.T) {
	cfg, err := Load(writeConfig(t, validJSON, 0o600))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SchemaVersion != 1 || cfg.Database.Host != "db.lab.internal" || cfg.Database.Port != 5432 ||
		cfg.Database.Name != "tlsbeacon" || cfg.Database.User != "tlsbeacon_app" {
		t.Fatalf("decoded configuration = %+v", cfg)
	}
	if cfg.Database.Password == nil || cfg.Database.Password.Reveal() != canaryPassword {
		t.Fatalf("password not decoded")
	}
}

func TestOwnerOnlyModesAreAccepted(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if _, err := Load(writeConfig(t, validJSON, mode)); err != nil {
			t.Errorf("mode %o: Load: %v", mode, err)
		}
	}
}

func TestPasswordIsOptional(t *testing.T) {
	body := `{"schema_version":1,"database":{"host":"h","port":5432,"name":"n","user":"u"}}`
	cfg, err := Load(writeConfig(t, body, 0o600))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.Password != nil {
		t.Fatalf("absent password decoded as present")
	}
}

func TestValidBoundaryValuesAreAccepted(t *testing.T) {
	bodies := []string{
		`{"schema_version":1,"database":{"host":"h","port":1,"name":"n","user":"u"}}`,
		`{"schema_version":1,"database":{"host":"h","port":65535,"name":"n","user":"u"}}`,
		`{"schema_version":1,"database":{"host":"h","port":5432,"name":"my db","user":"u"}}`,
		`{"schema_version":1,"database":{"host":"h","port":5432,"name":"n","user":"u","password":"  spaced "}}`,
	}
	for _, body := range bodies {
		if _, err := Load(writeConfig(t, body, 0o600)); err != nil {
			t.Errorf("%s: Load: %v", body, err)
		}
	}
}

func TestUnsafeFileModesAreRejected(t *testing.T) {
	modes := []os.FileMode{
		0o644, 0o640, 0o604, 0o620, 0o602, 0o666, 0o660,
		os.ModeSetuid | 0o600, os.ModeSetgid | 0o600, os.ModeSticky | 0o600,
	}
	for _, mode := range modes {
		_, err := Load(writeConfig(t, validJSON, mode))
		requireCode(t, err, codePermission)
		requireMessage(t, err, "accessible to group or others")
		requireNoLeak(t, err, canaryPassword)
	}
}

func TestUnsafeParentDirectoryModesAreRejected(t *testing.T) {
	for _, tc := range []struct {
		mode os.FileMode
		ok   bool
	}{
		{0o755, true},
		{0o775, false},
		{0o757, false},
	} {
		dir := filepath.Join(fixtureDir(t), "sub")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte(validJSON), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, tc.mode); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if tc.ok {
			if err != nil {
				t.Errorf("dir mode %o: Load: %v", tc.mode, err)
			}
			continue
		}
		requireCode(t, err, codePermission)
		requireMessage(t, err, "writable by group or others")
		requireNoLeak(t, err, canaryPassword)
	}
}

func TestSymlinkedFileIsRefused(t *testing.T) {
	dir := fixtureDir(t)
	realFile := filepath.Join(dir, "real.json")
	if err := os.WriteFile(realFile, []byte(validJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "config.json")
	if err := os.Symlink(realFile, link); err != nil {
		t.Fatal(err)
	}
	_, err := Load(link)
	requireCode(t, err, codePermission)
	requireMessage(t, err, "contains a symbolic link")
	requireNoLeak(t, err, canaryPassword)
}

func TestSymlinkedParentDirectoryIsRefused(t *testing.T) {
	root := fixtureDir(t)
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "config.json"), []byte(validJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	_, err := Load(filepath.Join(linkDir, "config.json"))
	requireCode(t, err, codePermission)
	requireMessage(t, err, "contains a symbolic link")
	requireNoLeak(t, err, canaryPassword)
}

// A FIFO must be rejected without blocking the open; the test fails by timeout
// if the loader blocks.
func TestNonRegularFileIsRefusedWithoutBlocking(t *testing.T) {
	path := filepath.Join(fixtureDir(t), "config.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Load(path)
		done <- err
	}()
	select {
	case err := <-done:
		requireCode(t, err, codeConfiguration)
		requireMessage(t, err, "does not name a regular file")
	case <-time.After(10 * time.Second):
		t.Fatal("Load blocked on a FIFO")
	}
}

func TestMissingFileAndDirectoryAreConfigurationErrors(t *testing.T) {
	dir := fixtureDir(t)
	for _, path := range []string{
		filepath.Join(dir, "absent.json"),
		filepath.Join(dir, "absent-dir", "config.json"),
	} {
		cfg, err := Load(path)
		if cfg != nil {
			t.Errorf("%s: returned a configuration on failure", path)
		}
		requireCode(t, err, codeConfiguration)
		requireMessage(t, err, "does not exist")
	}
}

func TestPathMustBeExplicitAbsoluteAndClean(t *testing.T) {
	for _, path := range []string{
		"", "relative/config.json", "./config.json", "/tmp/x/../config.json",
		"/tmp/config.json/", "/", "/tmp/a\x00b",
	} {
		cfg, err := Load(path)
		if cfg != nil {
			t.Errorf("%q: returned a configuration", path)
		}
		requireCode(t, err, codeInvalidInput)
	}
}

// The parent directory is replaced after verification. The loader must still
// read the verified original, not the substitute at the same name.
func TestParentReplacedAfterVerificationIsNotRead(t *testing.T) {
	dir := filepath.Join(fixtureDir(t), "cfg")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	orig := strings.Replace(validJSON, `"name":"tlsbeacon"`, `"name":"original"`, 1)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadWith(filepath.Join(dir, "config.json"), func() {
		if err := os.Rename(dir, dir+".moved"); err != nil {
			t.Errorf("rename: %v", err)
			return
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Errorf("mkdir: %v", err)
			return
		}
		sub := strings.Replace(validJSON, `"name":"tlsbeacon"`, `"name":"substituted"`, 1)
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(sub), 0o600); err != nil {
			t.Errorf("write substitute: %v", err)
		}
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.Name != "original" {
		t.Fatalf("read %q, want the verified original", cfg.Database.Name)
	}
}

// The leaf is replaced by a symbolic link after the directories are verified.
func TestLeafReplacedByLinkAfterVerificationIsRefused(t *testing.T) {
	dir := fixtureDir(t)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(validJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(fixtureDir(t), "target.json")
	if err := os.WriteFile(target, []byte(validJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadWith(path, func() {
		if err := os.Remove(path); err != nil {
			t.Errorf("remove: %v", err)
			return
		}
		if err := os.Symlink(target, path); err != nil {
			t.Errorf("symlink: %v", err)
		}
	})
	requireCode(t, err, codePermission)
	requireMessage(t, err, "contains a symbolic link")
	requireNoLeak(t, err, canaryPassword)
}

// The leaf is replaced by a readable file with an unsafe mode after
// verification. The check applies to the opened object, so it is refused.
func TestLeafReplacedWithUnsafeFileAfterVerificationIsRefused(t *testing.T) {
	dir := fixtureDir(t)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(validJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadWith(path, func() {
		if err := os.Remove(path); err != nil {
			t.Errorf("remove: %v", err)
			return
		}
		if err := os.WriteFile(path, []byte(validJSON), 0o644); err != nil {
			t.Errorf("write: %v", err)
			return
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Errorf("chmod: %v", err)
		}
	})
	requireCode(t, err, codePermission)
	requireMessage(t, err, "accessible to group or others")
	requireNoLeak(t, err, canaryPassword)
}

func TestOversizedFileIsRejected(t *testing.T) {
	body := validJSON + strings.Repeat(" ", MaxFileBytes)
	_, err := Load(writeConfig(t, body, 0o600))
	requireCode(t, err, codeConfiguration)
	requireMessage(t, err, "larger than 64 KiB")
}

// Each malformed input carries a canary in content. None of it may reach the
// diagnostic text, which reports only shape (offsets, field names, phrases).
func TestMalformedContentDoesNotEchoContent(t *testing.T) {
	bodies := map[string]string{
		"truncated-before-canary-close": `{"schema_version":1,"database":{"host":"h","port":5432,"name":"n","user":"u","password":"` + canaryPassword,
		"syntax-error-with-canary":      `{"schema_version":1 "x":"` + canaryText + `"}`,
		"wrong-type-port-with-canary":   `{"schema_version":1,"database":{"host":"h","port":"` + canaryText + `","name":"n","user":"u"}}`,
		"unknown-key-with-canary":       `{"` + canaryKey + `":1,"schema_version":1,"database":{"host":"h","port":5432,"name":"n","user":"u"}}`,
		"empty-password":                `{"schema_version":1,"database":{"host":"h","port":5432,"name":"n","user":"u","password":""}}`,
		"empty-file":                    ``,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeConfig(t, body, 0o600))
			requireCode(t, err, codeConfiguration)
			requireNoLeak(t, err, canaryPassword, canaryKey, canaryText)
		})
	}
}

func TestInvalidFieldsAreRejectedWithoutEchoingValues(t *testing.T) {
	base := func(db string) string {
		return `{"schema_version":1,"database":{` + db + `}}`
	}
	cases := map[string]string{
		"schema missing":            `{"database":{"host":"h","port":5432,"name":"n","user":"u"}}`,
		"schema 2":                  `{"schema_version":2,"database":{"host":"h","port":5432,"name":"n","user":"u"}}`,
		"schema as string":          `{"schema_version":"1","database":{"host":"h","port":5432,"name":"n","user":"u"}}`,
		"host empty":                base(`"host":"","port":5432,"name":"n","user":"u"`),
		"host blank":                base(`"host":"   ","port":5432,"name":"n","user":"u"`),
		"host with space+canary":    base(`"host":"h ` + canaryText + `","port":5432,"name":"n","user":"u"`),
		"host with control":         base(`"host":"h\u0001","port":5432,"name":"n","user":"u"`),
		"port zero":                 base(`"host":"h","port":0,"name":"n","user":"u"`),
		"port too large":            base(`"host":"h","port":65536,"name":"n","user":"u"`),
		"port negative":             base(`"host":"h","port":-1,"name":"n","user":"u"`),
		"port fractional":           base(`"host":"h","port":5432.5,"name":"n","user":"u"`),
		"port as string":            base(`"host":"h","port":"5432","name":"n","user":"u"`),
		"name empty":                base(`"host":"h","port":5432,"name":"","user":"u"`),
		"name control":              base(`"host":"h","port":5432,"name":"n\u0007","user":"u"`),
		"user blank":                base(`"host":"h","port":5432,"name":"n","user":"  "`),
		"password empty":            base(`"host":"h","port":5432,"name":"n","user":"u","password":""`),
		"password with NUL":         base(`"host":"h","port":5432,"name":"n","user":"u","password":"p\u0000` + canaryText + `"`),
		"unknown nested field":      base(`"host":"h","port":5432,"name":"n","user":"u","extra":"` + canaryText + `"`),
		"database missing":          `{"schema_version":1}`,
		"top-level null":            `null`,
		"top-level array":           `[` + canaryText + `]`,
		"trailing object":           validJSON + ` {}`,
		"trailing garbage":          validJSON + `x`,
		"invalid utf-8 in password": base(`"host":"h","port":5432,"name":"n","user":"u","password":"` + "\xff" + `"`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := Load(writeConfig(t, body, 0o600))
			if cfg != nil {
				t.Fatalf("returned a configuration for invalid input")
			}
			requireCode(t, err, codeConfiguration)
			requireNoLeak(t, err, canaryPassword, canaryKey, canaryText)
		})
	}
}

func TestDiagnosticsEscapeControlTextInPath(t *testing.T) {
	dir := filepath.Join(fixtureDir(t), "x\x1b[31m\nINJECTED")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := Load(filepath.Join(dir, "absent.json"))
	requireCode(t, err, codeConfiguration)
	msg := err.Error()
	if strings.ContainsRune(msg, 0x1b) || strings.Contains(msg, "\n") {
		t.Fatalf("raw control text reached the diagnostic: %q", msg)
	}
	// The temporary root is long, so the bounded path may be cut before the
	// newline; the escape itself is verified directly in TestQuoteEscapesAndBounds.
	if !strings.Contains(msg, `\x1b`) {
		t.Fatalf("escaped escape-character form missing: %q", msg)
	}
}

func TestQuoteEscapesAndBounds(t *testing.T) {
	if got := quote("a\x1b[31m\nb"); got != `"a\x1b[31m\nb"` {
		t.Fatalf("quote did not escape control text: %s", got)
	}
	long := strings.Repeat("é", 300) // multi-byte: the cut must stay on a rune boundary
	got := quote(long)
	if len(got) > maxQuotedBytes+8 || !strings.HasSuffix(got, `..."`) {
		t.Fatalf("quote did not bound the text: len=%d suffix=%q", len(got), got[len(got)-6:])
	}
	if strings.ContainsRune(got, '�') {
		t.Fatalf("truncation split a rune: %q", got)
	}
}

func TestRedactionInEveryFormattedForm(t *testing.T) {
	cfg, err := Load(writeConfig(t, validJSON, 0o600))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	marshalled, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	outputs := []string{
		fmt.Sprintf("%v", cfg),
		fmt.Sprintf("%+v", cfg),
		fmt.Sprintf("%#v", cfg),
		fmt.Sprintf("%v", cfg.Database),
		fmt.Sprintf("%+v", cfg.Database),
		fmt.Sprintf("%#v", cfg.Database),
		fmt.Sprintf("%v", cfg.Database.Password),
		fmt.Sprintf("%s", *cfg.Database.Password),
		fmt.Sprintf("%q", *cfg.Database.Password),
		fmt.Sprintf("%x", *cfg.Database.Password),
		string(marshalled),
	}
	for i, out := range outputs {
		if strings.Contains(out, canaryPassword) {
			t.Errorf("form %d leaks the password: %q", i, out)
		}
	}
	if !strings.Contains(string(marshalled), redacted) {
		t.Errorf("marshalled form lacks the redaction marker: %s", marshalled)
	}
}

// The ownership and mode policy is also tested on synthetic stat results, so
// it is verified independently of the identity the tests run under.
func TestDirectoryPolicyTable(t *testing.T) {
	const euid = 1000
	cases := []struct {
		name string
		uid  uint32
		mode uint32
		code string
	}{
		{"owned 0755", 1000, syscall.S_IFDIR | 0o755, ""},
		{"owned group-writable 0775", 1000, syscall.S_IFDIR | 0o775, codePermission},
		{"owned other-writable 0757", 1000, syscall.S_IFDIR | 0o757, codePermission},
		{"root-owned 0755", 0, syscall.S_IFDIR | 0o755, ""},
		{"root-owned sticky 1777", 0, syscall.S_IFDIR | 0o1777, ""},
		{"root-owned 0777 without sticky", 0, syscall.S_IFDIR | 0o777, codePermission},
		{"other user 0755", 1001, syscall.S_IFDIR | 0o755, codePermission},
		{"regular file in path", 1000, syscall.S_IFREG | 0o600, codeConfiguration},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &syscall.Stat_t{Mode: tc.mode, Uid: tc.uid}
			checkCode(t, vetDir("p", st, euid), tc.code)
		})
	}
}

func TestFilePolicyTable(t *testing.T) {
	const euid = 1000
	cases := []struct {
		name string
		uid  uint32
		mode uint32
		code string
	}{
		{"owned 0600", 1000, syscall.S_IFREG | 0o600, ""},
		{"owned 0400", 1000, syscall.S_IFREG | 0o400, ""},
		{"group-read 0640", 1000, syscall.S_IFREG | 0o640, codePermission},
		{"other-read 0604", 1000, syscall.S_IFREG | 0o604, codePermission},
		{"group-write 0620", 1000, syscall.S_IFREG | 0o620, codePermission},
		{"other-write 0602", 1000, syscall.S_IFREG | 0o602, codePermission},
		{"setuid 04600", 1000, syscall.S_IFREG | 0o4600, codePermission},
		{"setgid 02600", 1000, syscall.S_IFREG | 0o2600, codePermission},
		{"sticky 01600", 1000, syscall.S_IFREG | 0o1600, codePermission},
		{"other owner 0600", 1001, syscall.S_IFREG | 0o600, codePermission},
		{"directory at file path", 1000, syscall.S_IFDIR | 0o600, codeConfiguration},
		{"fifo at file path", 1000, syscall.S_IFIFO | 0o600, codeConfiguration},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &syscall.Stat_t{Mode: tc.mode, Uid: tc.uid}
			checkCode(t, vetFile("p", st, euid), tc.code)
		})
	}
}

func checkCode(t *testing.T, err error, code string) {
	t.Helper()
	if code == "" {
		if err != nil {
			t.Fatalf("rejected: %v", err)
		}
		return
	}
	requireCode(t, err, code)
}
