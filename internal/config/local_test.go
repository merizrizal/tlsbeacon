package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func protectedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func protectedFile(t *testing.T, data string) string {
	t.Helper()
	dir := protectedDir(t)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadProtectedConfiguration(t *testing.T) {
	path := protectedFile(t, `{"database_url":"postgres://test:secret@localhost/db"}`)
	value, err := Load(path)
	if err != nil || value.DatabaseURL != "postgres://test:secret@localhost/db" {
		t.Fatalf("protected configuration failed: %v", err)
	}
	for _, formatted := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value)} {
		if strings.Contains(formatted, "secret") {
			t.Fatal("formatted configuration exposed a secret")
		}
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("owner-readable configuration rejected: %v", err)
	}
}

func TestUnsafeFilePermissionsAndOwnership(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("permission tests require a non-root operator")
	}
	path := protectedFile(t, `{"database_url":"fixture"}`)
	if _, err := Load(path); err != nil {
		t.Fatalf("safe path prerequisite: %v", err)
	}
	for _, mode := range []os.FileMode{0000, 0200, 0640, 0604, 0620, 0602} {
		t.Run(fmt.Sprintf("mode_%04o", mode), func(t *testing.T) {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("unsafe mode %04o accepted", mode)
			}
		})
	}
	info, err := os.Stat("/etc/hosts")
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("foreign-owned file prerequisite unavailable: %v", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == uint32(os.Geteuid()) {
		t.Fatal("foreign-owned file prerequisite is not met")
	}
	foreign := *st
	foreign.Mode = (foreign.Mode &^ 0777) | 0600
	if safeFile(foreign) {
		t.Fatal("foreign ownership accepted with otherwise safe permissions")
	}
	if _, err := Load("/etc/hosts"); err == nil {
		t.Fatal("foreign-owned configuration accepted")
	}
}

func TestUnsafeParentsAndSymlinks(t *testing.T) {
	path := protectedFile(t, `{"database_url":"fixture"}`)
	parent := filepath.Dir(path)
	if _, err := Load(path); err != nil {
		t.Fatalf("safe path prerequisite: %v", err)
	}
	for _, mode := range []os.FileMode{0720, 0702, 0777} {
		if err := os.Chmod(parent, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("unsafe parent mode %04o accepted", mode)
		}
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("file symlink accepted")
	}
	outer := protectedDir(t)
	linkDir := filepath.Join(outer, "parent-link")
	if err := os.Symlink(parent, linkDir); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(linkDir, "config.json")); err == nil {
		t.Fatal("parent symlink accepted")
	}
}

func TestReplacementAfterOpenFailsClosed(t *testing.T) {
	outer := protectedDir(t)
	parent := filepath.Join(outer, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "config.json")
	if err := os.WriteFile(path, []byte(`{"database_url":"original"}`), 0600); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(outer, "replacement")
	if err := os.Mkdir(replacement, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(replacement, "config.json"), []byte(`{"database_url":"replacement-secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("safe path prerequisite: %v", err)
	}
	_, err := load(path, func() {
		if err := os.Rename(parent, filepath.Join(outer, "original")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(replacement, parent); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil || strings.Contains(err.Error(), "replacement-secret") {
		t.Fatalf("replacement was not rejected safely: %v", err)
	}
}

func TestFileReplacementAfterOpenFailsClosed(t *testing.T) {
	path := protectedFile(t, `{"database_url":"original"}`)
	if _, err := Load(path); err != nil {
		t.Fatalf("safe path prerequisite: %v", err)
	}
	_, err := load(path, func() {
		if err := os.Rename(path, path+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"database_url":"replacement-secret"}`), 0600); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil || strings.Contains(err.Error(), "replacement-secret") {
		t.Fatalf("file replacement was not rejected safely: %v", err)
	}
}

func TestInvalidConfigurationAndRedactedErrors(t *testing.T) {
	for _, data := range []string{
		"", "{", `{}`, `{"database_url":""}`, `{"database_url":null}`,
		`{"database_url":"secret\ncontrol","other":"secret"}`,
		`{"database_url":"secret","database_url":"other"}`,
		`{"database_url":"secret"} {}`, `{"database_url":123}`,
	} {
		path := protectedFile(t, data)
		_, err := Load(path)
		if err == nil {
			t.Fatal("invalid configuration accepted")
		}
		if e, ok := err.(*Error); !ok || e.Code != "configuration_error" {
			t.Fatalf("invalid data returned wrong error: %v", err)
		}
		if strings.Contains(err.Error(), "secret") || strings.ContainsAny(err.Error(), "\n\r\x1b") {
			t.Fatalf("unsafe diagnostic: %q", err.Error())
		}
	}
	_, err := Load(filepath.Join(protectedDir(t), "secret\nmissing"))
	if err == nil || strings.Contains(err.Error(), "secret") || strings.ContainsAny(err.Error(), "\n\r\x1b") {
		t.Fatalf("unsafe missing-file diagnostic: %v", err)
	}
	if e, ok := err.(*Error); !ok || e.Code != "configuration_error" {
		t.Fatalf("missing file returned wrong error: %v", err)
	}
}
