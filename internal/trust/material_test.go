package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

func certificate(t *testing.T, serial int64, ca bool, expired bool) ([]byte, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	if expired {
		end = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: start, NotAfter: end, BasicConstraintsValid: true, IsCA: ca}
	if ca {
		template.KeyUsage = x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func source(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCanonicalMaterialAndIsolation(t *testing.T) {
	a, ap := certificate(t, 1, true, false)
	b, bp := certificate(t, 2, true, false)
	bundle := append(append(bytes.Clone(bp), ap...), bp...)
	path := source(t, bundle)
	m, err := Import(Custom, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]byte{a, b}
	sort.Slice(want, func(i, j int) bool { return bytes.Compare(want[i], want[j]) < 0 })
	got := m.Roots()
	if len(got) != 2 || !bytes.Equal(got[0], want[0]) || !bytes.Equal(got[1], want[1]) || m.Mode() != Custom {
		t.Fatal("incorrect exported selected roots or mode")
	}
	var encoded bytes.Buffer
	for _, root := range want {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(root)))
		encoded.Write(length[:])
		encoded.Write(root)
	}
	if m.Digest() != sha256.Sum256(encoded.Bytes()) || len(m.SourceDigests()) != 1 || m.SourceDigests()[0] != sha256.Sum256(bundle) {
		t.Fatal("root-set encoding or source digest mismatch")
	}
	other, err := Import(Custom, []string{source(t, append(bytes.Clone(ap), bp...))})
	if err != nil || !m.EqualMaterial(other) || m.Digest() != other.Digest() {
		t.Fatal("reordered/deduplicated roots not equal")
	}
	system, err := Import(System, []string{source(t, append(bytes.Clone(ap), bp...))})
	if err != nil || system.Digest() != m.Digest() || m.EqualMaterial(system) {
		t.Fatal("source modes are not distinct")
	}
	changed, err := Import(Custom, []string{source(t, ap)})
	if err != nil || m.EqualMaterial(changed) || m.Digest() == changed.Digest() {
		t.Fatal("changed roots not distinguished")
	}
	got[0][0] ^= 0xff
	got[1] = nil
	digests := m.SourceDigests()
	digests[0][0] ^= 0xff
	if err := os.WriteFile(path, ap, 0600); err != nil {
		t.Fatal(err)
	}
	if !m.EqualMaterial(other) || !bytes.Equal(m.Roots()[0], want[0]) || m.SourceDigests()[0] != sha256.Sum256(bundle) {
		t.Fatal("snapshot changed through alias or source overwrite")
	}
	if (Material{}).EqualMaterial(Material{}) {
		t.Fatal("empty material considered valid")
	}
}

func TestExplicitSourcesAndExpiredCA(t *testing.T) {
	a, ap := certificate(t, 3, true, true)
	b, bp := certificate(t, 4, true, false)
	for _, mode := range []Mode{System, Custom} {
		t.Run(string(mode), func(t *testing.T) {
			m, err := Import(mode, []string{source(t, ap), source(t, bp)})
			if err != nil || len(m.Roots()) != 2 || len(m.SourceDigests()) != 2 || m.SourceDigests()[0] != sha256.Sum256(ap) || m.SourceDigests()[1] != sha256.Sum256(bp) {
				t.Fatalf("explicit sources rejected: %v", err)
			}
			set := m.Roots()
			if !(bytes.Equal(set[0], a) && bytes.Equal(set[1], b) || bytes.Equal(set[0], b) && bytes.Equal(set[1], a)) {
				t.Fatal("unexpected root set")
			}
		})
	}
	m, err := Import(Custom, []string{source(t, a)})
	if err != nil || len(m.Roots()) != 1 || !bytes.Equal(m.Roots()[0], a) {
		t.Fatal("DER input or expired CA rejected")
	}
	for _, tc := range []struct {
		mode  Mode
		paths []string
	}{{Custom, nil}, {System, nil}, {Mode("other"), []string{source(t, ap)}}, {Custom, []string{""}}, {Custom, []string{source(t, ap), "/nonexistent/tlsbeacon-test"}}} {
		if _, err := Import(tc.mode, tc.paths); err == nil {
			t.Fatal("invalid mode or source accepted")
		}
	}
}

func TestStrictInputAndRedaction(t *testing.T) {
	_, good := certificate(t, 5, true, false)
	_, leaf := certificate(t, 6, false, false)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	secret := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cases := map[string][]byte{
		"empty":                  nil,
		"whitespace":             []byte(" \n"),
		"overlapping end marker": []byte("-----BEGIN CERTIFICATE-----END CERTIFICATE-----"),
		"malformed":              []byte("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"),
		"truncated":              good[:len(good)-5],
		"leaf":                   leaf,
		"key":                    secret,
		"valid then key":         append(bytes.Clone(good), secret...),
		"key then valid":         append(bytes.Clone(secret), good...),
		"valid then garbage":     append(bytes.Clone(good), []byte("junk")...),
		"invalid end line":       append(bytes.TrimSuffix(bytes.Clone(good), []byte("\n")), good...),
		"valid then malformed":   append(bytes.Clone(good), []byte("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----")...),
		"nested malformed":       append([]byte("-----BEGIN CERTIFICATE-----\n!!!\n"), good...),
		"valid then leaf":        append(bytes.Clone(good), leaf...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			m, err := Import(Custom, []string{source(t, data)})
			if err == nil || len(m.Roots()) != 0 || strings.Contains(err.Error(), string(secret)) || strings.Contains(err.Error(), "PRIVATE KEY") {
				t.Fatalf("unsafe import or diagnostic: %v", err)
			}
		})
	}
}

func TestProtectedSourcePaths(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("test requires non-root operator")
	}
	_, good := certificate(t, 7, true, false)
	path := source(t, good)
	if _, err := Import(Custom, []string{path}); err != nil {
		t.Fatalf("safe source prerequisite: %v", err)
	}
	for _, mode := range []os.FileMode{0000, 0200, 0620, 0602} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Import(Custom, []string{path}); err == nil {
			t.Fatalf("unsafe file mode %o", mode)
		}
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(Custom, []string{path}); err != nil {
		t.Fatal("owner-writable CA source rejected")
	}
	parent := filepath.Dir(path)
	if err := os.Chmod(parent, 0720); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(Custom, []string{path}); err == nil {
		t.Fatal("unsafe parent accepted")
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(Custom, []string{link}); err == nil {
		t.Fatal("symlink source accepted")
	}
	outer := filepath.Dir(source(t, good))
	parentLink := filepath.Join(outer, "parent-link")
	if err := os.Symlink(parent, parentLink); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(Custom, []string{filepath.Join(parentLink, "roots.pem")}); err == nil {
		t.Fatal("symlink parent accepted")
	}
	stat := syscall.Stat_t{Mode: syscall.S_IFREG | 0644, Uid: 0}
	if safeSource(stat, Custom) || !safeSource(stat, System) {
		t.Fatal("foreign or system root ownership policy incorrect")
	}
}

func TestInPlaceChangeDuringReadFailsClosed(t *testing.T) {
	_, original := certificate(t, 9, true, false)
	_, replacement := certificate(t, 10, true, false)
	path := source(t, original)
	_, err := importMaterial(Custom, []string{path}, func() {
		if err := os.WriteFile(path, replacement, 0600); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil {
		t.Fatal("in-place source modification accepted")
	}
}

func TestReplacementDuringReadFailsClosed(t *testing.T) {
	_, good := certificate(t, 8, true, false)
	for _, parentSwap := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "parent"}[parentSwap], func(t *testing.T) {
			outer := filepath.Dir(source(t, good))
			parent := filepath.Join(outer, "parent")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "roots.pem")
			if err := os.WriteFile(path, good, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := importMaterial(Custom, []string{path}, func() {
				if parentSwap {
					if err := os.Rename(parent, parent+"-old"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(parent, 0700); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Rename(path, path+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, good, 0600); err != nil {
					t.Fatal(err)
				}
			})
			if err == nil {
				t.Fatal("replacement accepted")
			}
		})
	}
}
