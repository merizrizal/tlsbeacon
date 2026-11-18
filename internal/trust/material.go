package trust

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

type Mode string

const (
	System Mode = "system"
	Custom Mode = "custom"
)

var invalidMaterial = errors.New("trust configuration error: cannot import selected CA material; check source, ownership, permissions and certificate contents")

type Material struct {
	mode    Mode
	roots   [][]byte
	digest  [sha256.Size]byte
	sources [][sha256.Size]byte
}

// Import snapshots only the explicitly supplied sources. It never searches for roots.
func Import(mode Mode, paths []string) (Material, error) {
	return importMaterial(mode, paths, nil)
}

func importMaterial(mode Mode, paths []string, afterOpen func()) (Material, error) {
	if (mode != System && mode != Custom) || len(paths) == 0 {
		return Material{}, invalidMaterial
	}
	var roots [][]byte
	var sources [][sha256.Size]byte
	for _, path := range paths {
		data, err := readSource(path, mode, afterOpen)
		if err != nil {
			return Material{}, invalidMaterial
		}
		certs, err := parseCertificates(data)
		if err != nil {
			return Material{}, invalidMaterial
		}
		sources = append(sources, sha256.Sum256(data))
		roots = append(roots, certs...)
	}
	sort.Slice(roots, func(i, j int) bool { return bytes.Compare(roots[i], roots[j]) < 0 })
	unique := make([][]byte, 0, len(roots))
	for _, root := range roots {
		if len(unique) == 0 || !bytes.Equal(unique[len(unique)-1], root) {
			unique = append(unique, bytes.Clone(root))
		}
	}
	h := sha256.New()
	var length [8]byte
	for _, root := range unique {
		binary.BigEndian.PutUint64(length[:], uint64(len(root)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(root)
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return Material{mode: mode, roots: unique, digest: digest, sources: sources}, nil
}

func (m Material) Mode() Mode                { return m.mode }
func (m Material) Digest() [sha256.Size]byte { return m.digest }

func (m Material) SourceDigests() [][sha256.Size]byte {
	return append([][sha256.Size]byte(nil), m.sources...)
}

func (m Material) Roots() [][]byte {
	roots := make([][]byte, len(m.roots))
	for i, root := range m.roots {
		roots[i] = bytes.Clone(root)
	}
	return roots
}

// EqualMaterial identifies a no-op for material in the same source mode.
func (m Material) EqualMaterial(other Material) bool {
	if m.mode != other.mode || m.digest != other.digest || len(m.roots) == 0 || len(m.roots) != len(other.roots) {
		return false
	}
	for i := range m.roots {
		if !bytes.Equal(m.roots[i], other.roots[i]) {
			return false
		}
	}
	return true
}

func parseCertificates(data []byte) ([][]byte, error) {
	if len(data) == 0 {
		return nil, invalidMaterial
	}
	if cert, err := x509.ParseCertificate(data); err == nil {
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return nil, invalidMaterial
		}
		return [][]byte{bytes.Clone(cert.Raw)}, nil
	}
	remaining := bytes.TrimSpace(data)
	var roots [][]byte
	const begin = "-----BEGIN CERTIFICATE-----"
	const end = "-----END CERTIFICATE-----"
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte(begin)) {
			return nil, invalidMaterial
		}
		index := bytes.Index(remaining, []byte(end))
		if index < 0 || bytes.Contains(remaining[len(begin):index], []byte("-----BEGIN ")) {
			return nil, invalidMaterial
		}
		boundary := index + len(end)
		if boundary < len(remaining) && remaining[boundary] != '\n' && !(remaining[boundary] == '\r' && boundary+1 < len(remaining) && remaining[boundary+1] == '\n') {
			return nil, invalidMaterial
		}
		block, rest := pem.Decode(remaining[:boundary])
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, invalidMaterial
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.BasicConstraintsValid || !cert.IsCA {
			return nil, invalidMaterial
		}
		roots = append(roots, bytes.Clone(cert.Raw))
		remaining = bytes.TrimSpace(remaining[boundary:])
	}
	if len(roots) == 0 {
		return nil, invalidMaterial
	}
	return roots, nil
}

func readSource(path string, mode Mode, afterOpen func()) ([]byte, error) {
	if path == "" {
		return nil, invalidMaterial
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, invalidMaterial
	}
	first, before, err := openSource(path, mode)
	if err != nil {
		return nil, invalidMaterial
	}
	defer first.Close()
	if afterOpen != nil {
		afterOpen()
	}
	data, err := io.ReadAll(first)
	if err != nil {
		return nil, invalidMaterial
	}
	var after syscall.Stat_t
	if syscall.Fstat(int(first.Fd()), &after) != nil || !sameSource(before, after) {
		return nil, invalidMaterial
	}
	second, current, err := openSource(path, mode)
	if err != nil {
		return nil, invalidMaterial
	}
	second.Close()
	if !sameSource(before, current) {
		return nil, invalidMaterial
	}
	return data, nil
}

func sameSource(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func openSource(path string, mode Mode) (*os.File, syscall.Stat_t, error) {
	var st syscall.Stat_t
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, st, invalidMaterial
	}
	defer func() { syscall.Close(fd) }()
	if syscall.Fstat(fd, &st) != nil || !safeDirectory(st) {
		return nil, st, invalidMaterial
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) == 0 || parts[len(parts)-1] == "" {
		return nil, st, invalidMaterial
	}
	for _, part := range parts[:len(parts)-1] {
		next, err := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, st, invalidMaterial
		}
		syscall.Close(fd)
		fd = next
		if syscall.Fstat(fd, &st) != nil || !safeDirectory(st) {
			return nil, st, invalidMaterial
		}
	}
	file, err := syscall.Openat(fd, parts[len(parts)-1], syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, st, invalidMaterial
	}
	if syscall.Fstat(file, &st) != nil || !safeSource(st, mode) {
		syscall.Close(file)
		return nil, st, invalidMaterial
	}
	return os.NewFile(uintptr(file), "protected trust source"), st, nil
}

func safeDirectory(st syscall.Stat_t) bool {
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
		return false
	}
	return st.Mode&0022 == 0 || st.Uid == 0 && st.Mode&syscall.S_ISVTX != 0
}

func safeSource(st syscall.Stat_t, mode Mode) bool {
	owner := st.Uid == uint32(os.Geteuid()) || mode == System && st.Uid == 0
	return st.Mode&syscall.S_IFMT == syscall.S_IFREG && owner && st.Mode&0022 == 0 && st.Mode&0400 != 0
}
