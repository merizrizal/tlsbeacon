package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

type Local struct {
	DatabaseURL string
}

func (Local) String() string   { return "local configuration [redacted]" }
func (Local) GoString() string { return "local configuration [redacted]" }

type Error struct {
	Code    string
	Message string
	Action  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message + " " + e.Action }

func pathError() error {
	return &Error{"permission_error", "Cannot safely read the local configuration.", "Check the selected path, ownership and permissions."}
}

func dataError() error {
	return &Error{"configuration_error", "The local configuration is missing or invalid.", "Provide a valid protected configuration with a database_url."}
}

// Load reads an explicitly selected local bootstrap configuration without opening a database.
func Load(path string) (Local, error) { return load(path, nil) }

func load(path string, afterOpen func()) (Local, error) {
	var result Local
	if path == "" {
		return result, dataError()
	}
	if !strings.HasPrefix(path, "/") {
		cwd, err := os.Getwd()
		if err != nil {
			return result, pathError()
		}
		path = cwd + "/" + path
	}
	first, stat, err := openProtected(path)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return result, dataError()
		}
		return result, pathError()
	}
	defer first.Close()
	if afterOpen != nil {
		afterOpen()
	}
	content, err := io.ReadAll(first)
	if err != nil {
		return result, pathError()
	}
	second, secondStat, err := openProtected(path)
	if err != nil {
		return result, pathError()
	}
	second.Close()
	if stat.Dev != secondStat.Dev || stat.Ino != secondStat.Ino {
		return result, pathError()
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return result, dataError()
	}
	seen := false
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil || key != "database_url" || seen {
			return Local{}, dataError()
		}
		seen = true
		if err := decoder.Decode(&result.DatabaseURL); err != nil {
			return Local{}, dataError()
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || !seen || strings.TrimSpace(result.DatabaseURL) == "" {
		return Local{}, dataError()
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Local{}, dataError()
	}
	return result, nil
}

func openProtected(path string) (*os.File, syscall.Stat_t, error) {
	var st syscall.Stat_t
	parts := strings.Split(path, "/")
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, st, err
	}
	defer func() {
		if fd >= 0 {
			syscall.Close(fd)
		}
	}()
	if err = syscall.Fstat(fd, &st); err != nil || !safeDirectory(st) {
		return nil, st, fmt.Errorf("unsafe directory")
	}
	var components []string
	for _, part := range parts {
		if part != "" && part != "." {
			components = append(components, part)
		}
	}
	if len(components) == 0 || strings.HasSuffix(path, "/") {
		return nil, st, fmt.Errorf("invalid path")
	}
	for _, part := range components[:len(components)-1] {
		next, err := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, st, err
		}
		syscall.Close(fd)
		fd = next
		if err = syscall.Fstat(fd, &st); err != nil || !safeDirectory(st) {
			return nil, st, fmt.Errorf("unsafe directory")
		}
	}
	file, err := syscall.Openat(fd, components[len(components)-1], syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, st, err
	}
	if err = syscall.Fstat(file, &st); err != nil || !safeFile(st) {
		syscall.Close(file)
		return nil, st, fmt.Errorf("unsafe configuration")
	}
	return os.NewFile(uintptr(file), "protected configuration"), st, nil
}

func safeFile(st syscall.Stat_t) bool {
	return st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Uid == uint32(os.Geteuid()) && st.Mode&0077 == 0 && st.Mode&0400 != 0
}

func safeDirectory(st syscall.Stat_t) bool {
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
		return false
	}
	if st.Mode&0022 == 0 {
		return true
	}
	return st.Uid == 0 && st.Mode&syscall.S_ISVTX != 0
}
