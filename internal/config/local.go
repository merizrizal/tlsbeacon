//go:build linux

// Package config loads the protected local bootstrap configuration.
//
// The file may carry database connection settings, including a password, so it
// is accepted only when every directory on its path is trusted and the file
// itself is owner-only. Each path component is opened relative to the
// descriptor of the directory already verified, with symbolic links refused,
// and the file is checked through the descriptor it reads. A path replaced
// after verification therefore cannot substitute different content.
//
// Diagnostics name fixed field names and the configuration path (escaped and
// bounded). They never echo file contents or secret values. The loader supplies
// no default location and no defaults for missing values.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

// CurrentSchemaVersion is the only configuration schema version this build reads.
const CurrentSchemaVersion = 1

// MaxFileBytes bounds how much of a configuration file is read.
const MaxFileBytes = 64 << 10

// Stable v1 execution-failure codes used by this package (S10 §7.3).
const (
	codeInvalidInput  = "invalid_input"
	codeConfiguration = "configuration_error"
	codePermission    = "permission_error"
)

const (
	maxQuotedBytes = 200
	redacted       = "[REDACTED]"
	allowedFields  = "schema_version; database.host, database.port, database.name, database.user, database.password (optional)"
	fieldsAction   = "Correct the named field in the configuration file."
	shapeAction    = "Write the configuration as one JSON object that matches the documented fields."
)

// Config is a validated protected bootstrap configuration.
type Config struct {
	SchemaVersion int      `json:"schema_version"`
	Database      Database `json:"database"`
}

// Database holds the connection settings for the PostgreSQL registry. The
// password is optional; when present it is a Secret and is never printed.
type Database struct {
	Host     string  `json:"host"`
	Port     int     `json:"port"`
	Name     string  `json:"name"`
	User     string  `json:"user"`
	Password *Secret `json:"password,omitempty"`
}

// Secret is a credential value whose text forms are always redacted.
type Secret string

// Reveal returns the credential. Callers must not log, print or wrap its result.
func (s Secret) Reveal() string { return string(s) }

// String, GoString and MarshalJSON all emit the redaction marker, so formatting
// or marshalling a configuration cannot disclose the value.
func (Secret) String() string   { return redacted }
func (Secret) GoString() string { return redacted }

func (Secret) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(redacted)), nil }

// Error is a typed configuration failure. Its text is redacted by construction.
type Error struct {
	Code    string
	Message string
	Action  string
}

func (e *Error) Error() string {
	return "tlsbeacon configuration: [" + e.Code + "] " + e.Message
}

// Load reads and validates the configuration file at an explicit absolute
// path. It returns no configuration on any failure, never an empty default.
func Load(path string) (*Config, error) {
	return loadWith(path, nil)
}

// loadWith is Load with a test seam: afterParents runs once every directory on
// the path has been verified and before the file itself is opened.
func loadWith(path string, afterParents func()) (*Config, error) {
	if err := checkPath(path); err != nil {
		return nil, err
	}
	euid := uint32(os.Geteuid())

	dirFD, err := openVerifiedDir(path, euid)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(dirFD)

	if afterParents != nil {
		afterParents()
	}
	data, err := readVerifiedFile(dirFD, path, euid)
	if err != nil {
		return nil, err
	}
	return decode(data, path)
}

func checkPath(path string) error {
	if path == "" || strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path || path == "/" {
		return fail(codeInvalidInput, path,
			"must name a file by an absolute, clean path",
			"Pass the explicit absolute path of the configuration file. No default location is used.")
	}
	return nil
}

// openVerifiedDir opens each directory on the path relative to the previous,
// already verified, descriptor. It refuses symbolic links at every step and
// returns the descriptor of the file's parent directory.
func openVerifiedDir(path string, euid uint32) (int, error) {
	cur, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, fail(codeConfiguration, path, "could not open the root directory",
			"Check the system file hierarchy and retry.")
	}
	if err := verifyDescriptor(cur, path, euid, vetDir); err != nil {
		syscall.Close(cur)
		return -1, err
	}
	for _, name := range strings.Split(filepath.Dir(path), "/") {
		if name == "" {
			continue
		}
		next, err := syscall.Openat(cur, name,
			syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		syscall.Close(cur)
		if err != nil {
			return -1, openError(err, path)
		}
		cur = next
		if err := verifyDescriptor(cur, path, euid, vetDir); err != nil {
			syscall.Close(cur)
			return -1, err
		}
	}
	return cur, nil
}

// readVerifiedFile opens the leaf relative to the verified parent descriptor,
// checks the opened object itself, and only then reads it.
func readVerifiedFile(dirFD int, path string, euid uint32) ([]byte, error) {
	fd, err := syscall.Openat(dirFD, filepath.Base(path),
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, openError(err, path)
	}
	// The file is closed on every return path. Non-blocking open ensures that a
	// FIFO is rejected by the check below instead of blocking here.
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, fail(codeConfiguration, path, "could not be inspected", "Check the file and retry.")
	}
	if err := vetFile(path, &st, euid); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, fail(codeConfiguration, path, "could not be read", "Check the file and retry.")
	}
	if len(data) > MaxFileBytes {
		return nil, fail(codeConfiguration, path, "is larger than 64 KiB",
			"Remove content that is not configuration.")
	}
	return data, nil
}

func verifyDescriptor(fd int, path string, euid uint32,
	check func(string, *syscall.Stat_t, uint32) error) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fail(codeConfiguration, path, "a directory on the path could not be inspected",
			"Check the path and retry.")
	}
	return check(path, &st, euid)
}

// vetDir accepts a directory owned by the effective user or by root and not
// writable by group or others. A root-owned sticky directory such as /tmp is
// accepted because only the owners of its entries can change them.
func vetDir(path string, st *syscall.Stat_t, euid uint32) error {
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fail(codeConfiguration, path, "has a component that is not a directory",
			"Pass the correct path.")
	}
	if st.Uid != euid && st.Uid != 0 {
		return fail(codePermission, path,
			"has a directory on its path that is not owned by this user or by root",
			"Use directories owned by this user or by root on the configuration path.")
	}
	writableByOthers := st.Mode&0o022 != 0
	sticky := st.Mode&0o1000 != 0 && st.Uid == 0
	if writableByOthers && !sticky {
		return fail(codePermission, path,
			"has a directory on its path that is writable by group or others",
			"Remove group and other write permission from each directory on the path.")
	}
	return nil
}

// vetFile accepts only a regular file owned by the effective user whose mode
// grants no access to group or others and sets no setuid, setgid or sticky bit.
func vetFile(path string, st *syscall.Stat_t, euid uint32) error {
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return fail(codeConfiguration, path, "does not name a regular file",
			"Point the configuration path at a regular file.")
	}
	if st.Uid != euid {
		return fail(codePermission, path, "is not owned by this user",
			"Make the configuration file owned by this user.")
	}
	if st.Mode&0o7077 != 0 {
		return fail(codePermission, path,
			"is accessible to group or others, or has setuid, setgid or sticky bits",
			"Set the file mode to 0600 or 0400 so only its owner can access it.")
	}
	return nil
}

func openError(err error, path string) *Error {
	switch {
	case errors.Is(err, syscall.ELOOP):
		return fail(codePermission, path, "contains a symbolic link, which is not allowed",
			"Use the real file and directory paths without symbolic links.")
	case errors.Is(err, syscall.ENOENT):
		return fail(codeConfiguration, path, "does not exist, or a directory on its path does not exist",
			"Create the configuration file at the explicit path, or pass the correct path. Nothing was created.")
	case errors.Is(err, syscall.ENOTDIR):
		return fail(codeConfiguration, path, "has a component that is not a directory",
			"Pass the correct path.")
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return fail(codePermission, path, "cannot be opened by this user",
			"Make each directory on the path searchable, and the file readable, by this user.")
	default:
		return fail(codeConfiguration, path, "could not be opened", "Check the path and retry.")
	}
}

func decode(data []byte, path string) (*Config, error) {
	if !utf8.Valid(data) {
		return nil, fail(codeConfiguration, path, "is not valid UTF-8", "Rewrite the file as UTF-8 JSON.")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, decodeError(err, path)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fail(codeConfiguration, path, "contains data after the configuration object",
			"Keep exactly one JSON object in the file.")
	}
	if err := cfg.validate(path); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// decodeError reports the shape of a decoding failure without its input: the
// syntax-error byte offset, the wrong-typed field name and fixed phrases only.
func decodeError(err error, path string) *Error {
	var syntax *json.SyntaxError
	var wrongType *json.UnmarshalTypeError
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return fail(codeConfiguration, path, "is empty or incomplete", shapeAction)
	case errors.As(err, &syntax):
		return fail(codeConfiguration, path,
			fmt.Sprintf("is not valid JSON near byte offset %d", syntax.Offset), shapeAction)
	case errors.As(err, &wrongType):
		if wrongType.Field == "" {
			return fail(codeConfiguration, path, "has the wrong JSON type at the top level", shapeAction)
		}
		return fail(codeConfiguration, path,
			"has the wrong JSON type for field "+wrongType.Field, shapeAction)
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		// The unknown name is deliberately not repeated: it is operator text
		// that may contain control characters or sensitive material.
		return fail(codeConfiguration, path, "contains a field that is not allowed",
			"Allowed fields: "+allowedFields+".")
	default:
		return fail(codeConfiguration, path, "could not be decoded as the configuration object", shapeAction)
	}
}

func (c *Config) validate(path string) error {
	if c.SchemaVersion != CurrentSchemaVersion {
		return fail(codeConfiguration, path, "must set schema_version to 1; this build reads only that version",
			fieldsAction)
	}
	db := c.Database
	if strings.TrimSpace(db.Host) == "" || strings.ContainsFunc(db.Host, isSpaceOrControl) {
		return fail(codeConfiguration, path,
			"requires database.host: a nonblank host name without spaces or control characters", fieldsAction)
	}
	if db.Port < 1 || db.Port > 65535 {
		return fail(codeConfiguration, path, "requires database.port: an integer from 1 to 65535", fieldsAction)
	}
	if !plainText(db.Name) {
		return fail(codeConfiguration, path,
			"requires database.name: nonblank text without control characters", fieldsAction)
	}
	if !plainText(db.User) {
		return fail(codeConfiguration, path,
			"requires database.user: nonblank text without control characters", fieldsAction)
	}
	if db.Password != nil {
		if *db.Password == "" {
			return fail(codeConfiguration, path,
				"has an empty database.password; omit the field instead", fieldsAction)
		}
		if strings.ContainsRune(string(*db.Password), 0) {
			return fail(codeConfiguration, path, "has a database.password containing a NUL byte", fieldsAction)
		}
	}
	return nil
}

func isSpaceOrControl(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }

func plainText(s string) bool {
	return strings.TrimSpace(s) != "" && !strings.ContainsFunc(s, unicode.IsControl)
}

// fail builds a redacted *Error whose message names the path only in escaped,
// bounded form.
func fail(code, path, msg, action string) *Error {
	return &Error{
		Code:    code,
		Message: "configuration file " + quote(path) + " " + msg,
		Action:  action,
	}
}

// quote escapes and bounds operator-supplied text before it is shown.
func quote(s string) string {
	if len(s) > maxQuotedBytes {
		cut := maxQuotedBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "..."
	}
	return strconv.Quote(s)
}
