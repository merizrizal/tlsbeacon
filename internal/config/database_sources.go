package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

var postgresEnvironmentVariables = []string{
	"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE",
	"PGAPPNAME", "PGCONNECT_TIMEOUT", "PGSSLMODE", "PGSSLKEY", "PGSSLCERT",
	"PGSSLCERTMODE", "PGSSLSNI", "PGSSLROOTCERT", "PGSSLPASSWORD",
	"PGSSLNEGOTIATION", "PGTARGETSESSIONATTRS", "PGSERVICE", "PGSERVICEFILE",
	"PGTZ", "PGOPTIONS", "PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION",
	"PGCHANNELBINDING", "PGREQUIREAUTH",
}

const connectionWhitespace = " \t\n\r\v\f"

func unsupportedDatabaseSourceError() error {
	return &Error{
		Code:    "configuration_error",
		Message: "The database configuration uses an unsupported external source.",
		Action:  "Use direct database_url settings; PostgreSQL environment overrides and service-file indirection are not supported.",
	}
}

func databaseSourcePathError() error {
	return &Error{
		Code:    "permission_error",
		Message: "Cannot safely read a configured database source.",
		Action:  "Check the referenced file ownership, permissions and parent directories.",
	}
}

func invalidDatabaseSourceError() error {
	return &Error{
		Code:    "configuration_error",
		Message: "The selected database configuration is invalid.",
		Action:  "Check the protected database_url value without sharing credentials.",
	}
}

func unsupportedSystemRootEnvironmentError() error {
	return &Error{
		Code:    "configuration_error",
		Message: "The database TLS configuration uses an unsupported external trust source.",
		Action:  "Unset SSL_CERT_FILE and SSL_CERT_DIR to use default system roots, or specify a protected explicit sslrootcert file.",
	}
}

func databaseUsesSystemRoots(databaseURL string, options map[string]string) bool {
	if !databaseHasTCPHost(databaseURL, options) {
		return false
	}

	rootCert, explicitlySet := options["sslrootcert"]
	if explicitlySet {
		if rootCert == "system" {
			return true
		}
		if rootCert != "" {
			return false
		}
	} else if home, err := os.UserHomeDir(); err == nil && home != "" && fileExists(filepath.Join(home, ".postgresql", "root.crt")) {
		return false
	}

	return options["sslmode"] == "verify-ca" || options["sslmode"] == "verify-full"
}

func databaseHasTCPHost(databaseURL string, options map[string]string) bool {
	hosts, found := options["host"]
	if !found {
		var err error
		hosts, found, err = postgresURIHosts(databaseURL)
		if err != nil {
			return true
		}
		if !found {
			hosts = defaultDatabaseHost()
		}
	}
	for _, host := range strings.Split(hosts, ",") {
		if host == "" {
			host = defaultDatabaseHost()
		}
		if !filepath.IsAbs(host) {
			return true
		}
	}
	return false
}

// postgresURIHosts mirrors pgconn's URI authority host-list parsing for TLS-path selection.
func postgresURIHosts(databaseURL string) (string, bool, error) {
	remaining, ok := strings.CutPrefix(databaseURL, "postgresql://")
	if !ok {
		remaining, ok = strings.CutPrefix(databaseURL, "postgres://")
	}
	if !ok {
		return "", false, nil
	}
	if index := strings.IndexAny(remaining, "@/"); index >= 0 && remaining[index] == '@' {
		remaining = remaining[index+1:]
	}

	var hosts strings.Builder
	for remaining != "" && remaining[0] != '/' && remaining[0] != '?' {
		if remaining[0] == '[' {
			index := strings.IndexByte(remaining, ']')
			if index < 0 {
				return "", false, errors.New("invalid URI host")
			}
			hosts.WriteString(remaining[1:index])
			remaining = remaining[index+1:]
		} else {
			index := strings.IndexAny(remaining, ":/?,")
			if index < 0 {
				index = len(remaining)
			}
			hosts.WriteString(remaining[:index])
			remaining = remaining[index:]
		}
		if strings.HasPrefix(remaining, ":") {
			remaining = remaining[1:]
			if index := strings.IndexAny(remaining, "/?,"); index >= 0 {
				remaining = remaining[index:]
			} else {
				remaining = ""
			}
		}
		if strings.HasPrefix(remaining, ",") {
			remaining = remaining[1:]
			hosts.WriteByte(',')
			continue
		}
		break
	}
	if hosts.Len() == 0 {
		return "", false, nil
	}
	decoded, err := decodePostgresURIComponent(hosts.String())
	if err != nil {
		return "", false, err
	}
	return decoded, true, nil
}

// Keep these candidates aligned with pgconn.defaultHost in the pinned pgx version.
func defaultDatabaseHost() string {
	for _, path := range []string{"/var/run/postgresql", "/private/tmp", "/tmp"} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return "localhost"
}

// QualifyDatabaseSources pins every local file pgx may read to an already checked descriptor.
// The caller must retain the returned cleanup until its registry connection is closed because
// pgx reloads client certificates by path during TLS handshakes.
func QualifyDatabaseSources(databaseURL string) (string, func(), error) {
	for _, name := range postgresEnvironmentVariables {
		if _, present := os.LookupEnv(name); present {
			return "", nil, unsupportedDatabaseSourceError()
		}
	}

	options, err := databaseURLParameters(databaseURL)
	if err != nil {
		return "", nil, invalidDatabaseSourceError()
	}
	if _, present := options["service"]; present {
		return "", nil, unsupportedDatabaseSourceError()
	}
	if _, present := options["servicefile"]; present {
		return "", nil, unsupportedDatabaseSourceError()
	}
	if mode, present := options["sslcertmode"]; present && mode != "disable" && mode != "allow" && mode != "require" {
		return "", nil, invalidDatabaseSourceError()
	}
	if databaseUsesSystemRoots(databaseURL, options) && (os.Getenv("SSL_CERT_FILE") != "" || os.Getenv("SSL_CERT_DIR") != "") {
		return "", nil, unsupportedSystemRootEnvironmentError()
	}

	files := make([]*os.File, 0, 4)
	qualifiedURL, err := qualifyDatabaseFileSources(databaseURL, options, &files)
	if err != nil {
		closeDatabaseSources(files)
		return "", nil, err
	}
	return qualifiedURL, func() { closeDatabaseSources(files) }, nil
}

func qualifyDatabaseFileSources(databaseURL string, options map[string]string, files *[]*os.File) (string, error) {
	home, homeErr := os.UserHomeDir()
	if homeErr != nil {
		home = ""
	}

	overrides := map[string]string{}
	passfile := ""
	if options["password"] == "" {
		if configured, explicit := options["passfile"]; explicit {
			if configured != "" {
				path, err := openDatabaseSource(configured, true, true, files)
				if err != nil {
					return "", err
				}
				passfile = path
			}
		} else if home != "" {
			path, err := openDatabaseSource(filepath.Join(home, ".pgpass"), true, true, files)
			if err != nil {
				return "", err
			}
			passfile = path
		}
	}
	overrides["passfile"] = passfile

	rootCert, rootCertSet := options["sslrootcert"]
	if !rootCertSet && home != "" {
		candidate := filepath.Join(home, ".postgresql", "root.crt")
		if fileExists(candidate) {
			rootCert = candidate
		}
	}
	if rootCert != "" && rootCert != "system" {
		path, err := openDatabaseSource(rootCert, false, false, files)
		if err != nil {
			return "", err
		}
		rootCert = path
	}
	overrides["sslrootcert"] = rootCert

	clientCert, certSet := options["sslcert"]
	clientKey, keySet := options["sslkey"]
	if home != "" && (!certSet || !keySet) {
		defaultCert := filepath.Join(home, ".postgresql", "postgresql.crt")
		defaultKey := filepath.Join(home, ".postgresql", "postgresql.key")
		if fileExists(defaultCert) && fileExists(defaultKey) {
			if !certSet {
				clientCert = defaultCert
			}
			if !keySet {
				clientKey = defaultKey
			}
		}
	}
	if options["sslmode"] == "disable" || options["sslcertmode"] == "disable" {
		clientCert, clientKey = "", ""
	} else if clientCert != "" && clientKey != "" {
		path, err := openDatabaseSource(clientCert, false, false, files)
		if err != nil {
			return "", err
		}
		clientCert = path
		path, err = openDatabaseSource(clientKey, true, false, files)
		if err != nil {
			return "", err
		}
		clientKey = path
	}
	overrides["sslcert"] = clientCert
	overrides["sslkey"] = clientKey

	qualifiedURL, err := appendDatabaseOverrides(databaseURL, overrides)
	if err != nil {
		return "", invalidDatabaseSourceError()
	}
	return qualifiedURL, nil
}

func closeDatabaseSources(files []*os.File) {
	for index := len(files) - 1; index >= 0; index-- {
		_ = files[index].Close()
	}
}

func openDatabaseSource(path string, secret, optional bool, files *[]*os.File) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", databaseSourcePathError()
	}
	file, _, err := openOwnedFile(absolute, func(st syscall.Stat_t) bool {
		return safeDatabaseSourceFile(st, secret)
	})
	if err != nil {
		if optional && errors.Is(err, syscall.ENOENT) {
			return "", nil
		}
		return "", databaseSourcePathError()
	}
	*files = append(*files, file)
	return fmt.Sprintf("/proc/self/fd/%d", file.Fd()), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func safeDatabaseSourceFile(st syscall.Stat_t, secret bool) bool {
	uid := uint32(os.Geteuid())
	ownerAllowed := st.Uid == uid || (!secret && st.Uid == 0)
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || !ownerAllowed || st.Mode&0022 != 0 || st.Mode&07000 != 0 || st.Mode&0400 == 0 {
		return false
	}
	if secret && (st.Uid != uid || st.Mode&0077 != 0) {
		return false
	}
	return true
}

func appendDatabaseOverrides(databaseURL string, overrides map[string]string) (string, error) {
	keys := []string{"passfile", "sslrootcert", "sslcert", "sslkey"}
	if strings.HasPrefix(databaseURL, "postgres://") || strings.HasPrefix(databaseURL, "postgresql://") {
		prefix := "postgres://"
		if strings.HasPrefix(databaseURL, "postgresql://") {
			prefix = "postgresql://"
		}
		remaining := strings.TrimPrefix(databaseURL, prefix)
		if index := strings.IndexAny(remaining, "@/"); index >= 0 && remaining[index] == '@' {
			remaining = remaining[index+1:]
		}
		query, present, err := postgresURIQuery(remaining)
		if err != nil {
			return "", err
		}
		separator := "?"
		if present {
			separator = "&"
			if query == "" || strings.HasSuffix(query, "&") {
				separator = ""
			}
		}
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, key+"="+encodePostgresURIComponent(overrides[key]))
		}
		return databaseURL + separator + strings.Join(parts, "&"), nil
	}

	if trailingBackslashes := trailingBackslashCount(databaseURL); trailingBackslashes%2 == 1 {
		// pgconn drops a final unquoted escape. Remove that byte before appending
		// options so it cannot escape the separator and swallow the overrides.
		databaseURL = databaseURL[:len(databaseURL)-1]
	}
	if hasTerminalEmptyKeywordValue(databaseURL) {
		// An empty unquoted value consumes the next token as its value in pgconn.
		// Close it explicitly so the first qualified override remains a key.
		databaseURL += "''"
	}
	for _, key := range keys {
		databaseURL += " " + key + "='" + strings.NewReplacer("\\", "\\\\", "'", "\\'").Replace(overrides[key]) + "'"
	}
	return databaseURL, nil
}

func trailingBackslashCount(value string) int {
	count := 0
	for index := len(value) - 1; index >= 0 && value[index] == '\\'; index-- {
		count++
	}
	return count
}

func hasTerminalEmptyKeywordValue(value string) bool {
	value = strings.TrimRight(value, connectionWhitespace)
	if !strings.HasSuffix(value, "=") {
		return false
	}
	key := strings.TrimRight(value[:len(value)-1], connectionWhitespace)
	start := strings.LastIndexAny(key, connectionWhitespace) + 1
	key = key[start:]
	return key != "" && !strings.ContainsAny(key, "='\"")
}

func encodePostgresURIComponent(value string) string {
	const hexadecimal = "0123456789ABCDEF"
	var encoded strings.Builder
	for index := 0; index < len(value); index++ {
		c := value[index]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", rune(c)) {
			encoded.WriteByte(c)
			continue
		}
		encoded.WriteByte('%')
		encoded.WriteByte(hexadecimal[c>>4])
		encoded.WriteByte(hexadecimal[c&0x0f])
	}
	return encoded.String()
}

// DatabaseConnectionKeys returns the parsed connection keys plus the path keys
// added by QualifyDatabaseSources, for pgconn's ConnStringAllowedKeys check.
func DatabaseConnectionKeys(databaseURL string) ([]string, error) {
	parameters, err := databaseURLParameters(databaseURL)
	if err != nil {
		return nil, invalidDatabaseSourceError()
	}
	if _, present := parameters["service"]; present {
		return nil, unsupportedDatabaseSourceError()
	}
	if _, present := parameters["servicefile"]; present {
		return nil, unsupportedDatabaseSourceError()
	}

	keys := make(map[string]struct{}, len(parameters)+10)
	for key := range parameters {
		keys[key] = struct{}{}
	}
	for _, key := range []string{"host", "port", "database", "dbname", "user", "password", "passfile", "sslrootcert", "sslcert", "sslkey"} {
		keys[key] = struct{}{}
	}
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	sort.Strings(result)
	return result, nil
}

func databaseURLParameters(databaseURL string) (map[string]string, error) {
	if strings.HasPrefix(databaseURL, "postgres://") || strings.HasPrefix(databaseURL, "postgresql://") {
		return postgresURIParameters(databaseURL)
	}
	return keywordValueParameters(databaseURL)
}

func postgresURIParameters(databaseURL string) (map[string]string, error) {
	parameters := make(map[string]string)
	prefix := "postgres://"
	if strings.HasPrefix(databaseURL, "postgresql://") {
		prefix = "postgresql://"
	}
	remaining := strings.TrimPrefix(databaseURL, prefix)
	if index := strings.IndexAny(remaining, "@/"); index >= 0 && remaining[index] == '@' {
		userinfo := remaining[:index]
		remaining = remaining[index+1:]
		if _, password, hasPassword := strings.Cut(userinfo, ":"); hasPassword && password != "" {
			decoded, err := decodePostgresURIComponent(password)
			if err != nil {
				return nil, err
			}
			if decoded != "" {
				parameters["password"] = decoded
			}
		}
	}

	query, present, err := postgresURIQuery(remaining)
	if err != nil {
		return nil, err
	}
	if !present {
		return parameters, nil
	}
	for query != "" {
		pair := query
		if index := strings.IndexByte(query, '&'); index >= 0 {
			pair, query = query[:index], query[index+1:]
		} else {
			query = ""
		}
		rawName, rawValue, found := strings.Cut(pair, "=")
		if !found || strings.Contains(rawValue, "=") {
			return nil, errors.New("invalid URI parameter")
		}
		name, err := decodePostgresURIComponent(rawName)
		if err != nil {
			return nil, err
		}
		value, err := decodePostgresURIComponent(rawValue)
		if err != nil {
			return nil, err
		}
		parameters[name] = value
	}
	return parameters, nil
}

func postgresURIQuery(remaining string) (string, bool, error) {
	for {
		if remaining == "" {
			return "", false, nil
		}
		if remaining[0] == '[' {
			end := strings.IndexByte(remaining, ']')
			if end < 0 {
				return "", false, errors.New("invalid URI host")
			}
			remaining = remaining[end+1:]
			if strings.HasPrefix(remaining, ":") {
				remaining = remaining[1:]
				if end := strings.IndexAny(remaining, "/?,"); end >= 0 {
					remaining = remaining[end:]
				} else {
					return "", false, nil
				}
			}
		} else {
			index := strings.IndexAny(remaining, ":/?,")
			if index < 0 {
				return "", false, nil
			}
			delimiter := remaining[index]
			remaining = remaining[index:]
			if delimiter == ':' {
				remaining = remaining[1:]
				if end := strings.IndexAny(remaining, "/?,"); end >= 0 {
					remaining = remaining[end:]
				} else {
					return "", false, nil
				}
			}
		}

		if strings.HasPrefix(remaining, ",") {
			remaining = remaining[1:]
			continue
		}
		if strings.HasPrefix(remaining, "/") {
			remaining = remaining[1:]
			if index := strings.IndexByte(remaining, '?'); index >= 0 {
				return remaining[index+1:], true, nil
			}
			return "", false, nil
		}
		if strings.HasPrefix(remaining, "?") {
			return remaining[1:], true, nil
		}
		if remaining == "" {
			return "", false, nil
		}
		return "", false, errors.New("invalid URI host")
	}
}

func decodePostgresURIComponent(raw string) (string, error) {
	var decoded strings.Builder
	decoded.Grow(len(raw))
	index := 0
	for index < len(raw) && raw[index] == ' ' {
		index++
	}
	for index < len(raw) && raw[index] != ' ' {
		if raw[index] != '%' {
			decoded.WriteByte(raw[index])
			index++
			continue
		}
		if index+2 >= len(raw) {
			return "", errors.New("invalid URI escape")
		}
		hi, okHi := postgresHexDigit(raw[index+1])
		lo, okLo := postgresHexDigit(raw[index+2])
		if !okHi || !okLo {
			return "", errors.New("invalid URI escape")
		}
		value := hi<<4 | lo
		if value == 0 {
			return "", errors.New("invalid URI value")
		}
		decoded.WriteByte(value)
		index += 3
	}
	for index < len(raw) && raw[index] == ' ' {
		index++
	}
	if index < len(raw) {
		return "", errors.New("invalid URI whitespace")
	}
	return decoded.String(), nil
}

func postgresHexDigit(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	default:
		return 0, false
	}
}

func keywordValueParameters(connection string) (map[string]string, error) {
	parameters := make(map[string]string)
	if strings.IndexByte(connection, 0) >= 0 {
		return nil, errors.New("invalid connection string")
	}
	for connection = strings.TrimLeft(connection, connectionWhitespace); connection != ""; connection = strings.TrimLeft(connection, connectionWhitespace) {
		separator := strings.IndexByte(connection, '=')
		if separator < 0 {
			return nil, errors.New("invalid connection string")
		}
		name := strings.Trim(connection[:separator], connectionWhitespace)
		if name == "" || strings.ContainsAny(name, connectionWhitespace) {
			return nil, errors.New("invalid connection string")
		}
		connection = strings.TrimLeft(connection[separator+1:], connectionWhitespace)

		var value string
		if strings.HasPrefix(connection, "'") {
			connection = connection[1:]
			var decoded strings.Builder
			closed := false
			for index := 0; index < len(connection); index++ {
				switch connection[index] {
				case '\\':
					index++
					if index == len(connection) {
						return nil, errors.New("invalid connection string")
					}
					decoded.WriteByte(connection[index])
				case '\'':
					connection = connection[index+1:]
					closed = true
					index = len(connection)
				default:
					decoded.WriteByte(connection[index])
				}
			}
			if !closed {
				return nil, errors.New("invalid connection string")
			}
			value = decoded.String()
		} else {
			var decoded strings.Builder
			index := 0
			for index < len(connection) && !strings.ContainsRune(connectionWhitespace, rune(connection[index])) {
				if connection[index] == '\\' {
					index++
					if index == len(connection) {
						break
					}
				}
				decoded.WriteByte(connection[index])
				index++
			}
			value = decoded.String()
			connection = connection[index:]
		}
		parameters[name] = value
	}
	return parameters, nil
}
