package registry

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/merizrizal/tlsbeacon/internal/endpoint"
)

type EndpointRecord struct {
	RegistrationID        string
	MonitoringID          string
	ConfigurationRevision uint64
	Values                endpoint.Values
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

type storedName struct {
	Original string `json:"original"`
	DNS      string `json:"dns,omitempty"`
	IP       string `json:"ip,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

type storedTrustSelection struct {
	Profile  string `json:"profile"`
	Version  string `json:"version"`
	Material string `json:"material"`
}

type storedEndpointValues struct {
	Label      string               `json:"label"`
	Host       storedName           `json:"host"`
	Port       int                  `json:"port"`
	Identity   storedName           `json:"identity"`
	Trust      storedTrustSelection `json:"trust"`
	IntervalNS int64                `json:"interval_ns"`
	WarningNS  int64                `json:"warning_ns"`
	CriticalNS int64                `json:"critical_ns"`
	Enabled    bool                 `json:"enabled"`
}

type storedEndpointRecord struct {
	RegistrationID        string               `json:"registration_id"`
	MonitoringID          string               `json:"monitoring_id"`
	ConfigurationRevision uint64               `json:"configuration_revision"`
	Values                storedEndpointValues `json:"values"`
	CreatedAt             time.Time            `json:"created_at"`
	UpdatedAt             time.Time            `json:"updated_at"`
}

func endpointInputError() error {
	return &Error{"invalid_input", "The endpoint configuration is invalid.", "Check required fields, host, identity, port, durations and thresholds."}
}

func trustSelectionError() error {
	return &Error{"trust_configuration_error", "The selected trust profile or version is invalid.", "Select an imported profile and one of its stored material versions."}
}

func endpointRollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func commitEndpointTransaction(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return classifyCommit(err)
	}
	return nil
}

func storedNameFromValue(value endpoint.Name) storedName {
	result := storedName{Original: value.Original, DNS: value.DNS, Scope: value.Scope}
	if value.IP.IsValid() {
		result.IP = value.IP.String()
	}
	return result
}

func restoreStoredName(value storedName, identity bool) (endpoint.Name, error) {
	var result endpoint.Name
	var err error
	if identity {
		result, err = endpoint.NormalizeIdentity(value.Original)
	} else {
		result, err = endpoint.NormalizeHost(value.Original)
	}
	if err != nil {
		return endpoint.Name{}, storageError()
	}
	ip := ""
	if result.IP.IsValid() {
		ip = result.IP.String()
	}
	if value.DNS != result.DNS || value.IP != ip || value.Scope != result.Scope {
		return endpoint.Name{}, storageError()
	}
	return result, nil
}

func encodeEndpointRecord(record EndpointRecord) ([]byte, error) {
	if !validEndpointRecord(record) {
		return nil, storageError()
	}
	stored := storedEndpointRecord{
		RegistrationID:        record.RegistrationID,
		MonitoringID:          record.MonitoringID,
		ConfigurationRevision: record.ConfigurationRevision,
		Values: storedEndpointValues{
			Label:      record.Values.Label,
			Host:       storedNameFromValue(record.Values.Host),
			Port:       record.Values.Port,
			Identity:   storedNameFromValue(record.Values.Identity),
			Trust:      storedTrustSelection{record.Values.Trust.Profile, record.Values.Trust.Version, record.Values.Trust.Material},
			IntervalNS: int64(record.Values.Interval),
			WarningNS:  int64(record.Values.Warning),
			CriticalNS: int64(record.Values.Critical),
			Enabled:    record.Values.Enabled,
		},
		CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt,
	}
	data, err := json.Marshal(stored)
	if err != nil {
		return nil, storageError()
	}
	return data, nil
}

func decodeEndpointRecord(data []byte, key string) (EndpointRecord, error) {
	var stored storedEndpointRecord
	if decodeCanonical(data, &stored) != nil || stored.RegistrationID != key || !validID(key) || !validID(stored.MonitoringID) || stored.ConfigurationRevision == 0 {
		return EndpointRecord{}, storageError()
	}
	host, err := restoreStoredName(stored.Values.Host, false)
	if err != nil {
		return EndpointRecord{}, storageError()
	}
	identity, err := restoreStoredName(stored.Values.Identity, true)
	if err != nil {
		return EndpointRecord{}, storageError()
	}
	interval := time.Duration(stored.Values.IntervalNS)
	warning := time.Duration(stored.Values.WarningNS)
	critical := time.Duration(stored.Values.CriticalNS)
	enabled := stored.Values.Enabled
	values, err := endpoint.NewValues(endpoint.CreateInput{
		Label: stored.Values.Label, Host: host.Original, Port: stored.Values.Port,
		Identity: identity.Original,
		Trust: endpoint.TrustSelection{
			Profile:  stored.Values.Trust.Profile,
			Version:  stored.Values.Trust.Version,
			Material: stored.Values.Trust.Material,
		},
		Interval: &interval, Warning: &warning, Critical: &critical, Enabled: &enabled,
	})
	if err != nil || values.Host != host || values.Identity != identity {
		return EndpointRecord{}, storageError()
	}
	record := EndpointRecord{
		RegistrationID: stored.RegistrationID, MonitoringID: stored.MonitoringID,
		ConfigurationRevision: stored.ConfigurationRevision, Values: values,
		CreatedAt: stored.CreatedAt, UpdatedAt: stored.UpdatedAt,
	}
	if !validEndpointRecord(record) {
		return EndpointRecord{}, storageError()
	}
	return record, nil
}

func validEndpointRecord(record EndpointRecord) bool {
	if !validID(record.RegistrationID) || !validID(record.MonitoringID) || record.RegistrationID == record.MonitoringID || record.ConfigurationRevision == 0 || record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() || record.CreatedAt.Location() != time.UTC || record.UpdatedAt.Location() != time.UTC || record.UpdatedAt.Before(record.CreatedAt) {
		return false
	}
	_, err := endpoint.ApplyPatch(record.Values, endpoint.Patch{})
	return err == nil
}

func trustSelectionInTransaction(ctx context.Context, tx pgx.Tx, selection endpoint.TrustSelection, lock bool) error {
	if !validID(selection.Profile) || !validID(selection.Version) {
		return trustSelectionError()
	}
	query := `SELECT value, digest FROM tlsbeacon_registry.records WHERE kind=$1 AND key=$2`
	if lock {
		query += ` FOR SHARE`
	}
	var data, digest []byte
	err := tx.QueryRow(ctx, query, "trust", selection.Profile).Scan(&data, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return trustSelectionError()
	}
	if err != nil || data == nil {
		return storageError()
	}
	hash := recordDigest("trust", selection.Profile, data)
	if !bytes.Equal(digest, hash[:]) {
		return storageError()
	}
	var profile TrustProfile
	if decodeCanonical(data, &profile) != nil || validateProfile(profile, selection.Profile) != nil {
		return storageError()
	}
	for _, version := range profile.Versions {
		if version.ID == selection.Version {
			if selection.Material != hex.EncodeToString(version.Digest[:]) {
				return trustSelectionError()
			}
			return nil
		}
	}
	return trustSelectionError()
}

func validateStoredTrustSelection(ctx context.Context, tx pgx.Tx, selection endpoint.TrustSelection, lock bool) error {
	err := trustSelectionInTransaction(ctx, tx, selection, lock)
	var registryError *Error
	if errors.As(err, &registryError) && registryError.Code == "trust_configuration_error" {
		return storageError()
	}
	return err
}

func readEndpointRecord(ctx context.Context, tx pgx.Tx, id string, lock bool) (EndpointRecord, error) {
	query := `SELECT value, digest FROM tlsbeacon_registry.records WHERE kind=$1 AND key=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	var data, digest []byte
	err := tx.QueryRow(ctx, query, "endpoint", id).Scan(&data, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return EndpointRecord{}, notFound()
	}
	if err != nil || data == nil {
		return EndpointRecord{}, storageError()
	}
	hash := recordDigest("endpoint", id, data)
	if !bytes.Equal(digest, hash[:]) {
		return EndpointRecord{}, storageError()
	}
	record, err := decodeEndpointRecord(data, id)
	if err != nil {
		return EndpointRecord{}, storageError()
	}
	if err := validateStoredTrustSelection(ctx, tx, record.Values.Trust, lock); err != nil {
		return EndpointRecord{}, err
	}
	return record, nil
}

func newMonitoringID(registrationID, previous string) (string, error) {
	for range 8 {
		id, err := newID()
		if err != nil {
			return "", err
		}
		if id != registrationID && id != previous {
			return id, nil
		}
	}
	return "", storageError()
}

func nextEndpointTimestamp(previous time.Time) time.Time {
	now := time.Now().UTC()
	if !now.After(previous) {
		now = previous.Add(time.Nanosecond)
	}
	return now
}

// AddEndpoint persists a complete registration after validating its actual selected trust version.
func (db *DB) AddEndpoint(ctx context.Context, input endpoint.CreateInput) (EndpointRecord, error) {
	if !validID(input.Trust.Profile) || !validID(input.Trust.Version) {
		return EndpointRecord{}, trustSelectionError()
	}
	values, err := endpoint.NewValues(input)
	if err != nil {
		return EndpointRecord{}, endpointInputError()
	}
	if err := db.enter(ctx); err != nil {
		return EndpointRecord{}, err
	}
	defer db.leave()
	tx, err := db.conn.Begin(ctx)
	if err != nil {
		return EndpointRecord{}, storageError()
	}
	defer endpointRollback(tx)
	if err := trustSelectionInTransaction(ctx, tx, values.Trust, true); err != nil {
		return EndpointRecord{}, err
	}
	registrationID, err := newID()
	if err != nil {
		return EndpointRecord{}, err
	}
	monitoringID, err := newMonitoringID(registrationID, "")
	if err != nil {
		return EndpointRecord{}, err
	}
	now := time.Now().UTC()
	record := EndpointRecord{
		RegistrationID: registrationID, MonitoringID: monitoringID,
		ConfigurationRevision: 1, Values: values, CreatedAt: now, UpdatedAt: now,
	}
	data, err := encodeEndpointRecord(record)
	if err != nil {
		return EndpointRecord{}, err
	}
	digest := recordDigest("endpoint", registrationID, data)
	var kind, key string
	var stored, storedDigest []byte
	err = tx.QueryRow(ctx, `INSERT INTO tlsbeacon_registry.records (kind, key, value, digest) VALUES ($1, $2, $3, $4) ON CONFLICT (kind, key) DO NOTHING RETURNING kind, key, value, digest`, "endpoint", registrationID, data, digest[:]).Scan(&kind, &key, &stored, &storedDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tlsbeacon_registry.records WHERE kind=$1 AND key=$2)`, "endpoint", registrationID).Scan(&exists); err != nil || !exists {
			return EndpointRecord{}, storageError()
		}
		return EndpointRecord{}, revisionConflict()
	}
	if err != nil || kind != "endpoint" || key != registrationID || !bytes.Equal(stored, data) || !bytes.Equal(storedDigest, digest[:]) {
		return EndpointRecord{}, storageError()
	}
	if err := commitEndpointTransaction(ctx, tx); err != nil {
		return EndpointRecord{}, err
	}
	return record, nil
}

func beginEndpointRead(ctx context.Context, db *DB) (pgx.Tx, error) {
	tx, err := db.conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, storageError()
	}
	return tx, nil
}

// ListEndpoints returns every registration in one validated database snapshot.
func (db *DB) ListEndpoints(ctx context.Context) ([]EndpointRecord, error) {
	if err := db.enter(ctx); err != nil {
		return nil, err
	}
	defer db.leave()
	tx, err := beginEndpointRead(ctx, db)
	if err != nil {
		return nil, err
	}
	defer endpointRollback(tx)
	rows, err := tx.Query(ctx, `SELECT key, value, digest FROM tlsbeacon_registry.records WHERE kind=$1 ORDER BY key`, "endpoint")
	if err != nil {
		return nil, storageError()
	}
	records := make([]EndpointRecord, 0)
	for rows.Next() {
		var key string
		var data, digest []byte
		if err := rows.Scan(&key, &data, &digest); err != nil || data == nil {
			rows.Close()
			return nil, storageError()
		}
		hash := recordDigest("endpoint", key, data)
		if !bytes.Equal(digest, hash[:]) {
			rows.Close()
			return nil, storageError()
		}
		record, err := decodeEndpointRecord(data, key)
		if err != nil {
			rows.Close()
			return nil, storageError()
		}
		records = append(records, record)
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return nil, storageError()
	}
	for _, record := range records {
		if err := validateStoredTrustSelection(ctx, tx, record.Values.Trust, false); err != nil {
			return nil, err
		}
	}
	if err := commitEndpointTransaction(ctx, tx); err != nil {
		return nil, err
	}
	return records, nil
}

// ShowEndpoint returns one complete, validated registration or not_found.
func (db *DB) ShowEndpoint(ctx context.Context, id string) (EndpointRecord, error) {
	if !validID(id) {
		return EndpointRecord{}, notFound()
	}
	if err := db.enter(ctx); err != nil {
		return EndpointRecord{}, err
	}
	defer db.leave()
	tx, err := beginEndpointRead(ctx, db)
	if err != nil {
		return EndpointRecord{}, err
	}
	defer endpointRollback(tx)
	record, err := readEndpointRecord(ctx, tx, id, false)
	if err != nil {
		return EndpointRecord{}, err
	}
	if err := commitEndpointTransaction(ctx, tx); err != nil {
		return EndpointRecord{}, err
	}
	return record, nil
}

// PatchEndpoint applies an omission-preserving patch under the endpoint row lock.
func (db *DB) PatchEndpoint(ctx context.Context, id string, patch endpoint.Patch) (EndpointRecord, bool, error) {
	if !validID(id) {
		return EndpointRecord{}, false, notFound()
	}
	if err := db.enter(ctx); err != nil {
		return EndpointRecord{}, false, err
	}
	defer db.leave()
	tx, err := db.conn.Begin(ctx)
	if err != nil {
		return EndpointRecord{}, false, storageError()
	}
	defer endpointRollback(tx)
	current, err := readEndpointRecord(ctx, tx, id, true)
	if err != nil {
		return EndpointRecord{}, false, err
	}
	if patch.Trust != nil {
		if err := trustSelectionInTransaction(ctx, tx, *patch.Trust, true); err != nil {
			return EndpointRecord{}, false, err
		}
	}
	decision, err := endpoint.ApplyPatch(current.Values, patch)
	if err != nil {
		return EndpointRecord{}, false, endpointInputError()
	}
	if !decision.Changed {
		if err := commitEndpointTransaction(ctx, tx); err != nil {
			return EndpointRecord{}, false, err
		}
		return current, false, nil
	}
	if current.ConfigurationRevision == ^uint64(0) {
		return EndpointRecord{}, false, storageError()
	}
	replacement := current
	replacement.Values = decision.Values
	replacement.ConfigurationRevision++
	replacement.UpdatedAt = nextEndpointTimestamp(current.UpdatedAt)
	if decision.NewMonitoringIdentity {
		replacement.MonitoringID, err = newMonitoringID(replacement.RegistrationID, current.MonitoringID)
		if err != nil {
			return EndpointRecord{}, false, err
		}
	}
	data, err := encodeEndpointRecord(replacement)
	if err != nil {
		return EndpointRecord{}, false, err
	}
	digest := recordDigest("endpoint", id, data)
	var kind, key string
	var stored, storedDigest []byte
	err = tx.QueryRow(ctx, `UPDATE tlsbeacon_registry.records SET value=$3, digest=$4 WHERE kind=$1 AND key=$2 RETURNING kind, key, value, digest`, "endpoint", id, data, digest[:]).Scan(&kind, &key, &stored, &storedDigest)
	if err != nil || kind != "endpoint" || key != id || !bytes.Equal(stored, data) || !bytes.Equal(storedDigest, digest[:]) {
		return EndpointRecord{}, false, storageError()
	}
	if err := commitEndpointTransaction(ctx, tx); err != nil {
		return EndpointRecord{}, false, err
	}
	return replacement, true, nil
}

// EnableEndpoint durably enables monitoring without changing monitoring identity.
func (db *DB) EnableEndpoint(ctx context.Context, id string) (EndpointRecord, bool, error) {
	enabled := true
	return db.PatchEndpoint(ctx, id, endpoint.Patch{Enabled: &enabled})
}

// DisableEndpoint changes configuration only; it does not erase history or imply recovery.
func (db *DB) DisableEndpoint(ctx context.Context, id string) (EndpointRecord, bool, error) {
	enabled := false
	return db.PatchEndpoint(ctx, id, endpoint.Patch{Enabled: &enabled})
}
