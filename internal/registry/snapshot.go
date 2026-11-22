package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/merizrizal/tlsbeacon/internal/endpoint"
	"github.com/merizrizal/tlsbeacon/internal/policy"
	"github.com/merizrizal/tlsbeacon/internal/trust"
)

// TrustContext contains the immutable material selected by an endpoint.
type TrustContext struct {
	ProfileID string
	VersionID string
	Material  trust.Material
}

// PolicyContext identifies the complete effective policy revision.
type PolicyContext struct {
	RevisionID string
	Digest     [sha256.Size]byte
	Policy     policy.Policy
}

// AttemptSnapshot is one coherent, validated endpoint, trust and policy view.
type AttemptSnapshot struct {
	Endpoint EndpointRecord
	Trust    TrustContext
	Policy   PolicyContext
}

func policyConfigurationError() error {
	return &Error{"policy_configuration_error", "No destination policy is configured.", "Install or restore a valid policy before inspection."}
}

func readTrustContext(ctx context.Context, tx pgx.Tx, selection endpoint.TrustSelection) (TrustContext, error) {
	if !validID(selection.Profile) || !validID(selection.Version) {
		return TrustContext{}, storageError()
	}
	var data, digest []byte
	err := tx.QueryRow(ctx, `SELECT value, digest FROM tlsbeacon_registry.records WHERE kind=$1 AND key=$2`, "trust", selection.Profile).Scan(&data, &digest)
	if err != nil || data == nil {
		return TrustContext{}, storageError()
	}
	hash := recordDigest("trust", selection.Profile, data)
	if !bytes.Equal(digest, hash[:]) {
		return TrustContext{}, storageError()
	}
	var profile TrustProfile
	if decodeCanonical(data, &profile) != nil || validateProfile(profile, selection.Profile) != nil {
		return TrustContext{}, storageError()
	}
	for _, version := range profile.Versions {
		if version.ID != selection.Version {
			continue
		}
		if selection.Material != hex.EncodeToString(version.Digest[:]) {
			return TrustContext{}, storageError()
		}
		material, err := trust.Restore(version.Mode, version.Roots, version.Sources)
		if err != nil || material.Digest() != version.Digest {
			return TrustContext{}, storageError()
		}
		return TrustContext{ProfileID: profile.ID, VersionID: version.ID, Material: material}, nil
	}
	return TrustContext{}, storageError()
}

func readPolicyContext(ctx context.Context, tx pgx.Tx) (PolicyContext, error) {
	var data, digest []byte
	err := tx.QueryRow(ctx, `SELECT value, digest FROM tlsbeacon_registry.records WHERE kind=$1 AND key=$2`, "policy", "current").Scan(&data, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return PolicyContext{}, policyConfigurationError()
	}
	if err != nil || data == nil {
		return PolicyContext{}, storageError()
	}
	hash := recordDigest("policy", "current", data)
	if !bytes.Equal(digest, hash[:]) {
		return PolicyContext{}, storageError()
	}
	var history policyHistory
	if decodeCanonical(data, &history) != nil || validateHistory(history) != nil {
		return PolicyContext{}, storageError()
	}
	revision := history.Revisions[len(history.Revisions)-1]
	selected, err := policy.Restore(revision.Policy)
	if err != nil {
		return PolicyContext{}, storageError()
	}
	policyDigest, valid := selected.Digest()
	if !valid {
		return PolicyContext{}, storageError()
	}
	return PolicyContext{RevisionID: revision.ID, Digest: policyDigest, Policy: selected}, nil
}

// CaptureAttemptSnapshot reads the endpoint, selected roots and policy in one short transaction.
// It commits and releases the database connection before returning the immutable context.
func (db *DB) CaptureAttemptSnapshot(ctx context.Context, id string) (AttemptSnapshot, error) {
	return db.captureAttemptSnapshot(ctx, id, nil)
}

func (db *DB) captureAttemptSnapshot(ctx context.Context, id string, afterEndpointRead func()) (AttemptSnapshot, error) {
	if !validID(id) {
		return AttemptSnapshot{}, notFound()
	}
	if err := db.enter(ctx); err != nil {
		return AttemptSnapshot{}, err
	}
	defer db.leave()
	tx, err := beginEndpointRead(ctx, db)
	if err != nil {
		return AttemptSnapshot{}, err
	}
	defer endpointRollback(tx)

	endpoint, err := readEndpointRecord(ctx, tx, id, false)
	if err != nil {
		return AttemptSnapshot{}, err
	}
	if afterEndpointRead != nil {
		afterEndpointRead()
	}
	selectedTrust, err := readTrustContext(ctx, tx, endpoint.Values.Trust)
	if err != nil {
		return AttemptSnapshot{}, err
	}
	selectedPolicy, err := readPolicyContext(ctx, tx)
	if err != nil {
		return AttemptSnapshot{}, err
	}
	if err := commitEndpointTransaction(ctx, tx); err != nil {
		return AttemptSnapshot{}, err
	}
	return AttemptSnapshot{Endpoint: endpoint, Trust: selectedTrust, Policy: selectedPolicy}, nil
}
