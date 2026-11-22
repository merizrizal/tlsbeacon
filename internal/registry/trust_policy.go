package registry

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/merizrizal/tlsbeacon/internal/policy"
	"github.com/merizrizal/tlsbeacon/internal/trust"
)

type TrustVersion struct {
	ID      string              `json:"id"`
	Mode    trust.Mode          `json:"mode"`
	Roots   [][]byte            `json:"roots"`
	Digest  [sha256.Size]byte   `json:"digest"`
	Sources [][sha256.Size]byte `json:"sources"`
}

type TrustProfile struct {
	ID       string         `json:"id"`
	Versions []TrustVersion `json:"versions"`
}

type PolicyRevision struct {
	ID     string          `json:"id"`
	Policy json.RawMessage `json:"policy"`
}

type policyHistory struct {
	Revisions []PolicyRevision `json:"revisions"`
}

func newID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", storageError()
	}
	return hex.EncodeToString(id[:]), nil
}

func validID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16 && hex.EncodeToString(b) == id
}

func decodeCanonical(data []byte, target any) error {
	if json.Unmarshal(data, target) != nil {
		return storageError()
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(data, canonical) {
		return storageError()
	}
	return nil
}

func validateProfile(p TrustProfile, id string) error {
	if p.ID != id || !validID(id) || len(p.Versions) == 0 {
		return storageError()
	}
	seen := make(map[string]bool)
	for _, v := range p.Versions {
		m, err := trust.Restore(v.Mode, v.Roots, v.Sources)
		if err != nil || !validID(v.ID) || seen[v.ID] || m.Digest() != v.Digest {
			return storageError()
		}
		seen[v.ID] = true
	}
	return nil
}

func versionFromMaterial(m trust.Material) (TrustVersion, error) {
	valid, err := trust.Restore(m.Mode(), m.Roots(), m.SourceDigests())
	if err != nil || !valid.EqualMaterial(m) {
		return TrustVersion{}, storageError()
	}
	id, err := newID()
	if err != nil {
		return TrustVersion{}, err
	}
	return TrustVersion{ID: id, Mode: m.Mode(), Roots: m.Roots(), Digest: m.Digest(), Sources: m.SourceDigests()}, nil
}

// ImportTrust creates a profile containing its first immutable material version.
func (db *DB) ImportTrust(ctx context.Context, material trust.Material) (TrustProfile, error) {
	version, err := versionFromMaterial(material)
	if err != nil {
		return TrustProfile{}, err
	}
	id, err := newID()
	if err != nil {
		return TrustProfile{}, err
	}
	profile := TrustProfile{ID: id, Versions: []TrustVersion{version}}
	data, err := json.Marshal(profile)
	if err != nil {
		return TrustProfile{}, storageError()
	}
	if err := db.Write(ctx, "trust", id, nil, data); err != nil {
		return TrustProfile{}, err
	}
	return profile, nil
}

func (db *DB) ReadTrust(ctx context.Context, id string) (TrustProfile, error) {
	if !validID(id) {
		return TrustProfile{}, notFound()
	}
	data, err := db.Read(ctx, "trust", id)
	if err != nil {
		return TrustProfile{}, err
	}
	var profile TrustProfile
	if decodeCanonical(data, &profile) != nil || validateProfile(profile, id) != nil {
		return TrustProfile{}, storageError()
	}
	return profile, nil
}

// RefreshTrust replaces one complete profile using compare-and-swap; a concurrent edit conflicts.
func (db *DB) RefreshTrust(ctx context.Context, id string, material trust.Material) (TrustProfile, bool, error) {
	candidate, err := trust.Restore(material.Mode(), material.Roots(), material.SourceDigests())
	if err != nil || !candidate.EqualMaterial(material) {
		return TrustProfile{}, false, storageError()
	}
	if !validID(id) {
		return TrustProfile{}, false, notFound()
	}
	data, err := db.Read(ctx, "trust", id)
	if err != nil {
		return TrustProfile{}, false, err
	}
	var profile TrustProfile
	if decodeCanonical(data, &profile) != nil || validateProfile(profile, id) != nil {
		return TrustProfile{}, false, storageError()
	}
	last := profile.Versions[len(profile.Versions)-1]
	current, _ := trust.Restore(last.Mode, last.Roots, last.Sources)
	if current.EqualMaterial(candidate) {
		if err := db.Write(ctx, "trust", id, data, data); err != nil {
			return TrustProfile{}, false, err
		}
		return profile, false, nil
	}
	version, err := versionFromMaterial(candidate)
	if err != nil {
		return TrustProfile{}, false, err
	}
	for _, existing := range profile.Versions {
		if existing.ID == version.ID {
			return TrustProfile{}, false, storageError()
		}
	}
	profile.Versions = append(profile.Versions, version)
	replacement, err := json.Marshal(profile)
	if err != nil {
		return TrustProfile{}, false, storageError()
	}
	if err := db.Write(ctx, "trust", id, data, replacement); err != nil {
		return TrustProfile{}, false, err
	}
	return profile, true, nil
}

// ListTrust lists only validated complete profiles.
func (db *DB) ListTrust(ctx context.Context) ([]TrustProfile, error) {
	if err := db.enter(ctx); err != nil {
		return nil, err
	}
	defer db.leave()
	rows, err := db.conn.Query(ctx, `SELECT key, value, digest FROM tlsbeacon_registry.records WHERE kind=$1 ORDER BY key`, "trust")
	if err != nil {
		return nil, storageError()
	}
	defer rows.Close()
	profiles := []TrustProfile{}
	for rows.Next() {
		var key string
		var data, digest []byte
		if rows.Scan(&key, &data, &digest) != nil {
			return nil, storageError()
		}
		hash := recordDigest("trust", key, data)
		var p TrustProfile
		if !bytes.Equal(hash[:], digest) || decodeCanonical(data, &p) != nil || validateProfile(p, key) != nil {
			return nil, storageError()
		}
		profiles = append(profiles, p)
	}
	if rows.Err() != nil {
		return nil, storageError()
	}
	return profiles, nil
}

func validateHistory(h policyHistory) error {
	if len(h.Revisions) == 0 {
		return storageError()
	}
	seen := make(map[string]bool)
	for _, r := range h.Revisions {
		if !validID(r.ID) || seen[r.ID] {
			return storageError()
		}
		if _, err := policy.Restore(r.Policy); err != nil {
			return storageError()
		}
		seen[r.ID] = true
	}
	return nil
}

func (db *DB) ReadPolicy(ctx context.Context) (PolicyRevision, policy.Policy, error) {
	data, err := db.Read(ctx, "policy", "current")
	if err != nil {
		return PolicyRevision{}, policy.Policy{}, err
	}
	var h policyHistory
	if decodeCanonical(data, &h) != nil || validateHistory(h) != nil {
		return PolicyRevision{}, policy.Policy{}, storageError()
	}
	r := h.Revisions[len(h.Revisions)-1]
	p, err := policy.Restore(r.Policy)
	if err != nil {
		return PolicyRevision{}, policy.Policy{}, storageError()
	}
	return r, p, nil
}

// PolicyWriteResult reports the committed revision and whether it created or changed the registry record.
type PolicyWriteResult struct {
	Revision PolicyRevision
	Created  bool
	Changed  bool
}

func (db *DB) ReplacePolicy(ctx context.Context, candidate policy.Policy) (PolicyRevision, bool, error) {
	result, err := db.ReplacePolicyWithResult(ctx, candidate)
	return result.Revision, result.Changed, err
}

// ReplacePolicyWithResult atomically installs a complete revision and reports whether it created the policy record.
func (db *DB) ReplacePolicyWithResult(ctx context.Context, candidate policy.Policy) (PolicyWriteResult, error) {
	encoded, err := candidate.Snapshot()
	if err != nil {
		return PolicyWriteResult{}, storageError()
	}
	validated, err := policy.Restore(encoded)
	if err != nil || !validated.Equal(candidate) {
		return PolicyWriteResult{}, storageError()
	}
	data, err := db.Read(ctx, "policy", "current")
	var h policyHistory
	created := false
	if err != nil {
		var e *Error
		if !errors.As(err, &e) || e.Code != "not_found" {
			return PolicyWriteResult{}, err
		}
		created = true
	} else {
		if decodeCanonical(data, &h) != nil || validateHistory(h) != nil {
			return PolicyWriteResult{}, storageError()
		}
		last := h.Revisions[len(h.Revisions)-1]
		current, _ := policy.Restore(last.Policy)
		if current.Equal(candidate) {
			if err := db.Write(ctx, "policy", "current", data, data); err != nil {
				return PolicyWriteResult{}, err
			}
			return PolicyWriteResult{Revision: last}, nil
		}
	}
	id, err := newID()
	if err != nil {
		return PolicyWriteResult{}, err
	}
	for _, existing := range h.Revisions {
		if existing.ID == id {
			return PolicyWriteResult{}, storageError()
		}
	}
	revision := PolicyRevision{ID: id, Policy: encoded}
	h.Revisions = append(h.Revisions, revision)
	replacement, err := json.Marshal(h)
	if err != nil {
		return PolicyWriteResult{}, storageError()
	}
	if err := db.Write(ctx, "policy", "current", data, replacement); err != nil {
		return PolicyWriteResult{}, err
	}
	return PolicyWriteResult{Revision: revision, Created: created, Changed: true}, nil
}
