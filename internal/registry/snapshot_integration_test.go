package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/merizrizal/tlsbeacon/internal/endpoint"
	"github.com/merizrizal/tlsbeacon/internal/policy"
	"github.com/merizrizal/tlsbeacon/internal/trust"
)

func snapshotPolicy(t *testing.T, cidr string, port int) policy.Policy {
	t.Helper()
	result, err := policy.New(&policy.Input{Version: policy.Version, Rules: []policy.Rule{{CIDR: cidr, Port: port, Acknowledge: policy.Private}}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func snapshotTrust(t *testing.T, db *DB, serial int64) (endpoint.TrustSelection, trust.Material) {
	t.Helper()
	material := fixtureMaterial(t, trust.Custom, fixtureCA(t, serial))
	protectedFixture(t)
	profile, err := db.ImportTrust(context.Background(), material)
	if err != nil {
		t.Fatalf("import snapshot trust fixture: %v", err)
	}
	version := profile.Versions[0]
	return endpoint.TrustSelection{Profile: profile.ID, Version: version.ID, Material: hexDigest(version.Digest)}, material
}

func hexDigest(digest [32]byte) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, len(digest)*2)
	for i, value := range digest {
		encoded[i*2] = alphabet[value>>4]
		encoded[i*2+1] = alphabet[value&15]
	}
	return string(encoded)
}

func snapshotEndpoint(t *testing.T, db *DB, selection endpoint.TrustSelection) EndpointRecord {
	t.Helper()
	return endpointAdd(t, db, endpointCreateInput(selection))
}

func installSnapshotPolicy(t *testing.T, ctx context.Context, db *DB, cidr string, port int) PolicyRevision {
	t.Helper()
	candidate := snapshotPolicy(t, cidr, port)
	protectedFixture(t)
	revision, changed, err := db.ReplacePolicy(ctx, candidate)
	if err != nil || !changed {
		t.Fatalf("install snapshot policy: %v", err)
	}
	return revision
}

func replaceSnapshotRecord(t *testing.T, setup *pgx.Conn, kind, key string, value []byte) {
	t.Helper()
	protectedFixture(t)
	digest := recordDigest(kind, key, value)
	command, err := setup.Exec(context.Background(), `UPDATE tlsbeacon_registry.records SET value=$1, digest=$2 WHERE kind=$3 AND key=$4`, value, digest[:], kind, key)
	if err != nil || command.RowsAffected() != 1 {
		t.Fatalf("update snapshot corruption fixture: %v", err)
	}
}

func requireSnapshotError(t *testing.T, db *DB, id, want string) {
	t.Helper()
	protectedFixture(t)
	if _, err := db.CaptureAttemptSnapshot(context.Background(), id); errorCode(err) != want {
		t.Fatalf("snapshot error = %v, want %s", err, want)
	}
	if db.conn.PgConn().TxStatus() != 'I' {
		t.Fatal("failed snapshot left a database transaction open")
	}
}

func assertSnapshotMatches(t *testing.T, got AttemptSnapshot, endpoint EndpointRecord, selection endpoint.TrustSelection, material trust.Material, revision PolicyRevision, wantPolicy policy.Policy) {
	t.Helper()
	if got.Endpoint.RegistrationID != endpoint.RegistrationID || got.Endpoint.MonitoringID != endpoint.MonitoringID || got.Endpoint.ConfigurationRevision != endpoint.ConfigurationRevision || got.Endpoint.Values != endpoint.Values || got.Endpoint.CreatedAt != endpoint.CreatedAt || got.Endpoint.UpdatedAt != endpoint.UpdatedAt {
		t.Fatal("snapshot endpoint differs from its committed record")
	}
	if got.Trust.ProfileID != selection.Profile || got.Trust.VersionID != selection.Version || got.Trust.Material.Mode() != material.Mode() || got.Trust.Material.Digest() != material.Digest() {
		t.Fatal("snapshot selected trust identity differs")
	}
	gotRoots, wantRoots := got.Trust.Material.Roots(), material.Roots()
	if len(gotRoots) != len(wantRoots) {
		t.Fatal("snapshot selected root count differs")
	}
	for i := range wantRoots {
		if !bytes.Equal(gotRoots[i], wantRoots[i]) {
			t.Fatal("snapshot selected root DER differs")
		}
	}
	gotSources, wantSources := got.Trust.Material.SourceDigests(), material.SourceDigests()
	if len(gotSources) != len(wantSources) {
		t.Fatal("snapshot trust source count differs")
	}
	for i := range wantSources {
		if gotSources[i] != wantSources[i] {
			t.Fatal("snapshot trust source digest differs")
		}
	}
	wantDigest, valid := wantPolicy.Digest()
	gotPolicyBytes, gotErr := got.Policy.Policy.Snapshot()
	wantPolicyBytes, wantErr := wantPolicy.Snapshot()
	if !valid || gotErr != nil || wantErr != nil || got.Policy.RevisionID != revision.ID || got.Policy.Digest != wantDigest || !bytes.Equal(gotPolicyBytes, wantPolicyBytes) {
		t.Fatal("snapshot policy revision, digest or complete policy differs")
	}
}

func TestAttemptSnapshotIsCoherentAcrossConcurrentUpdates(t *testing.T) {
	_, db, setup := endpointFixtureDB(t)
	defer closeEndpointDB(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	oldSelection, oldMaterial := snapshotTrust(t, db, 801)
	oldPolicy := snapshotPolicy(t, "10.0.0.0/8", 443)
	oldRevision := installSnapshotPolicy(t, ctx, db, "10.0.0.0/8", 443)
	oldEndpoint := snapshotEndpoint(t, db, oldSelection)
	protectedFixture(t)
	profile, err := db.ReadTrust(ctx, oldSelection.Profile)
	if err != nil {
		t.Fatalf("read old trust profile: %v", err)
	}
	newMaterial := fixtureMaterial(t, trust.Custom, fixtureCA(t, 802))
	newVersion, err := versionFromMaterial(newMaterial)
	if err != nil {
		t.Fatalf("create next immutable trust version: %v", err)
	}
	newProfile := profile
	newProfile.Versions = append(newProfile.Versions, newVersion)
	newProfileData, err := json.Marshal(newProfile)
	if err != nil {
		t.Fatal(err)
	}
	newSelection := endpoint.TrustSelection{Profile: profile.ID, Version: newVersion.ID, Material: hexDigest(newVersion.Digest)}
	newEndpoint := oldEndpoint
	newEndpoint.Values.Host, err = endpoint.NormalizeHost("new-endpoint.invalid")
	if err != nil {
		t.Fatal(err)
	}
	newEndpoint.Values.Port = 8443
	newEndpoint.Values.Label = "new coherent endpoint"
	newEndpoint.Values.Trust = newSelection
	newEndpoint.ConfigurationRevision++
	newEndpoint.UpdatedAt = nextEndpointTimestamp(oldEndpoint.UpdatedAt)
	newEndpoint.MonitoringID, err = newMonitoringID(oldEndpoint.RegistrationID, oldEndpoint.MonitoringID)
	if err != nil {
		t.Fatal(err)
	}
	newEndpointData, err := encodeEndpointRecord(newEndpoint)
	if err != nil {
		t.Fatalf("encode new endpoint: %v", err)
	}

	newPolicy := snapshotPolicy(t, "192.168.0.0/16", 8443)
	newPolicyBytes, err := newPolicy.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	newRevisionID, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	protectedFixture(t)
	oldPolicyData, err := db.Read(ctx, "policy", "current")
	if err != nil {
		t.Fatalf("read policy history: %v", err)
	}
	var history policyHistory
	if decodeCanonical(oldPolicyData, &history) != nil || validateHistory(history) != nil {
		t.Fatal("initial policy history was not canonical")
	}
	newRevision := PolicyRevision{ID: newRevisionID, Policy: newPolicyBytes}
	history.Revisions = append(history.Revisions, newRevision)
	newPolicyData, err := json.Marshal(history)
	if err != nil {
		t.Fatal(err)
	}

	endpointRead := make(chan struct{})
	releaseRead := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseRead) }) }
	defer release()
	result := make(chan struct {
		snapshot AttemptSnapshot
		err      error
	}, 1)
	protectedFixture(t)
	go func() {
		captured, captureErr := db.captureAttemptSnapshot(ctx, oldEndpoint.RegistrationID, func() {
			close(endpointRead)
			<-releaseRead
		})
		result <- struct {
			snapshot AttemptSnapshot
			err      error
		}{captured, captureErr}
	}()
	select {
	case <-endpointRead:
	case <-ctx.Done():
		t.Fatal("snapshot did not reach the endpoint-read barrier")
	}

	protectedFixture(t)
	writer, err := setup.Begin(ctx)
	if err != nil {
		t.Fatalf("begin concurrent context update: %v", err)
	}
	defer writer.Rollback(context.Background())
	profileDigest := recordDigest("trust", profile.ID, newProfileData)
	endpointDigest := recordDigest("endpoint", newEndpoint.RegistrationID, newEndpointData)
	policyDigest := recordDigest("policy", "current", newPolicyData)
	for _, update := range []struct {
		query string
		args  []any
	}{
		{`UPDATE tlsbeacon_registry.records SET value=$1, digest=$2 WHERE kind=$3 AND key=$4`, []any{newProfileData, profileDigest[:], "trust", profile.ID}},
		{`UPDATE tlsbeacon_registry.records SET value=$1, digest=$2 WHERE kind=$3 AND key=$4`, []any{newEndpointData, endpointDigest[:], "endpoint", newEndpoint.RegistrationID}},
		{`UPDATE tlsbeacon_registry.records SET value=$1, digest=$2 WHERE kind=$3 AND key=$4`, []any{newPolicyData, policyDigest[:], "policy", "current"}},
	} {
		protectedFixture(t)
		command, updateErr := writer.Exec(ctx, update.query, update.args...)
		if updateErr != nil || command.RowsAffected() != 1 {
			t.Fatalf("write concurrent context component: %v", updateErr)
		}
	}
	protectedFixture(t)
	if err := writer.Commit(ctx); err != nil {
		t.Fatalf("commit concurrent context update: %v", err)
	}
	protectedFixture(t)
	release()
	captured := <-result
	if captured.err != nil {
		t.Fatalf("capture old coherent context: %v", captured.err)
	}
	assertSnapshotMatches(t, captured.snapshot, oldEndpoint, oldSelection, oldMaterial, oldRevision, oldPolicy)
	if db.conn.PgConn().TxStatus() != 'I' {
		t.Fatal("successful snapshot returned with an open transaction")
	}

	protectedFixture(t)
	current, err := db.CaptureAttemptSnapshot(ctx, oldEndpoint.RegistrationID)
	if err != nil {
		t.Fatalf("capture new coherent context: %v", err)
	}
	assertSnapshotMatches(t, current, newEndpoint, newSelection, newMaterial, newRevision, newPolicy)
	if current.Endpoint.MonitoringID == oldEndpoint.MonitoringID || current.Endpoint.Values.Host.DNS != "new-endpoint.invalid" {
		t.Fatal("new endpoint identity was not captured")
	}

	roots := captured.snapshot.Trust.Material.Roots()
	originalRoot := bytes.Clone(roots[0])
	roots[0][0] ^= 0xff
	sources := captured.snapshot.Trust.Material.SourceDigests()
	originalSource := sources[0]
	sources[0][0] ^= 0xff
	policyBytes, err := captured.snapshot.Policy.Policy.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	originalPolicy := bytes.Clone(policyBytes)
	policyBytes[0] ^= 0xff
	if !bytes.Equal(captured.snapshot.Trust.Material.Roots()[0], originalRoot) || captured.snapshot.Trust.Material.SourceDigests()[0] != originalSource {
		t.Fatal("snapshot trust material exposes mutable aliases")
	}
	policyBytesAgain, err := captured.snapshot.Policy.Policy.Snapshot()
	if err != nil || !bytes.Equal(policyBytesAgain, originalPolicy) {
		t.Fatal("snapshot policy exposes a mutable alias")
	}
	captured.snapshot.Endpoint.Values.Label = "caller mutation"
	if current.Endpoint.Values.Label != newEndpoint.Values.Label {
		t.Fatal("endpoint value was aliased across snapshots")
	}
}

func TestAttemptSnapshotRequiresUsableSelections(t *testing.T) {
	t.Run("missing endpoint", func(t *testing.T) {
		_, db, _ := endpointFixtureDB(t)
		defer closeEndpointDB(t, db)
		requireSnapshotError(t, db, strings.Repeat("f", 32), "not_found")
	})

	t.Run("missing policy", func(t *testing.T) {
		_, db, _ := endpointFixtureDB(t)
		defer closeEndpointDB(t, db)
		selection, _ := snapshotTrust(t, db, 812)
		created := snapshotEndpoint(t, db, selection)
		requireSnapshotError(t, db, created.RegistrationID, "policy_configuration_error")
	})

	t.Run("missing selected trust version", func(t *testing.T) {
		_, db, setup := endpointFixtureDB(t)
		defer closeEndpointDB(t, db)
		selection, _ := snapshotTrust(t, db, 813)
		installSnapshotPolicy(t, context.Background(), db, "10.0.0.0/8", 443)
		created := snapshotEndpoint(t, db, selection)
		created.Values.Trust.Version = strings.Repeat("e", 32)
		data, err := encodeEndpointRecord(created)
		if err != nil {
			t.Fatal(err)
		}
		replaceSnapshotRecord(t, setup, "endpoint", created.RegistrationID, data)
		requireSnapshotError(t, db, created.RegistrationID, "storage_error")
	})

	t.Run("mismatched selected material", func(t *testing.T) {
		_, db, setup := endpointFixtureDB(t)
		defer closeEndpointDB(t, db)
		selection, _ := snapshotTrust(t, db, 814)
		installSnapshotPolicy(t, context.Background(), db, "10.0.0.0/8", 443)
		created := snapshotEndpoint(t, db, selection)
		created.Values.Trust.Material = strings.Repeat("0", 64)
		data, err := encodeEndpointRecord(created)
		if err != nil {
			t.Fatal(err)
		}
		replaceSnapshotRecord(t, setup, "endpoint", created.RegistrationID, data)
		requireSnapshotError(t, db, created.RegistrationID, "storage_error")
	})

	t.Run("corrupt selected root material", func(t *testing.T) {
		_, db, setup := endpointFixtureDB(t)
		defer closeEndpointDB(t, db)
		selection, _ := snapshotTrust(t, db, 815)
		installSnapshotPolicy(t, context.Background(), db, "10.0.0.0/8", 443)
		created := snapshotEndpoint(t, db, selection)
		protectedFixture(t)
		profile, err := db.ReadTrust(context.Background(), selection.Profile)
		if err != nil {
			t.Fatalf("read trust profile: %v", err)
		}
		profile.Versions[0].Roots[0] = []byte("invalid DER")
		data, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		replaceSnapshotRecord(t, setup, "trust", selection.Profile, data)
		requireSnapshotError(t, db, created.RegistrationID, "storage_error")
	})

	t.Run("corrupt policy history", func(t *testing.T) {
		_, db, setup := endpointFixtureDB(t)
		defer closeEndpointDB(t, db)
		selection, _ := snapshotTrust(t, db, 816)
		installSnapshotPolicy(t, context.Background(), db, "10.0.0.0/8", 443)
		created := snapshotEndpoint(t, db, selection)
		replaceSnapshotRecord(t, setup, "policy", "current", []byte(`{"revisions":[]}`))
		requireSnapshotError(t, db, created.RegistrationID, "storage_error")
	})
}

func TestAttemptSnapshotReleasesTransactionBeforeLaterWork(t *testing.T) {
	name, db, _ := endpointFixtureDB(t)
	defer closeEndpointDB(t, db)
	selection, _ := snapshotTrust(t, db, 821)
	installSnapshotPolicy(t, context.Background(), db, "10.0.0.0/8", 443)
	created := snapshotEndpoint(t, db, selection)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	protectedFixture(t)
	if _, err := db.CaptureAttemptSnapshot(ctx, created.RegistrationID); err != nil {
		t.Fatalf("capture snapshot: %v", err)
	}
	if db.conn.PgConn().TxStatus() != 'I' {
		t.Fatal("snapshot returned before its database transaction closed")
	}
	observer := connectFixture(t, protectedFixture(t), "tlsbeacon_runtime", name)
	pid := db.conn.PgConn().PID()
	protectedFixture(t)
	var state string
	var noTransaction bool
	if err := observer.QueryRow(ctx, `SELECT state, xact_start IS NULL FROM pg_catalog.pg_stat_activity WHERE pid=$1`, pid).Scan(&state, &noTransaction); err != nil || state != "idle" || !noTransaction {
		t.Fatalf("snapshot backend remains active: state=%q no_transaction=%v error=%v", state, noTransaction, err)
	}

	laterWork := make(chan struct{})
	laterWorkStarted := make(chan struct{})
	go func() {
		close(laterWorkStarted)
		<-laterWork
	}()
	defer close(laterWork)
	<-laterWorkStarted
	writer, err := Open(ctx, fixtureConnection(t, name))
	if err != nil {
		t.Fatalf("open concurrent context writer: %v", err)
	}
	defer closeEndpointDB(t, writer)
	laterPolicy := snapshotPolicy(t, "192.168.0.0/16", 8443)
	protectedFixture(t)
	writeDone := make(chan error, 1)
	go func() {
		_, _, writeErr := writer.ReplacePolicy(ctx, laterPolicy)
		writeDone <- writeErr
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("writer was blocked during later work: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("writer did not commit while later work remained blocked")
	}
}

func TestAttemptSnapshotHasNoTargetNetworkImports(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "snapshot.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"bytes": true, "context": true, "crypto/sha256": true, "encoding/hex": true, "errors": true,
		"github.com/jackc/pgx/v5": true, "github.com/merizrizal/tlsbeacon/internal/endpoint": true,
		"github.com/merizrizal/tlsbeacon/internal/policy": true, "github.com/merizrizal/tlsbeacon/internal/trust": true,
	}
	for _, spec := range file.Imports {
		name, err := strconv.Unquote(spec.Path.Value)
		if err != nil || !allowed[name] {
			t.Fatalf("unexpected snapshot import: %s", spec.Path.Value)
		}
	}
}
