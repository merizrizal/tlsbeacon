package registry

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"go/parser"
	"go/token"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/merizrizal/tlsbeacon/internal/endpoint"
	"github.com/merizrizal/tlsbeacon/internal/trust"
)

func endpointFixtureDB(t *testing.T) (string, *DB, *pgx.Conn) {
	t.Helper()
	name, setup := newFixtureDatabase(t, true)
	connection := fixtureConnection(t, name)
	protectedFixture(t)
	db, err := Open(context.Background(), connection)
	if err != nil {
		t.Fatalf("open endpoint fixture registry: %v", err)
	}
	return name, db, setup
}

func closeEndpointDB(t *testing.T, db *DB) {
	t.Helper()
	protectedFixture(t)
	if err := db.Close(context.Background()); err != nil {
		t.Errorf("close endpoint fixture registry: %v", err)
	}
}

func endpointTrustSelection(t *testing.T, db *DB, serial int64) endpoint.TrustSelection {
	t.Helper()
	material := fixtureMaterial(t, trust.Custom, fixtureCA(t, serial))
	protectedFixture(t)
	profile, err := db.ImportTrust(context.Background(), material)
	if err != nil {
		t.Fatalf("import endpoint trust fixture: %v", err)
	}
	version := profile.Versions[0]
	return endpoint.TrustSelection{Profile: profile.ID, Version: version.ID, Material: hex.EncodeToString(version.Digest[:])}
}

func endpointCreateInput(selection endpoint.TrustSelection) endpoint.CreateInput {
	return endpoint.CreateInput{Label: "same lab endpoint", Host: "endpoint.invalid", Port: 443, Identity: "service.example", Trust: selection}
}

func endpointAdd(t *testing.T, db *DB, input endpoint.CreateInput) EndpointRecord {
	t.Helper()
	protectedFixture(t)
	record, err := db.AddEndpoint(context.Background(), input)
	if err != nil {
		t.Fatalf("add endpoint: %v", err)
	}
	return record
}

func endpointShow(t *testing.T, db *DB, id string) EndpointRecord {
	t.Helper()
	protectedFixture(t)
	record, err := db.ShowEndpoint(context.Background(), id)
	if err != nil {
		t.Fatalf("show endpoint: %v", err)
	}
	return record
}

func endpointList(t *testing.T, db *DB) []EndpointRecord {
	t.Helper()
	protectedFixture(t)
	records, err := db.ListEndpoints(context.Background())
	if err != nil {
		t.Fatalf("list endpoints: %v", err)
	}
	return records
}

func endpointPatch(t *testing.T, db *DB, id string, patch endpoint.Patch) (EndpointRecord, bool) {
	t.Helper()
	protectedFixture(t)
	record, changed, err := db.PatchEndpoint(context.Background(), id, patch)
	if err != nil {
		t.Fatalf("patch endpoint: %v", err)
	}
	return record, changed
}

func endpointXmin(t *testing.T, db *DB, id string) string {
	t.Helper()
	protectedFixture(t)
	var xmin string
	if err := db.conn.QueryRow(context.Background(), `SELECT xmin::text FROM tlsbeacon_registry.records WHERE kind=$1 AND key=$2`, "endpoint", id).Scan(&xmin); err != nil {
		t.Fatal("read endpoint row version")
	}
	return xmin
}

func endpointPtr[T any](value T) *T { return &value }

func TestEndpointPersistenceRoundTripNoOpAndDuplicates(t *testing.T) {
	_, db, _ := endpointFixtureDB(t)
	defer closeEndpointDB(t, db)
	selection := endpointTrustSelection(t, db, 101)
	interval, warning, critical := time.Duration(987654321), 35*24*time.Hour, 8*24*time.Hour
	input := endpoint.CreateInput{
		Label: "  lab 🐙  ", Host: "[fe80::1%eth0]", Port: 9443, Identity: "BÜCHER.example.", Trust: selection,
		Interval: &interval, Warning: &warning, Critical: &critical,
	}
	first := endpointAdd(t, db, input)
	if first.RegistrationID == first.MonitoringID || first.ConfigurationRevision != 1 || first.CreatedAt.IsZero() || !first.CreatedAt.Equal(first.UpdatedAt) {
		t.Fatal("new endpoint identity, revision or timestamps are invalid")
	}
	if first.Values.Label != input.Label || first.Values.Host.Original != input.Host || first.Values.Host.IP != netip.MustParseAddr("fe80::1") || first.Values.Host.Scope != "eth0" || first.Values.Identity.Original != input.Identity || first.Values.Identity.DNS != "xn--bcher-kva.example" || first.Values.Port != 9443 || first.Values.Trust != selection || first.Values.Interval != interval || first.Values.Warning != warning || first.Values.Critical != critical || !first.Values.Enabled {
		t.Fatalf("complete effective endpoint values did not round-trip: %#v", first.Values)
	}
	shown := endpointShow(t, db, first.RegistrationID)
	if shown.Values != first.Values || shown.MonitoringID != first.MonitoringID || shown.ConfigurationRevision != first.ConfigurationRevision {
		t.Fatal("show did not return the complete stored endpoint")
	}
	second := endpointAdd(t, db, input)
	if second.RegistrationID == first.RegistrationID || second.MonitoringID == first.MonitoringID {
		t.Fatal("duplicate target or label was not retained as a distinct endpoint")
	}
	defaultRecord := endpointAdd(t, db, endpointCreateInput(selection))
	if defaultRecord.Values.Interval != time.Hour || defaultRecord.Values.Warning != 30*24*time.Hour || defaultRecord.Values.Critical != 7*24*time.Hour || !defaultRecord.Values.Enabled {
		t.Fatal("endpoint defaults were not persisted as effective values")
	}
	for i := 3; i < 101; i++ {
		endpointAdd(t, db, endpointCreateInput(selection))
	}
	listed := endpointList(t, db)
	if len(listed) != 101 {
		t.Fatalf("endpoint listing/count cap: got %d records, want 101", len(listed))
	}
	for i := 1; i < len(listed); i++ {
		if listed[i-1].RegistrationID >= listed[i].RegistrationID {
			t.Fatal("endpoint listing is not deterministically ordered")
		}
	}

	before := endpointShow(t, db, first.RegistrationID)
	beforeXmin := endpointXmin(t, db, first.RegistrationID)
	noOpPatches := []struct {
		name  string
		patch endpoint.Patch
	}{
		{"canonical host spelling", endpoint.Patch{Host: endpointPtr("fe80:0:0:0:0:0:0:1%eth0")}},
		{"same port", endpoint.Patch{Port: endpointPtr(input.Port)}},
		{"canonical identity spelling", endpoint.Patch{Identity: endpointPtr("xn--bcher-kva.example")}},
		{"same trust selection", endpoint.Patch{Trust: &selection}},
		{"same interval", endpoint.Patch{Interval: &interval}},
		{"same warning", endpoint.Patch{Warning: &warning}},
		{"same critical", endpoint.Patch{Critical: &critical}},
		{"same label", endpoint.Patch{Label: endpointPtr(input.Label)}},
		{"same enabled state", endpoint.Patch{Enabled: endpointPtr(true)}},
	}
	for _, test := range noOpPatches {
		unchanged, changed := endpointPatch(t, db, first.RegistrationID, test.patch)
		if changed || unchanged.RegistrationID != before.RegistrationID || unchanged.MonitoringID != before.MonitoringID || unchanged.ConfigurationRevision != before.ConfigurationRevision || unchanged.CreatedAt != before.CreatedAt || unchanged.UpdatedAt != before.UpdatedAt || unchanged.Values != before.Values || endpointXmin(t, db, first.RegistrationID) != beforeXmin {
			t.Fatalf("%s wrote or altered the endpoint", test.name)
		}
	}
	protectedFixture(t)
	if _, changed, err := db.EnableEndpoint(context.Background(), first.RegistrationID); err != nil || changed {
		t.Fatalf("repeated enable was not unchanged: %v", err)
	}
	if endpointXmin(t, db, first.RegistrationID) != beforeXmin {
		t.Fatal("repeated enable physically wrote the endpoint")
	}

	updated, changed := endpointPatch(t, db, first.RegistrationID, endpoint.Patch{Label: endpointPtr("renamed")})
	if !changed || updated.ConfigurationRevision != before.ConfigurationRevision+1 || updated.MonitoringID != before.MonitoringID || !updated.UpdatedAt.After(before.UpdatedAt) || updated.Values.Host.Original != input.Host || updated.Values.Identity.Original != input.Identity {
		t.Fatal("label update did not preserve omitted values and monitoring identity")
	}
	protectedFixture(t)
	disabled, disableChanged, err := db.DisableEndpoint(context.Background(), first.RegistrationID)
	if err != nil || !disableChanged || disabled.Values.Enabled || disabled.MonitoringID != updated.MonitoringID || disabled.ConfigurationRevision != updated.ConfigurationRevision+1 {
		t.Fatalf("disable changed the wrong endpoint state: %v", err)
	}
	disabledXmin := endpointXmin(t, db, first.RegistrationID)
	protectedFixture(t)
	repeatedDisable, disableChanged, err := db.DisableEndpoint(context.Background(), first.RegistrationID)
	if err != nil || disableChanged || repeatedDisable.UpdatedAt != disabled.UpdatedAt || repeatedDisable.ConfigurationRevision != disabled.ConfigurationRevision || endpointXmin(t, db, first.RegistrationID) != disabledXmin {
		t.Fatalf("repeated disable was not a physical no-op: %v", err)
	}
	protectedFixture(t)
	reenabled, enableChanged, err := db.EnableEndpoint(context.Background(), first.RegistrationID)
	if err != nil || !enableChanged || !reenabled.Values.Enabled || reenabled.MonitoringID != disabled.MonitoringID || reenabled.ConfigurationRevision != disabled.ConfigurationRevision+1 {
		t.Fatalf("enable changed the wrong endpoint state: %v", err)
	}
	if len(endpointList(t, db)) != 101 {
		t.Fatal("disabled registrations disappeared from list")
	}
}

func TestEndpointIdentityAndNonIdentityRevisionTransitions(t *testing.T) {
	_, db, _ := endpointFixtureDB(t)
	defer closeEndpointDB(t, db)
	selectionA := endpointTrustSelection(t, db, 201)
	selectionB := endpointTrustSelection(t, db, 202)
	input := endpointCreateInput(selectionA)
	input.Host = "[fe80::1%eth0]"
	current := endpointAdd(t, db, input)
	seen := map[string]bool{current.MonitoringID: true}
	applyIdentityChange := func(name string, patch endpoint.Patch) {
		t.Helper()
		previous := current
		updated, changed := endpointPatch(t, db, current.RegistrationID, patch)
		if !changed || updated.ConfigurationRevision != previous.ConfigurationRevision+1 || updated.MonitoringID == previous.MonitoringID || seen[updated.MonitoringID] {
			t.Fatalf("%s did not create a fresh monitoring identity and revision", name)
		}
		seen[updated.MonitoringID] = true
		current = updated
	}
	applyIdentityChange("scope", endpoint.Patch{Host: endpointPtr("fe80::1%eth1")})
	firstScopeChange := current.MonitoringID
	applyIdentityChange("scope revert", endpoint.Patch{Host: endpointPtr("[fe80::1%eth0]")})
	if current.MonitoringID == firstScopeChange {
		t.Fatal("reverting to a former scope reused a monitoring identity")
	}
	applyIdentityChange("port", endpoint.Patch{Port: endpointPtr(8443)})
	applyIdentityChange("expected identity", endpoint.Patch{Identity: endpointPtr("other.example")})
	applyIdentityChange("trust profile", endpoint.Patch{Trust: &selectionB})

	materialA2 := fixtureMaterial(t, trust.Custom, fixtureCA(t, 203))
	protectedFixture(t)
	profileA, err := db.ReadTrust(context.Background(), selectionA.Profile)
	if err != nil {
		t.Fatalf("read original trust profile: %v", err)
	}
	protectedFixture(t)
	refreshed, changed, err := db.RefreshTrust(context.Background(), profileA.ID, materialA2)
	if err != nil || !changed || len(refreshed.Versions) != 2 {
		t.Fatalf("create second immutable trust version: %v", err)
	}
	versionA2 := refreshed.Versions[1]
	selectionA2 := endpoint.TrustSelection{Profile: refreshed.ID, Version: versionA2.ID, Material: hex.EncodeToString(versionA2.Digest[:])}
	applyIdentityChange("trust version and material", endpoint.Patch{Trust: &selectionA2})

	monitoringID := current.MonitoringID
	nonIdentityPatches := []struct {
		name  string
		patch endpoint.Patch
	}{
		{"label", endpoint.Patch{Label: endpointPtr("new label")}},
		{"interval", endpoint.Patch{Interval: endpointPtr(2 * time.Hour)}},
		{"warning", endpoint.Patch{Warning: endpointPtr(40 * 24 * time.Hour)}},
		{"critical", endpoint.Patch{Critical: endpointPtr(6 * 24 * time.Hour)}},
		{"disable", endpoint.Patch{Enabled: endpointPtr(false)}},
		{"enable", endpoint.Patch{Enabled: endpointPtr(true)}},
	}
	for _, test := range nonIdentityPatches {
		previous := current
		updated, changed := endpointPatch(t, db, current.RegistrationID, test.patch)
		if !changed || updated.ConfigurationRevision != previous.ConfigurationRevision+1 || updated.MonitoringID != monitoringID || !updated.UpdatedAt.After(previous.UpdatedAt) {
			t.Fatalf("%s edit changed monitoring identity or omitted its revision", test.name)
		}
		current = updated
	}
}

func TestEndpointTrustValidationAndMissingRecords(t *testing.T) {
	_, db, _ := endpointFixtureDB(t)
	defer closeEndpointDB(t, db)
	selectionA := endpointTrustSelection(t, db, 301)
	selectionB := endpointTrustSelection(t, db, 302)
	missingProfile := endpoint.TrustSelection{Profile: strings.Repeat("0", 32), Version: selectionA.Version, Material: selectionA.Material}
	missingVersion := endpoint.TrustSelection{Profile: selectionA.Profile, Version: strings.Repeat("f", 32), Material: selectionA.Material}
	wrongProfile := endpoint.TrustSelection{Profile: selectionB.Profile, Version: selectionA.Version, Material: selectionA.Material}
	wrongMaterial := endpoint.TrustSelection{Profile: selectionA.Profile, Version: selectionA.Version, Material: selectionB.Material}
	for _, test := range []struct {
		name      string
		selection endpoint.TrustSelection
	}{
		{"missing profile", missingProfile},
		{"missing version", missingVersion},
		{"version from another profile", wrongProfile},
		{"mismatched material digest", wrongMaterial},
		{"missing selection", endpoint.TrustSelection{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := endpointCreateInput(test.selection)
			protectedFixture(t)
			if _, err := db.AddEndpoint(context.Background(), input); errorCode(err) != "trust_configuration_error" {
				t.Fatalf("invalid stored trust selection was accepted: %v", err)
			}
			if len(endpointList(t, db)) != 0 {
				t.Fatal("invalid trust selection created an endpoint")
			}
		})
	}
	invalid := endpointCreateInput(selectionA)
	invalid.Port = 0
	protectedFixture(t)
	if _, err := db.AddEndpoint(context.Background(), invalid); errorCode(err) != "invalid_input" {
		t.Fatalf("invalid endpoint values were accepted: %v", err)
	}
	if len(endpointList(t, db)) != 0 {
		t.Fatal("invalid endpoint values created a record")
	}

	created := endpointAdd(t, db, endpointCreateInput(selectionA))
	before := endpointShow(t, db, created.RegistrationID)
	protectedFixture(t)
	if _, _, err := db.PatchEndpoint(context.Background(), created.RegistrationID, endpoint.Patch{Trust: &wrongMaterial}); errorCode(err) != "trust_configuration_error" {
		t.Fatalf("mismatched patch trust selection was accepted: %v", err)
	}
	after := endpointShow(t, db, created.RegistrationID)
	if after.Values != before.Values || after.MonitoringID != before.MonitoringID || after.ConfigurationRevision != before.ConfigurationRevision || after.UpdatedAt != before.UpdatedAt {
		t.Fatal("failed trust patch changed last-valid endpoint state")
	}

	missingID := strings.Repeat("d", 32)
	for _, operation := range []struct {
		name string
		call func() error
	}{
		{"show", func() error { _, err := db.ShowEndpoint(context.Background(), missingID); return err }},
		{"patch", func() error {
			_, _, err := db.PatchEndpoint(context.Background(), missingID, endpoint.Patch{})
			return err
		}},
		{"enable", func() error { _, _, err := db.EnableEndpoint(context.Background(), missingID); return err }},
		{"disable", func() error { _, _, err := db.DisableEndpoint(context.Background(), missingID); return err }},
	} {
		t.Run("not_found/"+operation.name, func(t *testing.T) {
			protectedFixture(t)
			if err := operation.call(); errorCode(err) != "not_found" {
				t.Fatalf("missing endpoint was not not_found: %v", err)
			}
		})
	}
	if len(endpointList(t, db)) != 1 {
		t.Fatal("missing-record operations implicitly created a registration")
	}
}

func TestEndpointTrustAndRecordCorruptionFailClosed(t *testing.T) {
	t.Run("corrupt selected trust", func(t *testing.T) {
		_, db, setup := endpointFixtureDB(t)
		defer closeEndpointDB(t, db)
		selection := endpointTrustSelection(t, db, 401)
		created := endpointAdd(t, db, endpointCreateInput(selection))
		badTrust, err := json.Marshal(TrustProfile{ID: selection.Profile, Versions: []TrustVersion{}})
		if err != nil {
			t.Fatal(err)
		}
		digest := recordDigest("trust", selection.Profile, badTrust)
		protectedFixture(t)
		if _, err := setup.Exec(context.Background(), `UPDATE tlsbeacon_registry.records SET value=$1, digest=$2 WHERE kind=$3 AND key=$4`, badTrust, digest[:], "trust", selection.Profile); err != nil {
			t.Fatal("corrupt selected trust fixture setup failed")
		}
		protectedFixture(t)
		if _, err := db.ShowEndpoint(context.Background(), created.RegistrationID); errorCode(err) != "storage_error" {
			t.Fatalf("endpoint show accepted invalid selected trust data: %v", err)
		}
		protectedFixture(t)
		if _, _, err := db.PatchEndpoint(context.Background(), created.RegistrationID, endpoint.Patch{Label: endpointPtr("not-written")}); errorCode(err) != "storage_error" {
			t.Fatalf("endpoint mutation accepted invalid selected trust data: %v", err)
		}
	})

	t.Run("typed endpoint record corruption", func(t *testing.T) {
		_, db, setup := endpointFixtureDB(t)
		defer closeEndpointDB(t, db)
		selection := endpointTrustSelection(t, db, 402)
		created := endpointAdd(t, db, endpointCreateInput(selection))
		data, err := encodeEndpointRecord(created)
		if err != nil {
			t.Fatal(err)
		}
		corrupt := bytes.Replace(data, []byte(`"dns":"endpoint.invalid"`), []byte(`"dns":"other.example"`), 1)
		if bytes.Equal(corrupt, data) {
			t.Fatal("endpoint corruption fixture did not match canonical record")
		}
		digest := recordDigest("endpoint", created.RegistrationID, corrupt)
		protectedFixture(t)
		if _, err := setup.Exec(context.Background(), `UPDATE tlsbeacon_registry.records SET value=$1, digest=$2 WHERE kind=$3 AND key=$4`, corrupt, digest[:], "endpoint", created.RegistrationID); err != nil {
			t.Fatal("corrupt endpoint fixture setup failed")
		}
		protectedFixture(t)
		if _, err := db.ShowEndpoint(context.Background(), created.RegistrationID); errorCode(err) != "storage_error" {
			t.Fatalf("typed endpoint corruption was accepted: %v", err)
		}
		protectedFixture(t)
		if _, err := db.ListEndpoints(context.Background()); errorCode(err) != "storage_error" {
			t.Fatalf("list accepted typed endpoint corruption: %v", err)
		}
	})
}

func TestEndpointFailedWritesPreserveLastValidState(t *testing.T) {
	_, db, setup := endpointFixtureDB(t)
	defer closeEndpointDB(t, db)
	selection := endpointTrustSelection(t, db, 501)
	created := endpointAdd(t, db, endpointCreateInput(selection))
	before := endpointShow(t, db, created.RegistrationID)
	beforeXmin := endpointXmin(t, db, created.RegistrationID)
	protectedFixture(t)
	_, err := setup.Exec(context.Background(), `CREATE FUNCTION tlsbeacon_registry.reject_endpoint_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind = 'endpoint' AND position('reject-endpoint-commit' in convert_from(NEW.value, 'UTF8')) > 0 THEN RAISE EXCEPTION 'fixture failure' USING ERRCODE = '23514'; END IF; RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER reject_endpoint_commit AFTER INSERT OR UPDATE ON tlsbeacon_registry.records DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION tlsbeacon_registry.reject_endpoint_commit();`, pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		t.Fatal("endpoint failure trigger setup failed")
	}
	protectedFixture(t)
	if _, _, err := db.PatchEndpoint(context.Background(), created.RegistrationID, endpoint.Patch{Label: endpointPtr("reject-endpoint-commit")}); errorCode(err) != "storage_error" {
		t.Fatalf("known endpoint commit failure was acknowledged: %v", err)
	}
	after := endpointShow(t, db, created.RegistrationID)
	if after.Values != before.Values || after.MonitoringID != before.MonitoringID || after.ConfigurationRevision != before.ConfigurationRevision || after.UpdatedAt != before.UpdatedAt || endpointXmin(t, db, created.RegistrationID) != beforeXmin {
		t.Fatal("failed endpoint commit changed last-valid row")
	}
	rejected := endpointCreateInput(selection)
	rejected.Label = "reject-endpoint-commit"
	protectedFixture(t)
	if _, err := db.AddEndpoint(context.Background(), rejected); errorCode(err) != "storage_error" {
		t.Fatalf("failed endpoint creation was acknowledged: %v", err)
	}
	if len(endpointList(t, db)) != 1 {
		t.Fatal("failed endpoint creation left a partial registration")
	}
}

func waitForEndpointLock(t *testing.T, ctx context.Context, observer *pgx.Conn, pid uint32) {
	t.Helper()
	for ctx.Err() == nil {
		var wait *string
		if err := observer.QueryRow(ctx, `SELECT wait_event_type FROM pg_catalog.pg_stat_activity WHERE pid=$1`, pid).Scan(&wait); err != nil {
			t.Fatalf("observe endpoint mutation barrier: %v", err)
		}
		if wait != nil && *wait == "Lock" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("endpoint mutation did not reach the database row-lock barrier")
}

func lockEndpointForTest(t *testing.T, ctx context.Context, setup *pgx.Conn, id string) pgx.Tx {
	t.Helper()
	protectedFixture(t)
	tx, err := setup.Begin(ctx)
	if err != nil {
		t.Fatal("begin endpoint barrier transaction")
	}
	t.Cleanup(func() {
		protectedFixture(t)
		_ = tx.Rollback(context.Background())
	})
	var key string
	protectedFixture(t)
	if err := tx.QueryRow(ctx, `SELECT key FROM tlsbeacon_registry.records WHERE kind=$1 AND key=$2 FOR UPDATE`, "endpoint", id).Scan(&key); err != nil || key != id {
		t.Fatalf("lock endpoint barrier row: %v", err)
	}
	return tx
}

func TestEndpointConcurrentEditsAndNoOpAreSerialized(t *testing.T) {
	name, first, setup := endpointFixtureDB(t)
	defer closeEndpointDB(t, first)
	selection := endpointTrustSelection(t, first, 601)
	created := endpointAdd(t, first, endpointCreateInput(selection))
	secondConfig := fixtureConnection(t, name)
	protectedFixture(t)
	second, err := Open(context.Background(), secondConfig)
	if err != nil {
		t.Fatalf("open second endpoint editor: %v", err)
	}
	defer closeEndpointDB(t, second)
	observer := connectFixture(t, protectedFixture(t), "tlsbeacon_runtime", name)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	barrier := lockEndpointForTest(t, ctx, setup, created.RegistrationID)
	results := make(chan error, 2)
	protectedFixture(t)
	go func() {
		_, _, err := first.PatchEndpoint(ctx, created.RegistrationID, endpoint.Patch{Label: endpointPtr("concurrent label")})
		results <- err
	}()
	waitForEndpointLock(t, ctx, observer, first.conn.PgConn().PID())
	protectedFixture(t)
	go func() {
		_, _, err := second.PatchEndpoint(ctx, created.RegistrationID, endpoint.Patch{Interval: endpointPtr(2 * time.Hour)})
		results <- err
	}()
	waitForEndpointLock(t, ctx, observer, second.conn.PgConn().PID())
	protectedFixture(t)
	if err := barrier.Commit(ctx); err != nil {
		t.Fatal("release concurrent endpoint editors")
	}
	if err := <-results; err != nil {
		t.Fatalf("first serialized edit failed: %v", err)
	}
	if err := <-results; err != nil {
		t.Fatalf("second serialized edit failed: %v", err)
	}
	current := endpointShow(t, first, created.RegistrationID)
	if current.Values.Label != "concurrent label" || current.Values.Interval != 2*time.Hour || current.ConfigurationRevision != created.ConfigurationRevision+2 || current.MonitoringID != created.MonitoringID {
		t.Fatal("disjoint concurrent edits lost state or changed monitoring identity")
	}

	barrier = lockEndpointForTest(t, ctx, setup, created.RegistrationID)
	resultsWithState := make(chan struct {
		record  EndpointRecord
		changed bool
		err     error
	}, 2)
	beforeXmin := endpointXmin(t, first, created.RegistrationID)
	protectedFixture(t)
	go func() {
		record, changed, err := first.PatchEndpoint(ctx, created.RegistrationID, endpoint.Patch{Label: endpointPtr("barrier label")})
		resultsWithState <- struct {
			record  EndpointRecord
			changed bool
			err     error
		}{record, changed, err}
	}()
	waitForEndpointLock(t, ctx, observer, first.conn.PgConn().PID())
	protectedFixture(t)
	go func() {
		record, changed, err := second.PatchEndpoint(ctx, created.RegistrationID, endpoint.Patch{Host: endpointPtr("ENDPOINT.INVALID.")})
		resultsWithState <- struct {
			record  EndpointRecord
			changed bool
			err     error
		}{record, changed, err}
	}()
	waitForEndpointLock(t, ctx, observer, second.conn.PgConn().PID())
	protectedFixture(t)
	if err := barrier.Commit(ctx); err != nil {
		t.Fatal("release no-op versus edit barrier")
	}
	firstResult, secondResult := <-resultsWithState, <-resultsWithState
	for _, result := range []struct {
		record  EndpointRecord
		changed bool
		err     error
	}{firstResult, secondResult} {
		if result.err != nil {
			t.Fatalf("serialized no-op/edit returned an error: %v", result.err)
		}
	}
	changedCount := 0
	for _, result := range []struct {
		record  EndpointRecord
		changed bool
		err     error
	}{firstResult, secondResult} {
		if result.changed {
			changedCount++
		}
	}
	if changedCount != 1 {
		t.Fatalf("no-op/edit pair made %d effective changes, want one", changedCount)
	}
	final := endpointShow(t, first, created.RegistrationID)
	if final.Values.Label != "barrier label" || final.Values.Host.Original != "endpoint.invalid" || final.ConfigurationRevision != current.ConfigurationRevision+1 || final.MonitoringID != created.MonitoringID || endpointXmin(t, first, created.RegistrationID) == beforeXmin {
		t.Fatal("canonical no-op raced with an edit and changed or lost effective state")
	}
}

func TestEndpointLifecycleHasNoTargetNetworkImports(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "endpoints.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"bytes": true, "context": true, "encoding/hex": true, "encoding/json": true, "errors": true, "time": true,
		"github.com/jackc/pgx/v5":                           true,
		"github.com/merizrizal/tlsbeacon/internal/endpoint": true,
	}
	for _, spec := range file.Imports {
		name, err := strconv.Unquote(spec.Path.Value)
		if err != nil || !allowed[name] {
			t.Fatalf("unexpected endpoint lifecycle import: %s", spec.Path.Value)
		}
	}
}
