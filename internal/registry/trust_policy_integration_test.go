package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/merizrizal/tlsbeacon/internal/policy"
	"github.com/merizrizal/tlsbeacon/internal/trust"
)

func fixtureCA(t *testing.T, serial int64) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func fixtureMaterial(t *testing.T, mode trust.Mode, data []byte) trust.Material {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "roots")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	m, err := trust.Import(mode, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestTrustPolicyPersistenceRoundTripAndNoOp(t *testing.T) {
	name, _ := newFixtureDatabase(t, true)
	ctx := context.Background()
	db, err := Open(ctx, fixtureConnection(t, name))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)
	a, b := fixtureCA(t, 1), fixtureCA(t, 2)
	bundle := append(bytes.Clone(a), b...)
	m := fixtureMaterial(t, trust.Custom, bundle)
	profile, err := db.ImportTrust(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Write(ctx, "endpoint", "sentinel", nil, []byte(profile.Versions[0].ID)); err != nil {
		t.Fatal(err)
	}
	got, err := db.ReadTrust(ctx, profile.ID)
	if err != nil || len(got.Versions) != 1 || got.ID != profile.ID {
		t.Fatal("trust read failed")
	}
	v := got.Versions[0]
	if v.Digest != m.Digest() || v.Mode != trust.Custom || len(v.Sources) != 1 || v.Sources[0] != sha256.Sum256(bundle) || len(v.Roots) != len(m.Roots()) {
		t.Fatal("trust metadata mismatch")
	}
	for i, root := range m.Roots() {
		if !bytes.Equal(root, v.Roots[i]) {
			t.Fatal("root mismatch")
		}
	}
	v.Roots[0][0] ^= 1
	gotAgain, err := db.ReadTrust(ctx, profile.ID)
	if err != nil || !bytes.Equal(gotAgain.Versions[0].Roots[0], m.Roots()[0]) {
		t.Fatal("snapshot alias")
	}
	var before, after string
	if err := db.conn.QueryRow(ctx, `SELECT xmin::text FROM tlsbeacon_registry.records WHERE kind='trust' AND key=$1`, profile.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	equivalent := fixtureMaterial(t, trust.Custom, append(append(bytes.Clone(b), a...), b...))
	unchanged, changed, err := db.RefreshTrust(ctx, profile.ID, equivalent)
	if err != nil || changed || unchanged.Versions[0].ID != profile.Versions[0].ID {
		t.Fatal("equivalent trust changed")
	}
	if err := db.conn.QueryRow(ctx, `SELECT xmin::text FROM tlsbeacon_registry.records WHERE kind='trust' AND key=$1`, profile.ID).Scan(&after); err != nil || before != after {
		t.Fatal("trust no-op wrote")
	}
	updated, changed, err := db.RefreshTrust(ctx, profile.ID, fixtureMaterial(t, trust.Custom, a))
	if err != nil || !changed || len(updated.Versions) != 2 || updated.Versions[0].ID != profile.Versions[0].ID || updated.Versions[1].ID == updated.Versions[0].ID {
		t.Fatal("trust refresh failed")
	}
	system := fixtureMaterial(t, trust.System, a)
	modeChanged, changed, err := db.RefreshTrust(ctx, profile.ID, system)
	if err != nil || !changed || len(modeChanged.Versions) != 3 || modeChanged.Versions[2].Mode != trust.System {
		t.Fatal("source mode change not versioned")
	}
	profiles, err := db.ListTrust(ctx)
	if err != nil || len(profiles) != 1 || len(profiles[0].Versions) != 3 {
		t.Fatal("trust listing failed")
	}
	endpoint, err := db.Read(ctx, "endpoint", "sentinel")
	if err != nil || string(endpoint) != profile.Versions[0].ID {
		t.Fatal("refresh activated an endpoint")
	}

	p, err := policy.New(&policy.Input{Version: policy.Version, Rules: []policy.Rule{{CIDR: "10.0.0.7/8", Port: 443, Acknowledge: policy.Private}}, Metadata: []string{"10.2.0.0/16"}})
	if err != nil {
		t.Fatal(err)
	}
	rev, changed, err := db.ReplacePolicy(ctx, p)
	if err != nil || !changed {
		t.Fatal("policy create failed")
	}
	read, restored, err := db.ReadPolicy(ctx)
	if err != nil || read.ID != rev.ID || !restored.Equal(p) {
		t.Fatal("policy round trip failed")
	}
	c := policy.Candidate{Address: netip.MustParseAddr("10.2.3.4"), Port: 443, Target: "10.2.3.4", Route: policy.RouteGateway}
	if restored.Authorize(c) {
		t.Fatal("metadata overlay lost")
	}
	if err := db.conn.QueryRow(ctx, `SELECT xmin::text FROM tlsbeacon_registry.records WHERE kind='policy' AND key='current'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	equivalentPolicy, err := policy.New(&policy.Input{Version: policy.Version, Rules: []policy.Rule{{CIDR: "10.0.0.0/8", Port: 443, Acknowledge: policy.Private}, {CIDR: "10.1.2.3/8", Port: 443, Acknowledge: policy.Private}}, Metadata: []string{"10.2.1.0/24", "10.2.0.0/16"}})
	if err != nil || !p.Equal(equivalentPolicy) {
		t.Fatal("canonical policy prerequisite failed")
	}
	rev2, changed, err := db.ReplacePolicy(ctx, equivalentPolicy)
	if err != nil || changed || rev2.ID != rev.ID {
		t.Fatal("policy no-op failed")
	}
	if err := db.conn.QueryRow(ctx, `SELECT xmin::text FROM tlsbeacon_registry.records WHERE kind='policy' AND key='current'`).Scan(&after); err != nil || before != after {
		t.Fatal("policy no-op wrote")
	}
	complex, err := policy.New(&policy.Input{Version: policy.Version, Rules: []policy.Rule{
		{CIDR: "fe80::/10", Port: 443, Acknowledge: policy.Private | policy.Loopback | policy.LinkLocal | policy.SpecialUse | policy.Metadata, Target: "service.example", Interface: "eth0"},
		{CIDR: "fe80::2/128", Port: 443, Deny: true, Target: "service.example", Interface: "eth0"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	newRevision, changed, err := db.ReplacePolicy(ctx, complex)
	if err != nil || !changed || newRevision.ID == rev.ID {
		t.Fatal("policy replacement failed")
	}
	_, actual, err := db.ReadPolicy(ctx)
	if err != nil || !actual.Equal(complex) {
		t.Fatal("complete policy revision lost")
	}
	allowed := policy.Candidate{Address: netip.MustParseAddr("fe80::1"), Port: 443, Target: "service.example", Interface: "eth0"}
	denied := allowed
	denied.Address = netip.MustParseAddr("fe80::2")
	wrongScope := allowed
	wrongScope.Interface = "eth1"
	wrongTarget := allowed
	wrongTarget.Target = "other.example"
	if !actual.Authorize(allowed) || actual.Authorize(denied) || actual.Authorize(wrongScope) || actual.Authorize(wrongTarget) {
		t.Fatal("restored policy changed narrowing or deny precedence")
	}
}

func TestTrustPolicyCorruptionAndSourceOverwrite(t *testing.T) {
	name, setup := newFixtureDatabase(t, true)
	ctx := context.Background()
	db, err := Open(ctx, fixtureConnection(t, name))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)
	if _, _, err := db.ReadPolicy(ctx); errorCode(err) != "not_found" {
		t.Fatal("missing policy accepted")
	}
	if _, _, err := db.ReplacePolicy(ctx, policy.Policy{}); err == nil {
		t.Fatal("invalid policy accepted")
	}
	if _, err := db.ImportTrust(ctx, trust.Material{}); err == nil {
		t.Fatal("invalid trust accepted")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "roots")
	a, b := fixtureCA(t, 5), fixtureCA(t, 6)
	if err := os.WriteFile(path, a, 0600); err != nil {
		t.Fatal(err)
	}
	material, err := trust.Import(trust.System, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := db.ImportTrust(ctx, material)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	old, err := db.ReadTrust(ctx, profile.ID)
	if err != nil || old.Versions[0].Digest != material.Digest() {
		t.Fatal("source overwrite changed snapshot")
	}
	changed, err := trust.Import(trust.System, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	newProfile, updated, err := db.RefreshTrust(ctx, profile.ID, changed)
	if err != nil || !updated || len(newProfile.Versions) != 2 || newProfile.Versions[0].Digest != material.Digest() || newProfile.Versions[1].Digest != changed.Digest() {
		t.Fatal("refresh failed to preserve old roots")
	}
	if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Import(trust.System, []string{path}); err == nil {
		t.Fatal("malformed trust accepted")
	}
	after, err := db.ReadTrust(ctx, profile.ID)
	if err != nil || len(after.Versions) != 2 {
		t.Fatal("invalid import changed profile")
	}
	empty, _ := policy.New(&policy.Input{Version: policy.Version})
	if _, _, err := db.ReplacePolicy(ctx, empty); err != nil {
		t.Fatal(err)
	}
	_, actual, err := db.ReadPolicy(ctx)
	if err != nil || !actual.Equal(empty) || actual.Authorize(policy.Candidate{Address: netip.MustParseAddr("8.8.8.8"), Port: 443, Target: "8.8.8.8", Route: policy.RouteGateway}) {
		t.Fatal("valid empty policy not deny-all")
	}
	bad := []byte(`{"revisions":[{"id":"00000000000000000000000000000000","policy":{"version":999}}]}`)
	digest := recordDigest("policy", "current", bad)
	protectedFixture(t)
	if _, err := setup.Exec(ctx, `UPDATE tlsbeacon_registry.records SET value=$1, digest=$2 WHERE kind='policy' AND key='current'`, bad, digest[:]); err != nil {
		t.Fatal("fixture corruption failed")
	}
	if _, _, err := db.ReadPolicy(ctx); errorCode(err) != "storage_error" {
		t.Fatal("typed policy corruption accepted")
	}
	if _, _, err := db.ReplacePolicy(ctx, empty); errorCode(err) != "storage_error" {
		t.Fatal("typed policy corruption overwritten")
	}
	badTrust := []byte(`{"id":"` + profile.ID + `","versions":[{"id":"00000000000000000000000000000000","mode":"custom","roots":["AA=="],"digest":[0],"sources":[]}]}`)
	trustHash := recordDigest("trust", profile.ID, badTrust)
	protectedFixture(t)
	if _, err := setup.Exec(ctx, `UPDATE tlsbeacon_registry.records SET value=$1, digest=$2 WHERE kind='trust' AND key=$3`, badTrust, trustHash[:], profile.ID); err != nil {
		t.Fatal("fixture corruption failed")
	}
	if _, err := db.ReadTrust(ctx, profile.ID); errorCode(err) != "storage_error" {
		t.Fatal("typed trust corruption accepted")
	}
	if _, err := db.ListTrust(ctx); errorCode(err) != "storage_error" {
		t.Fatal("corrupt profile listed")
	}
}

func TestTrustPolicyRealRollbackAndConcurrency(t *testing.T) {
	name, setup := newFixtureDatabase(t, true)
	ctx := context.Background()
	config := fixtureConnection(t, name)
	first, err := Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close(ctx)
	second, err := Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(ctx)
	m := fixtureMaterial(t, trust.Custom, fixtureCA(t, 3))
	profile, err := first.ImportTrust(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := policy.New(&policy.Input{Version: policy.Version})
	original, _, err := first.ReplacePolicy(ctx, empty)
	if err != nil {
		t.Fatal(err)
	}
	protectedFixture(t)
	_, err = setup.Exec(ctx, `CREATE FUNCTION tlsbeacon_registry.reject_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END $$; CREATE CONSTRAINT TRIGGER reject_update AFTER UPDATE ON tlsbeacon_registry.records DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION tlsbeacon_registry.reject_update();`, pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		t.Fatal("fixture trigger setup failed")
	}
	changedMaterial := fixtureMaterial(t, trust.Custom, fixtureCA(t, 4))
	if _, _, err := first.RefreshTrust(ctx, profile.ID, changedMaterial); errorCode(err) != "storage_error" {
		t.Fatal("failed trust commit acknowledged")
	}
	got, err := first.ReadTrust(ctx, profile.ID)
	if err != nil || len(got.Versions) != 1 {
		t.Fatal("partial trust version persisted")
	}
	p, _ := policy.New(&policy.Input{Version: policy.Version, Rules: []policy.Rule{{CIDR: "8.8.8.0/24", Port: 443}}})
	if _, _, err := first.ReplacePolicy(ctx, p); errorCode(err) != "storage_error" {
		t.Fatal("failed policy commit acknowledged")
	}
	read, restored, err := first.ReadPolicy(ctx)
	if err != nil || read.ID != original.ID || !restored.Equal(empty) {
		t.Fatal("last valid policy lost")
	}
	concurrentName, concurrentSetup := newFixtureDatabase(t, true)
	concurrentConfig := fixtureConnection(t, concurrentName)
	first, err = Open(ctx, concurrentConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close(ctx)
	second, err = Open(ctx, concurrentConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(ctx)
	if _, _, err := first.ReplacePolicy(ctx, empty); err != nil {
		t.Fatal(err)
	}
	barrierCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := concurrentSetup.Begin(barrierCtx)
	if err != nil {
		t.Fatal("fixture lock failed")
	}
	defer tx.Rollback(context.Background())
	var locked string
	if err := tx.QueryRow(barrierCtx, `SELECT key FROM tlsbeacon_registry.records WHERE kind='policy' AND key='current' FOR UPDATE`).Scan(&locked); err != nil {
		t.Fatal("fixture lock failed")
	}
	observer := connectFixture(t, protectedFixture(t), "tlsbeacon_runtime", concurrentName)
	pids := []uint32{first.conn.PgConn().PID(), second.conn.PgConn().PID()}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i, db := range []*DB{first, second} {
		wg.Add(1)
		go func(i int, db *DB) {
			defer wg.Done()
			<-start
			candidate, _ := policy.New(&policy.Input{Version: policy.Version, Rules: []policy.Rule{{CIDR: "8.8.8.0/24", Port: 443 + i}}})
			_, _, err := db.ReplacePolicy(ctx, candidate)
			results <- err
		}(i, db)
	}
	close(start)
	for _, pid := range pids {
		for {
			var wait *string
			if err := observer.QueryRow(barrierCtx, `SELECT wait_event_type FROM pg_catalog.pg_stat_activity WHERE pid=$1`, pid).Scan(&wait); err != nil {
				t.Fatal("fixture lock observation failed")
			}
			if wait != nil && *wait == "Lock" {
				break
			}
			if barrierCtx.Err() != nil {
				t.Fatal("concurrent replacement did not reach lock")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	protectedFixture(t)
	if err := tx.Commit(barrierCtx); err != nil {
		t.Fatal("fixture lock release failed")
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errorCode(err) == "revision_conflict" {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent outcome: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal("concurrent replacements did not conflict")
	}
	if _, _, err := first.ReadPolicy(ctx); err != nil {
		t.Fatal("concurrent policy unreadable")
	}
}
