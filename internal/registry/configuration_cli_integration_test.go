package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type configurationCLIResult struct {
	code   int
	stdout string
	stderr string
}

func configurationCLIEnvironment(t *testing.T) []string {
	t.Helper()
	home := t.TempDir()
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal("cannot protect CLI home directory")
	}
	values := map[string]string{
		"GOTOOLCHAIN": "local", "GOPROXY": "off", "HOME": home,
	}
	env := make([]string, 0, len(os.Environ())+len(values))
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if _, replaced := values[key]; !replaced && !strings.HasPrefix(key, "PG") {
			env = append(env, item)
		}
	}
	for key, value := range values {
		env = append(env, key+"="+value)
	}
	return env
}

func buildConfigurationCLI(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("cannot resolve repository root")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("cannot protect CLI build directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("CLI build directory is not protected")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		t.Fatal("CLI build directory has the wrong owner")
	}
	binary := filepath.Join(dir, "tlsbeacon")
	build := exec.Command("go", "build", "-mod=readonly", "-o", binary, "./cmd/tlsbeacon")
	build.Dir = root
	build.Env = configurationCLIEnvironment(t)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("CLI build failed: %v (%d output bytes)", err, len(output))
	}
	return binary
}

func writeConfigurationCLIFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal("cannot write protected CLI fixture")
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal("cannot set protected CLI fixture mode")
	}
}

func writeConfigurationCLIConfig(t *testing.T, dir, dsn string) string {
	return writeConfigurationCLIConfigNamed(t, dir, "local.json", dsn)
}

func writeConfigurationCLIConfigNamed(t *testing.T, dir, name, dsn string) string {
	t.Helper()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("cannot protect CLI configuration directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("CLI configuration directory is not protected")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		t.Fatal("CLI configuration directory has the wrong owner")
	}
	content, err := json.Marshal(map[string]string{"database_url": dsn})
	if err != nil {
		t.Fatal("cannot encode CLI test configuration")
	}
	path := filepath.Join(dir, name)
	writeConfigurationCLIFile(t, path, content, 0600)
	return path
}

func configurationCLIDSN(t *testing.T, database string) string {
	t.Helper()
	socket := protectedFixture(t)
	return fmt.Sprintf("host=%s user=tlsbeacon_runtime dbname=%s sslmode=disable application_name=tlsbeacon_chunk11", socket, database)
}

func startConfigurationCLI(t *testing.T, binary, configPath string, args ...string) *exec.Cmd {
	t.Helper()
	protectedFixture(t)
	commandArgs := append([]string{"--config", configPath}, args...)
	cmd := exec.Command(binary, commandArgs...)
	cmd.Env = configurationCLIEnvironment(t)
	return cmd
}

func runConfigurationCLI(t *testing.T, binary, configPath string, args ...string) configurationCLIResult {
	t.Helper()
	return executeConfigurationCLI(t, startConfigurationCLI(t, binary, configPath, args...))
}

func runConfigurationCLIWithoutConfig(t *testing.T, binary string, args ...string) configurationCLIResult {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = configurationCLIEnvironment(t)
	return executeConfigurationCLI(t, cmd)
}

func runTracedConfigurationCLI(t *testing.T, binary, configPath, tracePath string, args ...string) configurationCLIResult {
	t.Helper()
	protectedFixture(t)
	commandArgs := []string{"-f", "-qq", "-e", "trace=network", "-o", tracePath, binary, "--config", configPath}
	commandArgs = append(commandArgs, args...)
	cmd := exec.Command("strace", commandArgs...)
	cmd.Env = configurationCLIEnvironment(t)
	result := executeConfigurationCLI(t, cmd)
	trace, err := os.ReadFile(tracePath)
	if err != nil || bytes.Contains(trace, []byte("AF_INET")) || bytes.Contains(trace, []byte("AF_INET6")) {
		t.Fatalf("configuration command made a non-local network syscall: trace=%q", trace)
	}
	return result
}

func executeConfigurationCLI(t *testing.T, cmd *exec.Cmd) configurationCLIResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	result := configurationCLIResult{stdout: stdout.String(), stderr: stderr.String()}
	if err == nil {
		return result
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("CLI process could not run: %v", err)
	}
	result.code = exit.ExitCode()
	return result
}

func assertConfigurationEnvelope(t *testing.T, result configurationCLIResult, command, outcome string, exitCode int) map[string]any {
	t.Helper()
	if result.code != exitCode || result.stderr != "" || strings.Count(result.stdout, "\n") != 1 || !strings.HasSuffix(result.stdout, "\n") {
		t.Fatalf("CLI streams/exit: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(result.stdout), &envelope); err != nil {
		t.Fatalf("invalid single JSON envelope: %v", err)
	}
	if len(envelope) != 5 || envelope["schema_version"] != "tlsbeacon.cli.v1" || envelope["command"] != command || envelope["outcome"] != outcome {
		t.Fatalf("unexpected CLI envelope: %#v", envelope)
	}
	return envelope
}

func expectConfigurationSuccess(t *testing.T, result configurationCLIResult, command string) map[string]any {
	t.Helper()
	envelope := assertConfigurationEnvelope(t, result, command, "success", 0)
	if envelope["error"] != nil {
		t.Fatalf("success contains error: %#v", envelope["error"])
	}
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		t.Fatalf("success data is not an object: %#v", envelope["data"])
	}
	return data
}

func expectConfigurationFailure(t *testing.T, result configurationCLIResult, command, code string) {
	t.Helper()
	envelope := assertConfigurationEnvelope(t, result, command, "execution_failed", 2)
	if envelope["data"] != nil {
		t.Fatalf("failure contains data: %#v", envelope["data"])
	}
	failure, ok := envelope["error"].(map[string]any)
	if !ok || len(failure) != 3 || failure["code"] != code || failure["message"] == "" || failure["action"] == "" {
		t.Fatalf("unexpected failure: %#v", envelope["error"])
	}
	if strings.Contains(result.stdout, "fixture-secret-sentinel") || strings.Contains(result.stderr, "fixture-secret-sentinel") || strings.Contains(result.stdout, "password=") || strings.Contains(result.stderr, "password=") {
		t.Fatal("database credential leaked in CLI failure")
	}
}

func configurationCLIObject(t *testing.T, value any, key string) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected object for %s, got %#v", key, value)
	}
	return object
}

func configurationCLIInt(t *testing.T, value any) int64 {
	t.Helper()
	number, ok := value.(float64)
	if !ok {
		t.Fatalf("expected number, got %#v", value)
	}
	return int64(number)
}

func TestConfigurationCLIWithProtectedRegistry(t *testing.T) {
	binary := buildConfigurationCLI(t)
	name, setup := newFixtureDatabase(t, true)
	configDir := t.TempDir()
	configPath := writeConfigurationCLIConfig(t, configDir, configurationCLIDSN(t, name))
	protectedFixture(t)
	db, err := Open(context.Background(), fixtureConnection(t, name))
	if err != nil {
		t.Fatal("cannot open fixture registry for read-back")
	}
	defer db.Close(context.Background())

	rootA := filepath.Join(configDir, "root-a.pem")
	rootB := filepath.Join(configDir, "root-b.pem")
	writeConfigurationCLIFile(t, rootA, fixtureCA(t, 11), 0600)
	writeConfigurationCLIFile(t, rootB, fixtureCA(t, 12), 0600)

	imported := runConfigurationCLI(t, binary, configPath, "trust", "import", "--mode", "custom", "--source", rootA, "--json")
	importData := expectConfigurationSuccess(t, imported, "trust import")
	if importData["result"] != "created" {
		t.Fatalf("trust import result = %#v", importData["result"])
	}
	profile := configurationCLIObject(t, importData["profile"], "profile")
	profileID := profile["id"].(string)
	versions := profile["versions"].([]any)
	if len(versions) != 1 || strings.Contains(imported.stdout, "BEGIN CERTIFICATE") {
		t.Fatalf("unsafe trust import response: %#v", profile)
	}
	version1 := configurationCLIObject(t, versions[0], "version")
	version1ID := version1["id"].(string)
	if version1["mode"] != "custom" || len(version1["material_sha256"].(string)) != 64 {
		t.Fatalf("trust version metadata incomplete: %#v", version1)
	}
	if strings.Contains(imported.stdout, "roots") {
		t.Fatal("trust import exposed root certificate material")
	}

	unchangedTrust := runConfigurationCLI(t, binary, configPath, "trust", "refresh", "--id", profileID, "--mode", "custom", "--source", rootA, "--json")
	unchangedTrustData := expectConfigurationSuccess(t, unchangedTrust, "trust refresh")
	if unchangedTrustData["result"] != "unchanged" {
		t.Fatalf("identical trust refresh result = %#v", unchangedTrustData["result"])
	}
	updatedTrust := runConfigurationCLI(t, binary, configPath, "trust", "refresh", "--id", profileID, "--mode", "custom", "--source", rootB, "--json")
	updatedTrustData := expectConfigurationSuccess(t, updatedTrust, "trust refresh")
	if updatedTrustData["result"] != "updated" {
		t.Fatalf("changed trust refresh result = %#v", updatedTrustData["result"])
	}
	updatedProfile := configurationCLIObject(t, updatedTrustData["profile"], "profile")
	versions = updatedProfile["versions"].([]any)
	if len(versions) != 2 || configurationCLIObject(t, versions[0], "old version")["id"] != version1ID {
		t.Fatalf("trust refresh did not preserve immutable version: %#v", updatedProfile)
	}
	version2ID := configurationCLIObject(t, versions[1], "new version")["id"].(string)

	trustList := runConfigurationCLI(t, binary, configPath, "trust", "list", "--json")
	trustListData := expectConfigurationSuccess(t, trustList, "trust list")
	if got := trustListData["profiles"].([]any); len(got) != 1 {
		t.Fatalf("trust list profiles = %#v", got)
	}
	invalidSource := filepath.Join(configDir, "invalid.pem")
	writeConfigurationCLIFile(t, invalidSource, []byte("not a certificate\n"), 0600)
	badTrust := runConfigurationCLI(t, binary, configPath, "trust", "import", "--mode", "custom", "--source", invalidSource, "--json")
	expectConfigurationFailure(t, badTrust, "trust import", "trust_configuration_error")
	missingTrust := runConfigurationCLI(t, binary, configPath, "trust", "refresh", "--id", "00000000000000000000000000000000", "--mode", "custom", "--source", rootA, "--json")
	expectConfigurationFailure(t, missingTrust, "trust refresh", "not_found")

	policyA := `{"version":1,"rules":[{"cidr":"127.0.0.0/8","port":443,"acknowledgements":["loopback"]}],"metadata":[]}`
	policySet := runConfigurationCLI(t, binary, configPath, "policy", "set", "--rules-json", policyA, "--json")
	policyData := expectConfigurationSuccess(t, policySet, "policy set")
	if policyData["result"] != "created" || len(policyData["revision_id"].(string)) != 32 {
		t.Fatalf("policy create result incomplete: %#v", policyData)
	}
	policyRevision := policyData["revision_id"].(string)
	policyShow := runConfigurationCLI(t, binary, configPath, "policy", "show", "--json")
	policyShowData := expectConfigurationSuccess(t, policyShow, "policy show")
	if policyShowData["revision_id"] != policyRevision || policyShowData["policy"].(map[string]any)["classification"] == "" {
		t.Fatalf("policy show did not return effective revision: %#v", policyShowData)
	}
	policyNoOp := `{"rules":[{"cidr":"127.5.6.7/8","port":443,"acknowledgements":["loopback"]}],"version":1}`
	policyNoOpResult := runConfigurationCLI(t, binary, configPath, "policy", "set", "--rules-json="+policyNoOp, "--json")
	policyNoOpData := expectConfigurationSuccess(t, policyNoOpResult, "policy set")
	if policyNoOpData["result"] != "unchanged" || policyNoOpData["revision_id"] != policyRevision {
		t.Fatalf("canonical policy no-op changed state: %#v", policyNoOpData)
	}
	badPolicy := runConfigurationCLI(t, binary, configPath, "policy", "set", "--rules-json", `{"version":1,"rules":[],"unsafe":true}`, "--json")
	expectConfigurationFailure(t, badPolicy, "policy set", "invalid_input")

	const hostileLabel = "Pilot\n\x1b[31m"
	added := runTracedConfigurationCLI(t, binary, configPath, filepath.Join(configDir, "endpoint-add.strace"), "endpoint", "add", "--label", hostileLabel, "--host", "TLSBEACON-NO-DNS.invalid", "--port", "443", "--identity", "certificate.example", "--trust-profile", profileID, "--trust-version", version1ID, "--json")
	addedData := expectConfigurationSuccess(t, added, "endpoint add")
	if addedData["result"] != "created" {
		t.Fatalf("endpoint add result = %#v", addedData["result"])
	}
	endpointData := configurationCLIObject(t, addedData["endpoint"], "endpoint")
	registrationID := endpointData["registration_id"].(string)
	monitoringID := endpointData["monitoring_id"].(string)
	if len(registrationID) != 32 || len(monitoringID) != 32 || configurationCLIInt(t, endpointData["configuration_revision"]) != 1 {
		t.Fatalf("endpoint IDs/revision incomplete: %#v", endpointData)
	}
	for field, expected := range map[string]any{
		"label": hostileLabel, "connection_host": "TLSBEACON-NO-DNS.invalid", "connection_host_canonical": "tlsbeacon-no-dns.invalid",
		"connection_scope": "", "port": float64(443), "expected_identity": "certificate.example", "expected_identity_canonical": "certificate.example",
		"expected_identity_type": "dns", "trust_profile_id": profileID, "trust_version_id": version1ID,
		"interval_ns": "3600000000000", "warning_ns": "2592000000000000", "critical_ns": "604800000000000", "enabled": true,
		"freshness": nil, "freshness_reason": "inspection_history_not_retained",
	} {
		if endpointData[field] != expected {
			t.Fatalf("endpoint field %s = %#v, want %#v", field, endpointData[field], expected)
		}
	}
	if len(endpointData["trust_material_sha256"].(string)) != 64 || endpointData["created_at"] == "" || endpointData["updated_at"] == "" {
		t.Fatalf("endpoint trust/timestamps incomplete: %#v", endpointData)
	}
	if _, err := time.Parse(time.RFC3339Nano, endpointData["created_at"].(string)); err != nil {
		t.Fatal("endpoint created_at is not RFC3339Nano")
	}
	if strings.Contains(added.stdout, "fixture-secret-sentinel") || strings.Contains(added.stdout, "BEGIN CERTIFICATE") {
		t.Fatal("endpoint response leaked secret or trust material")
	}

	humanShow := runConfigurationCLI(t, binary, configPath, "endpoint", "show", "--id", registrationID)
	if humanShow.code != 0 || humanShow.stderr != "" || !strings.Contains(humanShow.stdout, `label: "Pilot\n\x1b[31m"`) || strings.Contains(humanShow.stdout, hostileLabel) || !strings.Contains(humanShow.stdout, "freshness: null\nfreshness_reason: inspection_history_not_retained") {
		t.Fatalf("human endpoint report mishandled fields/controls: code=%d stdout=%q stderr=%q", humanShow.code, humanShow.stdout, humanShow.stderr)
	}
	listed := runConfigurationCLI(t, binary, configPath, "endpoint", "list", "--json")
	listData := expectConfigurationSuccess(t, listed, "endpoint list")
	if got := listData["endpoints"].([]any); len(got) != 1 || configurationCLIObject(t, got[0], "listed endpoint")["registration_id"] != registrationID {
		t.Fatalf("endpoint list incomplete: %#v", listData)
	}
	listTracePath := filepath.Join(configDir, "endpoint-list.strace")
	tracedList := runTracedConfigurationCLI(t, binary, configPath, listTracePath, "endpoint", "list", "--json")
	expectConfigurationSuccess(t, tracedList, "endpoint list")

	patchLabel := runConfigurationCLI(t, binary, configPath, "endpoint", "edit", "--id", registrationID, "--label", "Primary", "--json")
	patchData := expectConfigurationSuccess(t, patchLabel, "endpoint edit")
	patched := configurationCLIObject(t, patchData["endpoint"], "patched endpoint")
	if patchData["result"] != "updated" || patched["monitoring_id"] != monitoringID || configurationCLIInt(t, patched["configuration_revision"]) != 2 || patched["connection_host"] != "TLSBEACON-NO-DNS.invalid" {
		t.Fatalf("omitted patch fields or monitoring identity changed: %#v", patchData)
	}
	updatedAt := patched["updated_at"]
	canonicalNoOp := runConfigurationCLI(t, binary, configPath, "endpoint", "edit", "--id", registrationID, "--host", "tlsbeacon-no-dns.invalid.", "--json")
	canonicalNoOpData := expectConfigurationSuccess(t, canonicalNoOp, "endpoint edit")
	noOpEndpoint := configurationCLIObject(t, canonicalNoOpData["endpoint"], "no-op endpoint")
	if canonicalNoOpData["result"] != "unchanged" || noOpEndpoint["monitoring_id"] != monitoringID || noOpEndpoint["connection_host"] != "TLSBEACON-NO-DNS.invalid" || noOpEndpoint["updated_at"] != updatedAt || configurationCLIInt(t, noOpEndpoint["configuration_revision"]) != 2 {
		t.Fatalf("canonical endpoint no-op changed state: %#v", canonicalNoOpData)
	}
	trustEdit := runConfigurationCLI(t, binary, configPath, "endpoint", "edit", "--id", registrationID, "--trust-profile", profileID, "--trust-version", version2ID, "--json")
	trustEditData := expectConfigurationSuccess(t, trustEdit, "endpoint edit")
	trustEdited := configurationCLIObject(t, trustEditData["endpoint"], "trust-edited endpoint")
	if trustEditData["result"] != "updated" || trustEdited["monitoring_id"] == monitoringID || trustEdited["trust_version_id"] != version2ID || configurationCLIInt(t, trustEdited["configuration_revision"]) != 3 {
		t.Fatalf("trust identity edit did not create new monitoring identity: %#v", trustEditData)
	}
	for _, tc := range []struct {
		command string
		want    string
	}{
		{"disable", "updated"}, {"disable", "unchanged"}, {"enable", "updated"},
	} {
		result := runConfigurationCLI(t, binary, configPath, "endpoint", tc.command, "--id", registrationID, "--json")
		data := expectConfigurationSuccess(t, result, "endpoint "+tc.command)
		if data["result"] != tc.want {
			t.Fatalf("endpoint %s result = %#v, want %s", tc.command, data["result"], tc.want)
		}
	}
	badEndpointTrust := runConfigurationCLI(t, binary, configPath, "endpoint", "add", "--label", "bad-trust", "--host", "another-no-dns.invalid", "--port", "443", "--identity", "certificate.example", "--trust-profile", "00000000000000000000000000000000", "--trust-version", version1ID, "--json")
	expectConfigurationFailure(t, badEndpointTrust, "endpoint add", "trust_configuration_error")
	missingEndpoint := runConfigurationCLI(t, binary, configPath, "endpoint", "show", "--id", "00000000000000000000000000000000", "--json")
	expectConfigurationFailure(t, missingEndpoint, "endpoint show", "not_found")

	pipeReader, pipeWriter, err := os.Pipe()
	if err != nil {
		t.Fatal("cannot create output-failure pipe")
	}
	if err := pipeReader.Close(); err != nil {
		t.Fatal("cannot close output-failure reader")
	}
	failedOutput := startConfigurationCLI(t, binary, configPath, "endpoint", "add", "--label", "output-failed", "--host", "output-no-dns.invalid", "--port", "443", "--identity", "certificate.example", "--trust-profile", profileID, "--trust-version", version1ID, "--json")
	failedOutput.Stdout = pipeWriter
	var failedOutputStderr bytes.Buffer
	failedOutput.Stderr = &failedOutputStderr
	err = failedOutput.Run()
	_ = pipeWriter.Close()
	var failedExit *exec.ExitError
	if !errors.As(err, &failedExit) || failedExit.ExitCode() != 2 || !strings.Contains(failedOutputStderr.String(), "output_error") || !strings.Contains(failedOutputStderr.String(), "list and reconcile the relevant records") {
		t.Fatalf("committed output failure was not actionable: exit=%v stderr=%q", err, failedOutputStderr.String())
	}
	protectedFixture(t)
	readback, err := db.ListEndpoints(context.Background())
	if err != nil {
		t.Fatal("cannot read back after broken output")
	}
	foundOutputFailed := false
	for _, record := range readback {
		foundOutputFailed = foundOutputFailed || record.Values.Label == "output-failed"
	}
	if !foundOutputFailed {
		t.Fatal("output failure test mutation was not committed")
	}

	missingConfig := runConfigurationCLIWithoutConfig(t, binary, "policy", "show", "--json")
	expectConfigurationFailure(t, missingConfig, "policy show", "configuration_error")
	malformedConfig := filepath.Join(configDir, "malformed.json")
	writeConfigurationCLIFile(t, malformedConfig, []byte(`{"database_url":`), 0600)
	expectConfigurationFailure(t, runConfigurationCLI(t, binary, malformedConfig, "trust", "list", "--json"), "trust list", "configuration_error")
	protectedPath := filepath.Join(configDir, "insecure.json")
	writeConfigurationCLIFile(t, protectedPath, []byte(`{"database_url":"host=/tmp/no-socket user=tlsbeacon_runtime dbname=missing sslmode=disable"}`), 0644)
	expectConfigurationFailure(t, runConfigurationCLI(t, binary, protectedPath, "policy", "show", "--json"), "policy show", "permission_error")
	unavailablePath := writeConfigurationCLIConfigNamed(t, configDir, "unavailable.json", "host=/no-such-tlsbeacon-socket user=tlsbeacon_runtime password=fixture-secret-sentinel dbname=unavailable sslmode=disable")
	expectConfigurationFailure(t, runConfigurationCLI(t, binary, unavailablePath, "trust", "list", "--json"), "trust list", "storage_error")

	missingPolicyDB, _ := newFixtureDatabase(t, true)
	missingPolicyConfig := writeConfigurationCLIConfigNamed(t, configDir, "missing-policy.json", configurationCLIDSN(t, missingPolicyDB))
	expectConfigurationFailure(t, runConfigurationCLI(t, binary, missingPolicyConfig, "policy", "show", "--json"), "policy show", "policy_configuration_error")

	conflictA := `{"version":1,"rules":[{"cidr":"127.0.0.0/8","port":8443,"acknowledgements":["loopback"]}]}`
	conflictB := `{"version":1,"rules":[{"cidr":"127.0.0.0/8","port":9443,"acknowledgements":["loopback"]}]}`
	conflictC := `{"version":1,"rules":[{"cidr":"127.0.0.0/8","port":10443,"acknowledgements":["loopback"]}]}`
	protectedFixture(t)
	lock, err := setup.Begin(context.Background())
	if err != nil {
		t.Fatal("cannot begin conflict barrier")
	}
	defer lock.Rollback(context.Background())
	var lockedValue []byte
	protectedFixture(t)
	if err := lock.QueryRow(context.Background(), `SELECT value FROM tlsbeacon_registry.records WHERE kind='policy' AND key='current' FOR UPDATE`).Scan(&lockedValue); err != nil {
		t.Fatal("cannot hold policy record barrier")
	}
	policyBodies := []string{conflictA, conflictB, conflictC}
	commands := make([]*exec.Cmd, len(policyBodies))
	outputs := make([]bytes.Buffer, len(policyBodies))
	errorsOut := make([]bytes.Buffer, len(policyBodies))
	for i, body := range policyBodies {
		commands[i] = startConfigurationCLI(t, binary, configPath, "policy", "set", "--rules-json", body, "--json")
		commands[i].Stdout = &outputs[i]
		commands[i].Stderr = &errorsOut[i]
		if err := commands[i].Start(); err != nil {
			t.Fatal("cannot start concurrent policy command")
		}
	}
	observer := connectFixture(t, protectedFixture(t), "tlsbeacon_runtime", name)
	defer observer.Close(context.Background())
	deadline := time.Now().Add(20 * time.Second)
	waiting := false
	for time.Now().Before(deadline) {
		protectedFixture(t)
		var count int
		if err := observer.QueryRow(context.Background(), `SELECT count(*) FROM pg_stat_activity WHERE application_name='tlsbeacon_chunk11' AND wait_event_type='Lock' AND state='active'`).Scan(&count); err != nil {
			t.Fatal("cannot observe policy conflict barrier")
		}
		if count == len(commands) {
			waiting = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("concurrent CLI policy writes did not all reach the registry lock")
	}
	protectedFixture(t)
	if err := lock.Commit(context.Background()); err != nil {
		t.Fatal("cannot release policy conflict barrier")
	}
	codes := make([]int, len(commands))
	for i, cmd := range commands {
		err := cmd.Wait()
		if err == nil {
			codes[i] = 0
			continue
		}
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("concurrent policy process failed: %v", err)
		}
		codes[i] = exit.ExitCode()
	}
	successes, conflicts := 0, 0
	for i, code := range codes {
		result := configurationCLIResult{code: code, stdout: outputs[i].String(), stderr: errorsOut[i].String()}
		if code == 0 {
			data := expectConfigurationSuccess(t, result, "policy set")
			if data["result"] != "updated" {
				t.Fatalf("concurrent policy update result = %#v", data["result"])
			}
			successes++
		} else {
			expectConfigurationFailure(t, result, "policy set", "revision_conflict")
			conflicts++
		}
	}
	if successes != 1 || conflicts != 2 {
		t.Fatalf("concurrent CLI results: successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestConfigurationCLIValueCanEqualGlobalJSONFlag(t *testing.T) {
	binary := buildConfigurationCLI(t)
	name, _ := newFixtureDatabase(t, true)
	configDir := t.TempDir()
	configPath := writeConfigurationCLIConfig(t, configDir, configurationCLIDSN(t, name))
	rootPath := filepath.Join(configDir, "value-test-root.pem")
	writeConfigurationCLIFile(t, rootPath, fixtureCA(t, 1901), 0600)

	imported := runConfigurationCLI(t, binary, configPath, "trust", "import", "--mode", "custom", "--source", rootPath, "--json")
	importData := expectConfigurationSuccess(t, imported, "trust import")
	profile := configurationCLIObject(t, importData["profile"], "profile")
	profileID := profile["id"].(string)
	versions := profile["versions"].([]any)
	if len(versions) != 1 {
		t.Fatalf("trust import versions = %#v", versions)
	}
	versionID := configurationCLIObject(t, versions[0], "version")["id"].(string)

	common := []string{"--host", "value-no-dns.invalid", "--port", "443", "--identity", "value-no-dns.invalid", "--trust-profile", profileID, "--trust-version", versionID, "--interval", "1h", "--warning", "30d", "--critical", "7d", "--enabled", "true"}
	separate := append([]string{"--json", "endpoint", "add", "--label", "--json"}, common...)
	separateResult := expectConfigurationSuccess(t, runConfigurationCLI(t, binary, configPath, separate...), "endpoint add")
	if configurationCLIObject(t, separateResult["endpoint"], "separate label endpoint")["label"] != "--json" {
		t.Fatal("separate command-option value was not stored as the label")
	}
	inline := append([]string{"endpoint", "add", "--label=--json"}, common...)
	inline = append(inline, "--json")
	inlineResult := expectConfigurationSuccess(t, runConfigurationCLI(t, binary, configPath, inline...), "endpoint add")
	if configurationCLIObject(t, inlineResult["endpoint"], "inline label endpoint")["label"] != "--json" {
		t.Fatal("inline command-option value was not stored as the label")
	}

	db, err := Open(context.Background(), fixtureConnection(t, name))
	if err != nil {
		t.Fatal("cannot reopen fixture registry for label read-back")
	}
	defer db.Close(context.Background())
	records, err := db.ListEndpoints(context.Background())
	if err != nil || len(records) != 2 || records[0].Values.Label != "--json" || records[1].Values.Label != "--json" {
		t.Fatalf("stored command-option labels = %#v, error=%v", records, err)
	}
}
