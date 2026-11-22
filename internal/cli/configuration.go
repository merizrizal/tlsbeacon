package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/merizrizal/tlsbeacon/internal/config"
	"github.com/merizrizal/tlsbeacon/internal/endpoint"
	"github.com/merizrizal/tlsbeacon/internal/policy"
	"github.com/merizrizal/tlsbeacon/internal/registry"
	"github.com/merizrizal/tlsbeacon/internal/trust"
)

type commandOptions map[string][]string

type endpointView struct {
	RegistrationID            string `json:"registration_id"`
	MonitoringID              string `json:"monitoring_id"`
	ConfigurationRevision     uint64 `json:"configuration_revision"`
	CreatedAt                 string `json:"created_at"`
	UpdatedAt                 string `json:"updated_at"`
	Label                     string `json:"label"`
	ConnectionHost            string `json:"connection_host"`
	ConnectionHostCanonical   string `json:"connection_host_canonical"`
	ConnectionScope           string `json:"connection_scope"`
	Port                      int    `json:"port"`
	ExpectedIdentity          string `json:"expected_identity"`
	ExpectedIdentityCanonical string `json:"expected_identity_canonical"`
	ExpectedIdentityType      string `json:"expected_identity_type"`
	TrustProfileID            string `json:"trust_profile_id"`
	TrustVersionID            string `json:"trust_version_id"`
	TrustMaterialSHA256       string `json:"trust_material_sha256"`
	IntervalNS                string `json:"interval_ns"`
	WarningNS                 string `json:"warning_ns"`
	CriticalNS                string `json:"critical_ns"`
	Enabled                   bool   `json:"enabled"`
	Freshness                 any    `json:"freshness"`
	FreshnessReason           string `json:"freshness_reason"`
}

type trustVersionView struct {
	ID             string   `json:"id"`
	Mode           string   `json:"mode"`
	MaterialSHA256 string   `json:"material_sha256"`
	SourceSHA256   []string `json:"source_sha256"`
}

type trustProfileView struct {
	ID       string             `json:"id"`
	Versions []trustVersionView `json:"versions"`
}

type policyRuleInput struct {
	CIDR             string        `json:"cidr"`
	Port             int           `json:"port"`
	Deny             bool          `json:"deny,omitempty"`
	Acknowledge      *policy.Class `json:"acknowledge,omitempty"`
	Acknowledgements []string      `json:"acknowledgements,omitempty"`
	Target           string        `json:"target,omitempty"`
	Interface        string        `json:"interface,omitempty"`
}

type policyDocument struct {
	Version        *int               `json:"version"`
	Classification *string            `json:"classification,omitempty"`
	Rules          *[]policyRuleInput `json:"rules"`
	Metadata       *[]string          `json:"metadata,omitempty"`
}

type policyRuleView struct {
	CIDR             string   `json:"cidr"`
	Port             int      `json:"port"`
	Deny             bool     `json:"deny"`
	Acknowledgements []string `json:"acknowledgements"`
	Target           string   `json:"target,omitempty"`
	Interface        string   `json:"interface,omitempty"`
}

type policyView struct {
	Version        int              `json:"version"`
	Classification string           `json:"classification"`
	Rules          []policyRuleView `json:"rules"`
	Metadata       []string         `json:"metadata"`
}

func parseGlobalArguments(args []string) (bool, string, []string, *responseError) {
	jsonOutput := false
	configPath := ""
	configSeen := false
	malformed := false
	commandValuePending := false
	commandArgs := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if commandValuePending {
			commandArgs = append(commandArgs, arg)
			commandValuePending = false
			continue
		}
		if arg == "--json" {
			jsonOutput = true
			continue
		}
		if arg == "--config" {
			if configSeen {
				malformed = true
			}
			configSeen = true
			if i+1 == len(args) {
				malformed = true
				continue
			}
			i++
			if args[i] == "" {
				malformed = true
				continue
			}
			if configPath == "" && !malformed {
				configPath = args[i]
			}
			continue
		}
		if strings.HasPrefix(arg, "--config=") {
			if configSeen {
				malformed = true
			} else {
				configSeen = true
				configPath = strings.TrimPrefix(arg, "--config=")
				if configPath == "" {
					malformed = true
				}
			}
			continue
		}
		commandArgs = append(commandArgs, arg)
		command := canonicalCommand(commandArgs)
		allowed, _ := commandOptionSpec(command)
		name, _, inline := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if strings.HasPrefix(arg, "--") && arg != "--" && allowed[name] && !inline {
			commandValuePending = true
		}
	}
	if malformed {
		return jsonOutput, "", commandArgs, invalidInputFailure()
	}
	return jsonOutput, configPath, commandArgs, nil
}

func invalidInputFailure() *responseError {
	return &responseError{Code: "invalid_input", Message: "The command arguments are invalid.", Action: "Check the command name and required options, then run tlsbeacon --help."}
}

func unavailableInspectFailure() *responseError {
	return &responseError{Code: "invalid_input", Message: "Manual inspection is not available yet.", Action: "Use the policy, trust and endpoint configuration commands."}
}

func writeFailure(command string, jsonOutput bool, stdout, stderr io.Writer, failure *responseError) int {
	if failure == nil {
		failure = &responseError{Code: "internal_error", Message: "The command could not be completed safely.", Action: "Check the registry state before retrying."}
	}
	if jsonOutput {
		encoded, err := json.Marshal(envelope{schemaVersion, command, "execution_failed", nil, failure})
		if err != nil {
			return reportOutputFailure(stderr, failure.Code == "commit_outcome_unknown")
		}
		writeCommandOutput(stdout, stderr, append(encoded, '\n'), failure.Code == "commit_outcome_unknown")
		return 2
	}
	_, _ = fmt.Fprintf(stderr, "%s: %s %s\n", failure.Code, failure.Message, failure.Action)
	return 2
}

func reportOutputFailure(stderr io.Writer, mutation bool) int {
	message := "output_error: the command response could not be delivered."
	if mutation {
		message += " The change may already be committed; list and reconcile the relevant records or current policy before deciding whether to retry. If a generated identifier was not delivered, reconcile by effective values; labels are not unique. Do not blindly repeat a creation."
	} else {
		message += " Check the output stream before retrying the read."
	}
	_, _ = fmt.Fprintln(stderr, message)
	return 2
}

func writeCommandOutput(stdout, stderr io.Writer, content []byte, mutation bool) int {
	n, err := stdout.Write(content)
	if err == nil && n == len(content) {
		return 0
	}
	return reportOutputFailure(stderr, mutation)
}

func writeConfigurationSuccess(command string, jsonOutput bool, stdout, stderr io.Writer, data any, human string, mutation bool) int {
	var content []byte
	if jsonOutput {
		encoded, err := json.Marshal(envelope{schemaVersion, command, "success", data, nil})
		if err != nil {
			return reportOutputFailure(stderr, mutation)
		}
		content = append(encoded, '\n')
	} else {
		content = []byte(human)
	}
	return writeCommandOutput(stdout, stderr, content, mutation)
}

func commandOptionSpec(command string) (map[string]bool, map[string]bool) {
	allowed := map[string]bool{}
	repeated := map[string]bool{}
	add := func(names ...string) {
		for _, name := range names {
			allowed[name] = true
		}
	}
	switch command {
	case "policy set":
		add("rules-json")
	case "policy show", "trust list", "endpoint list":
	case "trust import":
		add("mode", "source")
		repeated["source"] = true
	case "trust refresh":
		add("id", "mode", "source")
		repeated["source"] = true
	case "endpoint add":
		add("label", "host", "port", "identity", "trust-profile", "trust-version", "interval", "warning", "critical", "enabled")
	case "endpoint show", "endpoint enable", "endpoint disable":
		add("id")
	case "endpoint edit":
		add("id", "label", "host", "port", "identity", "trust-profile", "trust-version", "interval", "warning", "critical", "enabled")
	}
	return allowed, repeated
}

func parseCommandOptions(command string, args []string) (commandOptions, *responseError) {
	allowed, repeated := commandOptionSpec(command)
	options := make(commandOptions)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") || arg == "--" {
			return nil, invalidInputFailure()
		}
		name, value, inline := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if !allowed[name] {
			return nil, invalidInputFailure()
		}
		if !inline {
			if i+1 == len(args) {
				return nil, invalidInputFailure()
			}
			i++
			value = args[i]
		}
		if _, exists := options[name]; exists && !repeated[name] {
			return nil, invalidInputFailure()
		}
		options[name] = append(options[name], value)
	}
	return options, nil
}

func (options commandOptions) one(name string) (string, bool) {
	values, ok := options[name]
	if !ok {
		return "", false
	}
	return values[0], true
}

func (options commandOptions) required(name string) (string, *responseError) {
	value, ok := options.one(name)
	if !ok || value == "" {
		return "", invalidInputFailure()
	}
	return value, nil
}

func (options commandOptions) optionalDuration(name string) (*time.Duration, *responseError) {
	value, ok := options.one(name)
	if !ok {
		return nil, nil
	}
	parsed, err := endpoint.ParseDuration(value)
	if err != nil {
		return nil, invalidInputFailure()
	}
	return &parsed, nil
}

func parseBoolean(value string) (bool, bool) {
	switch value {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func parsePolicyInput(raw string) (policy.Policy, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document policyDocument
	if decoder.Decode(&document) != nil || document.Version == nil || document.Rules == nil {
		return policy.Policy{}, errors.New("invalid policy input")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || document.Classification != nil {
		return policy.Policy{}, errors.New("invalid policy input")
	}
	metadata := []string{}
	if document.Metadata != nil {
		metadata = *document.Metadata
	}
	rules := make([]policy.Rule, 0, len(*document.Rules))
	for _, input := range *document.Rules {
		acknowledgements, ok := parseAcknowledgements(input)
		if !ok {
			return policy.Policy{}, errors.New("invalid policy input")
		}
		rules = append(rules, policy.Rule{CIDR: input.CIDR, Port: input.Port, Deny: input.Deny, Acknowledge: acknowledgements, Target: input.Target, Interface: input.Interface})
	}
	return policy.New(&policy.Input{Version: *document.Version, Rules: rules, Metadata: metadata})
}

func parseAcknowledgements(input policyRuleInput) (policy.Class, bool) {
	if input.Acknowledge != nil && len(input.Acknowledgements) != 0 {
		return 0, false
	}
	if input.Acknowledge != nil {
		return *input.Acknowledge, true
	}
	classes := map[string]policy.Class{
		"private": policy.Private, "loopback": policy.Loopback, "link-local": policy.LinkLocal,
		"special-use": policy.SpecialUse, "metadata": policy.Metadata,
	}
	var result policy.Class
	for _, name := range input.Acknowledgements {
		class, ok := classes[name]
		if !ok {
			return 0, false
		}
		result |= class
	}
	return result, true
}

func policyViewFrom(value policy.Policy) (policyView, error) {
	snapshot, err := value.Snapshot()
	if err != nil {
		return policyView{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(snapshot)))
	decoder.DisallowUnknownFields()
	var document policyDocument
	if decoder.Decode(&document) != nil || document.Version == nil || document.Rules == nil || document.Classification == nil || *document.Classification == "" {
		return policyView{}, errors.New("invalid stored policy")
	}
	metadata := []string{}
	if document.Metadata != nil {
		metadata = *document.Metadata
	}
	view := policyView{Version: *document.Version, Classification: *document.Classification, Rules: make([]policyRuleView, 0, len(*document.Rules)), Metadata: metadata}
	for _, input := range *document.Rules {
		acknowledgements, ok := parseAcknowledgements(input)
		if !ok {
			return policyView{}, errors.New("invalid stored policy")
		}
		view.Rules = append(view.Rules, policyRuleView{CIDR: input.CIDR, Port: input.Port, Deny: input.Deny, Acknowledgements: acknowledgementNames(acknowledgements), Target: input.Target, Interface: input.Interface})
	}
	return view, nil
}

func acknowledgementNames(classes policy.Class) []string {
	result := make([]string, 0, 5)
	for _, item := range []struct {
		name  string
		class policy.Class
	}{{"private", policy.Private}, {"loopback", policy.Loopback}, {"link-local", policy.LinkLocal}, {"special-use", policy.SpecialUse}, {"metadata", policy.Metadata}} {
		if classes&item.class != 0 {
			result = append(result, item.name)
		}
	}
	return result
}

func failureFromError(err error) *responseError {
	var configFailure *config.Error
	if errors.As(err, &configFailure) {
		return &responseError{Code: configFailure.Code, Message: configFailure.Message, Action: configFailure.Action}
	}
	var registryFailure *registry.Error
	if errors.As(err, &registryFailure) {
		return &responseError{Code: registryFailure.Code, Message: registryFailure.Message, Action: registryFailure.Action}
	}
	return &responseError{Code: "internal_error", Message: "The command could not be completed safely.", Action: "Check the registry state before retrying."}
}

func parseConfiguredDatabaseURL(databaseURL string) (*pgx.ConnConfig, func(), error) {
	qualifiedURL, cleanup, err := config.QualifyDatabaseSources(databaseURL)
	if err != nil {
		return nil, nil, err
	}
	allowedKeys, err := config.DatabaseConnectionKeys(qualifiedURL)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	connection, err := pgx.ParseConfigWithOptions(qualifiedURL, pgx.ParseConfigOptions{
		ParseConfigOptions: pgconn.ParseConfigOptions{ConnStringAllowedKeys: allowedKeys},
	})
	if err != nil {
		cleanup()
		return nil, nil, &config.Error{
			Code:    "configuration_error",
			Message: "The selected database configuration is invalid.",
			Action:  "Check the protected database_url value without sharing credentials.",
		}
	}
	return connection, cleanup, nil
}

func openConfiguredRegistry(path string) (*registry.DB, context.Context, context.CancelFunc, func(), *responseError) {
	local, err := config.Load(path)
	if err != nil {
		return nil, nil, nil, nil, failureFromError(err)
	}
	connection, cleanup, err := parseConfiguredDatabaseURL(local.DatabaseURL)
	if err != nil {
		return nil, nil, nil, nil, failureFromError(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	db, err := registry.Open(ctx, connection)
	if err != nil {
		cancel()
		cleanup()
		return nil, nil, nil, nil, failureFromError(err)
	}
	return db, ctx, cancel, cleanup, nil
}

func runConfiguration(command, configPath string, args []string, jsonOutput bool, stdout, stderr io.Writer) int {
	options, failure := parseCommandOptions(command, args)
	if failure != nil {
		return writeFailure(command, jsonOutput, stdout, stderr, failure)
	}
	var candidatePolicy policy.Policy
	if command == "policy set" {
		raw, err := options.required("rules-json")
		if err != nil {
			return writeFailure(command, jsonOutput, stdout, stderr, err)
		}
		parsed, parseErr := parsePolicyInput(raw)
		if parseErr != nil {
			return writeFailure(command, jsonOutput, stdout, stderr, invalidInputFailure())
		}
		candidatePolicy = parsed
	}
	var material trust.Material
	if command == "trust import" || command == "trust refresh" {
		modeText, err := options.required("mode")
		if err != nil {
			return writeFailure(command, jsonOutput, stdout, stderr, err)
		}
		mode := trust.Mode(modeText)
		if mode != trust.System && mode != trust.Custom || len(options["source"]) == 0 {
			return writeFailure(command, jsonOutput, stdout, stderr, invalidInputFailure())
		}
		var importErr error
		material, importErr = trust.Import(mode, options["source"])
		if importErr != nil {
			return writeFailure(command, jsonOutput, stdout, stderr, &responseError{Code: "trust_configuration_error", Message: "The selected trust source is invalid or unsafe.", Action: "Check the protected source path and provide valid CA certificates."})
		}
	}
	db, ctx, cancel, cleanup, failure := openConfiguredRegistry(configPath)
	if failure != nil {
		return writeFailure(command, jsonOutput, stdout, stderr, failure)
	}
	defer cleanup()
	defer cancel()
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		_ = db.Close(closeCtx)
	}()
	data, human, mutation, failure := executeConfiguration(ctx, db, command, options, candidatePolicy, material)
	if failure != nil {
		return writeFailure(command, jsonOutput, stdout, stderr, failure)
	}
	return writeConfigurationSuccess(command, jsonOutput, stdout, stderr, data, human, mutation)
}

func executeConfiguration(ctx context.Context, db *registry.DB, command string, options commandOptions, candidatePolicy policy.Policy, material trust.Material) (any, string, bool, *responseError) {
	switch command {
	case "policy set":
		result, err := db.ReplacePolicyWithResult(ctx, candidatePolicy)
		if err != nil {
			return nil, "", false, failureFromError(err)
		}
		view, err := policyViewFrom(candidatePolicy)
		if err != nil {
			return nil, "", false, failureFromError(err)
		}
		name := "updated"
		if !result.Changed {
			name = "unchanged"
		} else if result.Created {
			name = "created"
		}
		digest, _ := candidatePolicy.Digest()
		body := map[string]any{"result": name, "revision_id": result.Revision.ID, "digest": hex.EncodeToString(digest[:]), "policy": view}
		return body, humanPolicy(name, result.Revision.ID, digest, view), true, nil
	case "policy show":
		revision, stored, err := db.ReadPolicy(ctx)
		if err != nil {
			var missing *registry.Error
			if errors.As(err, &missing) && missing.Code == "not_found" {
				return nil, "", false, &responseError{Code: "policy_configuration_error", Message: "No destination policy is configured.", Action: "Set an explicit policy before attempting an inspection."}
			}
			return nil, "", false, failureFromError(err)
		}
		view, err := policyViewFrom(stored)
		if err != nil {
			return nil, "", false, failureFromError(err)
		}
		digest, ok := stored.Digest()
		if !ok {
			return nil, "", false, failureFromError(errors.New("invalid policy"))
		}
		body := map[string]any{"revision_id": revision.ID, "digest": hex.EncodeToString(digest[:]), "policy": view}
		return body, humanPolicy("", revision.ID, digest, view), false, nil
	case "trust import":
		profile, err := db.ImportTrust(ctx, material)
		if err != nil {
			return nil, "", false, failureFromError(err)
		}
		view := trustProfileViewFrom(profile)
		return map[string]any{"result": "created", "profile": view}, humanTrust("created", view), true, nil
	case "trust refresh":
		id, failure := options.required("id")
		if failure != nil {
			return nil, "", false, failure
		}
		profile, changed, err := db.RefreshTrust(ctx, id, material)
		if err != nil {
			return nil, "", false, failureFromError(err)
		}
		result := "unchanged"
		if changed {
			result = "updated"
		}
		view := trustProfileViewFrom(profile)
		return map[string]any{"result": result, "profile": view}, humanTrust(result, view), true, nil
	case "trust list":
		profiles, err := db.ListTrust(ctx)
		if err != nil {
			return nil, "", false, failureFromError(err)
		}
		views := make([]trustProfileView, 0, len(profiles))
		for _, profile := range profiles {
			views = append(views, trustProfileViewFrom(profile))
		}
		return map[string]any{"profiles": views}, humanTrustList(views), false, nil
	case "endpoint add":
		return addEndpoint(ctx, db, options)
	case "endpoint list":
		records, err := db.ListEndpoints(ctx)
		if err != nil {
			return nil, "", false, failureFromError(err)
		}
		views := make([]endpointView, 0, len(records))
		for _, record := range records {
			views = append(views, endpointViewFrom(record))
		}
		return map[string]any{"endpoints": views}, humanEndpoints("", views), false, nil
	case "endpoint show":
		id, failure := options.required("id")
		if failure != nil {
			return nil, "", false, failure
		}
		record, err := db.ShowEndpoint(ctx, id)
		if err != nil {
			return nil, "", false, failureFromError(err)
		}
		view := endpointViewFrom(record)
		return map[string]any{"endpoint": view}, humanEndpoints("", []endpointView{view}), false, nil
	case "endpoint edit":
		return editEndpoint(ctx, db, options)
	case "endpoint enable", "endpoint disable":
		id, failure := options.required("id")
		if failure != nil {
			return nil, "", false, failure
		}
		var record registry.EndpointRecord
		var changed bool
		var err error
		if command == "endpoint enable" {
			record, changed, err = db.EnableEndpoint(ctx, id)
		} else {
			record, changed, err = db.DisableEndpoint(ctx, id)
		}
		if err != nil {
			return nil, "", false, failureFromError(err)
		}
		result := "unchanged"
		if changed {
			result = "updated"
		}
		view := endpointViewFrom(record)
		return map[string]any{"result": result, "endpoint": view}, humanEndpoints(result, []endpointView{view}), true, nil
	}
	return nil, "", false, invalidInputFailure()
}

func addEndpoint(ctx context.Context, db *registry.DB, options commandOptions) (any, string, bool, *responseError) {
	label, failure := options.required("label")
	if failure != nil {
		return nil, "", false, failure
	}
	host, failure := options.required("host")
	if failure != nil {
		return nil, "", false, failure
	}
	identity, failure := options.required("identity")
	if failure != nil {
		return nil, "", false, failure
	}
	portText, failure := options.required("port")
	if failure != nil {
		return nil, "", false, failure
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, "", false, invalidInputFailure()
	}
	profile, failure := options.required("trust-profile")
	if failure != nil {
		return nil, "", false, failure
	}
	version, failure := options.required("trust-version")
	if failure != nil {
		return nil, "", false, failure
	}
	selection, failure := selectedTrust(ctx, db, profile, version)
	if failure != nil {
		return nil, "", false, failure
	}
	interval, failure := options.optionalDuration("interval")
	if failure != nil {
		return nil, "", false, failure
	}
	warning, failure := options.optionalDuration("warning")
	if failure != nil {
		return nil, "", false, failure
	}
	critical, failure := options.optionalDuration("critical")
	if failure != nil {
		return nil, "", false, failure
	}
	var enabled *bool
	if raw, ok := options.one("enabled"); ok {
		parsed, valid := parseBoolean(raw)
		if !valid {
			return nil, "", false, invalidInputFailure()
		}
		enabled = &parsed
	}
	record, err := db.AddEndpoint(ctx, endpoint.CreateInput{Label: label, Host: host, Port: port, Identity: identity, Trust: selection, Interval: interval, Warning: warning, Critical: critical, Enabled: enabled})
	if err != nil {
		return nil, "", false, failureFromError(err)
	}
	view := endpointViewFrom(record)
	return map[string]any{"result": "created", "endpoint": view}, humanEndpoints("created", []endpointView{view}), true, nil
}

func editEndpoint(ctx context.Context, db *registry.DB, options commandOptions) (any, string, bool, *responseError) {
	id, failure := options.required("id")
	if failure != nil {
		return nil, "", false, failure
	}
	patch := endpoint.Patch{}
	if value, ok := options.one("label"); ok {
		patch.Label = &value
	}
	if value, ok := options.one("host"); ok {
		patch.Host = &value
	}
	if value, ok := options.one("identity"); ok {
		patch.Identity = &value
	}
	if value, ok := options.one("port"); ok {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return nil, "", false, invalidInputFailure()
		}
		patch.Port = &parsed
	}
	profile, hasProfile := options.one("trust-profile")
	version, hasVersion := options.one("trust-version")
	if hasProfile != hasVersion {
		return nil, "", false, invalidInputFailure()
	}
	if hasProfile {
		selection, failure := selectedTrust(ctx, db, profile, version)
		if failure != nil {
			return nil, "", false, failure
		}
		patch.Trust = &selection
	}
	var err *responseError
	patch.Interval, err = options.optionalDuration("interval")
	if err != nil {
		return nil, "", false, err
	}
	patch.Warning, err = options.optionalDuration("warning")
	if err != nil {
		return nil, "", false, err
	}
	patch.Critical, err = options.optionalDuration("critical")
	if err != nil {
		return nil, "", false, err
	}
	if raw, ok := options.one("enabled"); ok {
		parsed, valid := parseBoolean(raw)
		if !valid {
			return nil, "", false, invalidInputFailure()
		}
		patch.Enabled = &parsed
	}
	record, changed, updateErr := db.PatchEndpoint(ctx, id, patch)
	if updateErr != nil {
		return nil, "", false, failureFromError(updateErr)
	}
	result := "unchanged"
	if changed {
		result = "updated"
	}
	view := endpointViewFrom(record)
	return map[string]any{"result": result, "endpoint": view}, humanEndpoints(result, []endpointView{view}), true, nil
}

func selectedTrust(ctx context.Context, db *registry.DB, profileID, versionID string) (endpoint.TrustSelection, *responseError) {
	profile, err := db.ReadTrust(ctx, profileID)
	if err != nil {
		var missing *registry.Error
		if errors.As(err, &missing) && missing.Code == "not_found" {
			return endpoint.TrustSelection{}, &responseError{Code: "trust_configuration_error", Message: "The selected trust profile does not exist.", Action: "Import a profile and select one of its stored versions."}
		}
		return endpoint.TrustSelection{}, failureFromError(err)
	}
	for _, version := range profile.Versions {
		if version.ID == versionID {
			return endpoint.TrustSelection{Profile: profile.ID, Version: version.ID, Material: hex.EncodeToString(version.Digest[:])}, nil
		}
	}
	return endpoint.TrustSelection{}, &responseError{Code: "trust_configuration_error", Message: "The selected trust version does not belong to this profile.", Action: "Select a version listed for the requested profile."}
}

func endpointViewFrom(record registry.EndpointRecord) endpointView {
	value := record.Values
	return endpointView{
		RegistrationID: record.RegistrationID, MonitoringID: record.MonitoringID, ConfigurationRevision: record.ConfigurationRevision,
		CreatedAt: record.CreatedAt.UTC().Format(time.RFC3339Nano), UpdatedAt: record.UpdatedAt.UTC().Format(time.RFC3339Nano),
		Label: value.Label, ConnectionHost: value.Host.Original, ConnectionHostCanonical: canonicalName(value.Host), ConnectionScope: value.Host.Scope,
		Port: value.Port, ExpectedIdentity: value.Identity.Original, ExpectedIdentityCanonical: canonicalName(value.Identity),
		ExpectedIdentityType: identityType(value.Identity), TrustProfileID: value.Trust.Profile, TrustVersionID: value.Trust.Version,
		TrustMaterialSHA256: value.Trust.Material, IntervalNS: strconv.FormatInt(int64(value.Interval), 10),
		WarningNS: strconv.FormatInt(int64(value.Warning), 10), CriticalNS: strconv.FormatInt(int64(value.Critical), 10),
		Enabled: value.Enabled, Freshness: nil, FreshnessReason: "inspection_history_not_retained",
	}
}

func canonicalName(value endpoint.Name) string {
	if value.IP.IsValid() {
		return value.IP.String()
	}
	return value.DNS
}

func identityType(value endpoint.Name) string {
	if value.IP.IsValid() {
		return "ip"
	}
	return "dns"
}

func trustProfileViewFrom(profile registry.TrustProfile) trustProfileView {
	view := trustProfileView{ID: profile.ID, Versions: make([]trustVersionView, 0, len(profile.Versions))}
	for _, version := range profile.Versions {
		sources := make([]string, 0, len(version.Sources))
		for _, digest := range version.Sources {
			sources = append(sources, hex.EncodeToString(digest[:]))
		}
		view.Versions = append(view.Versions, trustVersionView{ID: version.ID, Mode: string(version.Mode), MaterialSHA256: hex.EncodeToString(version.Digest[:]), SourceSHA256: sources})
	}
	return view
}

func humanEndpoints(result string, endpoints []endpointView) string {
	var output strings.Builder
	if result != "" {
		fmt.Fprintf(&output, "result: %s\n", result)
	}
	fmt.Fprintf(&output, "endpoints: %d\n", len(endpoints))
	for _, value := range endpoints {
		fmt.Fprintf(&output, "registration_id: %s\nmonitoring_id: %s\nconfiguration_revision: %d\n", value.RegistrationID, value.MonitoringID, value.ConfigurationRevision)
		fmt.Fprintf(&output, "created_at: %s\nupdated_at: %s\nlabel: %s\n", value.CreatedAt, value.UpdatedAt, strconv.Quote(value.Label))
		fmt.Fprintf(&output, "connection_host: %s\nconnection_host_canonical: %s\nconnection_scope: %s\nport: %d\n", strconv.Quote(value.ConnectionHost), strconv.Quote(value.ConnectionHostCanonical), strconv.Quote(value.ConnectionScope), value.Port)
		fmt.Fprintf(&output, "expected_identity: %s\nexpected_identity_canonical: %s\nexpected_identity_type: %s\n", strconv.Quote(value.ExpectedIdentity), strconv.Quote(value.ExpectedIdentityCanonical), value.ExpectedIdentityType)
		fmt.Fprintf(&output, "trust_profile_id: %s\ntrust_version_id: %s\ntrust_material_sha256: %s\n", value.TrustProfileID, value.TrustVersionID, value.TrustMaterialSHA256)
		fmt.Fprintf(&output, "interval_ns: %s\nwarning_ns: %s\ncritical_ns: %s\nenabled: %t\nfreshness: null\nfreshness_reason: %s\n", value.IntervalNS, value.WarningNS, value.CriticalNS, value.Enabled, value.FreshnessReason)
	}
	return output.String()
}

func humanTrust(result string, profile trustProfileView) string {
	var output strings.Builder
	if result != "" {
		fmt.Fprintf(&output, "result: %s\n", result)
	}
	fmt.Fprintf(&output, "profile_id: %s\nversions: %d\n", profile.ID, len(profile.Versions))
	for _, version := range profile.Versions {
		fmt.Fprintf(&output, "version_id: %s\nmode: %s\nmaterial_sha256: %s\n", version.ID, version.Mode, version.MaterialSHA256)
		for _, source := range version.SourceSHA256 {
			fmt.Fprintf(&output, "source_sha256: %s\n", source)
		}
	}
	return output.String()
}

func humanTrustList(profiles []trustProfileView) string {
	var output strings.Builder
	fmt.Fprintf(&output, "profiles: %d\n", len(profiles))
	for _, profile := range profiles {
		output.WriteString(humanTrust("", profile))
	}
	return output.String()
}

func humanPolicy(result, revision string, digest [32]byte, value policyView) string {
	var output strings.Builder
	if result != "" {
		fmt.Fprintf(&output, "result: %s\n", result)
	}
	fmt.Fprintf(&output, "revision_id: %s\ndigest: %s\n", revision, hex.EncodeToString(digest[:]))
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err == nil {
		fmt.Fprintf(&output, "policy: %s\n", encoded)
	}
	return output.String()
}
