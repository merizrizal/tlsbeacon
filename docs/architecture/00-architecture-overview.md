# TLSBeacon architecture overview and D1 technical baseline

**Status:** The owner reviewed, approved and accepted the current partial Compose reconciliation. The reconciliation remains incomplete: native-only, optional-fixture and stale ladder statements elsewhere still require correction and source/plan drift assessment. This document remains subordinate to the PRD, approved ADRs and task contracts, and is not execution authority.

**Partial Compose reconciliation approval:** The owner explicitly reviewed, approved and accepted the current reconciliation in the conversation. Before this approval record, the uncommitted overview SHA-256 was `dca96c80345ab6ae3f5a36c695f47e0bbd6175cecef865d575eb7410b448452c`, on branch `phase-01-delivery-1-manual-inspection` at HEAD `787b821a83d1754540bc1460041c80895b6596f2`, tree `ad62556f71744e93a721a47fa95f6d56cb7de2f1`. This identifies the approved bytes before this record, not the resulting file hash. Approval does not establish reconciliation completeness, independent review, preflight or execution authority.

**Approval record:** Following the independent INITIAL draft specification review, which returned `DRAFT_SPEC_READY` with no substantiated material blocker, the user explicitly confirmed review, approval and acceptance of the documents in the current conversation and requested this approval record. The reviewer's fresh-session separation was user-attested, not independently verified by session identity. Approval covers this overview and the preserved reference copy **as supporting reference material**, not wholesale adoption of the reference proposal's architecture.

**Command-example cleanup approval:** The owner explicitly reviewed, approved and accepted the removal of harness-specific command prefixes in §9 and the paired [D1 execution plan changes](../chunked-implementation/01-delivery-1-manual-inspection-execution-plan.md). At approval, on `phase-01-delivery-1-manual-inspection` at HEAD `0766e7760df658cec62a558a3cd0bd2c0c4b6149`, the overview candidate SHA-256 was `f13aaf264ed8bed0ac35d21ed8d0187805736febd91624e4e092c8e2f5155547` before this approval record was added. This approval does not reconcile the overview with the Compose amendments or authorize preflight or execution.

**Reviewed candidates (historical baseline):** Before this approval-record update, on `main` at HEAD `af5e8dec0fcd60ca3bfa7167132b4157de6779c0`, tree `ed734052ea76fd68fe2816bd20d2e443591df334`, the untracked overview SHA-256 was `54217700bad9ceeb0fbd8111b1d7cf643a88fc75f4bdb1fc714c7e4f5db9b940` and the verbatim reference copy SHA-256 was `25841d4b031382e594f6ecebb46babc52bc0c43db50f4925a7d59736379cf5e9`. The review verdict applies to those candidate bytes, not automatically to this later approval-record update; assess its actual impact and any subsequent material drift.

**Approval boundary:** Acceptance records the overview's practical baseline and its Level 1 conventions and alternatives, not a claim that they are installed, tested or mandatory over equivalent compliant choices. References below to proposed choices describe their design character and unimplemented state, not a pending owner-acceptance gate. The reference copy retains its original historical status and wording without alteration. Approval does not commit files, authorize plan changes, preflight, implementation, provisioning or deployment, or establish any product test result.

**Scope:** Delivery 1 (D1), the manual inspection pilot. Later deliveries are described only by their existing product obligations and explicitly unadopted architectural options. This is neither a new ADR nor an implementation contract, ADS, installation script or execution ladder.

**Evidence date:** 17 November 2026 (UTC).

**Authoring base:** `main`, HEAD `af5e8dec0fcd60ca3bfa7167132b4157de6779c0`, tree `ed734052ea76fd68fe2816bd20d2e443591df334`. Staged, unstaged, untracked and ignored inventories were empty before authoring. The repository contained documentation, license and ignore rules only: no application, module manifest, schema, migrations, tests, CI or deployable artifacts. No existing implementation is accepted as coverage.

## 1. How to use this baseline

The architecture should answer two questions: what D1 is allowed to build, and how its implementation can be organized reproducibly without building future deliveries early.

| Source | Role and precedence |
| --- | --- |
| [PRD v0.2](../prd-v0.2.md) | Current approved product behavior, PD-001–006, FR-001–012 and AC-001–019. PRD v0.1 is historical provenance, not the active baseline |
| [ADR-001](01-adr-001-delivery-1-manual-inspection.md) and [Compose amendment](02-adr-001-amendment-d1-compose.md) | Approved D1 engineering decisions; the amendment governs the Compose topology and supersedes native-only deployment and optional-fixture boundaries |
| [D1 task contract](../tasks/01-delivery-1-manual-inspection-contract.md) and [Compose amendment](../tasks/02-delivery-1-compose-contract-amendment.md) | Exact D1 semantics and mandatory V-01–V-10, plus Compose lifecycle, security and C-V01–C-V05 including appended evidence |
| [Roadmap overview](../implementation-plan/00-implementation-overview.md), [phase 01](../implementation-plan/01-registry-and-safety-foundations.md), [phase 02](../implementation-plan/02-trustworthy-manual-inspection.md) | Approved D1 scope decomposition, not a second technical or execution authority |
| [D1 execution plan](../chunked-implementation/01-delivery-1-manual-inspection-execution-plan.md) | The sole controlling ladder, Chunks 0–30; approval, current affected preflight and execution remain distinct |
| This overview | Owner-accepted explanation and practical Level 1 baseline. It does not supersede the sources above, alter their guarantees or authorize execution |

Existing source documents retain their own approval and historical review provenance. A new overview cannot make old reviews cover different bytes. If a summary here appears inconsistent with a controlling requirement, inspect the complete sources and resolve the affected boundary; never select the more permissive wording.

The [Initial System Architecture Proposal](../proposed-architecture-baseline.md), architecture proposal v0.1 dated 17 November 2026, is preserved verbatim in the repository as accepted supporting reference material; its proposed architecture is not approved wholesale. This overview distills compatible ideas rather than adopting it wholesale. Its daemon/socket, product Compose deployment, mutable policy-file model and broader future repository tree are not adopted by implication. The reference copy retains historical claims, including stale PRD-status wording; its baseline filename does not make it approved or authoritative.

## 2. D1 system shape — existing approved decisions

D1 is one trusted Linux operator using a persistent Compose PostgreSQL configuration registry. The normal one-off CLI probes container-reachable targets; the supported host-run CLI probes host-loopback-only targets. Both use the same enrolled registry. It is a manual pilot, not a continuously running monitoring service or the complete MVP.

```text
Trusted local operator
        |
        v
Host CLI: tlsbeacon
        |
        +--> validate configuration / registry mutations --> PostgreSQL
        |                                                   configuration only
        |
        +--> capture endpoint + selected roots + policy snapshot
                    |
                    +--> release database transaction
                    |
                    v
             authorized numeric dial + bounded TLS observation
                    |
                    v
             independent certificate assessment
                    |
                    v
             human or tlsbeacon.cli.v1 report, exit 0 / 1 / 2
             inspection not retained by the application
```

- The CLI accesses the registry and performs the requested inspection directly. No mandatory daemon, Unix control socket, HTTP API or listening management service is introduced.
- PostgreSQL is the durable source of truth for endpoint configuration, selected trust-profile versions and destination policy. A local file supplies bootstrap connection/path settings, not a competing live endpoint or policy store.
- The approved Compose pilot comprises the PostgreSQL registry and a short-lived one-off CLI; host-run CLI access uses the protected PostgreSQL Unix socket. Cloud provisioning, a database administration platform, systemd packaging and a TLSBeacon daemon are not D1 additions. Full verification uses separate owned disposable Compose fixtures (§8).
- The OS/operator boundary is the authority boundary. Ordinary registry commands must not resolve or contact monitored targets. Explicit `inspect` selects an existing registration; no ad hoc unregistered-target bypass exists.
- Only configuration is durable. No inspection-history, current-monitoring-status, scheduler, condition, event or webhook schema/module is introduced in D1.

These choices preserve ADR-001 §§3, 8–9. PostgreSQL's engineering benefit is transactional consistency, concurrent mutation control and durable related changes; filesystem storage can also be persistent, but substituting it is not an approved Level 1 change.

## 3. Proposed technology and version baseline

### 3.1 Concrete candidates and evidence strength

The table is a proposed qualification baseline, not an installed dependency manifest or an assertion that TLSBeacon already works. Public release/compatibility metadata was retrieved over verified HTTPS; no archive, Go module implementation, database package or container image was installed. References and retrieval limits are in §12.

| Component | Proposed D1 baseline | Observed evidence and remaining limitation |
| --- | --- | --- |
| Language/toolchain | Go `1.27.4` | Official stable download metadata and release history agree; released 10 November 2026. Upstream supports a major release until two newer majors exist. Local `GOTOOLCHAIN=local` version output is `go1.27.4 linux/amd64`. This is not product build evidence |
| Database | PostgreSQL `18.7` | Official GitHub source tag `REL_18_7` and its release notes identify 12 November 2026. PostgreSQL 18 initially released 25 September 2025, within the official five-year major-support policy. Native package availability and an actual server/role/cluster were not established |
| PostgreSQL driver | `github.com/jackc/pgx/v5` `v5.13.0`, native API and explicit parameterized SQL | Module release metadata identifies 11 November 2026 and its `go.mod` declares Go `1.25.0`. Its README describes supported upstream Go/PostgreSQL releases and PostgreSQL 14–18 testing. No combined TLSBeacon compatibility test or vulnerability audit ran |
| DNS normalization | `golang.org/x/net` `v0.62.0`, package `idna` | Module metadata identifies 27 October 2026 and its `go.mod` requires Go `1.26.0`. The proposed toolchain meets that declared minimum; correct non-transitional/STD3 processing still needs V-02 evidence |
| TLS and certificate handling | Selected Go standard library: `crypto/tls`, `crypto/x509`, `net`, `net/netip` | No separate TLS engine is proposed. Partial-handshake capture, cancellation and independent verification behavior must be proven, not inferred from library names |
| CLI/configuration/logging | Standard-library command dispatch and flag parsing; JSON bootstrap configuration through `encoding/json`; `log/slog` when structured diagnostics are needed | Proposed dependency-minimizing conventions, not new command semantics. Preserve task §§4/7; sanitized diagnostics use stderr, never corrupt JSON stdout. No Cobra, YAML parser or logging framework is required initially |
| Qualification environment | Observed Ubuntu `26.04.1 LTS`, Linux `amd64` | Host metadata and architecture were inspected. This is a qualification target, not a new product restriction on other compliant Linux installations. Vendor support dates, native packaging and complete environment behavior remain unverified |

Go `1.26.11` also appeared in official stable release metadata. The plan's Go `1.26.x` entry was explicitly a proposal, not an approved compatibility ceiling. Choosing `1.27.4` as the initial qualification compiler follows the maintained-release policy and the observed host; it does not change the Go/PostgreSQL architecture. Record the eventual adopted baseline in the same plan's §4.2 and Chunk 0 evidence through an authorized update; this overview does not edit that plan.

### 3.2 Reproducibility and updates

- Proposed module identity: `github.com/merizrizal/tlsbeacon`, derived from the inspected local `origin` URL. This is a naming proposal, not proof of remote freshness, repository visibility or ownership verification.
- When implementation is authorized, record Go `1.27.4` as the initial minimum patch/compiler baseline and run with `GOTOOLCHAIN=local` to avoid an unnoticed automatic toolchain download. No `go.mod` is created by this document.
- Pin direct dependencies at their first actual use and commit the resulting `go.mod`/`go.sum` only through separately authorized Git work. Do not add unused dependencies during bootstrap. The exact complete module graph and checksums are future implementation evidence.
- The inspected driver and IDNA module files require different `golang.org/x/text` versions (`v0.41.0` and `v0.43.0`). Go's resolved graph must be inspected and tested; satisfying declared Go minima is not proof that the combined graph works. No transitive dependency set is declared tested here.
- Record PostgreSQL server/client and distribution package revisions, not only the major number. If a Docker fixture is chosen later, record the actual maintained image tag, immutable digest and platform separately; no image or digest has been selected or pulled here.
- Recheck upstream support, release notes and security advisories before adoption and before an update. Maintenance is a policy, not a one-time claim that a version has no vulnerabilities. Refresh exact patches through a recorded Level 1 change with affected tests; never silently follow `latest` or change a recorded candidate mid-run.
- Before a Go/PostgreSQL major or dependency update, inspect compatibility and persistence implications. Compliant mechanism/version choices remain Level 1; changing architecture, approved TLS compatibility, trust/network authority or evidence semantics is Level 2. Database upgrades involving real pilot state require an authorized preservation/recovery procedure, not destructive recreation.

### 3.3 Why these practical choices

| Proposed choice | Benefit | Cost / compliant alternative |
| --- | --- | --- |
| Standard-library CLI dispatch | Small dependency surface and direct control over the existing JSON/exit contract | More subcommand/help plumbing than Cobra. A maintained CLI library remains a Level 1 alternative if the same contract is preserved |
| JSON bootstrap configuration | Built-in parser, no extra configuration dependency, suitable for a small connection/path file | Less friendly for comments than TOML/YAML. Those formats remain Level 1 alternatives with explicit parser pins and unchanged protection/authority rules |
| Native pgx with explicit SQL | Matches the approved PostgreSQL-only storage and keeps transaction/error boundaries visible | Requires hand-maintained SQL and integration tests. `database/sql` is a compliant alternative; an ORM is not needed to satisfy D1 |
| One module and domain packages | Current responsibilities are visible without distributed coordination or speculative public APIs | Boundaries must be kept acyclic; exact type/package placement can change within Level 1 rather than introducing generic layers |

These are owner-accepted practical recommendations with tradeoffs, not new product requirements or prohibitions on equivalent compliant mechanisms.

## 4. Proposed repository convention and responsibilities

One repository, one Go module and one executable. This is a project convention, not a claim that Go prescribes a universal directory tree. All application/test paths below are proposed and currently absent; add each only when its existing plan chunk requires it.

```text
cmd/tlsbeacon/main.go         composition root and process exit
internal/
  cli/                       command adapters, human/JSON rendering, output errors
  config/                    protected local bootstrap configuration and redaction
  endpoint/                  normalization, exact values, patch/lifecycle decisions
  trust/                     strict CA import, immutable roots and material identity
  policy/                    canonical rules, address classes and authorization
  registry/                  PostgreSQL schema/version, transactions and snapshots
  probe/                     resolution, numeric dialing, TLS evidence and deadline
  assessment/                independent time, identity, path, expiry and report model
  testfixture/               shared test-only helpers when actually needed
tests/integration/           separate CLI processes, real DB/socket/fault evidence
go.mod, go.sum               actual module identity and resolved dependency pins
docs/                        existing requirements, architecture, tasks and plan paths
```

- `cmd` wires existing contracts; it does not accumulate parsing, SQL or certificate rules.
- `endpoint`, `trust` and `policy` own their current domain rules. `registry` persists their validated values and coherent snapshots rather than redefining canonicalization.
- `probe` acquires evidence under captured authority; it does not declare a certificate healthy. `assessment` interprets supplied evidence and one validation instant without network/database access. `cli` renders those facts rather than recalculating them.
- Keep dependencies directed and acyclic. Proposed starting direction: `cmd` composes adapters; `cli` invokes registry/probe/assessment; registry uses endpoint/trust/policy values; probe uses normalized inputs and policy; assessment consumes immutable evidence/root inputs. Exact value-type placement is Level 1: use small explicit boundaries rather than forcing an import cycle or adding a generic framework.
- Prefer concrete operations until a resolver/dial/clock/storage seam is needed for the contract or tests. Do not create an interface per struct, generic `utils`, parallel `models/services/repositories` layers, a public `pkg/` API or multiple modules without a demonstrated D1 need.
- Place unit tests beside behavior and real multi-process acceptance tests in `tests/integration/`. `internal/testfixture/` holds test-only material helpers, never runtime private-key support.
- Keep current PRD, ADR, task, roadmap and controlling-plan paths intact. The plan already proposes `docs/network-policy.md` and `docs/manual-pilot.md` when their implementation chunks arrive; they are future usage references, not files created here.
- Do not scaffold `control`, `scheduler`, `history`, `alerting`, `webhook`, deployment manifests or future database tables. No container build, Makefile or CI provider is a prerequisite imposed by this baseline.

## 5. Proposed local configuration and filesystem boundary

The configuration format/path selections below are Level 1 proposals. They do not make any existing path safe merely by naming it.

| Concern | Proposed convention | Preserved guarantee |
| --- | --- | --- |
| Bootstrap configuration | `config.json` under an absolute `$XDG_CONFIG_HOME/tlsbeacon/`; if XDG is unset/empty, `$HOME/.config/tlsbeacon/` | One operator-controlled location; an explicit alternate path may be provided. Missing/invalid config fails visibly, not an empty registry or implicit allow-all |
| Secrets | Protected bootstrap configuration may contain required database connection settings; never put real values in examples or Git | Operator-owned and owner-readable only for secret-bearing files; no connection credentials in reports, errors or logs |
| Managed configuration | PostgreSQL, including destination policy and immutable selected trust material | No shadow live policy/endpoint store in JSON. A policy input file may be validated and committed by `policy set`; editing that file alone does not activate policy |
| Linux system roots | Explicit import from `/etc/ssl/certs/ca-certificates.crt` for the proposed Ubuntu profile, or another explicitly configured/documented compliant source | The path exists on the observed host, but source provenance, secure access and actual imported set remain to be verified. No silent source search, opaque root pool or fallback |
| Custom roots | Explicit operator import/refresh into protected immutable registry versions | Source-file overwrite does not change selected material. Refresh then endpoint selection are separate actions, including for system roots |
| Scratch/artifacts | Absolute, unique, run-owned protected temporary directory; retain plan variable `TLSBEACON_TEST_ARTIFACT_DIR` for future build/test output | No keys, DSNs, `.env` files, binaries or generated fixture artifacts committed; no broad cleanup of shared paths |

Validate effective ownership, permissions, parent-path replacement and secure open/read behavior, not only filename spelling. State/import paths must be owner-only writable; secret-bearing files owner-readable only. An unsafe path fails with an actionable execution error. Protect against permission-check/replacement races. Do not enumerate or emit unrelated local secrets while validating a path.

No monitored private keys or client credentials are required or supported. Generated test-only CA/server keys belong solely to protected fixtures. Trust parsing rejects private-key-containing inputs without retaining or echoing key material.

## 6. Database lifecycle, integrity and privilege

### 6.1 Setup and runtime roles

Proposed native installation convention: a local PostgreSQL cluster, preferably reached through a configured Unix database socket. That database transport is not a new CLI-to-daemon control socket. A compliant loopback TCP fixture may instead be used under §8; explicitly record its connection, authentication and TLS configuration. Inspection's invalid-certificate capture settings must never alter database transport security or introduce insecure fallback.

- An explicitly authorized setup identity owns/initializes the dedicated database schema. A distinct runtime role receives only required registry privileges; it must not need superuser, role/database creation, schema modification or publicly callable elevated operations.
- Prefer an explicitly owned dedicated schema with constrained namespace/search-path behavior and no unintended public create/write grants. Effective privileges must be inspected and negatively tested, not inferred from role names.
- Setup privileges are not available to ordinary CLI commands. Document the initialization procedure when it exists; do not auto-initialize or modify an arbitrary database supplied by a DSN.
- Fresh initialization creates only D1 configuration structures and an explicit registry schema/format version. The plan's proposed `internal/registry/schema.sql` is sufficient as a starting organization; no ORM, migration platform or future table set is introduced.
- Startup rejects unsupported, corrupt or partially initialized state. It does not silently migrate, replace the registry or claim an empty successful installation. Actual later schema upgrades preserve real IDs/context under an authorized tested procedure.

### 6.2 Mutation and snapshot invariants

ADR-001 §§4–5/9 and task §§3/6 remain the exact contracts:

- Registration IDs are opaque, stable and never reused. Monitoring IDs change for actual canonical target/scope/port, expected identity or selected trust/version/material changes, including a revert; label/interval/threshold/enabled-only edits retain monitoring identity.
- Every real endpoint mutation commits its configuration revision and related identity changes atomically. Patch omission preserves existing values. Canonically unchanged mutations, including repeated enable/disable, do not write or advance IDs/revisions/timestamps or replace display spelling. Duplicate labels/targets remain allowed; no deletion or new registration cap is added.
- Use parameterized SQL and a lock or revision-CAS consistency boundary to prevent lost updates. Canonical no-op evaluation occurs inside that boundary. Exact transaction/locking details remain Level 1 with equivalent evidence.
- Trust imports/refreshes and whole-policy replacements are atomic. Invalid input or failed writes cannot partially replace valid roots/policy; immutable root versions and actual material attribution are preserved.
- Capture one coherent immutable endpoint/root/policy snapshot using a short consistent read transaction or equivalent mechanism. Release it before resolution/network work; a concurrent edit cannot relabel the report.
- Acknowledge persistence only after successful commit. A genuinely unknown commit response yields `commit_outcome_unknown` and read-back guidance, not asserted rollback or blind retry. Output failure after a committed mutation must not encourage a duplicate creation.
- Disabling changes durable configuration only. Explicit manual inspection while disabled is allowed but remains `disabled` and not monitoring-healthy. No event, recovery or history erasure is invented.

Only configuration is stored in D1. Future PostgreSQL upgrades and pilot carry-forward preserve registration/monitoring IDs, selected root generations, policy and configuration meaning; there is no manual-period inspection history to backfill.

## 7. Inspection and reporting boundaries

The overview does not redefine task §§3/6–7; the following constraints guide package boundaries and library qualification.

- Keep connection host, actual numeric address/port/scope, actual SNI and expected SAN identity distinct. DNS identity determines SNI even over an IP connection; expected IP identity omits SNI even for a DNS connection host. No arbitrary SNI override or Common Name fallback.
- Policy is a versioned numeric CIDR/port allowlist with explicit protected-class acknowledgments and deny precedence. Empty valid policy denies all; missing/malformed policy is an execution error. ADR-001 §6 defines metadata overlays, mapped IPv6, scopes, special-use and invalid-unicast rules; publish/test the actual classification table rather than substitute a generic private/public split.
- Authorize every actual candidate and retry under captured policy, then dial the vetted numeric address. No unchecked second resolution, proxy/environment tunnel, discovery or scanning. Denied candidates are recorded and never contacted. Socket-visible authority does not imply knowledge of downstream NAT/routing aliases.
- One default ten-second monotonic budget covers resolution, all connections and TLS handshakes. Cancellation prevents late dials. Retry only pre-certificate-evidence failures; once certificate evidence is obtained, finish that connection within the remaining budget and do not search another backend to hide an invalid certificate.
- Support approved TLS 1.2/1.3. Probe-local invalid-certificate observation must preserve actually available partial evidence and still perform explicit independent assessment. No application/HTTP request, application ALPN probe, client certificate or credentials are sent. Revocation is `not_checked`; no root/intermediate/AIA downloads or peer-as-root promotion.
- Both system and custom trust use the actual enumerable immutable selected root snapshot and deterministic DER-set identity. Custom roots are exclusive. An unreadable/malformed/empty/private-key-containing import fails rather than silently dropping entries or substituting roots. General PRD allowance for unknown system-root provenance does not weaken D1's stricter rule.
- Independent leaf time, SAN identity, server-authentication path and expiry retain every supportable finding. One UTC capture/validation instant is separate from real monotonic elapsed timing. Inclusive validity, exact unrounded 24-hour-day thresholds, zero-at-`notAfter` critical and overflow-safe lifetimes remain unchanged. Missing evidence is explicitly unavailable, never a guessed negative or pass.
- Human output and `tlsbeacon.cli.v1` convey the same snapshot facts and null reasons. Preserve every task §7.2 group and exact-duration strings. Report `retained_by_application: false`; manual freshness is `current` or `disabled` at completion only. Registry freshness is null with `inspection_history_not_retained`, not a fabricated last check.
- Exits remain 0 for successful configuration commands or a healthy completed inspection, 1 for a completed nonhealthy inspection including disabled/no-certificate outcomes, and 2 for execution/configuration/storage/output failures. A broken stdout cannot be successful delivery of a report.

## 8. Verification infrastructure — not product deployment

Use host-run Go tests and controlled local PostgreSQL/TLS/DNS/TCP fixtures. Full verification requires a distinct owned disposable Compose fixture stack; it also exercises the actual one-off image and installed host CLI. This document does not authorize provisioning.

| Fixture concern | Required boundary and evidence before affected use |
| --- | --- |
| Identity and lifecycle | Trusted run-specific ownership/identity for containers, volumes, networks, databases and relevant dependencies before attach/restart/modify/stop/cleanup; recheck changed/replaced resources. A label, name or DSN alone is insufficient. Stop on collision, mismatch or uncertainty |
| Exposure and host authority | Only minimum necessary ports, effectively loopback-only published bindings; no host networking, privileged fixtures, fixture Docker socket/API, sensitive host mounts or unapproved elevation/host/network changes |
| Data and privileges | Disposable run-owned storage, test-only protected keys/credentials, restricted application DB role and separate setup authority. No production or arbitrary supplied database. A restricted DB role does not constrain Docker daemon authority |
| Real dependency evidence | Preserve fixture data across an actual PostgreSQL restart. A container restart/reconnect alone proves neither database restart nor durability. Commit ambiguity and concurrent snapshots require real storage/fault evidence |
| Network and protocol | Actual authorized local sockets plus deterministic virtual-denial seams; never real metadata or public inspection targets. Record SNI, application bytes, client-credential behavior, AIA/proxy canaries and actual scoped IPv6 evidence where required |
| Time and cleanup | Controlled UTC assessment and separately measured monotonic deadlines; measurement uncertainty is not extra probe time. Stop only verified run-owned resources and preserve unrelated data/evidence |

Docker CLI presence was observed; no daemon/image/fixture operation ran. No image digest, daemon authorization, effective exposure, scoped-IPv6 topology or resource-ownership mechanism is declared proven. If a required boundary cannot be established, stop affected fixture work rather than weaken the boundary or silently skip acceptance.

## 9. Build, verification and automation interface

There is no runnable product baseline today. The following are proposed future commands from the existing plan, not commands executed during document authoring. Run them only once the relevant implementation and authorized local prerequisites exist, from repository root, with the recorded local toolchain and protected artifact directory.

```sh
go test -list . ./...
go test -count=1 -json ./...
go vet ./...
go build -o "$TLSBEACON_TEST_ARTIFACT_DIR/tlsbeacon" ./cmd/tlsbeacon
```

Use focused package checks first, `gofmt` on explicit changed Go files, and full verification at the plan's required gates. Raw test JSON must establish discovery, execution, failures and skips. An empty regex/package match or required integration skip cannot count as acceptance. Resolve real test names rather than blindly copy a proposed regex.

Task §9 V-01–V-10 remains mandatory: real PostgreSQL/process restart, effective privilege negatives, genuinely unknown commit/read-back, deterministic concurrent edits/no-ops/snapshot barriers, exact trust attribution, controlled certificate boundaries and combined negatives, every actual dial, no-payload/credential evidence, one real monotonic budget, actual CLI output/exits and full pilot reproduction. A green unit suite alone cannot establish these properties. Optional race checks complement, not replace, deterministic concurrency evidence.

No CI provider is selected or workflow created here. If CI is separately scoped later, reuse these native checks and the same fixture safety/secret boundaries; do not introduce a containerized product build, deployment pipeline or privileged fixture merely to obtain green CI. Do not run dependency-author development setup scripts as a shortcut to permission.

## 10. Requirement fidelity and delivery allocation

The detailed requirement/acceptance map remains task §8 and plan §§5–6; this summary explains architecture ownership without creating another ladder. All D1 implementation evidence below is future, not accepted behavior.

| PRD sources | D1 responsibility and evidence | Explicit later/outside boundary |
| --- | --- | --- |
| PD-001–002; §§1–3 | Local single-operator CLI, protected authority and human/versioned JSON; V-01/V-09/V-10 | D2 introduces one active monitoring service; no anonymous API, tenants or dashboard |
| PD-003–004 | Direct DNS/IP/explicit-port TLS and actual selected exclusive roots; V-02/V-03/V-05/V-08 | No STARTTLS, QUIC, client authentication, trust broadening or downloads |
| PD-005–006 | Hourly interval default and no new registry cap; V-02 | One HTTPS webhook in D3; shared maximum-five probes and 100-endpoint/five-minute proof in D2; target is not measured capacity |
| FR-001–002 | Complete persisted configuration, stable versus monitoring identities, patch/no-op/disable behavior and immutable attempt attribution; V-01/V-02/V-03/V-10 | D2 stores historical evidence; D3 preserves superseded historical conditions, not false recovery |
| FR-003–005 | Authorized manual observation, contacted address/SNI/identity distinction, independent assessment and immutable actual trust material; V-03–V-08 | D2 manual/scheduled ordering and retained context; D3 shared logical-event deduplication |
| FR-006–008 | Truthful nonretained manual report, precise times/unknowns and v1 output; V-04/V-06/V-09 | D2 scheduling, immutable history, latest overall attempt/latest certificate/latest scheduled completion, independent persisted inspection freshness and scheduler state |
| FR-009–010 | No D1 condition/event/webhook implementation | D3 independent conditions, atomic transitions/events, stable IDs, verified authorized HTTPS, no automatic redirects and durable retry/replay |
| FR-011–012 | Registry lifecycle/restart and actionable startup/configuration/storage/output failures; V-01/V-02/V-09/V-10 | D2 monitoring/history recovery and service/persistence/lag visibility; D3 pending deliveries, condition reconciliation and full release/backup/restore operations |
| AC-001–005 | Manual report, exact time/identity/path/trust/failure portions; V-02–V-06/V-09 | Retained history in D2, relevant alert transitions in D3 |
| AC-006–007 | Registry restart and captured-configuration attribution only; V-01–V-03/V-10 | D2 history/scheduling/re-enable/order; D3 logical-event deduplication; not full D1 acceptance of these scenarios |
| AC-008–010 | No D1 scheduling or notification claim | D2 AC-010 status/restart; D3 AC-008–009 and AC-010 staleness condition/events; no outage notification promised from a stopped sole process |
| AC-011–012 | Probe policy/no-HTTP and registry storage-failure safety; V-01/V-07/V-08/V-09 | D2 batch/history/probe-storage proof; D3 webhook/event/delivery and combined release proof |
| AC-013–016 | AC-013 trust-versioning portion, AC-014 and AC-016; V-02–V-09 as mapped in task §8 | D2 historical trust/context and independent AC-015 scheduled state; D3 superseded conditions and staleness events. Manual success never resets the scheduled clock |
| AC-017–019 | No D1 implementation | D3 verified authorized HTTPS/no redirects/redaction, queued delivery through disablement and fresh-evidence reconciliation, atomic inspection/status/condition/event persistence |
| §§5–6, 8–10 | Existing exact assessment, trust/network/evidence/privilege boundaries; V-01–V-10 and factual workflow evidence | Full release covers AC-001–019 and the seven-day 5–10-endpoint pilot; no cosmetic waiver for health misstatement, lost committed events or excess authority |

Other PRD MVP exclusions remain excluded: issuance/renewal/ACME/remediation, monitored private keys, discovery/scanning, public signup, multiple tenants/roles, browser dashboard, revocation, CT, cipher grading, general application availability and approaching-intermediate-expiry alerts. Already-invalid intermediate paths still fail path validation now. Optional expansion, new retention policy, production deployment and LabReserve replay require separate scope.

## 11. Later deliveries and source reconciliation

### 11.1 Reuse without premature decisions

- D2 reuses the same authorized observation/assessment path, adds durable immutable evidence, ordering, independent inspection/scheduler clocks and bounded scheduling. The daemon/control transport, single-active mechanism, history schema and clock details still need their own bounded contract; a Unix socket is a possible future option, not adopted here.
- D3 adds conditions, atomic required persistence and durable verified webhook delivery. A PostgreSQL transactional outbox is a credible design option, not a mandated D1 table or a substitute for the PRD's atomicity guarantee.
- The approved D1 Compose topology is limited to the pilot and fixtures specified in the amendments. Systemd packaging, host sizing, observability endpoints, CI provider, backup mechanics and future package names are not settled by reproducing the external proposal.

### 11.2 Reading the current documents accurately

This reconciles their interpretation; it does not rewrite approved records:

| Existing wording | Current interpretation / bounded follow-up |
| --- | --- |
| ADR §1 links v0.1 as the approved PRD | Historical authoring baseline; v0.2 is current, as explicitly recorded in the reconciled task/plan. No D1 trust or evidence guarantee is weakened |
| ADR §3 says the plan currently excludes containers and requires native fixtures | Stale present-tense statement: current plan §§4.2/6.1 and Chunks 7/18 already permit the compliant test-only exception. Product containers remain excluded |
| ADR header/§§3/11 retain pending fixture-remediation wording | Later handoff 11 reports design-level resolution of DOCKER-SPEC-001/002 with reviewer-isolation limits; the plan records later review/preflight chronology. This overview does not issue a retrospective review verdict or prove runtime safety |
| Task §§2/12 describe controlling-plan authoring as future | Historical stage wording, not evidence that the existing sole ladder is absent or permission to create another |
| Roadmaps describe Go/PostgreSQL as candidates | Their scope-only approval predates the separate ADR decision; do not reopen or silently replace the approved stack |
| Older overview/phases 03–05 reflect v0.1 freshness, redirect and release wording | v0.2 controls separate scheduler state, no automatic webhook redirects and AC-001–019 release coverage. Reconcile the affected later documents before their gates, not by building them in D1 |
| Plan §4.2 names Go 1.26.x and unpinned dependencies | Proposals deliberately delegated to Level 1. The owner has accepted this overview; record actual choices/source identities in the same plan's relevant sections and discovery evidence only under separately authorized plan ownership, retaining all 23 chunks and V-IDs |

No approved PRD/ADR/task/plan is edited by this authoring action. Their current commitments are real; their historical preflight is not evergreen. The reported `ea7af335...` affected preflight predates v0.2 and the final task/plan reconciliation. A current affected preflight against adopted, approved/committed sources remains a separate action; this document does not supply it. Chunk 0 remains previously reported blocked, not completed.

## 12. Evidence and source identities

### 12.1 Repository and reference proposal

Full governing PRDs, ADR, task, controlling plan and roadmaps 00–05 were read in the architecture discussion/authoring session, including their endings; revalidated working hashes matched the discussion handoff. Current PRD/ADR/task contents were re-read for authoring. No separate application knowledge base or legacy implemented contract was discovered. Applicable user-level instructions govern; no additional ancestor/repository `AGENTS.md` was found.

| Source | SHA-256 of inspected content |
| --- | --- |
| `docs/prd-v0.2.md` | `cb1e3fae00363348f040531ce4e820bd75069a489c9d84ba72d23968ded079fa` |
| `docs/prd-v0.1.md` — historical | `ce87476179bc0f903a2286c14a7e86f1c0c4c98d88a7165f8574874d3accf138` |
| `docs/architecture/01-adr-001-delivery-1-manual-inspection.md` | `66f58626f28ff1b26a51e2d51cf29b14f04863e0682822a72f3dabadcc6aee76` |
| `docs/tasks/01-delivery-1-manual-inspection-contract.md` | `ecc933cca65fd1dc92ce154a4ddfad552ae794dfd228b8d43507daf5c74245ee` |
| `docs/chunked-implementation/01-delivery-1-manual-inspection-execution-plan.md` | `124a64b30301a4814eb14fceb0e5fcc2e6abfcda673c85b376bf010ceacb3de5` |
| `docs/proposed-architecture-baseline.md` — supporting reference copy; proposal not adopted wholesale | `25841d4b031382e594f6ecebb46babc52bc0c43db50f4925a7d59736379cf5e9` |

The [reference proposal](../proposed-architecture-baseline.md) was copied without content changes from the original `initial-proposed-architecture.md`; the matching SHA-256 identifies its source bytes without recording a machine-specific location. The governing repository sources above were inspected at the authoring base; the reference copy was added afterward. Handoffs 11, 14–18 and the linked 17 instruction supply historical evidence with their stated limitations, not current execution authority. Exact earlier review reports/candidate bytes not separately archived remain unavailable; no reconstructed delta or strengthened independence claim is made here.

### 12.2 Public technology evidence retrieved on 17 November 2026

| Source | What was established / limitation |
| --- | --- |
| [Go stable release metadata](https://go.dev/dl/?mode=json) and [release/support history](https://go.dev/doc/devel/release) | Go 1.27.4 and 1.26.11 stable releases, 10 November 2026 patch dates and two-newer-majors support policy. No binary download/checksum validation or product execution |
| [Official PostgreSQL release refs](https://api.github.com/repos/postgres/postgres/git/matching-refs/tags/REL_18_) and [18.7 source release notes](https://github.com/postgres/postgres/blob/f5c41f6681c910b3f69951bf6fb97c6d74605d25/doc/src/sgml/release-18.sgml) | `REL_18_7` commit `f5c41f6681c910b3f69951bf6fb97c6d74605d25`, patch release date and original major-release date. No installed server, package or tested upgrade |
| [Official PostgreSQL website policy source](https://github.com/postgres/pgweb/blob/80bec0f47e78f4a0321e964c46fd6e45aeb01b78/templates/support/versioning.html) | Five-year major support, security/minor releases and recommendation to run the current minor. The source template does not include the rendered live release table. Direct access to the public support page timed out twice; policy was verified through the official source instead |
| [pgx release metadata](https://proxy.golang.org/github.com/jackc/pgx/v5/@latest), [v5.13.0 module file](https://proxy.golang.org/github.com/jackc/pgx/v5/@v/v5.13.0.mod), [versioned README](https://github.com/jackc/pgx/blob/v5.13.0/README.md) | Version/date, declared Go minimum and project support/API guidance. Release metadata pointed to tag commit `1e38d71d74e94fd3b35cbe5b3415109a870d5b91`; no module graph, signature or vulnerability audit |
| [x/net release metadata](https://proxy.golang.org/golang.org/x/net/@latest) and [v0.62.0 module file](https://proxy.golang.org/golang.org/x/net/@v/v0.62.0.mod) | Version/date and declared Go minimum; metadata points to `3de643db506517b3e652a13cc0b56034cea6b8e6`. No behavioral IDNA qualification or transitive build |
| Local OS/tool metadata; [Ubuntu release-cycle page](https://ubuntu.com/about/release-cycle) | Host reports Ubuntu 26.04.1 LTS/amd64; Go version was observed locally. Ubuntu's page returned HTTP 503, so vendor support dates were not independently established. PostgreSQL executables and Markdown formatters were not found on PATH; Docker executable presence is not daemon or fixture proof |

Two guessed PostgreSQL website-source paths returned HTTP 404 before repository inventory identified `templates/support/versioning.html`. Those failed requests establish no policy fact. All network access was public documentation/release metadata retrieval, not TLSBeacon probing, production access, dependency installation or fixture provisioning.

## 13. Review and stopping boundary

- The separate INITIAL review and owner acceptance are recorded above. The review applies to the identified pre-approval-record candidate bytes; revalidate affected changes rather than assuming that verdict covers later revisions.
- Level 0 remains routine authorized testing/debugging/fixture repair. Level 1 remains compliant versions, layout, parsing, SQL/locking and test mechanisms with meaningful decisions recorded. The review identified no unresolved Level 2 decision for the reviewed draft.
- A daemon/socket requirement, product container deployment, storage substitution, broader privileges, weakened root/socket/evidence guarantees, unsupported compatibility change or scope expansion requires an explicit affected architecture/product/security decision before dependent work. Do not infer such approval from this overview.
- This overview selects no execution mode, resets no failure budget and completes no chunk, V-ID, acceptance scenario or roadmap checkbox. Implementation tooling/access, full dependency resolution, native database setup, fixture ownership/exposure, scoped IPv6, selected-library behavior and real timing/fault evidence remain future prerequisites/results at the existing gates.
- Recording owner approval does not automatically authorize a controlling-plan change, preflight, implementation, provisioning, staging, commit, push or deployment.
