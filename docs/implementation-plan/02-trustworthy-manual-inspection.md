# 02. Trustworthy Manual Inspection

**Phase boundary:** APPROVED_AND_ACCEPTED as scope planning; completes PRD Delivery 1 after phase 01.

**Authority:** This file is an approved and accepted roadmap phase, not an approved implementation task contract or execution authorization.

**Approval and acceptance:** Explicitly granted by the user on 2026-11-15 (UTC+07:00) for this document's committed contents at `ea045cd39ee7aee8e67b2d5c11964573590a40df`, alongside the overview and phase 01, following the INITIAL Delivery 1 scope review (`SCOPE_READY`). See the [overview approval record](00-implementation-overview.md) for the candidate baseline and acceptance boundary. This accepts the scope/decomposition, not architecture, technology choices, completed implementation, or test results; specification authoring and implementation remain separately authorized actions.

**Source requirements:** [PRD v0.1](../prd-v0.1.md) §§2–6, 8, 10; PD-002–004; FR-003–005, manual-report portions of FR-007–008, probe-error portion of FR-012; manual portions of AC-001–005, probe-policy/no-application-request portion of AC-011, with registry restart evidence from phase 01. Source revision and baseline are in the overview.

**Decision gaps:** Delivery 1 contract must resolve supported TLS behavior, SNI/identity handling, output schema/versioning, exit codes, total-deadline enforcement, trust versioning, and fixtures. No new Level 2 product decision is identified for this phase split; changing approved security or assessment semantics requires escalation.

## 02.1 Goal

Give the operator a useful, truthful manual report for a registered endpoint, including invalid or unavailable certificate evidence without false health claims.

```text
registered endpoint + selected trust + authorized address
-> bounded direct TLS inspection
-> independent evidence-based assessments
-> timestamped human report and versioned JSON
```

## 02.2 Estimate

```text
5–8 engineer-days
30–48 focused hours
```

## 02.3 Scope

Included:

- Direct TLS/TCP inspection with DNS, connection, timeout, negotiation, and validation outcomes distinguished.
- Leaf fingerprint, issuer, SANs, validity dates, actual remaining duration, contacted address when available, effective configuration/trust context, and observation time.
- Separate observation, time validity, service identity, certification path, expiry band, and applicable freshness output; explicit unavailable assessments and revocation not checked.
- Custom-root isolation, honest chain diagnostics, local certificate/network fixtures, controlled validation time, CLI/JSON behavior and exit-code verification.

Excluded:

- Durable completed-inspection history and persisted current-status views, scheduled work, event lifecycle, notifications, and service-scale claims; assigned to 03–05.
- HTTP application requests, remote certificate repair, client credentials, intermediate/root fetching, revocation checks, or any broader security grade.
- Choosing a binary name or adding a browser interface solely to resolve README/PRD naming differences.

## 02.4 Assumptions

- [ ] Phase 01 supplies persisted configuration and a verified connection-policy boundary under the same Delivery 1 contract.
- [ ] The operator can reach controlled TLS fixtures, and tests can supply controlled validation time without depending on public sites.
- [ ] The approved contract distinguishes an execution failure from a completed inspection with adverse findings; numeric exit codes and exact JSON shape are not assigned by this roadmap.
- [ ] Invalid certificates must remain observable where technically available, while outgoing webhook TLS later remains verified; do not reuse inspection exceptions as notification transport settings.
- [ ] Single manual results may be useful without durable inspection history; the CLI must state this boundary instead of pretending Delivery 1 is full monitoring.

## 02.5 Ordered Tasks

### Step 1 - Implement the bounded, authorized observation path

Estimate: **2–3 engineer-days / 12–18 focused hours**.

- [ ] Resolve the configured target, enforce policy against actual selected addresses, connect with the explicit port, and perform direct TLS with the contracted SNI behavior independent of expected-identity evaluation.
- [ ] Enforce the default 10-second total probe deadline across resolution, connection, and handshake, including any address attempts. Do not multiply the total bound by retrying addresses.
- [ ] Preserve certificate evidence when available even if validation fails; distinguish insufficient evidence from a known negative assessment.
- [ ] Return distinct actionable DNS, refusal/connection, timeout, TLS-negotiation, and certificate-validation outcomes, with observation time, effective context, and contacted address when known.
- [ ] Verify actual destination-policy enforcement, including DNS-to-disallowed-address cases and any permitted retry path. Use a controlled listener to verify no HTTP/application request or client credential is sent.

Done when:

- [ ] A permitted local fixture produces evidence within the bound, disallowed connections are rejected, and each pre-certificate failure remains distinguishable without an invented certificate conclusion.

### Step 2 - Assess certificates without conflating result dimensions

Estimate: **2–3 engineer-days / 12–18 focused hours**.

- [ ] Extract leaf fingerprint, issuer, SANs, notBefore/notAfter, and remaining lifetime; evaluate leaf time, SAN-based DNS/IP identity, and server-authentication certification path independently.
- [ ] Use only the selected custom roots when configured, or the selected system roots; record their effective identity. Do not fetch intermediates/roots, fall back to system roots, or label a chain failure as a proven missing intermediate without evidence.
- [ ] Apply 30-day warning and 7-day critical defaults using actual duration, with a day equal to 24 hours. At exactly notAfter the leaf is not expired and is critical at zero remaining lifetime; only an observation after notAfter is expired. A not-yet-valid leaf remains invalid regardless of future expiry.
- [ ] Mark unavailable dimensions explicitly. Report healthy only with a current certificate observation, all in-scope checks passing, and no warning; state revocation is not checked and one observation is not all-backend coverage.
- [ ] Add controlled-time fixtures just before, at, and after notBefore, notAfter, and both expiry thresholds, including unrounded-duration edge cases and invalid threshold input regression.
- [ ] Cover matching trusted certificates, wrong DNS/IP identity, CN-only identity, explicit DNS identity while connecting to an IP, intended/unrelated custom roots, missing/expired intermediate, and unrelated trust anchor. Verify no unsupported causal diagnostic and no silent trust broadening.

Done when:

- [ ] Manual portions of AC-001–004 pass, and a failure or unavailable dimension cannot be hidden by another passing dimension or a future expiry date.

### Step 3 - Deliver and verify the manual operator workflow

Estimate: **1–2 engineer-days / 6–12 focused hours**.

- [ ] Expose manual inspection of a selected registration and human/JSON reporting under the approved command, JSON-version, and exit-code contract.
- [ ] Include endpoint/monitoring identity, effective configuration/trust context, observation time, freshness applicable to the report, all result dimensions, expiry band, and actionable diagnostics. Use explicit unavailable values rather than a misleading aggregate success.
- [ ] Test the execution-failure versus completed-adverse-finding distinction through the actual CLI exit status and parsed JSON. Keep human and JSON findings semantically consistent.
- [ ] Verify DNS failure, refusal, timeout, and negotiation failure produce unavailable new certificate assessments, not invented expiry conclusions; history assertions remain assigned to phase 03.
- [ ] Run the complete Delivery 1 subset: manual AC-001–005, registry restart AC-006, and probe portion of AC-011. Record actual fixture/time assumptions and repository-native commands.
- [ ] Document installing/running the manual pilot, policy and custom-root configuration, limitations, and target-side connection-log side effects. Explicitly state no durable inspection history, scheduling, or alerts yet.

Done when:

- [ ] The operator can register a lab endpoint, restart, inspect it, and interpret trustworthy human/JSON findings, with all Delivery 1 evidence recorded and limitations visible.

## 02.6 Phase Definition of Done

- [ ] Manual observation and all certificate dimensions match the approved semantics, including inclusive validity boundaries and no CN fallback.
- [ ] Custom trust, destination authority, total probe deadline, and no-application-request behavior are verified end to end.
- [ ] Completed adverse inspections and execution failures have tested, documented CLI/JSON/exit semantics.
- [ ] Required Delivery 1 acceptance portions pass against controlled fixtures; none are represented as full history/monitoring/notification acceptance.
- [ ] The useful manual pilot runs after registry restart without requiring routine operator intervention beyond the requested inspection.

## 02.7 Risks

| Risk | Mitigation |
| --- | --- |
| TLS library fail-fast validation hides usable certificate evidence | Separate observation from the approved assessment path and verify each known dimension under negative fixtures. |
| Library defaults disagree with approved validity or identity semantics | Test exact instants, SAN-only matching, and server-authentication path constraints with controlled time. |
| Per-address timeouts exceed the total deadline | Apply one whole-attempt budget and test multi-address/slow-resolution behavior under the approved runtime. |
| Display rounding changes warning classification | Classify using actual remaining duration, then independently format the display. |
| A manual report is mistaken for continuous health | State its timestamp and single-connection scope, expose unknowns, and do not claim durable history or monitoring before phase 03. |

## 02.8 Proposed Requirement Coverage and Handoff

| Requirement / AC source | Proposed phase responsibility | Existing accepted behavior / justified deferral | Risk or unapproved decision |
| --- | --- | --- | --- |
| FR-003–005; AC-001–005 manual portions | Authorized observation, independent assessment, exact semantics and diagnostics | No existing implementation; durable history in 03 | TLS support/SNI/context identity require contract decisions. |
| FR-007–008 manual portions; §5 | Timestamped current report, explicit unknowns, human/JSON and exit behavior | Latest-attempt/certificate historical views in 03 | Exact schema and exit values must be specified, not guessed. |
| §6 target/network/resource boundaries; AC-011 probe portion | Actual address enforcement, 10-second total default, no application requests | Shared scheduler bounds in 03; webhook protection in 04 | Inspection of invalid certificates must not weaken unrelated transport verification. |
| §8 Delivery 1; AC-006 registration portion | Complete manual-pilot demonstration with phase 01 evidence | Delivery 1 is not the full monitoring MVP | Scope is CLI-first, single operator, direct TLS only. |

Proposed handoff to phase 03: reusable authorized observation/assessment behavior, approved output semantics, immutable context inputs, deterministic fixtures, and actual Delivery 1 verification evidence. History, concurrency ordering, scheduling, and alerts remain unimplemented until separately authorized. Delivery 1 scope readiness was reviewed across phases 01–02 together, followed by the user approval and acceptance recorded above. A separately approved and committed task contract and implementation preflight remain required before implementation; this roadmap is not that contract.
