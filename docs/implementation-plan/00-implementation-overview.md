# 00. Implementation Plan Overview

**Roadmap authority:** APPROVED_AND_ACCEPTED as a planning roadmap; not an approved ADR, task contract, or execution authorization.

**Roadmap status:** APPROVED_AND_ACCEPTED; Delivery 1 scope review completed with `SCOPE_READY`.

**Approval and acceptance:** On 2026-11-15 (UTC+07:00), the user explicitly approved and accepted this overview, [phase 01](01-registry-and-safety-foundations.md), and [phase 02](02-trustworthy-manual-inspection.md), following the INITIAL Delivery 1 scope-readiness review in the preceding conversation response.

**Approved candidate:** Committed document contents at `ea045cd39ee7aee8e67b2d5c11964573590a40df`, tree `ca46327127abe09e23323833c7af5709626d4262`. The working tree was clean before this approval record was added.

**Acceptance boundary:** This records acceptance of the named roadmap/scope documents and the Delivery 1 decomposition across phases 01–02. It does not approve the phase 03–05 documents, architecture/ADRs, technology choices, or a bounded implementation contract; authorize implementation, commits, or deployment; or accept unimplemented behavior or unexecuted tests. Specification authoring remains a separately authorized next action.

**Historical authoring provenance:** The next three paragraphs describe roadmap authoring, not the approval baseline above. Their references to current/uncommitted state and absent scope approval apply to that earlier authoring state.

**Authoritative sources and revision:** [TLSBeacon PRD v0.1](../prd-v0.1.md), dated 10 November 2026, marked approved by product owner Merizrizal. The committed PRD baseline used to create this roadmap was Git blob `97f4e80c9bf394758432b1eb61c506149f52c06c`; its current user-updated working-tree blob is `9668a6c210364abbf0c0103b995afffa37f146ec`. The project name was updated to TLSBeacon per user instruction, with product requirements unchanged; this update is uncommitted. The recorded PRD approval covers product behavior, not architecture, phase boundaries, or implementation contracts.

**Repository/project state:** New-project mode; documentation-only repository at commit `8950be8a79c30e499dde3056e3c6578233522e8a`, tree `3d06e4446a428f62c29447f22bea72da2c49b6be`; working tree clean before these roadmap files were created. The current uncommitted changes also include the user-directed PRD/README name update.

Inspected sources: the complete PRD, `README.md`, `.gitignore`, tracked-file inventory, and non-Git file inventory. The PRD and README now identify the project as TLSBeacon; this roadmap does not decide a binary/package name. No application, schemas, migrations, tests, build manifests, CI, deployment setup, architecture, or ADRs were present. The output directory existed but contained no files. No product tests or builds were run; there is no executable baseline or measured capacity result. External RFC/library links were not fetched, and the PRD's referenced previous-session proposal was not present. No separate approval evidence for scope or phase boundaries beyond the PRD's recorded product approval was supplied; the product-name update was explicitly requested.

This directory translates the PRD into proposed phases with goals, scope, assumptions, ordered tasks, estimates, checkboxes, and definitions of done. Each phase needs a separately bounded contract and applicable review before code changes. PRD §8's product milestones guide the allocation. The Delivery 1 split across phases 01–02 is now approved and accepted as scope planning; the Delivery 3 phase documents remain proposed. No phase has an approved implementation contract.

## 00.1 Directory Name

```text
docs/implementation-plan
```

This is one ordered roadmap, not competing implementation variants. Phase files describe proposed work; they are not controlling execution ladders.

## 00.2 Estimation Rules

```text
1 engineer-day = about 6 focused engineering hours
```

Ranges assume one experienced engineer with reasonable access. They include implementation, focused regression coverage, integration, and documentation within each phase. They exclude waiting for access, credentials, infrastructure, DNS, approvals, and unrelated incidents. Separate specification/review cycles are not estimated as implementation work; record their elapsed and active human time under PRD §9 instead.

Phase 05 includes active pilot preparation, observation, and analysis, but the required seven-day pilot adds calendar time that is not seven full engineer-days. Estimates are provisional until contracts settle the architecture and verification environment.

## 00.3 Phase Summary

The overview is approved and accepted as roadmap planning. Phases 01–02 are approved and accepted Delivery 1 scope documents; phase 03–05 documents remain **PROPOSED** and require their own applicable review and approval. No phase is authorized for implementation by this roadmap.

| Phase | File | Goal and PRD milestone | Estimate |
| --- | --- | --- | --- |
| 00 | `00-implementation-overview.md` | Explain proposal and traceability | Documentation only |
| 01 | [01-registry-and-safety-foundations.md](01-registry-and-safety-foundations.md) | Persist authorized endpoint/trust configuration; first part of Delivery 1 | 3–5 engineer-days / 18–30 hours |
| 02 | [02-trustworthy-manual-inspection.md](02-trustworthy-manual-inspection.md) | Produce trustworthy manual CLI/JSON reports; completes Delivery 1 | 5–8 engineer-days / 30–48 hours |
| 03 | [03-continuous-monitoring-and-evidence.md](03-continuous-monitoring-and-evidence.md) | Schedule checks, preserve evidence, and expose freshness; Delivery 2 | 6–10 engineer-days / 36–60 hours |
| 04 | [04-durable-alerts-and-webhooks.md](04-durable-alerts-and-webhooks.md) | Persist condition transitions and deliver/replay events; notification portion of Delivery 3 | 6–10 engineer-days / 36–60 hours |
| 05 | [05-operations-and-mvp-validation.md](05-operations-and-mvp-validation.md) | Prove operability, recovery, acceptance, and lab usefulness; completes Delivery 3 | 4–7 engineer-days / 24–42 hours |

```text
Manual pilot (01–02): 8–13 engineer-days / 48–78 focused hours
Complete MVP (01–05): 24–40 engineer-days / 144–240 focused hours
Additional elapsed time: seven-day lab pilot, plus external/review waits
```

PRD Delivery 4 is optional expansion, not an estimated MVP phase.

## 00.4 Recommended Build Order

1. **01:** Establish the smallest runnable CLI and durable registry, effective trust/configuration identities, and connection authorization boundary. Do not scaffold scheduling or notification infrastructure yet.
2. **02:** Exercise that foundation against controlled TLS fixtures and deliver the useful manual pilot before building a background service or UI polish.
3. **03:** Reuse the inspection path for durable history and bounded scheduling; prove freshness, ordering, restart, and disablement behavior before alerts consume those facts.
4. **04:** Derive independent conditions from committed evidence, atomically retain events, then implement at-least-once HTTPS delivery and operator replay.
5. **05:** Complete operational guidance and failure visibility, run the full acceptance matrix against the release candidate, and perform the seven-day pilot.

These dependencies concern behavior, not a mandated package layout or job system. Basic errors, security, and focused tests belong in every phase; phase 05 integrates and validates them rather than postponing them. No existing data migration/backfill is observed; if a pilot installation is upgraded between deliveries, its registrations, history, and event IDs must be preserved and its upgrade tested.

## 00.5 Cross-Phase Principles

- [ ] Keep one trusted operator, one self-hosted Linux installation, and one active monitoring service. Do not introduce public signup, tenants, roles, or an anonymous network API.
- [ ] Inspect direct TLS over TCP only: DNS/IP targets, explicit port, no HTTP application request, client credentials, issuance, renewal, or remediation.
- [ ] Enforce destination policy on actual connection addresses, including DNS results. Private-lab access must be deliberately authorized; neither blanket private-network denial nor unrestricted egress is assumed.
- [ ] Keep custom trust exclusive to its configured roots, with no system-root fallback or automatic intermediate/root downloads. Webhook TLS verification stays enabled independently of inspection findings.
- [ ] Preserve independent observation, leaf-time, identity, path, expiry, and freshness dimensions. Unavailable evidence is not success; revocation is explicitly not checked.
- [ ] Bind evidence to effective endpoint/trust configuration, observation time, and contacted address when available. Completed records are immutable; retain all pilot records without silent pruning.
- [ ] Use bounded background work for scheduled probes and deliveries, not unbounded CLI blocking or automatic historical catch-up. No queue product or scheduling mechanism is selected here.
- [ ] Make committed transitions and delivery failures observable. Persist each alert transition with its event atomically; retries preserve logical event identity.
- [ ] Show latest attempt separately from latest certificate observation. Health requires current evidence, passing in-scope validation, and no expiry warning.
- [ ] Keep the normal monitoring/notification path automatic after operator configuration. Operator replay handles visible exhausted deliveries rather than hiding failures.
- [ ] Redact webhook secrets; never report persistence or receiver acceptance before the corresponding operation succeeds.
- [ ] Test external behavior with controlled TLS/DNS/network/storage fixtures and controlled validation time, not public websites. Add important failure and concurrency regressions as each behavior arrives.

## 00.6 Recommended MVP Slice

First useful vertical slice, corresponding to PRD Delivery 1:

```text
operator sets destination policy + trust profile
-> registers a stable endpoint
-> manually inspects direct TLS under the configured authority
-> reads timestamped human/JSON evidence and independent findings
-> restarts CLI and still has the registration
```

This manual pilot deliberately does not claim durable inspection history, automatic monitoring, or alerts. Those requirements remain assigned to phases 03–05; Delivery 1 is not the complete MVP.

## 00.7 Tracking Format

Tasks use unchecked Markdown checkboxes. Mark a task complete only after its behavior exists and the bounded contract's verification evidence is recorded; generating this roadmap completes no implementation task. Record revision, environment, command/procedure, actual result, and remaining limitations with each completion.

Begin the PRD §9 workflow ledger at the **first specification review**, not at phase 05: elapsed planning time, active human time, initial blockers, remediation rounds, reopened/new blockers and justification, stable finding IDs, requirement/evidence/closure/disposition, premature future-stage evidence demands, Level 0/1/2 classifications and escalation reasons, requirement-driven rework, escaped defects, unresolved findings, and human interventions. After two remediation rounds on the same specification, diagnose non-convergence; do not auto-accept or impose a hard review cap. The record location is a later workflow choice, not a new application feature.

## 00.8 Definition of MVP Done

```text
authorized operator configures lab targets, trust, and one HTTPS webhook
-> manual and scheduled probes preserve trustworthy, immutable evidence
-> status/history distinguish current attempts, certificate history, and freshness
-> independent conditions open/escalate/recover only on supported evidence
-> durable events retry/replay with stable IDs across failure and restart
-> operator sees service/storage/delivery health and can restore a backup
-> all AC-001–012 pass against the release candidate
-> seven-day pilot on 5–10 selected lab endpoints is evaluated
```

The complete MVP includes internal CA support, hourly-default monitoring up to the 100-endpoint target, history, and durable notifications. Prove the controlled five-minute batch target; do not present it as already measured. A stopped sole process cannot send external alerts; queried status and restart reconciliation must still expose staleness.

No known defect that misstates certificate health, loses committed events, or exceeds network authority may be accepted as cosmetic. Record incorrect assessments, unexplained stale periods, missing logical events, duplicate logical events, and receiver-level delivery duplicates separately. At-least-once delivery is not exactly-once receiver processing, human acknowledgement, or high availability. The pilot demonstrates usability, not HA or improvement over LabReserve; any historical workflow comparison is separately scoped.

## 00.9 Requirement-to-Phase Traceability

Source locators below refer to [PRD v0.1](../prd-v0.1.md). No existing implementation is accepted as coverage: none was found. A later phase assignment is not an approved deferral beyond the MVP.

### Product decisions and functional requirements

| PRD requirement / acceptance criterion | Proposed phase or accepted existing implementation | Deferred/outside current slice | Evidence and decision gap |
| --- | --- | --- | --- |
| §2 PD-001 | 01 local operator boundary; 03 single active monitoring service; 05 Linux installation | None beyond MVP | Runtime/storage and single-active enforcement need a contract; Go/PostgreSQL are candidates only. |
| §2 PD-002 | 01 registry CLI; 02 manual human/JSON; 03 status/history; 04 delivery inspection/replay | Browser UI outside MVP | Exact command names, JSON versioning, and exit codes require Delivery 1 contract decisions. |
| §2 PD-003 | 01 endpoint validation/policy; 02 direct TLS probe | STARTTLS/QUIC/client authentication outside MVP | Normalize DNS/IPv4/IPv6 and separate connection target from expected identity. |
| §2 PD-004 | 01 trust selection/context; 02 exclusive custom-root validation | None | Trust-material versioning/update semantics remain to specify. |
| §2 PD-005 | 04 one generic HTTPS webhook; 05 operations | Additional adapters outside MVP | Payload, authentication storage, delivery bounds/backoff are later contract choices. |
| §2 PD-006 | 01 interval default; 03 100-endpoint/batch proof; 05 release regression | None | Hourly default is approved; capacity is not yet measured. |
| §4 FR-001 | 01 stable persisted records, all required fields, input errors | None | Registry restart portion AC-006; no schema chosen. |
| §4 FR-002 | 01 lifecycle/configuration identity; 03 historical attribution and disabled status | History absent only from manual pilot | Connection host/port, expected identity, or trust-profile change must not relabel old evidence. |
| §4 FR-003 | 02 manual outcomes; 03 shared manual/scheduled ordering; 04 event deduplication | Concurrency/alerts assigned later, not removed | Attempt ordering mechanism is unapproved. |
| §4 FR-004 | 02 certificate data and independent validation; 03 retained results | None beyond MVP | Boundary fixtures must include SAN matching and exact validity instants. |
| §4 FR-005 | 01 context identity; 02 exclusive trust and truthful diagnostics; 03 stored context | None | No downloads or silent system-root fallback. |
| §4 FR-006 | 03 bounded scheduler, overdue restart and supersession | Not part of Delivery 1 | Scheduling/clock design and performance environment need Delivery 2 contract. |
| §4 FR-007 | 02 truthful current manual report; 03 immutable history/latest views/freshness | Durable history only begins in Delivery 2 | Retain failures and context, distinguish latest attempt/certificate. |
| §4 FR-008 | 02 manual output/exit semantics; 03 status/history; 04 delivery output; 05 compatibility check | History deferred from manual pilot to 03 | Versioned JSON must expose required fields and missing evidence explicitly. |
| §4 FR-009 | 04 independent condition/event lifecycle; 05 regression | Not part of Delivery 1 or 2 | No recovery from unavailability; expiry/identity/path remain independent. |
| §4 FR-010 | 04 durable webhook state, stable ID, retry/replay; 05 recovery proof | Not part of Delivery 1 or 2 | Receiver acceptance is not human read confirmation. |
| §4 FR-011 | 01 persisted registry/lifecycle; 03 scheduling/history recovery; 04 conditions/delivery recovery | Split by approved PRD deliveries | Disablement is not recovery; pre-existing events remain deliverable. |
| §4 FR-012 | 01 startup/configuration errors; 03 persistence/lag health; 04 delivery failures; 05 full runbooks/health | Final operational integration in 05 | Storage failure must never be reported as persistence/delivery success. |

### Acceptance scenario allocation

| PRD requirement / acceptance criterion | Proposed phase or accepted existing implementation | Deferred/outside current slice | Evidence and decision gap |
| --- | --- | --- | --- |
| §7 AC-001 | 02 healthy timestamped manual report; 03 history/status; 05 regression | None beyond MVP | Controlled valid matching fixture beyond warning threshold. |
| §7 AC-002 | 02 exact validity/expiry boundaries; 04 transition behavior; 05 regression | Alert portions wait for 04 | Just before/at/after notBefore, notAfter, 30-day warning, and 7-day critical thresholds. |
| §7 AC-003 | 01 separate target/identity; 02 DNS/IP/CN-only rejection cases; 05 regression | None | Explicit DNS identity while connecting to IP must be tested. |
| §7 AC-004 | 02 private CA/unrelated roots/intermediate cases; 03 stored trust context; 05 regression | None | Include missing and expired intermediate, unrelated anchor; do not assert unproven causes. |
| §7 AC-005 | 02 distinct DNS/refusal/timeout/negotiation reports; 03 timestamped history; 05 regression | History in 03 | No fresh expiry inference without new certificate evidence. |
| §7 AC-006 | 01 registration restart; 03 history restart/disable/re-enable/overdue resume; 05 regression | Continuous behavior in 03 | No catch-up flood; retained results stay historical after re-enablement. |
| §7 AC-007 | 03 current-status ordering/configuration binding; 04 duplicate-event prevention; 05 regression | Alert portions in 04 | Force delayed completion and overlapping manual/scheduled attempts. |
| §7 AC-008 | 04 repeated warning/escalation/timeout/supported recovery; 05 regression | None beyond MVP | Independent conditions must not recover one another. |
| §7 AC-009 | 04 event commit/crash/ambiguous receiver/exhaustion/replay; 05 recovery regression | None beyond MVP | Stable event ID through retry, restart, and operator replay. |
| §7 AC-010 | 03 query-time stale status/restart resume; 04 staleness events; 05 service/runbook proof | No external alert promised while sole process is down | Distinguish a failed completed attempt from stale evidence. |
| §7 AC-011 | 01–02 address policy and no application requests; 04 webhook policy/TLS/secret redaction; 05 regression | Webhook portions in 04 | Private/loopback/link-local/metadata handling must be defined before Delivery 1. |
| §7 AC-012 | 03 bounded 100-target batch and probe/storage failures; 04 delivery storage failures; 05 combined proof | No measured coverage yet | Contract must fix environment and clock assumptions; healthy storage for capacity test. |

### Interpretation, boundaries, and evaluation obligations

| PRD requirement / acceptance criterion | Proposed phase or accepted existing implementation | Deferred/outside current slice | Evidence and decision gap |
| --- | --- | --- | --- |
| §1 useful trustworthy monitoring; separate process success | 02 manual value; 03–05 complete workflow; workflow ledger from first review | Wider customer demand unproven | Process metrics never change health assessments. |
| §5 single-connection scope/contacted address | 02 report observation scope/address; 03 retain it | No backend/DNS/location coverage claim | One probe is not proof of every end-user connection. |
| §5 independent dimensions/healthy/revocation | 02 output; 03 current/history; 04 conditions | Revocation not checked, not silently passed | Health requires all required positive evidence and no expiry warning. |
| §5 threshold/validity/identity rules | 01 validate `0 < critical < warning`; 02 assessment; 04 transitions | Intermediate approaching-expiry alerts outside MVP | Defaults 30/7 days; 24-hour days; actual durations; exactly notAfter is critical, not expired; not-yet-valid stays invalid; no CN fallback. |
| §5 timeout/prior expired certificate/independent recovery | 02 unavailable current findings; 03 separate attempt/certificate views; 04 supported recovery | None | A new leaf can recover expiry without recovering identity/path. |
| §5 freshness and enablement epoch | 03 freshness at query/restart; 04 stale conditions | None | Stale only after two intervals without a completed attempt in current enabled period; recent failures are current evidence of failure. |
| §6 target behavior/network authority | 01 policy boundary; 02 actual bounded TLS probe; 04 webhook connections | No discovery/scanning/network API | DNS resolution and all connections obey policy; probes can still leave target connection logs. |
| §6 secrets | 01 local configuration protection; 04 webhook secrets/redaction/verified TLS; 05 audit | No monitored server private keys/client credentials | Secret source/permissions are contract decisions; test logs and all output surfaces. |
| §6 evidence integrity | 01 effective config/trust identity; 03 immutable records; 04 atomic transition/event | None | Durable event must not be lost after committed condition transition. |
| §6 notification semantics | 04 delivery/replay; 05 documentation/pilot classification | Exactly-once/human acknowledgement not promised | Ambiguous response may duplicate delivery, never logical event. |
| §6 resource defaults | 02 10-second total probe bound; 03 at most five concurrent probes and five-minute 100-target test; 05 regression | None | Apply shared bound to concurrent manual/scheduled service work; exact mechanism is unapproved. |
| §6 history retention | 03 retain all completed records; 05 growth/backup guidance | Retention policy is later product scope | No silent automatic pruning. |
| §3, §8 Delivery 1 | 01–02 manual inspection pilot | Explicitly not complete MVP | Delivery 1 contract must not include scheduler leases, webhook backoff, or dashboard design. |
| §3, §8 Delivery 2 | 03 continuous monitoring | Notifications wait for Delivery 3 | Scheduling/history/order/freshness/resources included. |
| §3, §8 Delivery 3 | 04–05 notifications and first complete MVP | None of the MVP removed | Includes operational readiness and all earlier regressions. |
| §3 exclusions; §8 Delivery 4 | No MVP phase | All explicitly outside MVP | Issuance/renewal/ACME/remediation/private keys, discovery/scanning, signup/tenants/roles/dashboard, STARTTLS/QUIC/mTLS, revocation/CT/cipher grading/general availability, approaching intermediate expiry; additional adapters/retention/multi-user require new scope decisions. Already-invalid chains still fail. |
| §9 product acceptance/pilot | 05 full AC matrix and seven-day, 5–10-endpoint pilot | Broader demand and HA not proven | Separate logical-event defects from receiver duplicate attempts; health/event-loss/authority defects block acceptance. |
| §9 workflow measures/convergence | Record from first specification review; 05 summarizes actual record | LabReserve historical replay outside scope | Stable findings/authority/rework metrics; two-round diagnostic is not auto-acceptance. |
| §10 next contract boundary | Delivery 1 scope review completed; separately authorize contract authoring for 01–02 | Later-delivery design excluded from first contract | Resolve normalization, output/exit behavior, trust versioning, policy, TLS support, and fixtures. |

**Allocation result:** PD-001–006, FR-001–012, AC-001–012, and the cross-cutting MVP obligations in §§1, 3, 5–6, 8–10 are assigned. No relevant MVP requirement is unassigned or proposed for removal. No conflicting product requirements were identified. Existing coverage is absent; all verification remains future work. Out-of-MVP items remain explicitly excluded, not silently deferred requirements.

## 00.10 Next Governance Gate

**Reviewed and accepted scope:** PRD Delivery 1, the manual inspection pilot, spanning phases 01–02. The INITIAL read-only scope-readiness review returned `SCOPE_READY` for the approved candidate identified above; the user's subsequent approval and acceptance of these three documents is recorded above. No architecture or task contract was approved by that review or this roadmap acceptance.

**Next action:** Separately authorize Delivery 1 specification authoring, followed by independent draft specification review. Do not start either automatically. The review's source-access limitations and the unresolved contract inputs below remain applicable; scope readiness is not implementation readiness.

Before a Delivery 1 implementation contract is approved, resolve:

| Contract input, not an approved roadmap design | Required boundary |
| --- | --- |
| Runtime, persistence, packaging, and Linux installation assumptions | Go/PostgreSQL are preferred candidates only; no versions, schema, or topology chosen. |
| Endpoint normalization and edit semantics | DNS/IPv4/IPv6, explicit port, expected DNS/IP identity, monitoring-identity changes, effective configuration snapshots. |
| Output and exit semantics | Versioned JSON, human reports, explicit unassessed fields; distinguish execution failure from a completed adverse inspection. |
| Trust-material identity and updates | Reproducible association with actual roots/configuration; custom roots exclusive; no automatic downloads. |
| Destination policy | Explicit treatment of private, loopback, link-local, and metadata destinations; enforce at connection time on resolved addresses without a resolution/connection bypass. |
| Supported TLS behavior | Protocol support, SNI/identity handling, collection of invalid-certificate evidence, 10-second total bound, and no application requests/client credentials. |
| Verification baseline | Local certificate/network fixtures, controlled time, persistence restart proof, and actual repository commands after tooling is chosen. No test command is asserted to exist today. |

These are known contract-design inputs, not product conflicts blocking this decomposition. Independent review must classify Level 0/1/2 authority; any proposal changing approved network authority, custom-trust isolation, or MVP behavior requires the appropriate human decision rather than a silent assumption. Later contracts must settle scheduling/ordering/clock details, atomic event persistence, webhook payload/backoff/replay, and release/pilot environment before their implementation—not in the first contract.

Following scope readiness, separately authorize specification authoring, independent specification review, human approval, and commitment of the bounded contract. Only then can the selected task proceed to its single controlling implementation plan and implementation preflight. No phase checklist or roadmap status authorizes implementation, commits, deployment, or expansion.
