# 05. Operations and MVP Validation

**Phase boundary:** PROPOSED; completes PRD Delivery 3 and the first complete MVP after phase 04.

**Authority:** This file is a roadmap phase, not an approved implementation task contract.

**Source requirements:** [PRD v0.1](../prd-v0.1.md) §§1–10; FR-012 and recovery/operability obligations across FR-001–011; all AC-001–012 as release regression; §9 seven-day pilot and workflow evaluation. Source revision and baseline are in the overview.

**Decision gaps:** Release contract must define supported Linux environment/installation, operational health surfaces, backup/restore and upgrade procedures, release-candidate evidence environment, and selected pilot endpoints. No new Level 2 product decision is identified; removing required evidence or accepting health/event-loss/network-authority defects requires escalation, not a cosmetic waiver.

## 05.1 Goal

Make the completed monitoring workflow installable, observable, recoverable, and demonstrably useful to the first operator without overstating reliability or coverage.

```text
install/configure one Linux service
-> monitor authorized lab endpoints and deliver durable events
-> observe and recover failures without false health claims
-> pass full acceptance and evaluate a seven-day lab pilot
```

## 05.2 Estimate

```text
4–7 engineer-days
24–42 focused hours
plus seven calendar days of pilot elapsed time, not seven full engineer-days
```

The active estimate includes pilot setup/review and bounded in-scope corrections. Re-run affected evidence after fixes; a material defect or source/scope change can require re-estimation. Access and approval waits remain excluded.

## 05.3 Scope

Included:

- Integrated startup/configuration, service health, persistence recency, scheduler lag, delivery failures, actionable logs/errors, and safe shutdown under the approved single-service architecture.
- Linux installation/configuration, custom trust and network-policy guidance, secret handling, backup/restore, any pilot-upgrade path, and storage-growth documentation.
- Full controlled acceptance matrix, failure/security/compatibility regression, observed capacity evidence, and seven-day pilot on 5–10 deliberately selected lab endpoints.
- Product defect classification and the accumulated workflow evaluation, without allowing process metrics to affect health findings.

Excluded:

- Deployment to production, push/merge/release publication without separate authorization, public customer onboarding, commercial readiness infrastructure, or HA.
- Dashboard, additional notification adapters, retention pruning, multi-user support, or any optional Delivery 4 capability.
- LabReserve historical replay or a claim that one successful workflow proves process improvement.

## 05.4 Assumptions

- [ ] Phases 01–04 have real recorded verification evidence; their checklists are not treated as proof merely because this roadmap exists.
- [ ] A separately approved release contract specifies the supported environment, candidate revision, capacity/time assumptions, and backup/restore evidence.
- [ ] The first operator can supply policy-authorized lab access and one controlled webhook destination; no credentials or local environment files are committed.
- [ ] The workflow ledger has been maintained since the first specification review, including authority/escalation and review-convergence records.
- [ ] The pilot is limited usability evidence, not high availability, multi-network certificate coverage, or broader customer validation.

## 05.5 Ordered Tasks

### Step 1 - Complete operational visibility and recovery guidance

Estimate: **1–2 engineer-days / 6–12 focused hours**.

- [ ] Integrate actionable startup/configuration errors, monitoring-service health, last successful persistence, scheduler lag, and delivery failure/exhaustion into the approved operator/log interfaces. Show degraded storage without claiming checks or events were saved.
- [ ] Verify orderly shutdown stops admission and handles bounded in-flight work under the contract; restart resumes overdue checks and pending deliveries without replaying missed intervals or changing event IDs.
- [ ] Document a repeatable Linux install/start/stop path, endpoint/trust/policy/webhook configuration, local permissions/secret protection, receiver deduplication, and execution/JSON semantics.
- [ ] Document and exercise backup/restore of registrations, effective configuration/trust context, completed evidence, conditions, and delivery state, plus separately protected secret/trust material needed for recovery. Preserve IDs and historical occurrence times.
- [ ] If a pilot instance is upgraded between deliveries, verify its actual upgrade/rollback procedure without silently dropping registrations, completed history, or events. Do not build a generic migration platform without need.
- [ ] Document all-record pilot retention and expected storage growth using measured or explicitly labeled estimated record sizes, intervals, and failure/event overhead. Explain how storage failure becomes visible; do not add automatic pruning.

Done when:

- [ ] A documented install/restore exercise produces an operable single-service instance, with truthful degraded-state visibility and no event/evidence loss in the tested recovery path.

### Step 2 - Prove the complete release-candidate acceptance matrix

Estimate: **2–3 engineer-days / 12–18 focused hours**.

- [ ] Assemble the actual test/build/format/verification entry points selected during implementation into reproducible Linux instructions or approved automation. This roadmap asserts no existing test command or CI provider.
- [ ] Run all AC-001–012 against the candidate using local certificate/network fixtures and controlled validation time, with requirement-to-evidence references rather than checkbox-only assertions.
- [ ] Recheck exact notBefore/notAfter and expiry thresholds, SAN-only identity, server-authentication path constraints, custom-root isolation, unknown dimensions, and latest-attempt versus certificate-history output.
- [ ] Recheck DNS/refusal/timeout/negotiation diagnostics, stopped/stalled scheduler freshness, edit/disable/re-enable races, concurrent manual/scheduled ordering, restart, and single-active-service/resource bounds.
- [ ] Reproduce the controlled 100-enabled-target timeout batch within five minutes with healthy local storage, default 10-second total attempts, and at most five concurrent probes; record environment/resources, clock assumptions, fixture design, and observed timing.
- [ ] Separately inject storage loss, transition/event commit failure, crash before send, receiver acceptance followed by timeout, exhaustion/replay, and restore. Verify no false persistence/delivery success, lost committed events, changed retry IDs, or duplicate logical transitions.
- [ ] Audit actual destination enforcement for probe and webhook DNS/IP paths, no HTTP requests from inspection, webhook TLS verification, and secret redaction across human/JSON/log/error surfaces. Verify no out-of-scope application behavior has appeared.
- [ ] Validate documented human/JSON/exit behavior and carried-forward installation compatibility. Repair reproduced in-scope defects and re-run affected checks, then the required full release verification; retain actual failures and final outcomes in the evidence record.

Done when:

- [ ] Every MVP acceptance scenario has passing release-candidate evidence in the stated environment, and no known health-misstatement, committed-event-loss, or network-authority defect remains.

### Step 3 - Evaluate the seven-day lab pilot and workflow record

Estimate: **1–2 engineer-days / 6–12 focused hours**, plus **seven calendar days** of pilot observation.

- [ ] Select 5–10 deliberate, policy-authorized lab endpoints representing useful DNS/IP and public/internal-CA cases; record effective settings and the candidate revision. Keep controlled failure injection on authorized fixtures, not unapproved external targets.
- [ ] Run the configured monitoring/notification path for seven days, checking status/history, event/delivery visibility, recovery guidance, and the absence of routine manual intervention after configuration.
- [ ] Record incorrect assessments, unexplained stale periods, missing logical events, duplicate logical events, and receiver-level duplicate deliveries as separate categories. Do not confuse expected same-ID delivery retries with a second logical alert.
- [ ] Substantiate findings with times, endpoint/configuration identity, actual evidence, stable finding IDs, and closure criteria. Repair in-scope defects and repeat affected acceptance/pilot evidence as needed; never waive unsafe behavior as cosmetic.
- [ ] Summarize operator usefulness and limitations, including single-location/single-connection observations, revocation not checked, no external notification while the sole process is down, and receiver acceptance not human acknowledgement.
- [ ] Summarize actual workflow measures from the first specification review: elapsed/active planning time, convergence rounds/blockers/reopenings, finding quality and premature evidence demands, authority/escalation reasoning, rework, escaped defects, unresolved findings, and human interventions. Diagnose any two-round non-convergence without automatic acceptance.
- [ ] Present the release evidence and remaining limitations for the human acceptance decision. Record optional improvements as separate candidates; do not implement Delivery 4 or claim workflow superiority over LabReserve.

Done when:

- [ ] Full acceptance evidence and the required seven-day, 5–10-endpoint pilot are evaluated, product/process findings are separated, and remaining issues have explicit dispositions consistent with the PRD.

## 05.6 Phase Definition of Done

- [ ] Installation, configuration, shutdown, service/storage/delivery health, backup/restore, and applicable pilot upgrade are documented and exercised.
- [ ] All AC-001–012 pass against the recorded release candidate, with controlled fixtures and measured resource-bound evidence.
- [ ] Seven days of pilot evidence on 5–10 selected endpoints has been reviewed, with defect categories and receiver duplicates recorded separately.
- [ ] No known defect misstates health, loses committed events, or exceeds network authority; claims remain limited to the approved checks and tested environment.
- [ ] Workflow evaluation is factual, does not alter product assessments, and does not substitute for independent review or human acceptance.
- [ ] No optional expansion, unapproved deployment/publication, or automatic progression has occurred.

## 05.7 Risks

| Risk | Mitigation |
| --- | --- |
| Existing test passes are treated as complete acceptance | Map every AC and cross-cutting boundary to concrete candidate evidence; retain missing or failing evidence visibly. |
| Pilot time or access is hidden in an effort estimate | Separate active engineering from seven calendar days and external waits. |
| Restore recovers records but loses trust context, IDs, or replay state | Exercise a representative backup/restore, protect external material, and verify histories/conditions/deliveries after recovery. |
| Single-service downtime is mistaken for an external alert guarantee | Test query/restart staleness and document that no sole stopped process can notify externally. |
| Normal at-least-once duplicates mask duplicate logical events | Count receiver attempts and logical events separately using stable event IDs. |
| Hardening becomes unbounded redesign or optional feature work | Fix reproduced in-scope defects only; escalate architecture/scope changes and leave Delivery 4 outside this MVP. |
| Process success becomes a substitute for product safety | Independently require all acceptance evidence and preserve the PRD's non-cosmetic defect boundary. |

## 05.8 Proposed Requirement Coverage and Handoff

| Requirement / AC source | Proposed phase responsibility | Existing accepted behavior / justified deferral | Risk or unapproved decision |
| --- | --- | --- | --- |
| FR-012; FR-001–011 operational/recovery portions | Integrated health, install/configure/shutdown, backup/restore, growth and upgrade guidance | Assumes future verified 01–04; no existing coverage today | Supported environment and recovery procedure remain contract inputs. |
| AC-001–012; §§5–6 | Complete candidate regression, failure/security checks, measured capacity | No scenario deferred past MVP | Exact command/environment evidence must come from implemented tooling, not this proposal. |
| §9 product acceptance | Seven-day pilot on 5–10 endpoints; distinct defect/delivery-duplicate categories | Wider demand/HA not proven | Material defects cannot be waived as cosmetic. |
| §§1, 9 workflow evaluation | Summarize records maintained from first specification review and diagnose convergence | Historical LabReserve replay separately scoped | Metrics do not affect health or replace independent review. |
| §3 exclusions; §8 Delivery 4 | Preserve explicit MVP boundary and list feedback separately | Optional dashboard/adapters/retention/multi-user remain outside MVP | New product/architecture scope needs separate decisions. |

Proposed final handoff: release-candidate revision, actual acceptance and pilot evidence, operational/recovery instructions, workflow findings, unresolved limitations, and a human acceptance decision request. This roadmap authorizes neither deployment nor publication. A scope-ready verdict and separate approved task contract are still required before implementing this phase; this file is neither one.
