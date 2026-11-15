# 03. Continuous Monitoring and Evidence

**Phase boundary:** PROPOSED; corresponds to PRD Delivery 2 after the manual pilot.

**Authority:** This file is a roadmap phase, not an approved implementation task contract.

**Source requirements:** [PRD v0.1](../prd-v0.1.md) §§2–8; PD-001, PD-006; FR-001–008, scheduling/history portions of FR-011–012; history/status portions of AC-001–005, AC-006, ordering portion of AC-007, status/restart portions of AC-010, probe/storage portions of AC-012. Source revision and baseline are in the overview.

**Decision gaps:** Delivery 2 contract must define storage evolution, single-active-service enforcement, attempt ordering/supersession, clock assumptions, scheduling/admission, in-flight disable/edit behavior, history access, and the controlled capacity environment. No new Level 2 product decision is identified; architecture changes or weakened evidence/network bounds require escalation.

## 03.1 Goal

Turn manual inspection into continuous, bounded monitoring whose status is supported by durable evidence rather than a stale success flag.

```text
enabled registrations become due
-> bounded shared inspection path
-> immutable completed attempts and ordered current views
-> queryable history, freshness, and service/storage health
```

## 03.2 Estimate

```text
6–10 engineer-days
36–60 focused hours
```

## 03.3 Scope

Included:

- Durable completed-inspection history, including failures and effective configuration/trust context.
- Separate latest-attempt and latest-certificate views, monitoring-identity attribution, and protection from older/superseded results.
- Hourly-default scheduling, bounded total attempt duration/concurrency, overdue restart without interval replay, and lifecycle behavior.
- Human/versioned JSON status and history, query-time freshness, basic service/last-persistence/scheduler-lag visibility, and controlled scale/failure tests.
- Upgrade compatibility for persisted manual-pilot registrations if an installation is carried forward.

Excluded:

- Alert transitions, webhook event/delivery state, replay, and external staleness notifications, assigned to phase 04.
- Distributed schedulers, multiple active monitoring services, high availability, retention pruning, or historical inspection backfill.
- New certificate checks or a dashboard beyond the approved manual assessment behavior.

## 03.4 Assumptions

- [ ] A separately approved Delivery 2 contract uses the verified manual inspection path rather than implementing a second assessment engine.
- [ ] One active monitoring service is enforced using the approved design, with manual/scheduled work coordinated sufficiently to meet ordering and resource bounds.
- [ ] The contract defines attempt/configuration ordering and clock behavior before concurrency/freshness implementation; completion order alone is not assumed sufficient.
- [ ] Controlled fixtures can stall and reorder work, simulate restart/storage failure, and exercise 100 enabled targets with healthy local storage for the capacity case.
- [ ] All completed pilot records are retained; growth is documented rather than silently pruned.

## 03.5 Ordered Tasks

### Step 1 - Retain immutable evidence and maintain ordered current views

Estimate: **2–3 engineer-days / 12–18 focused hours**.

- [ ] Extend persistence for completed manual and scheduled attempts, including failures, times, endpoint/monitoring identity, effective settings/trust, contacted address when known, certificate details when available, and all assessment/diagnostic outcomes.
- [ ] Preserve completed records unchanged and retain the context needed to interpret them after labels, intervals, thresholds, roots, or target identity change. Do not backfill invented observations for the manual-only period.
- [ ] Maintain latest attempt separately from latest certificate observation. A current failed attempt must not inherit an old certificate's success or imply a fresh expiry assessment.
- [ ] Apply the contracted ordering/supersession rule so delayed or old-identity work remains attributable history but cannot regress newer current status. Protect shared manual/scheduled updates under concurrency.
- [ ] Make evidence commit/current-view updates consistent; surface failed persistence without claiming a successfully stored check or advancing last-successful-persistence state.
- [ ] Verify immutable history, configuration/trust edits, delayed completion, concurrent manual checks, storage failures, and restart. If upgrading a Delivery 1 installation, test preservation of existing registrations with the actual selected migration mechanism.

Done when:

- [ ] Historical facts remain intact and correctly attributed while current status never regresses under deliberately reordered completion or storage failure.

### Step 2 - Schedule bounded work and implement monitoring lifecycle

Estimate: **2–4 engineer-days / 12–24 focused hours**.

- [ ] Schedule enabled endpoints at their configured interval, hourly by default, reusing the same authorized probe and default 10-second total deadline.
- [ ] Enforce the default maximum of five concurrent probes across the coordinated monitoring/manual work covered by the contract; make duplicate service startup fail or otherwise preserve the one-active-service boundary.
- [ ] Resume overdue endpoints with a current check after restart without replaying every missed interval or creating an unbounded queue.
- [ ] Stop new scheduled probes on disablement, preserve history, and prevent old/superseded in-flight work from becoming a newer monitoring identity's current evidence. Record the contracted treatment of completed in-flight attempts.
- [ ] On re-enablement, require fresh evidence: previous observations stay historical until a check in the new enabled period completes. Apply interval/configuration edits with effective context recorded.
- [ ] Test disabled targets receive no new scheduled connections, re-enable freshness, multiple missed intervals, single-active enforcement, slow probes, shared manual/scheduled admission, and clean shutdown with bounded work.

Done when:

- [ ] The service monitors enabled targets automatically, remains within resource limits, and survives lifecycle/restart races without a catch-up flood or status regression.

### Step 3 - Expose truthful history/freshness and prove Delivery 2 bounds

Estimate: **2–3 engineer-days / 12–18 focused hours**.

- [ ] Add human and versioned JSON status/history with endpoint identity, observation times, current/latest-attempt versus historical/latest-certificate evidence, validation results, expiry band, diagnostics, and disabled state.
- [ ] Derive freshness at query time: an enabled endpoint becomes stale after two configured intervals without a completed attempt in its current enabled period, or after two intervals since enablement if none has completed. Test the exact deadline and both sides of it.
- [ ] Treat a recent completed failure as current evidence of failure, not as stale or healthy. Show never-checked and disabled distinctly; after re-enable, do not reuse pre-enable observations as current.
- [ ] Ensure a query can reveal stale status while scheduling is stalled/stopped rather than relying on a cached healthy flag. Reconcile status and overdue work on restart; do not promise notifications from a stopped sole process.
- [ ] Expose monitoring-service health, last successful persistence, scheduler lag, and storage errors at the appropriate CLI/log surfaces; full operational packaging is completed in phase 05.
- [ ] Run a controlled 100-enabled-endpoint due batch, including timeout probes, with at most five concurrent attempts, the default total deadline, and healthy local storage. Record host/resources, fixture topology, clock assumptions, actual concurrency/duration, and the five-minute pass/fail result.
- [ ] Verify storage unavailability separately from the healthy-storage capacity case; extend AC-001–005 to history and run AC-006, ordering AC-007, status/restart AC-010, and probe/storage AC-012. Regress Delivery 1 policy and certificate semantics.

Done when:

- [ ] Status remains truthful with the scheduler stopped, completed-failure evidence stays current, all assigned acceptance portions pass, and the measured controlled batch meets five minutes.

## 03.6 Phase Definition of Done

- [ ] Enabled targets are checked automatically under the configured interval, deadline, concurrency, and single-active-service limits.
- [ ] All completed attempts, including failures, persist immutably with effective identity/trust context and no silent pruning.
- [ ] Latest attempt, latest certificate, historical evidence, current status, and freshness cannot be confused by timeout, restart, edit, disablement, or delayed completion.
- [ ] Delivery 2 acceptance portions and earlier regressions pass with controlled-time/concurrency evidence and measured capacity results.
- [ ] Storage failure is visible and cannot appear as successfully persisted monitoring; automatic alerts remain explicitly unavailable until phase 04.

## 03.7 Risks

| Risk | Mitigation |
| --- | --- |
| Older completion overwrites a newer/current-identity result | Contract ordering/generation rules and force delayed overlapping attempts in regression tests. |
| Restart or re-enable makes old success appear fresh | Track the current enabled period, derive freshness at query time, and require new evidence. |
| Real-time behavior differs from deterministic time fixtures | State clock assumptions and use both controlled-time semantic tests and the specified real-duration capacity measurement. |
| Storage errors advance current/persisted-success claims | Verify failure paths and atomic update boundaries, including restart after a failed write. |
| Catch-up or manual work defeats concurrency limits | Use the approved shared admission mechanism and test overdue batches with simultaneous manual work. |
| Pilot storage grows without limit | Preserve the approved all-record policy, expose failures, and document measured/estimated growth for phase 05 operations; do not add pruning. |

## 03.8 Proposed Requirement Coverage and Handoff

| Requirement / AC source | Proposed phase responsibility | Existing accepted behavior / justified deferral | Risk or unapproved decision |
| --- | --- | --- | --- |
| FR-003, FR-006–008; AC-001–007 assigned history/ordering portions | Immutable history, latest views, shared ordering, CLI status/history | Assumes future verified phases 01–02; no existing coverage today | Storage model and ordering mechanism remain unapproved. |
| FR-002, FR-011; AC-006 | Disable/re-enable, identity attribution, restart/overdue behavior | Conditions/events/pending delivery recovery in 04 | In-flight edit/disable semantics must not relabel or freshen old evidence. |
| §5 freshness; AC-010 status/restart | Query-derived staleness and restart reconciliation | External stale events in 04; no alerts while sole process is down | Clock assumptions and enabled-period handling need contract evidence. |
| PD-001, PD-006; §6 resource/history bounds; FR-012; AC-012 probe/storage | One active service, measured 100-target bound, persistence/lag health, retained history | Delivery failure health in 04; full runbooks in 05 | Exact capacity environment and repository commands must be observed at implementation time. |

Proposed handoff to phase 04: ordered committed evidence, current enabled/configuration identity, query-time freshness semantics, reusable controlled fixtures, storage-failure behavior, and actual Delivery 2 verification results. The next contract must use those facts for conditions without reopening completed-record immutability or inventing unsupported recovery. A scope-ready verdict and separate approved task contract are still required; this file is neither one.
