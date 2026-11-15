# 04. Durable Alerts and Webhooks

**Phase boundary:** PROPOSED; notification portion of PRD Delivery 3 after continuous monitoring. Delivery 3 is complete only after phase 05.

**Authority:** This file is a roadmap phase, not an approved implementation task contract.

**Source requirements:** [PRD v0.1](../prd-v0.1.md) §§2–8; PD-005; FR-009–011, alert/concurrency portion of FR-003, delivery portions of FR-008/FR-012; AC-008–009, alert portions of AC-002/AC-007/AC-010, webhook and delivery portions of AC-011–012. Source revision and baseline are in the overview.

**Decision gaps:** Delivery 3 contract must settle condition severity/recovery rules, event/payload versioning, atomic persistence design, webhook authentication/secret source, destination/redirect policy, delivery deadlines/backoff/exhaustion, and replay behavior. No new Level 2 product decision is identified; any changed delivery guarantee, authority boundary, or omission of a required condition requires escalation.

## 04.1 Goal

Convert trustworthy observations and freshness into durable, deduplicated logical events, then make failures and at-least-once delivery/replay transparent to the operator.

```text
committed evidence or reconciled staleness
-> independent condition transition + durable event
-> bounded HTTPS delivery with stable event ID
-> visible acceptance, retry, exhaustion, or replay
```

## 04.2 Estimate

```text
6–10 engineer-days
36–60 focused hours
```

## 04.3 Scope

Included:

- Independent expiry, identity, path-validation, reachability/negotiation, and monitoring-staleness conditions.
- One event per opening, severity change, or evidence-supported recovery, with transition/event atomicity and concurrency idempotence.
- One operator-configured generic HTTPS webhook destination, stable event IDs, durable delivery state, transient retry, visible exhaustion, and operator replay.
- Restart/crash/ambiguous-receiver recovery, disablement behavior, secret redaction, verified webhook TLS, and delivery failure/persistence health.

Excluded:

- Email/Slack/Telegram adapters, multiple destinations, acknowledgement/escalation routing, exactly-once receiver processing, or proof a human read a notification.
- External alerts while the only TLSBeacon process is down, distributed delivery workers, HA, or new certificate/availability checks.
- Optional expansion, retention policy, UI dashboard, and broader rollout outside the first lab MVP.

## 04.4 Assumptions

- [ ] Phase 03 provides committed immutable evidence, current identity/order, enabled-period context, and query/restart freshness semantics.
- [ ] A separately approved Delivery 3 contract defines exact payload/state/backoff behavior and the atomic transition/event boundary without weakening the PRD's stable-ID guarantee.
- [ ] A controlled HTTPS receiver can accept then withhold a response, fail transiently/permanently, and record IDs without exposing real webhook secrets.
- [ ] Delivery work has explicit concurrency/deadline/retry bounds specified by its contract; the 10-second probe default is not automatically a webhook transport rule.
- [ ] Inspection's ability to observe invalid certificates never disables webhook certificate verification or authorization of the actual receiver address.

## 04.5 Ordered Tasks

### Step 1 - Persist independent conditions and transition events atomically

Estimate: **2–3 engineer-days / 12–18 focused hours**.

- [ ] Define and implement the required condition families against the contracted evidence/freshness rules, preserving independent certificate, transport, and monitoring-staleness findings.
- [ ] Emit one logical event for a condition opening, severity change, or supported recovery; repeated unchanged results create no event. Apply idempotence under concurrent manual/scheduled results and staleness reconciliation.
- [ ] Do not recover a certificate condition from timeout, another unavailable assessment, endpoint disablement, or a different monitoring identity. A positively observed new leaf may recover expiry while identity/path problems remain open.
- [ ] Persist each condition transition with its stable event ID and corresponding event atomically. Retain original occurrence time, relevant identity/context, and evidence association through retries and restarts.
- [ ] Stop new monitoring alerts for disabled endpoints without treating disablement as recovery. Preserve old events and condition history; reconcile re-enable and new monitoring identities without attributing old evidence to them.
- [ ] Verify repeated warning, escalation, exact threshold behavior, timeout without false recovery, independent positive recovery, delayed overlapping checks, disablement, and stale/restart reconciliation. Inject failure at the transition/event commit boundary.

Done when:

- [ ] AC-008 and alert portions of AC-002/AC-007/AC-010 pass, and no committed transition can exist without its durable logical event.

### Step 2 - Deliver events through a protected, durable HTTPS path

Estimate: **2–4 engineer-days / 12–24 focused hours**.

- [ ] Configure one generic HTTPS webhook under operator authority, with protected secret storage and redaction across configuration display, errors, reports, logs, and persisted diagnostics.
- [ ] Send the contracted versioned payload with stable event ID, original occurrence time, endpoint/monitoring context, and actionable condition evidence. Do not invent a second logical event for a delivery attempt.
- [ ] Keep webhook TLS verification enabled and enforce destination policy on resolved/connected addresses. Resolve redirect handling and any webhook custom-trust behavior in the contract; inspection trust exceptions must not leak into this transport.
- [ ] Persist pending, receiver-accepted/successful, and exhausted delivery state plus useful attempt diagnostics; distinguish accepted by receiver from read by a human.
- [ ] Retry transient failures under the contracted bounded deadline, concurrency, backoff, and exhaustion rules. Persist retry eligibility across restart and keep the same event ID after ambiguous responses.
- [ ] Report storage failure rather than falsely marking an event durably queued or delivered. If receiver acceptance cannot be persisted, preserve ambiguity and allow same-ID retry instead of asserting reliable local success.
- [ ] Verify successful acceptance, transport/TLS rejection, transient retries, exhaustion, DNS-to-disallowed receiver address, and secret redaction. Regress the independent inspected-endpoint policy and invalid-certificate behavior.

Done when:

- [ ] A transition reaches the controlled receiver, retries remain bounded/durable with the same ID, transport authority remains intact, and failure is visible without false persisted-success claims.

### Step 3 - Expose replay and prove crash/disablement behavior end to end

Estimate: **2–3 engineer-days / 12–18 focused hours**.

- [ ] Add human/versioned JSON inspection of events and pending, accepted, or exhausted deliveries, including actionable failure information without secrets.
- [ ] Provide operator replay for failed/exhausted deliveries under the approved contract, preserving the event ID and occurrence time instead of creating a new logical event.
- [ ] Crash after event creation but before delivery, restart, and verify the event remains eligible; separately have the receiver accept then time out the response and prove retries reuse the ID even if receiver-level delivery is duplicated.
- [ ] Disable an endpoint with queued/exhausted events: verify no new scheduled probes or monitoring alerts, no false recovery event, and continued visibility/delivery eligibility for old events.
- [ ] Inject storage unavailability during event/attempt/result persistence and verify health/output cannot claim lost events are durable or unrecorded acceptance is durably successful.
- [ ] Run AC-009, event-deduplication AC-007, notification portions of AC-010–012, and prior acceptance regressions. Document actual command/environment evidence and the at-least-once/deduplication limitations.

Done when:

- [ ] Restart, ambiguous acceptance, replay, disablement, and storage failure preserve logical identity and visibility; receiver duplication is distinguishable from duplicate logical events.

## 04.6 Phase Definition of Done

- [ ] Every required condition family opens, changes severity, and resolves only on its supported evidence; unknown findings never falsely recover certificate problems.
- [ ] Condition transitions and events are atomic, ordered, durable, and idempotent under concurrent/replayed observations.
- [ ] One verified HTTPS destination receives stable IDs across retry, restart, and operator replay, with pending/accepted/exhausted state visible.
- [ ] Disablement stops new monitoring alerts without deleting history, recovering conditions, or discarding previously created deliveries.
- [ ] Assigned AC portions pass under controlled crash, storage, receiver, TLS, and destination-policy fixtures; webhook secrets remain absent from output.
- [ ] The normal notification path is automatic, but complete MVP/release acceptance remains assigned to phase 05.

## 04.7 Risks

| Risk | Mitigation |
| --- | --- |
| Alert state commits without an event, or retry creates a second event | Verify one atomic transition/event boundary and stable-ID reuse under commit failure, restart, and replay. |
| A timeout/disablement incorrectly closes an expiry alert | Preserve per-condition assessment availability and test independent unsupported/supported recovery. |
| Staleness processing promises alerts from a stopped service | Derive queried status independently and reconcile on restart; explicitly document the sole-process limitation. |
| Receiver accepted a request but TLSBeacon cannot know/persist it | Represent ambiguity, retry with the original ID, and document receiver deduplication; never claim exactly-once. |
| Redirects, resolution, or inspection settings bypass webhook security | Contract receiver authority/redirect behavior, enforce actual addresses, and keep TLS validation separate from inspection. |
| Endpoint edits or disable/re-enable races corrupt condition attribution | Bind conditions/events to effective monitoring identity and enabled state; retain old occurrence/context without fabricated recovery. |

## 04.8 Proposed Requirement Coverage and Handoff

| Requirement / AC source | Proposed phase responsibility | Existing accepted behavior / justified deferral | Risk or unapproved decision |
| --- | --- | --- | --- |
| FR-009; AC-008; alert portions AC-002/AC-007/AC-010 | Independent conditions, atomic/idempotent transitions, supported recovery and staleness events | Assumes future verified phase 03; no existing coverage today | Exact severity/reconciliation rules require the later contract. |
| PD-005; FR-010; AC-009 | Durable single-webhook delivery, retry/exhaustion/replay, stable IDs | Human acknowledgement/exactly-once intentionally not promised | Payload, secret source, backoff, deadlines unapproved. |
| FR-011; §6 evidence/notification boundaries | Restart and disablement preserve conditions/events and old delivery eligibility | Full operational backup/restore proof in 05 | Disablement cannot create recovery or discard queued events. |
| FR-003/FR-008/FR-012; AC-011–012 webhook/storage portions | Event/delivery CLI, concurrency deduplication, secret/policy/TLS protection, failure health | Final all-scenario release proof in 05 | Storage failure cannot become a false durable-success claim. |

Proposed handoff to phase 05: event/delivery state semantics, actual fault-injection and acceptance evidence, receiver deduplication guidance, redaction/policy coverage, and recovery/operational limitations. No broader adapter or acknowledgement design is implied. A scope-ready verdict and separate approved task contract are still required; this file is neither one.
