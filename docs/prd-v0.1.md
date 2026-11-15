# TLSBeacon Product Requirements Document

**Version:** 0.1 — Approved  
**Date:** 10 November 2026  
**Product owner:** Merizrizal

**Project name:** TLSBeacon

**Status:** Approved by the product owner. This approval covers the product requirements, scope, decisions, and defaults in this PRD; it is not approval of an architecture or implementation contract.

## 1. Purpose and first user

TLSBeacon helps an infrastructure operator detect certificate expiry, identity mismatches, and certificate-path validation failures on explicitly configured TLS endpoints. It preserves inspection evidence and delivers actionable notifications. It observes certificates; it does not issue, renew, install, or repair them.

The first intended user is Merizrizal operating a private infrastructure lab. The pilot should answer: “Which configured endpoints need attention, what did TLSBeacon actually observe, and when?” Broader customer demand remains a hypothesis to test after the pilot.

There are two separate success criteria: the product must provide useful, trustworthy monitoring, and the engineering workflow must deliver it with proportionate planning and convergent reviews. Process metrics must not change the product's health assessments.

## 2. Product decisions

| Decision | First-release boundary | Reason |
| --- | --- | --- |
| PD-001 Operator and deployment | One trusted operator, one self-hosted Linux installation, one active monitoring service | Fits the lab pilot and bounds identity and concurrency requirements. |
| PD-002 User interface | CLI for configuration, manual inspection, status, and history; machine-readable JSON output | Supports immediate operational use and automated verification. A dashboard is later scope. |
| PD-003 Endpoint protocol | Direct TLS over TCP, initially for HTTPS-style server endpoints, with DNS names or IPv4/IPv6 addresses and an explicit port | Covers a useful subset without protocol-specific negotiation. No HTTP request is required for inspection. |
| PD-004 Trust | System root certificates or an explicitly selected custom CA bundle | Internal CA support is essential for the lab. Custom trust must never be silently broadened. |
| PD-005 Notifications | One generic HTTPS webhook destination per installation | Gives a usable integration boundary without separate email, Slack, or Telegram adapters. |
| PD-006 Initial scale | Up to 100 enabled endpoints; hourly checks by default | A pilot target, not a measured capacity claim. |

Go and PostgreSQL remain preferred architecture candidates, not approved architecture choices. PD-001–006 are approved product decisions. This PRD does not approve a runtime version, schema, package structure, or specific scheduling mechanism.

## 3. User journey and scope

The operator starts TLSBeacon, configures the permitted network destinations and trust roots, and registers an endpoint. A manual inspection shows the certificate information and any validation problems. The background service repeats inspections, retains their history, and sends a webhook when a monitored condition opens, changes severity, or resolves. The operator can inspect failed notification deliveries and retry them.

The first complete MVP includes endpoint registration, manual and scheduled checks, durable history, status and freshness reporting, internal CA support, and durable webhook delivery. Delivery 1 is a useful manual inspection pilot; it is not yet the complete monitoring MVP.

Out of scope for the MVP: certificate issuance or renewal, ACME, remediation, private-key storage, endpoint discovery or subnet scanning, public signup, multiple tenants, user-role management, a browser dashboard, STARTTLS, QUIC, authenticated client-certificate sessions, revocation checking, Certificate Transparency analysis, cipher grading, and general application availability monitoring. Approaching expiry of intermediate CA certificates is also later scope; an already-invalid chain must still fail path validation.

## 4. Functional requirements

| ID | Required product behavior |
| --- | --- |
| FR-001 Endpoint registry | Register and list stable endpoint records with a label, connection host, port, expected DNS name or IP identity, selected trust profile, check interval, and enabled state. Reject malformed input with an actionable error. Persist configuration across restarts. |
| FR-002 Endpoint lifecycle | Enable or disable monitoring without erasing history. Display disabled endpoints distinctly. Connection target, expected identity, and trust-profile changes create a new monitoring identity so old evidence is not silently attributed to a different target. Labels, intervals, and thresholds may change with effective configuration recorded. |
| FR-003 Manual inspection | Inspect a selected endpoint on demand. Distinguish DNS, connection, timeout, TLS negotiation, and certificate-validation outcomes. A manual and scheduled check of the same endpoint must not corrupt status or create duplicate logical alerts. |
| FR-004 Certificate assessment | Report the observed leaf certificate's fingerprint, issuer, subject alternative names, validity dates, and remaining lifetime. Evaluate leaf time validity, expected identity, and certificate-path validity for server authentication. Preserve each known result; mark unavailable assessments explicitly. |
| FR-005 Trust context | Associate results with the trust material and configuration used. A custom profile uses its configured roots without silent system-root fallback. Do not download missing intermediates or roots automatically in the MVP. A chain-building failure must not assert an unproven cause such as “missing intermediate.” |
| FR-006 Scheduled checks | Check enabled endpoints at their configured interval with bounded concurrency and a bounded attempt duration. On restart, resume monitoring and perform a current check for overdue endpoints without replaying every missed interval. Older or superseded work must not overwrite newer current status. |
| FR-007 Evidence and freshness | Retain timestamped completed inspections, including failed attempts, certificate details when available, configuration/trust context, and diagnostic outcomes. Show latest attempt separately from the latest certificate observation. Historical success must not appear as current success after a failed or overdue check. |
| FR-008 Operator output | Provide human-readable and versioned JSON status/history output. Include endpoint identity, observation time, freshness, validation results, expiry band, and actionable diagnostics. Specify exit-code behavior in the Delivery 1 contract so scripts can distinguish execution failures from completed inspections with adverse findings. |
| FR-009 Alert lifecycle | Track expiry, identity, path-validation, reachability/negotiation, and monitoring-staleness conditions. Create one logical event for an opening, severity change, or supported recovery. Repeated observations of an unchanged condition create no new event. An unavailable assessment cannot resolve an existing certificate problem. |
| FR-010 Webhook delivery | Persist events and delivery state, send a stable event ID with each payload, retry transient failures, and expose pending, successful, and exhausted deliveries. Retries and operator replay retain the event ID. Local state must distinguish receiver acceptance from proof that a human read a notification. |
| FR-011 Recovery and disablement | Restart preserves completed history, current conditions, and pending deliveries. Disabling an endpoint stops new scheduled probes and new monitoring alerts; it is not a recovery. Previously created events remain visible and eligible for delivery with their original occurrence time. Re-enabling requires a fresh check. |
| FR-012 Operability | Provide startup/configuration errors, monitoring-service health, last successful persistence, scheduler lag, and delivery failures. Document installation, configuration, backup and restore, and shutdown. Storage failures must not be reported as successfully persisted checks or delivered events. |

## 5. Interpretation of results

An observation describes one connection from the TLSBeacon host at a particular time. It does not prove that every load-balancer backend, DNS answer, network location, or end-user connection presents the same certificate. Record the contacted address when available.

Use separate result dimensions rather than allowing one “healthy” flag to hide missing evidence:

| Dimension | Meaning |
| --- | --- |
| Observation | Certificate observed, or a specific failure before sufficient evidence was available |
| Leaf time validity | Valid, not yet valid, expired, or not assessed |
| Service identity | Match, mismatch, or not assessed |
| Certification path | Pass, fail with supported diagnostic, or not assessed; includes applicable path constraints and validity checks |
| Expiry band | Normal, warning, critical, expired, or not assessed for the observed leaf |
| Freshness | Current, stale, never checked, or disabled |

“Healthy” requires a current observation with all in-scope validation checks passing and no expiry warning. It means healthy under the selected checks and trust profile, not a complete security assessment. Revocation status is explicitly “not checked.”

Defaults: warning at 30 days remaining or less; critical at 7 days or less. One day means 24 hours; classification uses the actual remaining duration, not a rounded display value. Thresholds require `0 < critical < warning`. Certificate validity includes both `notBefore` and `notAfter`; an observation after `notAfter` is expired, while exactly `notAfter` is critical with zero remaining lifetime. A not-yet-valid certificate remains invalid regardless of its future expiry. Identity matching uses appropriate subject alternative names, without legacy Common Name fallback. [1][2]

A timeout produces an unavailable current assessment, even if a previous observation contained an expired certificate. Show both facts with their timestamps. A newly observed certificate may resolve an expiry condition while an independent identity or path condition remains open.

Freshness rule: an enabled endpoint is stale after two configured intervals without a completed attempt, or after two intervals since its most recent enablement if no attempt has completed in that enabled period. A recent failed attempt is current evidence of failure, not stale evidence and not a healthy endpoint. After re-enablement, retained results remain historical until a new check completes.

## 6. Reliability and security boundaries

- **Target behavior:** Inspection performs DNS resolution and bounded TLS probing only. It sends no application requests, credentials, or configuration changes to monitored endpoints. A target may still record connection logs; “read-only” does not mean zero observable side effects.
- **Network authority:** Only the trusted operator may configure targets, trust profiles, or webhook destinations. Runtime connections must obey an operator-defined destination policy, including resolved addresses. No anonymous network-access API. The Delivery 1 contract must define policy handling for private, loopback, link-local, and metadata destinations before implementation.
- **Secret handling:** No monitored server private keys or client credentials are required. Protect webhook secrets and redact them from reports and logs. Webhook TLS verification remains enabled even when inspected endpoints have invalid certificates.
- **Evidence integrity:** Keep completed inspection records immutable. Bind results to the effective endpoint configuration and trust context. Atomicity must prevent a committed alert transition from losing its corresponding durable event.
- **Notification semantics:** Durable retries provide at-least-once delivery attempts, not guaranteed delivery or exactly-once receiver processing. A receiver can deduplicate by event ID. An ambiguous response may cause the same event to be delivered twice; it must not create a second logical event.
- **Resource bounds:** Defaults are a 10-second total probe deadline and at most five concurrent probes. For the 100-endpoint target, complete one due batch within five minutes in a controlled timeout test with healthy local storage. The contract must specify the test environment and clock assumptions.
- **History:** Retention is all completed records during the pilot, with no silent automatic pruning. Document expected growth and expose storage failures. A retention policy can be a later product decision.

## 7. Acceptance scenarios

These are required future evidence, not claims that tests have run. Certificate cases use locally controlled fixtures and a controlled validation time; no dependency on public websites.

| ID | Scenario and expected observable result | Requirements |
| --- | --- | --- |
| AC-001 | A trusted, matching, currently valid certificate beyond the warning threshold is reported healthy with a timestamp and fingerprint. | FR-003–008 |
| AC-002 | Check just before, at, and after both validity boundaries and both expiry thresholds. Results follow the stated inclusive validity and unrounded-duration rules. | FR-004, FR-008–009 |
| AC-003 | Wrong DNS identity, wrong IP identity, and Common-Name-only identity do not pass. An explicit DNS identity is checked even when connecting to an IP address. | FR-001, FR-004 |
| AC-004 | A private-CA endpoint fails under unrelated roots and passes under its intended custom roots. Missing intermediate, expired intermediate, and unrelated trust-anchor fixtures fail without unsupported causal claims. | FR-004–005 |
| AC-005 | DNS failure, refusal, timeout, and TLS negotiation failure retain distinct diagnostics. No new certificate-expiry conclusion is inferred without certificate evidence; earlier observations remain timestamped history. | FR-003–008 |
| AC-006 | Restart preserves registrations and completed history. Disabled endpoints are not probed; re-enabled endpoints require fresh evidence. Overdue checks resume without a catch-up flood. | FR-001–002, FR-006–007, FR-011 |
| AC-007 | Concurrent manual/scheduled checks and delayed completion cannot regress current status or produce duplicate logical events. Results remain bound to their effective configuration. | FR-003, FR-006–009 |
| AC-008 | Repeated warning results create one opening event; escalation creates one new transition event. A later timeout does not falsely recover the expiry condition. Positive fresh evidence can resolve it. | FR-009 |
| AC-009 | Crash after event creation and timeout after receiver acceptance preserve the event and its ID across retry. Exhausted delivery is visible and replayable. | FR-009–012 |
| AC-010 | A stopped or stalled scheduler produces stale status when queried after the freshness deadline. On restart, reconcile staleness and resume checks. No external alert is promised while the only TLSBeacon process is down. | FR-006–009, FR-012 |
| AC-011 | Disallowed destinations are rejected at connection time, including DNS resolution to a disallowed address. Inspection sends no HTTP application request; webhook secrets do not appear in output. | FR-003, FR-010, security boundaries |
| AC-012 | The bounded 100-endpoint test meets the five-minute batch target. Storage unavailability is visible and cannot yield false persistence/delivery success. | FR-006–007, FR-010–012 |

## 8. Delivery boundaries

These are product milestones, not a competing implementation ladder. Each delivery needs a bounded contract and one controlling implementation plan when implementation begins.

| Delivery | Useful outcome | Included scope and evidence |
| --- | --- | --- |
| 1 Manual inspection pilot | Register a lab endpoint and obtain a trustworthy manual report | Registry persistence, lifecycle controls, direct TLS inspection, custom trust, CLI/JSON, network authority. Manual-report portions of AC-001–005, probe-policy portion of AC-011, and registry restart behavior from AC-006. History, scheduling, and notification portions remain assigned to later deliveries. |
| 2 Continuous monitoring | Leave TLSBeacon running and inspect its history and freshness | Scheduling, durable inspection history, effective configuration identity, current-status ordering, disable/re-enable behavior, bounded resource use. Remaining history portions of AC-001–005, AC-006, ordering portion of AC-007, status/restart portions of AC-010, probe/storage portions of AC-012. |
| 3 Notifications and first MVP release | Receive actionable events with durable delivery and recovery | Alert lifecycle, webhook, retry/replay, crash recovery, service health and installation/backup guidance. AC-008–009, alert portions of AC-002 and AC-007, and remaining portions of AC-010–012; regression of all earlier acceptance scenarios. |
| 4 Optional expansion | Improve usability after pilot feedback | Dashboard and any additional adapters, retention, or multi-user capability require separate scope decisions. They are not necessary for the first MVP. |

## 9. Product and workflow evaluation

Product acceptance requires all MVP scenarios to pass against the release candidate, plus a seven-day lab pilot using 5–10 deliberately selected endpoints. Record incorrect assessments, unexplained stale periods, missing logical events, duplicate logical events, and receiver-level delivery duplicates separately. No known defect that misstates certificate health, loses committed events, or exceeds network authority may remain accepted as a harmless cosmetic issue. The pilot is usability evidence, not proof of high availability.

Track workflow measures from the first specification review:

| Measure | Record |
| --- | --- |
| Planning effort | Elapsed time and active human time from selected scope to implementation readiness |
| Review convergence | Initial blockers, remediation rounds, reopened findings, and newly introduced blockers with their justification |
| Finding quality | Stable ID, source requirement, evidence, closure criterion, disposition, and whether future-stage evidence was incorrectly demanded |
| Decision authority | Level 0/1/2 classifications and the reason for each human escalation |
| Delivery quality | Requirement-driven rework, escaped defects, unresolved findings, and human interventions |

After two remediation rounds for the same bounded specification, inspect why convergence is failing. This is a process diagnostic trigger, not automatic acceptance and not a hard review cap. A revised workflow's success on TLSBeacon does not by itself establish improvement over LabReserve; a separately scoped historical replay would support comparison.

## 10. Next boundary

The approved product direction includes PD-001–006 and the MVP boundary. In particular, the user-facing choices are CLI-first operation, direct TLS without client credentials, and one generic webhook destination. Approval of this PRD does not approve a repository, architecture, or implementation baseline.

Define Delivery 1's bounded contract, resolving endpoint normalization, output/exit semantics, trust-material versioning, network-policy behavior, supported TLS behavior, and verification fixtures. Keep scheduler leases, notification backoff, and dashboard design out of that first contract. Independent scope/specification review should evaluate only the evidence appropriate to that stage.

## References

The attached previous-session proposal supplies the project rationale. The following technical references support the certificate semantics; release boundaries and numerical defaults above are approved product decisions.

1. [RFC 5280, section 4.1.2.5](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5): certificate validity includes both endpoints of the validity interval.
2. [RFC 9525, sections 4.1 and 6](https://www.rfc-editor.org/rfc/rfc9525.html): service-identity verification uses the relevant subject alternative names; the subject Common Name is not the service-identity fallback.
3. [Go crypto/x509 Certificate.Verify](https://pkg.go.dev/crypto/x509#Certificate.Verify): path verification uses configured roots/intermediates and does not perform revocation checking. This supports keeping revocation explicitly separate from the proposed Go implementation's basic validation.
