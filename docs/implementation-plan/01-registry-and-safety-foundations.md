# 01. Registry and Safety Foundations

**Phase boundary:** PROPOSED; first part of PRD Delivery 1, not a standalone complete manual pilot.

**Authority:** This file is a roadmap phase, not an approved implementation task contract.

**Source requirements:** [PRD v0.1](../prd-v0.1.md) §§2–6, 8, 10; PD-001–004, PD-006; FR-001–002, FR-005, configuration portions of FR-008, FR-011–012; registry restart portion of AC-006 and policy prerequisites of AC-003/AC-011. Source revision and baseline are recorded in the overview.

**Decision gaps:** Delivery 1 must settle runtime/storage, endpoint normalization, trust-material versioning, destination policy, and CLI contract. Go/PostgreSQL are candidates, not decisions. No new Level 2 product decision is needed for this proposed decomposition; review must escalate any design that changes product authority or scope.

## 01.1 Goal

Establish a usable, persistent configuration boundary for one trusted operator without prematurely building scheduler or alert infrastructure.

```text
operator configures destination authority and roots
-> registers and edits an endpoint
-> lists its stable identity and effective settings
-> restarts and retains the configuration
```

## 01.2 Estimate

```text
3–5 engineer-days
18–30 focused hours
```

## 01.3 Scope

Included:

- Minimal runnable Linux CLI/configuration and persistence path, using separately approved technology choices.
- Stable endpoint records: label, connection host, explicit port, expected DNS/IP identity, trust profile, interval, enabled state; threshold configuration with effective values.
- Enable/disable and edit semantics that distinguish stable registration identity from a changed monitoring identity.
- System-root/custom-root profile selection, effective trust/configuration identification, and a connection-policy boundary reusable by the probe.
- Startup/configuration errors, permission-conscious local state, and focused persistence/input/policy verification.

Excluded:

- Actual TLS assessment and manual certificate reports, assigned to phase 02.
- Durable inspection history, scheduler/leases, alert state, events, webhook/backoff, dashboard, or speculative schemas for them.
- Public configuration APIs, multiple operators/roles, endpoint discovery, and all other PRD MVP exclusions.

## 01.4 Assumptions

- [ ] A separately approved Delivery 1 contract covers phases 01–02 before either is implemented.
- [ ] One trusted operator controls the local installation; there is no anonymous network-access surface.
- [ ] Architecture approval selects runtime, persistence, packaging, and permissions before setup is implemented; no existing module or migration framework is available to extend.
- [ ] Policy explicitly handles private, loopback, link-local, and metadata addresses while supporting authorized lab endpoints; this plan supplies no implicit allow-all or blanket private deny default.
- [ ] Exact CLI names, threshold placement, normalization, trust-version updates, and configuration-edit semantics are contract decisions, not inferred product amendments.

## 01.5 Ordered Tasks

### Step 1 - Establish the smallest runnable configuration path

Estimate: **0.5–1 engineer-days / 3–6 focused hours**.

- [ ] Initialize only the runtime/build/dependency structure required by the approved Delivery 1 choice; provide a reproducible CLI build and focused verification entry point.
- [ ] Load local configuration, initialize required registry persistence, and report missing/invalid configuration or inaccessible storage with actionable failures.
- [ ] Define protected local configuration/state locations without committing credentials or local environment files; make ordinary operator access explicit.
- [ ] Add a CLI smoke check and startup/storage-error regression using the selected repository-native tools. These commands must be documented once they actually exist.

Done when:

- [ ] A clean checkout can build and start the minimal CLI under the documented Linux assumptions, or fail visibly when configuration/storage is unavailable.

### Step 2 - Persist endpoints and effective trust/configuration identities

Estimate: **1.5–2 engineer-days / 9–12 focused hours**.

- [ ] Register/list endpoints with all FR-001 fields; reject malformed hosts, ports, expected identities, intervals, thresholds, and unusable trust configuration with actionable errors.
- [ ] Apply the hourly interval and 30-day warning/7-day critical defaults; enforce `0 < critical < warning` and avoid display rounding as stored assessment semantics.
- [ ] Keep connection target separate from expected identity, supporting DNS, IPv4, and IPv6 without accidentally treating a DNS identity as the connection address.
- [ ] Persist stable registration identity and enabled state across restart. A connection target, expected identity, or trust-profile change creates a new monitoring identity; label/interval/threshold edits retain effective configuration context.
- [ ] Implement system-root versus custom-root selection and the approved way to identify the actual trust material used. Do not silently substitute roots or prepare automatic CA downloads.
- [ ] Verify registration/list/edit/disable/re-enable behavior, invalid input, trust/configuration changes, and registry restart. Do not claim inspection history retention yet.

Done when:

- [ ] Restart preserves the complete registration, changes cannot silently reattribute future evidence to an old target, and selected trust context is unambiguous for the future probe.

### Step 3 - Establish and verify the destination-authority boundary

Estimate: **1–2 engineer-days / 6–12 focused hours**.

- [ ] Implement the approved policy representation and authorization seam for connection host/port and actual IPv4/IPv6 destination addresses, including DNS-resolved addresses.
- [ ] Ensure later connections can use the authorized resolved address without an unchecked second resolution or another policy bypass; validation at registration alone is insufficient.
- [ ] Verify allowed and disallowed private, loopback, link-local, metadata, and other destinations according to the approved policy, including a hostname that resolves to a disallowed address.
- [ ] Test that only operator-controlled configuration can change targets or roots, and errors expose neither secret material nor misleading persistence success.
- [ ] Document the actual build/focused-check commands and known limits. Carry the approved policy and trust identities into phase 02 rather than inventing a separate probe policy.

Done when:

- [ ] Controlled policy fixtures prove the authorization boundary, and phase 02 has a defined connection-time enforcement path. End-to-end probe-policy AC-011 remains to be proven there.

## 01.6 Phase Definition of Done

- [ ] All required endpoint fields and defaults survive restart, and malformed input fails clearly.
- [ ] Disabled state and monitoring-identity changes are explicit; no history or monitoring capability is falsely advertised.
- [ ] Effective trust/configuration context and network authority are usable by the next phase without weakening isolation.
- [ ] Focused startup, persistence, registry, and policy checks pass with recorded commands, revision, and environment.
- [ ] Only foundation scope is implemented; future scheduler/alert infrastructure is absent.

## 01.7 Risks

| Risk | Mitigation |
| --- | --- |
| Preferred technology is mistaken for approved architecture | Resolve runtime/storage in the Delivery 1 specification before implementation; keep this roadmap technology-neutral. |
| Private-lab support is blocked or metadata access becomes accidental | Explicitly decide each address-class policy and verify the actual connection boundary; do not infer permission from private addressing alone. |
| Editing a target relabels old or in-flight evidence | Distinguish registration identity, monitoring identity, and effective configuration; phase 03 must preserve these associations. |
| Mutable CA files make reports irreproducible | Contract the material identity/update behavior now; record actual trust context during inspection rather than only a mutable path. |
| Foundation grows into speculative infrastructure | Build only registry/configuration and the safety seams used by the manual pilot. |

## 01.8 Proposed Requirement Coverage and Handoff

| Requirement / AC source | Proposed phase responsibility | Existing accepted behavior / justified deferral | Risk or unapproved decision |
| --- | --- | --- | --- |
| PD-001–004, PD-006; FR-001 | Local CLI, full persisted registry, trust selection, defaults | No existing implementation | Runtime/storage, normalization, command names unresolved. |
| FR-002, FR-005, FR-011; §6 evidence integrity | Enablement and effective configuration/trust identity | Inspection/history semantics verified in 02–03 | Actual trust-material versioning must not be just a mutable filename. |
| FR-008, FR-012; AC-006 registry portion | Actionable configuration/persistence output and restart proof | Certificate reports in 02; service health in 03–05 | No invented JSON/exit-code contract. |
| §6 network authority; AC-003/AC-011 prerequisites | Policy/input boundary and fixtures | Actual probe enforcement/no-HTTP proof in 02; webhook in 04 | Address-class behavior must be approved before connection code. |

Proposed handoff: runnable registry, observed verification commands, effective identity/trust rules, policy evidence, and explicit remaining Delivery 1 obligations to phase 02. No application baseline exists today. A scope-ready verdict and separate approved task contract are still required; this file is neither one. Scope readiness should consider phases 01–02 together as the manual-pilot delivery, not mistake this foundation for its complete user outcome.
