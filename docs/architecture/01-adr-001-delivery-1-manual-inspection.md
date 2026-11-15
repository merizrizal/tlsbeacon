# ADR-001 — Delivery 1 authorized manual TLS inspection

**Status:** APPROVED AND ACCEPTED by the user. Not execution authority; verify Git state separately.

**Approval record:** The user explicitly accepted and approved this ADR and its paired task contract in the current conversation, following the independent INITIAL draft specification review, which returned `DRAFT_SPEC_READY` with no blocking findings. Approval covers the reviewed candidate contents, including the Go/PostgreSQL architecture, TLS compatibility, trust-refresh, normalization, network policy and CLI/exit choices, not subsequent substantive changes.

**Reviewed candidate:** Before these approval-record updates, this ADR had SHA-256 `e0fa561f5f509bf40a33a86d1810ca40ddb3109375cf1454575d512a4f96af27` and the paired contract had SHA-256 `a643c2505832c1a0df330bad6797499105587d39aa21268e47e6936882fc2550`, on `main` at HEAD `376af5074b4fc1a8827cd54f46c399e1b3089e13`, tree `069882aa5a4466e921982c58bf4f873d529a43fc`. Both files were untracked. These hashes identify the reviewed content, not the files after recording approval.

**Boundary:** Approval does not commit either document, authorize an implementation plan, preflight, execution, infrastructure provisioning or deployment, or establish that any product tests passed. Subsequent substantive changes require appropriate revalidation and approval.

**Scope:** PRD Delivery 1, spanning approved roadmap phases 01–02 together.

**Origin:** AUTHORITATIVE_SPECIFICATION_AUTHORING; subsequently independently reviewed and approved as recorded above.

**Related contract:** [Delivery 1 task contract](../tasks/01-delivery-1-manual-inspection-contract.md).

## 1. Context, authority and observed baseline

The [approved PRD](../prd-v0.1.md) governs product behavior. The [overview](../implementation-plan/00-implementation-overview.md), [phase 01](../implementation-plan/01-registry-and-safety-foundations.md) and [phase 02](../implementation-plan/02-trustworthy-manual-inspection.md) are accepted scope planning, not implementation. This ADR's architecture decisions were subsequently approved as recorded above; the roadmap and PRD alone did not approve them.

At authoring start, `main` was clean, including staged, unstaged, untracked and ignored status, at HEAD `376af5074b4fc1a8827cd54f46c399e1b3089e13`, tree `069882aa5a4466e921982c58bf4f873d529a43fc`. Its complete parent diff contains only approval records in the three accepted roadmap files. Their recorded accepted candidate is parent `ea045cd39ee7aee8e67b2d5c11964573590a40df`, tree `ca46327127abe09e23323833c7af5709626d4262`. The overview explicitly qualifies older uncommitted-rename statements as historical provenance. They are not the present state.

At authoring time, inventory and relevant Git history contained no accepted ADR, legacy task contract, application code, schema, migration, tests, build manifest, CI or documentation-check entry point. The existing `docs/architecture/`, `docs/tasks/` and `docs/chunked-implementation/` directories were empty. There is no accepted implementation to preserve or executable baseline to test. These filenames and document IDs are proposed conventions, not discovered prior conventions.

At authoring time, the user had explicitly authorized draft specification authoring only. The paired external instruction/handoff were read completely and independently checked against primary sources. The earlier `SCOPE_READY` response is reported in the handoff and overview but its full digest is not accessible as a saved report; this ADR does not reconstruct it or claim independent closure of prior findings. PRD rationale from the referenced previous-session proposal and external RFC/library pages was not retrieved. The PRD itself specifies the binding certificate semantics; this design does not assert unverified library behavior.

## 2. Approved-decision fidelity and document allocation

Sources in this table are PRD sections/IDs; the PRD did not itself approve the architecture decisions below. Those decisions were subsequently approved as recorded above. Rationale is documented in PRD §2; engineering consequences here are the author's reasoning.

| Source | Affirmative rule and preserved invariant | Negative boundary | ADR location | Task location and required future evidence |
| --- | --- | --- | --- | --- |
| PD-001; §§1, 6 | One trusted operator, local Linux installation; later one active monitoring service | No anonymous network API, tenants or roles | §§3, 6, 9 | §§1–2, 6, V-01/V-07: local authority and protected state |
| PD-002; FR-008 | CLI and human/versioned JSON output | No dashboard; output must not conceal unknown evidence | §8 | §7, V-09: parsed JSON/human/exit equivalence |
| PD-003; FR-001/003 | DNS/IPv4/IPv6, explicit TCP port, separate expected identity; direct TLS | No HTTP/application request, STARTTLS, QUIC or client credentials | §§4, 7 | §§3, 6–7, V-02/V-08: target/identity and listener evidence |
| PD-004; FR-005 | Selected system roots or exclusive custom roots; actual trust attribution | No fallback to system roots for custom trust; no root/intermediate download | §5 | §§3, 6–7, V-03/V-05: immutable roots, custom isolation and diagnostics |
| PD-006; §5 | Hourly default; warning 30 days, critical 7 days; 24-hour days; `0 < critical < warning` | Target of 100 is not measured capacity or a registration cap | §§4, 10 | §§3, 8–9: exact defaults now; scale proof deferred to Delivery 2 |
| FR-001/002; registry FR-011/012 | Durable stable registrations, explicit lifecycle, new monitoring identity on target/identity/trust change; effective context on other edits | No erasure or reattribution of evidence; no false storage success | §§4–5, 9 | §§3, 6–7, V-01/V-02/V-03: restart, no-op, rollback and edits |
| FR-003/004; §5 | Independent observation, leaf time, SAN identity, server-authentication path, expiry and applicable freshness; contact address/time/certificate details | No CN fallback, unsupported chain-failure cause or inferred certificate result from missing evidence | §§7–8 | §§6–7, V-04/V-05/V-06: controlled-time certificates and failures |
| §§5–6; AC-011 probe portion | Operator policy controls actual resolved connection addresses; total 10-second default | No second-resolution bypass, accidental private-lab denial or implicit unrestricted egress | §§6–7 | §6, V-07/V-08: address classes, retries, no payload/credentials, one budget |
| §8; FR-006–012 future portions | Preserve later history, ordering, freshness, events, recovery and operations obligations | Do not scaffold them or waive them in the manual pilot | §§9–10 | §§5, 8–9: explicit Delivery 2/3 assignments |

## 3. Approved architecture and integration seams

**Approved architecture:** one local Go CLI using PostgreSQL for the registry, trust-profile versions and destination-policy configuration. The PRD identified these as preferred candidates; the user's subsequent approval of this ADR selects them for Delivery 1. No database has been provisioned, dependency installed or runtime version selected by this documentation action.

The implementation plan must record a supported, security-maintained Go toolchain and PostgreSQL version, Linux root-source locations, dependency versions and reproducible build/check entry points. Exact maintained versions and package layout are Level 1 selections after this architecture is approved; no version availability is claimed here. A different runtime/storage topology requires an explicit ADR revision/approval, not a silent executor substitution. Use ordinary local installation assumptions; do not introduce containers, cloud infrastructure or a database administration platform merely for this pilot.

Approved conceptual seams, not prescribed package names or function signatures:

- Registry/configuration operations validate, canonicalize and atomically commit complete changes.
- A trust loader supplies an immutable, enumerable selected root set and its material identity.
- An authorized dialer receives the effective policy, resolves once per authorized candidate set, validates every actual address and connects to numeric socket addresses.
- A probe consumes an immutable endpoint/configuration/trust/policy snapshot and one total deadline.
- Assessment consumes observed evidence and one validation instant; rendering consumes its independent dimensions, never re-derives health from a rounded string.

No scheduler, history repository, event bus, webhook transport, lease schema or second assessment engine is part of these seams. A later single controlling implementation plan is separately authorized work; this ADR and its task contract contain no execution ladder.

## 4. Approved endpoint and lifecycle contract

The task contract §3 supplies exact input rules. In summary:

- An opaque, never-reused registration ID identifies the operator's record. Labels need not be unique; identical targets may be separately registered. The 100-endpoint target is not a hard registry limit.
- An opaque monitoring ID changes whenever canonical connection host/port, expected identity, or selected trust profile/version/material changes, including reverting to a former target. Old IDs are not repurposed. Label, interval, threshold or enabled-state edits alone retain monitoring ID.
- Every actual endpoint edit creates an effective configuration revision. Canonically unchanged edits are no-ops: no new revision, monitoring ID, update timestamp or write. Enable/disable already in that state is also a no-op. No audit/event stream is added in Delivery 1.
- Required creation inputs are label, connection host, explicit port, expected identity and selected trust profile/version. Interval defaults to one hour, enabled defaults to true, warning/critical default to 30/7 days. All effective values are listed and reported; these defaulting/input choices were approved with this ADR, not established as additional pre-existing PRD decisions.
- Normalize DNS case/trailing root dot and IDNA non-transitional Unicode equivalents; parse IP addresses structurally, not by permissive legacy numeric address heuristics. Preserve original operator spelling for display. Support scoped IPv6 connection addresses where an interface is necessary; scope is not part of SAN identity. No arbitrary short length cap, label uniqueness or new endpoint-count cap is imposed.
- Enablement is durable configuration, not a claim that monitoring already runs. Disabled records are visibly disabled. Explicit manual inspection remains allowed while disabled: it is not a scheduled probe, re-enablement or recovery, and cannot yield a monitoring-healthy claim. Later automatic scheduling must not probe disabled records.

Edits never mutate a captured in-flight snapshot. A report identifies the configuration actually used even if the registration changes during the attempt. No persisted current-status ordering or historical-record model is invented now.

## 5. Approved trust selection and material identity

A trust profile has a stable ID and immutable material versions. A version contains the exact parsed CA certificate DER set used as roots, its source mode (`system` or `custom`), and a deterministic SHA-256 root-set identity. Hash an unambiguous length-delimited, sorted, deduplicated DER representation; also record source-file digests where applicable. A mutable filename, bundle label, OS label or modification time alone is not a material identity.

- Importing a custom CA bundle captures a protected local snapshot. Use only those roots. An unreadable/malformed/empty or private-key-containing bundle is an actionable configuration error, not a reason to use system roots. Do not silently drop malformed entries or broaden roots. Root expiry is not a configuration success criterion: an expired-root fixture can be imported and then fail assessment truthfully.
- A `system` import captures the configured Linux system-root sources into an explicit enumerable root set. The supported Linux installation must document those sources. Do not combine an opaque platform verifier/root pool with a digest of a different bundle and claim attribution to the actual roots used.
- Source files may later change. Refresh explicitly imports a new immutable version; it does not silently activate it for endpoints. Canonically identical material refresh is a no-op. Endpoint selection of a new profile/version is explicit and changes monitoring identity. This applies to system-root refresh too: reports show the selected snapshot, not an assertion that it tracks every later OS trust update.
- Reports bind to profile ID, material version/digest, source mode and actual effective roots. The selected set is loaded once for the attempt; a file change mid-attempt cannot swap its trust. Peer-supplied intermediates are candidates, not automatically trusted roots. No AIA/root fetching, implicit unrelated caches, system fallback for custom profiles or revocation request is allowed.

Tradeoff: explicit versions make attribution reproducible but require operator refresh/selection after trust changes. Document this clearly in manual-pilot instructions. Do not store private keys or require monitored-server/client secrets.

## 6. Approved destination policy and authority boundary

The trusted local operator configures a versioned policy. No anonymous service or remote configuration API exists. The approved representation is an explicit allowlist of numeric IPv4/IPv6 CIDRs, TCP ports and acknowledged address classes, optionally narrowed by canonical configured target and IPv6 interface scope. Explicit deny rules take precedence; no matching allow rule means denied. A missing/malformed policy is an execution/configuration failure. A valid empty policy permits no target connections; it is not an implicit private-network ban because the operator can explicitly authorize lab destinations.

| Address class | Approved behavior |
| --- | --- |
| Public/global unicast | Requires a matching address/port grant; never implicitly allowed |
| Private IPv4 RFC 1918 and IPv6 ULA | Supported; requires a matching grant that explicitly acknowledges private access |
| Loopback | Supported for lab/local fixtures; requires explicit loopback acknowledgment and matching grant |
| Link-local | Supported with explicit link-local acknowledgment and matching grant; scoped IPv6 must bind the approved interface |
| Metadata | Additional protected overlay, not a synonym for all link-local space; requires metadata acknowledgment as well as all other applicable class grants |
| Other special-use unicast | Requires explicit matching grant and special-use acknowledgment; do not call it public merely because it is not RFC 1918 |
| Unspecified, multicast or broadcast destination | Invalid direct unicast TLS target; reject rather than dial |

The built-in metadata overlay includes `169.254.169.254/32`, `169.254.170.2/32`, `100.100.100.200/32` and `fd00:ec2::254/128`. The operator may extend it for installation-specific addresses; it is not an exhaustive cloud catalog or discovery feature. A broad CIDR without metadata acknowledgment does not authorize these destinations. Overlapping protected classes require all applicable acknowledgments. Classify IPv4-mapped IPv6 by its underlying IPv4 address too. Normalize/check every actual candidate, not just the displayed hostname. The implementation must document a versioned special-use classification table and test its boundary addresses.

Resolution uses the installation's operator-controlled resolver within the probe budget. Resolver infrastructure is a local installation prerequisite, not an implicit grant for arbitrary target connections. No network discovery, HTTP proxy, proxy-environment tunnel or alternative transport bypass is permitted. Connect to an already checked numeric address, with the selected port/scope, and verify the socket peer where available. Each retry or refreshed resolution must repeat the full authorization check; never authorize a hostname once and then invoke a hostname dialer that resolves again unchecked. Denied candidates are recorded and never connected; permitted candidates may still be tried within the same budget. If none are permitted, complete a policy-denied inspection with unavailable certificate assessments.

This governs addresses visible at the process socket boundary, not unseen routing, NAT or a remote relay's downstream destinations. Installation-specific metadata routes/aliases must be included in operator policy; no claim of discovering every such route is made. Enlarging authority, weakening class acknowledgments or introducing proxies requires Level 2 approval, not a routine repair.

## 7. Approved TLS observation and assessment design

**Approved compatibility target:** TLS 1.2 and TLS 1.3 with the selected maintained TLS library's documented cipher/signature support. This boundary is approved with this ADR, not a protocol floor established by the PRD; no legacy-compatibility approval is inferred. Unsupported peers receive a truthful negotiation diagnostic, not an invented certificate defect. Do not silently downgrade or enable legacy cryptography. If the pilot needs older protocols, resolve that compatibility/risk change before implementing dependent behavior.

SNI is derived from the canonical expected DNS identity, including when connecting to an IP. For an expected IP identity omit SNI, even if the connection host is DNS. Record the actual SNI (or explicit absence). SNI selects a certificate; only independent SAN verification decides whether that certificate matches. No separate arbitrary SNI override is introduced in this delivery.

Use an observation-specific TLS path that can capture invalid-certificate evidence without library fail-fast hiding it. Any disabled automatic handshake certificate validation is confined to this probe; explicit leaf, SAN and server-authentication path assessment remains mandatory. Never export this TLS configuration to database connections or future webhook/other transports. Send no application data, HTTP request, ALPN application probe, client certificate, password or private key. A client-certificate request does not authorize credential use. A failed negotiation may still expose a peer certificate; preserve and assess whatever is actually available, while retaining the transport failure.

One default 10-second monotonic budget covers resolution, connection and TLS handshake across all candidate attempts, including slow resolution and retries. Cancellation prevents late connections; there is no fresh 10-second timer per address. Once a candidate yields peer certificate evidence, finish that connection's handshake within the remaining budget and do not try another backend, even if negotiation subsequently fails. Retry only pre-evidence connection/negotiation failures under the same budget and policy; never retry merely to hide a certificate-validation failure. Preserve candidate-attempt diagnostics, including observed evidence when available, without promising all-backend coverage.

At certificate capture sample one UTC observation/validation instant. Use it for all dimensions; controlled time is a test seam, not a way for normal CLI users to manufacture current health. Certificate validity is inclusive: `notBefore <= t <= notAfter`. Before `notBefore` is always invalid; after `notAfter` is expired. At exactly `notAfter`, leaf time is valid and expiry is critical with zero remaining duration. Compute remaining lifetime as `notAfter - t`, in actual duration, with a day exactly 24 hours; use overflow-safe arithmetic even for far-future certificate dates. After expiry use expired; otherwise use critical when remaining is at most critical, warning when at most warning, normal above warning. A not-yet-valid leaf can have a normal expiry band but cannot be healthy.

Assess SAN DNS/IP identity without CN fallback and path validity for server authentication independently of hostname matching. Path assessment includes applicable constraints, usage and chain validity; its failure must not suppress known leaf-time/identity results. Distinguish a supported validation error from an unproven causal explanation such as “missing intermediate.” Revocation is explicitly `not_checked`.

## 8. Approved report and exit design

The task contract §7 defines the versioned CLI contract and field semantics. Both renderings carry the same facts: stable/monitoring/configuration identities, selected material/policy, contacted address where known, attempt/observation times, fingerprint/issuer/SANs/validity/duration, independent outcomes, diagnostics and single-observation/no-history limitations.

Unavailable data is null with an explicit reason, not a default pass or an old certificate silently reused. A recent completed failure is current evidence of that failed manual attempt. Disabled configuration remains `disabled`. A completed manual report is a snapshot at its completion time, not an enduring live status view; registry listing does not claim a retained last check or manufacture `never_checked` from absent history. Durable latest-attempt/latest-certificate history and query-time staleness come in Delivery 2.

Approved exits are 0 for successful registry/configuration commands or a healthy completed inspection; 1 for a completed inspection that is not healthy (including validation/transport/policy findings or disabled monitoring); 2 for execution/configuration/storage/output failure. An inspection with no certificate can be a completed adverse inspection, not necessarily a tool execution failure. JSON distinguishes these cases structurally. Successful inspection output explicitly says it is not durably retained; a broken output stream is not successful delivery of a report.

## 9. Persistence, privilege, concurrency and compatibility

Only configuration is durable in Delivery 1. Commit endpoint changes and associated effective identity/revision changes atomically with PostgreSQL transaction semantics. Acknowledged mutations survive process restart. Validation, permission, write/commit and storage failures produce actionable execution errors without false success or partial replacement. A lost connection during commit may leave outcome unknown: report that ambiguity and require read-back rather than asserting rollback or blindly retrying creation.

Use a dedicated least-privilege local application role restricted to required registry data; no superuser requirement or public callable elevated operation is proposed. Protect state/configuration/trust import paths with operator ownership, owner-only writable permissions and redacted connection diagnostics. Local configuration files are not anonymous authorization tokens; the OS/operator boundary is the authority boundary.

Concurrent CLI edits must not lose updates: locking or compare-and-swap revision checks may serialize or reject conflicts. Canonical no-op checks occur against the committed/current record inside that consistency boundary. Explicit inspection uses a stable snapshot; it does not hold a transaction throughout the network probe. Future immutable completed records, current-status ordering and atomic condition/event storage remain requirements for their own deliveries, not schemas now.

No existing schema/data migration is observed. Persist a registry format/schema version sufficient to reject unsupported state safely. If the pilot is carried into Delivery 2, preserve registration IDs, monitoring IDs and selected trust/configuration meaning and test the actual upgrade. Do not backfill observations for the manual-only period or introduce a generic migration platform speculatively.

## 10. Alternatives, consequences and engineering latitude

| Choice | Approved direction / consequence | Alternatives and authority |
| --- | --- | --- |
| Runtime/storage | Go + PostgreSQL; one implementation language and transactional registry, but local DB operations are required | Go + durable file/embedded DB reduces setup; another runtime may also satisfy behavior. These are unadopted architecture alternatives, requiring selection/revision before implementation |
| Input/identity | Canonical DNS/IP and explicit expected identity; stable registration distinct from monitoring identity | Level 1 parsing/ID generation details may vary while preserving task §3; ASCII-only restrictions, conflated identity or reused historical identity are not equivalent alternatives |
| Roots | Immutable selected snapshots; reproducibility with explicit refresh burden | Mechanism for protected storage/hash encoding is Level 1; mutable-path-only attribution and custom/system blending are prohibited |
| Policy | Explicit grants for actual addresses/ports/classes; safe empty policy still supports lab opt-in | Equivalent representations/enforcement code are Level 1 after approval; blanket private denial or implicit allow-all is not authorized |
| TLS | Approved 1.2/1.3 support; honest diagnostics for unsupported peers | Compliant library/configuration selection is Level 1; legacy-risk changes require review/approval |
| Persistence/concurrency | Atomic registry mutations and stable probe snapshots | Row locks or optimistic revisions, transaction layout, package boundaries and test tooling are Level 1 if acceptance evidence is equivalent |
| Future delivery | No durable inspection history, scheduler or alerts yet | PRD §8 assigns history/scheduling/order/resource-scale tests to Delivery 2; conditions/atomic events/webhooks/operations to Delivery 3. No requirement is waived |

## 11. Open questions and approval boundary

The independently reviewed candidate had no identified blocking finding. The user has approved the concrete decisions in §§3–9, including architecture, TLS compatibility, explicit trust-refresh behavior, address-class policy and CLI/exits. This approval does not resolve a future material product/security conflict or authorize changes to those decisions without the appropriate review and authority.

Level 0 remains routine fixtures, debugging and in-scope repairs. Level 1 remains choices among compliant mechanisms after the architecture/contract is approved. Level 2 includes product-visible restrictions beyond this approved contract, weakened trust/network/evidence boundaries, unsupported compatibility/security changes, architecture substitution, unauthorized infrastructure or scope expansion. No blanket privilege or infrastructure permission is conferred.

The independent draft review and user approval have occurred. Verify commitment and the actual Git base before the applicable implementation gates; any controlling implementation plan, preflight or execution requires its respective authorization. Do not start them automatically. PRD §9 workflow evidence begins at the first specification review; its metrics cannot change health assessments.

## 12. Source identities and limitations

All working-source SHA-256 values matched the paired handoff at the observed HEAD:

| Source path | SHA-256 |
| --- | --- |
| `README.md` | `7530e52d65ef80dcc379ec46ee5372837aa4ce83078af357945e2b055c569880` |
| `docs/prd-v0.1.md` | `ce87476179bc0f903a2286c14a7e86f1c0c4c98d88a7165f8574874d3accf138` |
| `docs/implementation-plan/00-implementation-overview.md` | `8951b2176e9301a860a0f198c3f25a60bc78abaab6aff53bca2f53495a502741` |
| `docs/implementation-plan/01-registry-and-safety-foundations.md` | `50fea12e417b6691724c39a919b0c7b7a85ac76796bff7f922cd214342268b93` |
| `docs/implementation-plan/02-trustworthy-manual-inspection.md` | `3c40925bd8a2539f960490bc453d097959f2e34dd66e956585be085981965fc1` |
| `docs/implementation-plan/03-continuous-monitoring-and-evidence.md` | `2b8b90956e75f1c309f13a326da69629140c8ed71329a4a362b0fcab07704772` |
| `docs/implementation-plan/04-durable-alerts-and-webhooks.md` | `d773b62299c3285159ef3207bf71684b84e793c0f2346bb41804f9d8e133c9f8` |
| `docs/implementation-plan/05-operations-and-mvp-validation.md` | `4e3410ecd3880852e9c7dd1c139cd83ae6e9e9e466e92e70dff4e1539510f2e8` |

Later [phase 03](../implementation-plan/03-continuous-monitoring-and-evidence.md), [phase 04](../implementation-plan/04-durable-alerts-and-webhooks.md) and [phase 05](../implementation-plan/05-operations-and-mvp-validation.md) were read in full to check deferrals; they remain proposed roadmaps, not accepted contracts. No product builds/tests or library behavior experiments were run. Required future verification is specified in the paired contract, not claimed here. Both documents must be revalidated together if sources, scope, proposals or candidate state change.
