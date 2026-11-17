# TLSBeacon — Initial System Architecture Proposal
**Architecture proposal:** v0.1  
**Date:** 17 November 2026  
**Product baseline:** PRD v0.2 — Approved  
**Architecture status:** Proposed, awaiting review

## 1. Executive Recommendation

Now that you've approved TLSBeacon PRD v0.2, we can move from defining **what the product must do** to designing **how the system should work**.

My recommendation is to build TLSBeacon as a **modular monolith written in Go, backed by PostgreSQL, deployed initially using Docker Compose on a single Linux host**.

We should design it as production-quality software without introducing unnecessary distributed-system complexity.

### Recommended architecture

| Area | Recommendation |
|---|---|
| Architecture style | Modular monolith |
| Programming language | Go 1.27 |
| Database | PostgreSQL 18 |
| Database access | `pgx` with explicit SQL |
| CLI | Cobra or a small standard-library command dispatcher |
| Internal communication | Unix domain socket |
| TLS inspection | Go `crypto/tls` and `crypto/x509` |
| Configuration | TOML or YAML for service configuration; PostgreSQL for managed endpoint records |
| Database migrations | Versioned SQL migrations |
| Container runtime | Docker Engine |
| Deployment | Docker Compose |
| Monitoring scheduler | In-process Go scheduler |
| Notification processing | PostgreSQL-backed transactional outbox |
| Logging | Go `log/slog`, structured JSON |
| Testing | Go unit tests, PostgreSQL integration tests, controlled TLS fixtures |
| CI/CD | GitHub Actions |
| Deployment model | Single host, single active application instance |
| Operating system | Linux |
| Observability | Structured logs, service health, operational CLI |
| Security | Non-root containers, least-privilege database access, explicit network authorization |

**These are proposed architecture choices, not requirements already approved by the PRD.**

I checked the current official release documentation. Go 1.27.4 was released on November 10, 2026, and PostgreSQL 18 is a supported production release. We can pin reviewed patch versions and container digests in the implementation baseline. [Go](https://go.dev/doc/devel/release?utm_source=chatgpt.com)

### Why a modular monolith?

TLSBeacon's target is initially 100 endpoints, checked hourly, with up to five concurrent probes.

That workload does not justify microservices, Kubernetes, distributed message brokers, or a multi-node database architecture.

A modular monolith gives us:

- Clear boundaries between certificate inspection, persistence, scheduling, and notification delivery.
- A single deployable application.
- Fewer network and operational dependencies.
- Simpler transaction management.
- Easier integration testing and debugging.
- Room to introduce additional deployment models later if evidence justifies them.

The important distinction is that **modular does not mean distributed**.

We can create clean software boundaries without deploying each component as a separate service.

---

## 2. High-Level Architecture

I recommend one Go application binary, `tlsbeacon`, capable of running both the background service and operator CLI commands.

The background service owns monitoring activities and database access.

The CLI communicates with the service through a local Unix domain socket.

```text
                       TLSBeacon Operator
                               |
                               |
                    CLI: tlsbeacon <command>
                               |
                               |
                     Local Unix Domain Socket
                               |
                               v
+------------------------------------------------------------------+
|                         TLSBEACON                                |
|                   Go Modular Monolith                            |
|                                                                  |
|  +--------------------+        +-------------------------------+  |
|  | Local Control API  |------->| Application Services          |  |
|  +--------------------+        +-------------------------------+  |
|                                           |                      |
|                  +------------------------+---------+            |
|                  |                        |         |            |
|                  v                        v         v            |
|         +----------------+   +----------------+ +-------------+  |
|         | Endpoint       |   | TLS Inspection | | Trust       |  |
|         | Registry       |   | Engine         | | Management  |  |
|         +----------------+   +----------------+ +-------------+  |
|                                    |                             |
|                                    v                             |
|                            +----------------+                    |
|                            | Certificate    |                    |
|                            | Assessment     |                    |
|                            +----------------+                    |
|                                    |                             |
|             +----------------------+                             |
|             |                                                    |
|             v                                                    |
|     +----------------+       +---------------------+              |
|     | Scheduler      |       | Evidence & History  |              |
|     | Delivery 2     |------>| Delivery 2          |              |
|     +----------------+       +---------------------+              |
|                                         |                         |
|                                         v                         |
|                                +---------------------+            |
|                                | Condition / Alert   |            |
|                                | Engine - Delivery 3 |            |
|                                +---------------------+            |
|                                         |                         |
|                                         v                         |
|                                +---------------------+            |
|                                | Webhook Dispatcher  |            |
|                                | Delivery 3          |            |
|                                +---------------------+            |
|                                                                  |
|                +------------------------------+                  |
|                | PostgreSQL Persistence       |                  |
|                +------------------------------+                  |
+------------------------------------------------------------------+
         |                            |
         |                            |
         v                            v
  Authorized TLS              PostgreSQL
  Endpoints                   Database
         |
         |
         v
  TLS Inspection
  (no HTTP request)

  Delivery 3 also adds authorized outbound HTTPS webhook traffic.
```

This diagram represents the **complete MVP architecture**, not the implementation scope of Delivery 1.

### One important design decision: CLI versus daemon

There are two legitimate alternatives:

| Approach | Advantages | Disadvantages |
|---|---|---|
| CLI directly accesses PostgreSQL and performs inspections | Simpler first implementation | Duplicates operational authority between CLI and daemon; more difficult to keep manual and scheduled workflows consistent |
| CLI communicates with one local service | One authoritative inspection and persistence boundary; consistent behavior | Requires a local control protocol and a running service |

**I recommend the second approach.**

The service should own database access, network authorization, and inspection orchestration. The CLI should primarily handle input, output, and local command communication.

This becomes particularly valuable in Delivery 3, when manual and scheduled checks must use the same alert-deduplication rules.

We should keep that local protocol private and versioned. We do not need to design a public REST API.

---

## 3. Recommended GitHub Repository Structure

I recommend a **single repository with one Go module**.

The repository should contain the application, database migrations, deployment configuration, tests, and engineering documentation.

### Proposed structure

```text
tlsbeacon/
│
├── cmd/
│   └── tlsbeacon/
│       └── main.go
│
├── internal/
│   │
│   ├── app/
│   │   └── app.go
│   │
│   ├── cli/
│   │   ├── root.go
│   │   ├── endpoint.go
│   │   ├── inspect.go
│   │   └── trust.go
│   │
│   ├── control/
│   │   └── server.go
│   │
│   ├── endpoint/
│   │   ├── model.go
│   │   └── service.go
│   │
│   ├── trust/
│   │   ├── profile.go
│   │   └── store.go
│   │
│   ├── probe/
│   │   ├── resolver.go
│   │   ├── dialer.go
│   │   └── inspector.go
│   │
│   ├── assessment/
│   │   ├── certificate.go
│   │   ├── identity.go
│   │   ├── path.go
│   │   └── expiry.go
│   │
│   ├── policy/
│   │   └── network.go
│   │
│   ├── storage/
│   │   └── postgres/
│   │       ├── connection.go
│   │       ├── endpoint.go
│   │       └── trust.go
│   │
│   ├── history/             # Delivery 2
│   ├── scheduler/           # Delivery 2
│   ├── alerting/            # Delivery 3
│   └── webhook/             # Delivery 3
│
├── db/
│   └── migrations/
│
├── deployments/
│   └── compose/
│       └── compose.yaml
│
├── config/
│   └── config.example.yaml
│
├── tests/
│   ├── integration/
│   ├── fixtures/
│   │   └── tls/
│   └── e2e/
│
├── docs/
│   ├── product/
│   │   └── prd.md
│   │
│   ├── architecture/
│   │   ├── adr/
│   │   └── design/
│   │
│   ├── tasks/
│   ├── plans/
│   ├── reviews/
│   └── operations/
│
├── .github/
│   └── workflows/
│       └── ci.yaml
│
├── AGENTS.md
├── Dockerfile
├── Makefile
├── go.mod
├── go.sum
├── .gitignore
├── .dockerignore
├── LICENSE
└── README.md
```

This is the **target organization**, not a request to create every directory immediately. For example, `scheduler`, `alerting`, and `webhook` should not be implemented or populated during Delivery 1.

### Why organize by domain?

Consider these two possible structures.

A generic layered structure:

```text
internal/
├── models/
├── repositories/
├── services/
├── handlers/
└── utils/
```

A domain-oriented structure:

```text
internal/
├── endpoint/
├── trust/
├── probe/
├── assessment/
└── policy/
```

I prefer the second.

It makes component ownership clearer and avoids creating generic packages that gradually accumulate unrelated responsibilities.

For example, `probe` is responsible for acquiring TLS evidence, while `assessment` interprets that evidence.

That separation is important because TLSBeacon must report certificate information even when certificate verification fails.

### Suggested module path

Assuming you use a personal GitHub repository:

```text
github.com/<github-username>/tlsbeacon
```

Keep everything in one Go module initially. Multiple modules or a `pkg/` directory are unnecessary until there is a demonstrated external reuse case.

---

# 4. Core Application Components

The most important architectural decision is separating **observation, assessment, and monitoring state**.

These represent different concepts.

## 4.1 Endpoint Registry

The registry manages which TLS endpoints TLSBeacon is authorized to monitor.

Example conceptual endpoint:

```yaml
name: lab-dashboard

connection:
  host: 10.10.10.20
  port: 443

identity:
  type: dns
  expected: dashboard.lab.internal

trust:
  profile: lab-ca

monitoring:
  enabled: true
  interval: 1h
```

Notice that the connection address is different from the certificate identity.

TLSBeacon connects to:

```text
10.10.10.20:443
```

But expects a certificate valid for:

```text
dashboard.lab.internal
```

We must preserve this distinction.

### Stable endpoint identity versus monitoring generation

An endpoint should have a stable registry ID.

However, changing its connection host, expected identity, or effective trust material creates a new monitoring generation.

Conceptually:

```text
Endpoint
    ID: endpoint-001
    Name: lab-dashboard
          |
          +--- Generation 1
          |       Connection: 10.10.10.20
          |       Expected: dashboard.lab.internal
          |       Trust: lab-ca-v1
          |
          +--- Generation 2
                  Connection: 10.10.10.21
                  Expected: dashboard.lab.internal
                  Trust: lab-ca-v2
```

Historical observations remain associated with their original generation.

This directly supports PRD FR-002 and AC-013.

I also suggest recording configuration revisions for changes that do not create a new monitoring identity, such as interval or threshold adjustments.

## 4.2 TLS Inspection Engine

**This is TLSBeacon's most important technical component.**

It should answer:

> What TLS certificate information did this connection actually provide?

The proposed execution path is:

```text
Inspection Requested
        |
        v
Load Effective Endpoint Configuration
        |
        v
Resolve Connection Host
        |
        v
Authorize Resolved Address
        |
        v
Select Authorized Destination
        |
        v
Establish TCP Connection
        |
        v
Perform TLS Handshake
        |
        v
Capture Available Peer Certificates
        |
        v
Return Observation
        |
        v
Certificate Assessment Engine
```

A critical implementation detail concerns invalid certificates.

Go normally verifies a server certificate as part of the TLS handshake. That can terminate an inspection before we have captured all the evidence TLSBeacon needs.

For a certificate inspection tool, we need a controlled way to observe presented certificates even when they're invalid.

A potential implementation is to disable Go's automatic verification **only inside the isolated observation transport**, then perform explicit certificate verification using `crypto/x509`.

This requires careful design:

- An observed certificate is not automatically trusted.
- Explicit verification is mandatory before declaring a certificate healthy.
- No application data is sent after an unverified handshake.
- The inspection mechanism must never be reused as an insecure HTTP or webhook client.
- All connections remain subject to destination policy and deadlines.

Go documents custom verification mechanisms, including `VerifyConnection`, which can support this approach. The exact handshake and evidence-capture mechanism should receive focused security review before implementation. [Go Packages](https://pkg.go.dev/crypto/tls?utm_source=chatgpt.com)

### Separate the TLS probe from certificate assessment

I strongly recommend two distinct components.

**TLS Probe**

Responsible for DNS, destination authorization, TCP connection, TLS negotiation, and peer-certificate acquisition.

**Certificate Assessment**

Responsible for certificate-time validity, expected DNS/IP identity, certification path, and expiry-band classification.

The distinction enables useful behavior:

```text
TLS Handshake
     |
     +--- No certificate
     |       |
     |       +--- Certificate assessments: not assessed
     |
     +--- Certificate received
             |
             +--- Time validity
             +--- DNS/IP identity
             +--- Certification path
             +--- Expiry band
```

For example, TLSBeacon can observe an expired certificate that also has a hostname mismatch.

It should report both supported findings rather than stopping at the first validation error.

Custom trust profiles must be applied explicitly. They must not silently fall back to system roots.

### Trust material

I recommend storing immutable custom CA-bundle snapshots, identified by a SHA-256 digest.

An operator can import or update a named trust profile through the CLI.

When the same profile receives different CA material, TLSBeacon creates a distinguishable trust version.

This avoids historical reports changing meaning when a CA-bundle file is edited.

File import and trust reload semantics need to be specified in Delivery 1. My preference is **explicit import/update**, rather than automatically reloading arbitrary file changes.

System roots are different: they come from the runtime environment, and their exact version may not always be reproducible. The report should say so when necessary.

---

# 5. Persistence Architecture

## 5.1 Why PostgreSQL?

I recommend PostgreSQL because TLSBeacon has a substantial data-integrity requirement.

It needs to preserve immutable inspection evidence, manage concurrent status updates, and eventually commit condition transitions and webhook events atomically.

PostgreSQL provides transactional semantics suitable for those operations.

I would use `pgx/v5` with `pgxpool` and explicit SQL rather than introducing an ORM. The official pgx documentation recommends its native interface for applications that target PostgreSQL specifically. [GitHub](https://github.com/jackc/pgx?utm_source=chatgpt.com)

### Candidate data model

These are conceptual entities, not final table definitions.

| Entity | Purpose | Delivery |
|---|---|---|
| `endpoints` | Stable registered endpoints and lifecycle | 1 |
| `endpoint_generations` | Immutable monitoring identities and effective configuration references | 1 |
| `trust_profiles` | Named trust configuration | 1 |
| `trust_versions` | Immutable custom CA material and digest | 1 |
| `inspection_attempts` | Completed manual/scheduled inspection evidence | 2 |
| `monitor_state` | Latest attempts, certificate evidence, and scheduler state | 2 |
| `alert_conditions` | Current and superseded monitoring conditions | 3 |
| `alert_events` | Immutable condition-transition events | 3 |
| `webhook_deliveries` | Durable delivery and retry state | 3 |
| `webhook_attempts` | Delivery-attempt evidence | 3 |

This model separates registry identity from observations and notifications.

One important Delivery 1 boundary: although endpoint configuration must persist, **durable inspection history is not required until Delivery 2**. A manual report should not imply that historical inspection evidence was stored.

## 5.2 Database migrations

Use versioned SQL migrations stored in Git.

I recommend explicit migration execution rather than automatically applying schema changes whenever the service starts.

Also introduce separate database roles:

```text
Migration Role
    |
    +--- Schema creation
    +--- Schema modifications
    +--- Controlled migrations

Runtime Role
    |
    +--- Required SELECT
    +--- Required INSERT
    +--- Required UPDATE
    +--- No schema modification privileges
```

The service should refuse incompatible database schema versions.

A migration ledger with integrity checking is valuable, especially given the lessons from our previous engineering exercises.

Avoid introducing a general-purpose migration framework beyond what PostgreSQL and versioned SQL require.

---

# 6. Infrastructure and Container Architecture

## 6.1 Deployment topology

My preferred initial deployment is:

**One Linux VM running Docker Compose with two containers.**

```text
+------------------------------------------------------+
|                     Linux VM                         |
|                                                      |
|  +-----------------------------------------------+   |
|  |                Docker Engine                  |   |
|  |                                               |   |
|  |    +--------------------------+               |   |
|  |    | TLSBeacon Container      |               |   |
|  |    |                          |               |   |
|  |    | Go Application           |               |   |
|  |    | Local CLI Control        |               |   |
|  |    | TLS Inspection           |               |   |
|  |    | Scheduler (D2)           |               |   |
|  |    | Webhook Worker (D3)      |               |   |
|  |    +------------+-------------+               |   |
|  |                 |                             |   |
|  |                 | Private Docker Network      |   |
|  |                 v                             |   |
|  |    +--------------------------+               |   |
|  |    | PostgreSQL Container     |               |   |
|  |    |                          |               |   |
|  |    | Database                 |               |   |
|  |    +------------+-------------+               |   |
|  |                 |                             |   |
|  |                 v                             |   |
|  |           Persistent Volume                   |   |
|  +-----------------------------------------------+   |
|                                                      |
|            Host Routing / Network Policy             |
+----------------------+-------------------------------+
                       |
                       v
             Authorized TLS Endpoints
```

This could run on a small dedicated VM in your OpenStack lab.

For initial provisioning, I would start with approximately **2 vCPUs, 2–4 GiB RAM, and 20–40 GiB of storage**. Those are provisional pilot-sizing suggestions, not measured requirements.

We should benchmark actual CPU, memory, database growth, and network behavior before establishing a production capacity claim.

## 6.2 Docker networking

I suggest two Docker networks.

```text
                 TLSBeacon Container
                      |         |
                      |         |
              Database Network  Egress Network
                      |         |
                      |         |
                 PostgreSQL    Authorized
                               TLS Endpoints
```

A conceptual Compose network configuration:

```yaml
services:
  tlsbeacon:
    networks:
      - storage
      - egress

  postgres:
    networks:
      - storage

networks:
  storage:
    internal: true

  egress:
    driver: bridge
```

This is an architecture sketch, not a complete deployable Compose file.

The `storage` network is internal and connects TLSBeacon to PostgreSQL. The `egress` network lets TLSBeacon reach monitored endpoints.

Docker Compose supports assigning containers to multiple networks and defining internal networks with restricted external connectivity. [Docker Documentation](https://docs.docker.com/compose/how-tos/networking?utm_source=chatgpt.com)

### No externally published application ports

For the MVP, I would publish **no inbound TCP ports** for either application.

The CLI can initially be executed inside the application container:

```bash
docker compose exec -T tlsbeacon tlsbeacon endpoint list
```

The CLI communicates with the already-running daemon through its Unix socket.

This avoids exposing a network management API.

A separately installed host CLI could be supported later by mounting the control socket with appropriate local permissions.

### Important security qualification

A Docker bridge network does **not** provide an outbound destination allowlist.

TLSBeacon still needs application-level policy enforcement, including DNS-address validation and connection-time authorization.

For stronger protection against a compromised application, add host-level firewall controls on actual container egress traffic.

Docker's networking and NAT rules must be tested in the deployed environment; host firewall assumptions should not be accepted without verification.

### Protect sensitive destinations

For example, suppose the operator authorizes:

```text
10.20.30.0/24
```

TLSBeacon should be permitted to inspect explicitly registered endpoints in that range.

But it should not gain general network-scanning authority.

In particular, link-local and cloud metadata destinations such as `169.254.169.254` must remain denied unless covered by an explicit, narrowly reviewed policy exception.

The application should resolve a host, authorize the selected IP, and connect to that exact IP. It must not authorize one IP and later allow an unchecked DNS resolution to select another.

This is a critical requirement of the approved PRD v0.2.

---

## 6.3 Docker container hardening

For the TLSBeacon container, I recommend:

| Control | Recommendation |
|---|---|
| Runtime user | Dedicated non-root user |
| Privileged mode | Disabled |
| Linux capabilities | Drop unnecessary capabilities |
| Root filesystem | Read-only when practical |
| Writable paths | Explicit temporary paths only |
| Docker socket | Never mount into the application |
| Secrets | Restrict to explicitly required files |
| Network ports | None published |
| Restart | `unless-stopped` or equivalent host policy |
| Images | Pin versions and reviewed immutable digests |
| Shutdown | Graceful termination with bounded cleanup |

A multistage Dockerfile can compile TLSBeacon using the Go toolchain and copy the binary into a minimal runtime image.

The runtime image must still include the CA certificates needed for system-root validation.

For PostgreSQL 18, the official container image uses `/var/lib/postgresql` as its volume mount location, with version-specific database storage underneath. We should follow that layout rather than copy older PostgreSQL container examples blindly. [GitHub](https://github.com/docker-library/docs/blob/master/postgres/README.md?plain=1\&utm_source=chatgpt.com)

### Secrets

For database passwords and the future webhook secret, prefer file-backed secrets over hardcoded environment values or credentials committed to Git.

Docker Compose supports mounting explicitly granted secrets into `/run/secrets`. [Docker Documentation](https://docs.docker.com/compose/how-tos/use-secrets/?utm_source=chatgpt.com)

---

# 7. Scheduling, Monitoring State, and Alerts

These components belong to Deliveries 2 and 3, but they influence our initial architectural boundaries.

## 7.1 In-process scheduler

For 100 endpoints, a simple Go scheduler is sufficient.

I would use an in-process loop that determines due endpoints and submits bounded inspection work.

The PRD already specifies:

- Default hourly interval.
- Maximum five concurrent probes.
- Ten-second total probe deadline.
- No replay flood after restart.
- No regression of current status from older work.

With 100 endpoints, five concurrent probes, and ten-second probe deadlines, the theoretical timeout-only probe workload is approximately 200 seconds, excluding scheduling, database, and other overhead.

That leaves some margin against the five-minute controlled batch target, but the acceptance test still needs to verify it.

I would not introduce Redis, Celery, RabbitMQ, or Kafka.

### Ordering and persistence

Each inspection should be associated with its effective monitoring generation and an ordering identity.

When a result is persisted, an older inspection must not overwrite a newer result's current-status state.

The database transaction should enforce that condition; an in-memory mutex alone is insufficient for crash recovery.

## 7.2 Separate certificate freshness from scheduler health

Consider:

```text
08:00  Scheduled check succeeds
09:00  Scheduled check fails to execute
10:00  Scheduled check fails to execute
10:15  Operator performs successful manual check
```

The certificate evidence at 10:15 may be current.

But scheduled monitoring is still overdue.

TLSBeacon must represent both facts independently:

```text
Certificate Assessment: Healthy
Inspection Freshness:   Current
Scheduled Monitoring:   Overdue
Overall Monitoring:     Degraded
```

That distinction is essential to FR-006 through FR-009.

A recent manual inspection must not conceal a broken scheduler.

---

# 8. Notification Architecture — Delivery 3

I recommend using a **PostgreSQL transactional outbox**, not a separate message broker.

The flow would be:

```text
Completed Inspection
        |
        v
Persist Inspection Evidence
        |
        v
Evaluate Condition Transition
        |
        v
Create Logical Event
        |
        v
Insert Durable Outbox Record
        |
        v
COMMIT DATABASE TRANSACTION
        |
        v
Webhook Worker
        |
        v
Authorized HTTPS Destination
        |
        v
Record Delivery Outcome
```

The event and its corresponding state transition must commit atomically.

Network delivery happens **after** the database transaction commits. We should not hold a database transaction open while waiting for an external webhook receiver.

### Stable event identity

Every logical event receives a stable identifier.

Retries and manual replay reuse that event ID and its original occurrence time.

This supports receiver-side deduplication.

It does not guarantee exactly-once processing at the receiver.

### Webhook security

The webhook client should be separate from the TLS inspection transport.

It must:

- Verify the webhook server's TLS certificate and hostname.
- Enforce destination authorization on resolved addresses.
- Refuse automatic redirects.
- Avoid forwarding secrets to unexpected destinations.
- Use bounded connection and response times.
- Redact credentials from logs.
- Distinguish successful receiver acceptance from human acknowledgment.

These are requirements for Delivery 3, not implementation work for Delivery 1.

---

# 9. Configuration and Operational Design

I recommend separating configuration into two categories.

| Configuration type | Preferred location |
|---|---|
| Service paths and runtime settings | Protected configuration file |
| Network destination policy | Protected configuration file |
| Database connection settings | Protected configuration plus secret file |
| Registered endpoints | PostgreSQL |
| Endpoint monitoring generations | PostgreSQL |
| Custom CA snapshots | PostgreSQL |
| Check intervals and thresholds | PostgreSQL |
| Webhook integration configuration | Protected configuration/secret storage |
| Inspection history | PostgreSQL |
| Alert events and delivery state | PostgreSQL |

This avoids treating a static configuration file as a constantly changing operational database.

### Service configuration

A conceptual file might contain:

```yaml
service:
  socket: /run/tlsbeacon/control.sock

database:
  host: postgres
  port: 5432
  name: tlsbeacon
  password_file: /run/secrets/db_password

inspection:
  timeout: 10s
  max_concurrent: 5

network:
  default_deny: true
  allowed_cidrs:
    - 10.20.30.0/24

logging:
  format: json
  level: info
```

The exact configuration schema, default policy, and validation rules need specification before implementation.

For consistency, timestamps should be stored in UTC, with an injectable clock used by assessment and freshness calculations. This matters for reproducing expiry-boundary tests.

---

# 10. Observability and Operations

TLSBeacon is itself a monitoring service, so we must monitor its ability to monitor.

I recommend distinguishing:

**Application liveness:** Is the process running and responsive?

**Database readiness:** Can required state be read and persisted?

**Scheduler health:** Are scheduled checks occurring within their deadlines?

**Notification health:** Are delivery attempts progressing, or is the queue blocked?

These are not interchangeable.

A process can be alive while its scheduler is stalled.

### Initial observability

Use Go's `log/slog` for structured logs.

Include useful diagnostic fields such as:

```text
endpoint_id
monitoring_generation
inspection_id
inspection_origin
event_id
duration
outcome
error_category
```

Avoid logging secrets or unbounded certificate details.

I would not expose Prometheus metrics through a public listener in the first delivery. A local health command is sufficient initially; metrics can be added when operational requirements justify them.

### Backup and recovery

PostgreSQL must use persistent storage, but a persistent Docker volume is not a backup.

Before the complete MVP release, we should document and test:

- Consistent PostgreSQL backup.
- Off-host backup storage.
- Database restoration.
- Configuration and secret recovery.
- Schema compatibility after restore.
- Preservation of event IDs.
- Possible duplicate webhook delivery after restoring older state.

**A restore test is more meaningful than merely verifying that `pg_dump` exits successfully.**

We should also document the single-service failure limitation. When TLSBeacon is down, it cannot promise to deliver its own outage alert. Docker or systemd can attempt to restart it, while independent outage detection would be a separate future capability.

---

# 11. Testing and Verification Architecture

Because TLSBeacon assesses certificates, its correctness depends heavily on controlled test cases.

I recommend testing against local TLS servers and generated certificate fixtures rather than public internet endpoints.

### Test groups

| Test category | Purpose |
|---|---|
| Unit tests | Certificate validity boundaries, expiry thresholds, hostname matching |
| TLS fixture tests | Expired, not-yet-valid, mismatched, trusted, and untrusted certificates |
| Network tests | DNS failures, refused connections, timeouts, unauthorized destinations |
| PostgreSQL integration | Registry persistence, generation integrity, transactions |
| Concurrency tests | Concurrent manual/scheduled checks and ordering |
| Recovery tests | Restarts, database failures, interrupted notification delivery |
| End-to-end tests | CLI → daemon → TLS endpoint → observable result |
| Deployment smoke tests | Container startup, permissions, routing, storage persistence |

For Delivery 1, prioritize AC-001 through AC-005, the applicable portions of AC-006 and AC-011, and AC-014 and AC-016, plus the trust-versioning portion of AC-013.

### CI/CD

For GitHub, I recommend GitHub Actions with:

```text
Pull Request
     |
     v
Go Formatting Check
     |
     v
Static Analysis / go vet
     |
     v
Unit Tests
     |
     v
Race-Detector Tests
     |
     v
PostgreSQL Integration Tests
     |
     v
Controlled TLS Acceptance Tests
     |
     v
Container Build
```

Add dependency vulnerability checks and container-image scanning as the release pipeline matures.

Do not depend on external websites for normal certificate tests; their certificates, DNS records, and network availability can change independently of our code.

---

# 12. Architecture Choices I Would Deliberately Avoid

| Technology or pattern | Recommendation | Reason |
|---|---|---|
| Kubernetes | Defer | Unnecessary for one active monitoring service |
| Microservices | Avoid initially | Adds coordination and failure modes without a demonstrated need |
| Redis | Defer | PostgreSQL can handle the initial persistence and coordination needs |
| Kafka/RabbitMQ | Defer | PostgreSQL outbox is sufficient for the MVP |
| Public REST API | Defer | CLI-first, local-operator requirement |
| gRPC | Defer | No demonstrated need beyond a simple local control protocol |
| ORM | Avoid initially | Explicit SQL is suitable for this data model |
| Certificate discovery/scanning | Out of scope | Conflicts with explicit endpoint registration |
| Multiple monitoring workers | Defer | PRD specifies one active monitoring service |
| Dashboard | Out of scope | Explicitly deferred by the PRD |

This does not mean those technologies are inherently inappropriate.

It means they should enter the architecture only when a requirement or observed limitation justifies their operational cost.

---

# 13. Architecture Decisions to Formalize

Before implementation, I recommend recording the significant decisions in a small number of Architecture Decision Records.

| Proposed ADR | Decision |
|---|---|
| ADR-001 | Modular monolith, single Go binary, and local operator-control boundary |
| ADR-002 | PostgreSQL persistence, monitoring generations, and evidence-integrity strategy |
| ADR-003 | TLS observation, explicit verification, trust snapshots, and destination authorization |
| ADR-004 | Single-host container deployment and network-security boundaries |

These are proposed groupings; we do not need four separate ADRs if one coherent architecture record is easier to review.

The most consequential choices requiring explicit architecture approval are the local daemon/socket model, custom trust-material lifecycle, database ownership boundary, and deployment/network isolation.

Exact package names, migration-tool selection, and ordinary internal helper design can remain implementation-level decisions.

### One documentation correction

The v0.2 PRD file I reviewed still identifies itself as a *proposed revision*. Since you have approved it, its status metadata should be updated to **Approved**, recording the approval date without changing the accepted requirements.

That will prevent future agents from confusing the approved product baseline with an unapproved draft.

---

# 14. Recommended Development Sequence

The architecture above should support the whole MVP, but we should implement only the next bounded delivery.

## Delivery 1 — Manual Inspection Pilot

The first useful outcome is straightforward:

```text
Operator starts TLSBeacon
        |
        v
Imports a custom CA bundle if needed
        |
        v
Registers an endpoint
        |
        v
Requests manual inspection
        |
        v
TLSBeacon enforces destination policy
        |
        v
TLSBeacon observes the TLS certificate
        |
        v
TLSBeacon assesses the certificate
        |
        v
Operator receives a trustworthy CLI report
```

Delivery 1 should include the persisted registry, trust generations, authorized TLS probing, certificate assessment, and human/JSON output.

It should not include scheduled checks, historical inspection storage, webhook delivery, or the alert state machine.

## Delivery 2 — Continuous Monitoring

Extend the manual-inspection foundation with:

- An in-process scheduler.
- Durable inspection history.
- Latest-attempt and latest-certificate-evidence tracking.
- Independent scheduler health and inspection freshness.
- Concurrency, ordering, and restart recovery.
- Bounded 100-endpoint testing.

## Delivery 3 — Notifications and MVP Release

Add:

- Condition-transition management.
- Durable logical events.
- Transactional outbox.
- HTTPS webhook delivery.
- Retry, exhaustion, and replay behavior.
- Operational recovery and backup verification.
- The seven-day lab pilot.

These are product delivery boundaries, not a substitute for the eventual single controlling implementation plan.

---

# 15. Architecture Risks I Would Address First

Before committing to implementation, I would resolve these four technical risks.

| Risk | Recommended validation |
|---|---|
| **Invalid-certificate observation** | Build a small controlled experiment proving that Go can preserve the required peer-certificate evidence while keeping verification explicit and safe. |
| **Network authorization** | Test DNS changes, IPv4/IPv6 resolution, container routing, and connection-time address enforcement. |
| **Trust-material identity** | Demonstrate that replacing a same-named CA bundle cannot change the meaning of historical evidence. |
| **CLI-to-service complexity** | Verify that a Unix-socket control API supports the required local commands without unnecessarily complicating Delivery 1. |

I would prioritize the TLS observation and network authorization experiments because failure there could force significant changes to the initial design.

A fifth practical check is to confirm that the chosen Docker network topology can reach your actual private infrastructure endpoints without exposing PostgreSQL or bypassing the destination policy.

---

# 16. Final Architecture Verdict

My recommended direction is:

> **Build TLSBeacon as a single-process Go modular monolith, backed by PostgreSQL, operated through a local CLI and Unix socket, and deployed on one Linux host using Docker Compose. Make TLS evidence correctness, explicit trust management, network authorization, and durable state transitions the architectural priorities.**

For the first pilot, I would use the proposed two-container deployment and resist introducing additional infrastructure.

The largest risk is not insufficient scalability. It is **incorrectly interpreting an observation as proof of certificate health**, particularly across failed handshakes, configuration changes, stale scheduler state, and interrupted persistence.

A carefully bounded architecture can address those risks without becoming complicated.
