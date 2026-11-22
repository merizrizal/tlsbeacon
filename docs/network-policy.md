# Destination policy: classification v1

This document describes the pure policy rules in `internal/policy`. The rules are available through the `policy set` and `policy show` commands and are persisted in the registry. They are not yet wired to a resolver or socket; actual enforcement on every numeric connection and retry remains a later delivery step. These rules alone do not establish that any socket has been protected.

## Authority and input

A valid policy has version `1`, zero or more explicit numeric IPv4/IPv6 CIDR and TCP-port rules, and optional additional metadata CIDRs. Each allow rule carries the acknowledgments required by the destination's classes. Rules may also narrow the configured connection target and IPv6 interface. An explicit matching deny always wins. A valid empty policy denies all; a missing, invalid or unsupported-version policy is an error. Public unicast also requires an explicit matching CIDR and port: a hostname or DNS result alone never grants access.

For a protected destination, **one matching allow** must include every applicable acknowledgment; separate incomplete allow rules do not combine their acknowledgments. `private`, `loopback`, `link-local`, `special-use` and `metadata` are separate bits. Metadata is an additional overlay, not a synonym for link-local or private. For example, `169.254.169.254` needs both link-local and metadata; `100.100.100.200` needs both special-use and metadata; `fd00:ec2::254` needs both private and metadata. Broad CIDRs do not waive these requirements. The operator may extend the metadata overlay with numeric CIDRs for installation-specific routes and aliases.

Rules normalize CIDR host bits, IPv4-mapped prefixes contained in `::ffff:0:0/96`, and configured targets using the endpoint host normalizer. Duplicate rules and redundant metadata CIDRs are removed and rules are sorted before the policy digest is computed; spelling, order and duplicate-only changes are no-ops. The digest includes this classification version. It does not attempt to prove arbitrary logical equivalence of differently structured rule sets. Policy values do not retain caller-owned mutable input.

IPv4-mapped IPv6 candidates are evaluated as underlying IPv4, including IPv4 CIDR rules and class acknowledgments; an IPv6 broad rule is not an IPv4 grant. A configured numeric target must match the candidate. A configured DNS target may narrow a rule but is never a substitute for a numeric grant. IPv6 link-local candidates require an interface scope, and an interface-narrowed rule must match it. Scope and configured target are checked separately.

Unspecified, multicast and IPv4 limited broadcast addresses are invalid. Directed IPv4 broadcast depends on the actual outgoing link subnet, not the CIDR of a policy grant. The pure evaluator therefore requires explicit IPv4 route context: a gateway route, or a directly attached subnet containing the destination. It denies unknown/inconsistent route context and a directed broadcast on a supplied direct subnet; `/31` point-to-point and `/32` host prefixes do not have a directed broadcast here. **Future socket integration must obtain and validate this context for the actual route and recheck it where necessary.** The current helper cannot establish route facts itself or detect an unseen downstream broadcast.

## Versioned special-use table

Classification version: `tlsbeacon-special-use-v1`. This is a fixed table, not a live registry lookup. The IANA IPv4 and IPv6 special-purpose registry CSV snapshots retrieved for this implementation have SHA-256 respectively `cbc4b7653c8bc640ba1e8e5d4ebbf11e7c7a1d867e7f1593aad001d3f8632aac` and `bf56772aef97fbf9b4a27c98b8511f2bb1ba96da4b9ccc12ab203a2496faba66`. Sources: [IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml) and [IANA IPv6 special-purpose registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml). The table consolidates contained entries; a globally reachable IANA special-purpose entry is still special-use here. IPv6 reserved address-space categories and deprecated site-local are additionally classified as special-use. This version is not a promise to track later allocations, every local alias, or every downstream network. Changes require a new reviewed classification version and affected policy identity.

| Class | Exact ranges in v1 |
| --- | --- |
| Private | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` |
| Loopback | `127.0.0.0/8`, `::1/128` |
| Link-local | `169.254.0.0/16`, `fe80::/10` |
| Other special-use IPv4 | `0.0.0.0/8`, `100.64.0.0/10`, `192.0.0.0/24`, `192.0.2.0/24`, `192.31.196.0/24`, `192.52.193.0/24`, `192.88.99.0/24`, `192.175.48.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4` |
| Other special-use IPv6 | `::/8`, `100::/8`, `200::/7`, `400::/6`, `800::/5`, `1000::/4`, `4000::/3`, `6000::/3`, `8000::/3`, `a000::/3`, `c000::/3`, `e000::/4`, `f000::/5`, `f800::/6`, `fe00::/9`, `fec0::/10`, `64:ff9b::/96`, `64:ff9b:1::/48`, `100::/64`, `100:0:0:1::/64`, `2001::/23`, `2001:db8::/32`, `2002::/16`, `2620:4f:8000::/48`, `3fff::/20`, `5f00::/16` |
| Built-in metadata overlay | `169.254.169.254/32`, `169.254.170.2/32`, `100.100.100.200/32`, `fd00:ec2::254/128`; plus explicit operator extensions |

The `other special-use` class excludes addresses already classified as private, loopback or link-local, even where the listed reserved supernets overlap; metadata is then overlaid independently. IPv4 `255.255.255.255`, IPv4/IPv6 unspecified addresses and multicast are rejected before a grant is evaluated. IPv4-mapped IPv6 addresses are first unmapped, so the IPv6 `::/8` entry does not replace IPv4 classification. IPv4 addresses outside the listed special/private/loopback/link-local ranges, and IPv6 addresses outside the listed ranges, are treated as ordinary unicast **for this version only**, still requiring an explicit numeric/port grant. Network and broadcast addresses of a *grant prefix* are not automatically invalid: grants need not describe actual attached subnets.

## Installation and enforcement limits

Use the operator-controlled installation resolver within the probe budget; resolver infrastructure is a prerequisite, not target authorization. Later probe code must authorize every actual resolved address, port, scope and retry, connect only to the checked numeric address, and avoid unchecked re-resolution and proxy transports. A mixed DNS result must never cause a denied candidate to be contacted.

The policy controls the destination visible at the local process/socket boundary. It cannot see destinations beyond NAT, routing or a remote relay. Operators must add installation-specific metadata aliases and restrictions explicitly; the built-in metadata overlay is not an exhaustive cloud catalog. No public website or real metadata service is needed for unit testing.
