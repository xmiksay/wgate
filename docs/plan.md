# wgate — implementation plan

Architecture and decisions: [design.md](design.md). Each step = one branch + PR into
`master`. A step is done when `make lint` + `make test` are green (netns tests run in CI
under sudo).

## Phase 1 — MVP (the global admin manages everything)

### 1.1 Repo skeleton
- Cargo workspace `crates/{core,server,agent,wgate}`, edition 2024, `rust-toolchain.toml`
  pinning the same toolchain CI installs.
- `web/` Vue 3 + TS + Vite + Tailwind + Pinia, eslint + vue-tsc.
- Makefile targets:
  - `build`, `run-server`, `run-agent`, `lint` (clippy `--all-targets -D warnings`,
    fmt check, `npm run lint`, typecheck), `test` (unit + integration), `test-netns`
    (sudo), `release`
  - always `CARGO_BUILD_JOBS=4`
- CI (GitHub Actions): lint, test, test-netns. A release on a `v*` tag builds a static
  `x86_64-unknown-linux-musl` binary + sha256.
- `README.md`, `.claude/CLAUDE.md` (commands, layout, rules from design.md).

### 1.2 `core` — pure logic, no I/O
- Rights engine: `Proto`, `PortRange`, `Service::{Tcp(PortRange), Udp(PortRange), Icmp}`,
  `Rule { net, service }`, `RuleSet` (canonical, disjoint: nft rejects overlapping set
  elements) with union / intersect / difference, `covers(ceiling, rule) -> Result<(),
  Uncovered>`. The same types carry outbound rights (net = destination) and inbound
  (net = source).
- Allocation (design.md → Decisions):
  - `Slug` (`[a-z0-9-]{1,11}`, alphanumeric ends) → `wg-<slug>`
  - `Pool` (list of CIDRs): next free block of a given prefix for a tenant; checks a
    block is inside the pool and disjoint from the others
  - network CIDR: next free one of a given prefix inside the tenant's blocks, disjoint
    from its other networks; hub address = first host
  - peer IP: first free host of the network, not the hub address or broadcast
  - port: first free in `51800–51899`, skipping `51820`
  - routed subnets: rejected when overlapping the pool or another routed subnet
- `compile(&DesiredState) -> Compiled { peers, skipped, tenant_space }`: per peer
  `addrs`, `outbound`, `inbound` exactly per design.md → Rights (ceiling ∩ external
  rules − tenant space, rules between networks, federation, mesh, inbound grants
  clipped to outside sources + hub addresses). Peers with an unknown/invalid network,
  an invalid IP, a routed LAN in the pool, or an address an older peer already holds
  are skipped with a `Problem`.
- Rendering:
  - `render_nft(&NftState) -> NftRender { script, skipped }`: the whole
    `table inet wgate` per design.md from compiled peers and `tenant_space`
  - `render_client_config(&ClientConfig { address, hub_address, private_key,
    hub_public_key, endpoint, outbound, inbound }) -> String`
- Tests: unit tests for every function; proptest (set ops match pointwise semantics,
  `intersect` commutative, elements disjoint and exact, compile never grants external
  access beyond the ceiling or tenant space beyond rules/mesh/federation); golden
  files for nft and the client config; netns: the golden ruleset loads, replaces, and
  filters real packets (veth links named `wg-*`: allowed vs. denied per chain).

### 1.3 Database + migrations (`server`)
- SeaORM entities + migrations for the tables in design.md → Data model. Unique:
  `tenant.slug`, `network.slug`, `network.port`, `peer.public_key`, `peer.ip`,
  `(issuer, oidc_sub)`. Postgres exclusion constraints (`btree_gist`, `inet &&`) keep
  blocks, a tenant's networks and routed subnets disjoint; CHECKs for "exactly one
  target" on `rule` and icmp ⇔ NULL ports.
- Trigger-free NOTIFY: every write transaction ends with
  `SELECT pg_notify('wgate_changed', <revision>)`. `revision` is a counter in table
  `state_revision`.
- Table `agent_status (applied_revision, applied_at, error)`, which the agent writes.
- Grants: `wgate` = owner; `wgate_agent` = SELECT on everything except sessions,
  INSERT/UPDATE `hub_key` + `agent_status`.
- `wgate migrate` subcommand (run by ansible before the units restart).

### 1.4 `agent`
- Config `/etc/wgate/agent.toml`: `database_url`, `public_ip`, `snat_source`
  (172.19.9.10), `node_cidrs` (172.19.9.0/24), `keys_dir`, `reconcile_interval = 60s`.
- Loop:
  1. `LISTEN wgate_changed` or a tick
  2. load the desired state, `core::compile` it
  3. per network: key in `keys_dir` (generate if missing, write `hub_key`)
  4. interface via `defguard_wireguard_rs` (create / address hub/prefix / listen-port /
     delete a disabled one); routes for routed subnets via their interface
  5. diff peers → `remove` first, then `add`/`update` (`AllowedIPs` = `addrs(peer)`)
  6. `nft -f -` with the rendered table (atomic)
  7. `agent_status` (incl. `Compiled.skipped` and `NftRender.skipped` peers as errors)
- Only manages interfaces with the `wg-` prefix it has in its state; it never touches
  `wg0`. An unknown `wg-*` interface → warn, do not delete.
- An error in one network does not block the others; the error goes to `agent_status`
  + `tracing`.
- systemd: `User=root`, `CapabilityBoundingSet=CAP_NET_ADMIN`, `ProtectSystem=strict`,
  `ReadWritePaths=/var/lib/wgate`.

### 1.5 `server` — API + global-admin login
- Config `/etc/wgate/server.toml`:
  - `listen = 172.19.9.10:8470`, `database_url`, `public_url = https://vpn.mmik.cz`
  - `pool = ["10.50.0.0/16"]`, `session_key`
  - `[admin_oidc]` issuer/client_id/client_secret + `admin_emails`
  - `[[tenant_oidc]]` slug/issuer/client_id/client_secret (for phase 2)
- OIDC login (PKCE) for the global admin only; sessions in Postgres, cookie
  `HttpOnly; Secure; SameSite=Lax`, CSRF token on writes.
- REST `/api/v1`: CRUD tenants, blocks, networks (mesh flag), users, devices, peers
  (create with a server or pasted key, routed subnets, revoke), ceilings, rules (422
  with the uncovered part / wrong tenant / overlap), federations, inbound grants;
  `GET /status` (revision vs. applied). Authorization is role-based from the start
  (global admin vs. tenant admin scoped to their tenant), even though only the global
  admin can log in until phase 2.
- Peer create with a server key: the response contains the config + a QR (SVG). The
  private key is never stored or logged (`tracing` field skip, a test greps the log).
- Inbound grant with a broad source → warning in the response (it makes every target
  peer a full tunnel).
- Errors: typed `ApiError` → JSON, no raw DB errors to the client.
- Integration tests: Postgres in a container, a mock OIDC IdP; the CRUD flows, ceiling
  coverage, tenant boundaries (a tenant admin cannot touch another tenant), revoke →
  NOTIFY arrives.

### 1.6 UI (admin)
- Pages: Tenants → detail (blocks, ceiling, networks, users), Network → detail (mesh,
  rules, peers, routers), Users → detail (devices, peers), Federations, Inbound grants,
  Audit (simple list), status bar "applied / pending".
- Peer creation dialog: config shown once + QR + download `.conf`.

### 1.7 Netns tests (`make test-netns`)
- Rust test harness:
  - namespaces `hub`, `a1`/`a2` (tenant A, networks A1/A2), `b1` (tenant B), `lan`
    (behind a router peer in A1), `node` (stands in for 172.19.9.11), `pod` (outside
    the pool)
  - real wg interfaces; the agent runs in `hub` against a test Postgres
- Scenarios:
  - A1 pings `node` (allowed) and gets a reply through SNAT
  - A1 → TCP 6443 on the hub allowed, TCP 22 on the hub denied
  - inside A1: denied with mesh off, allowed with mesh on
  - A1 → A2 only with a rule A1 → A2; A2 → A1 still denied
  - A1 → B1 denied; allowed only with a federation; tenant-admin rules cannot do it
  - `lan` host reaches what its router may; others reach `lan` only per rules
  - `pod` reaches a peer only with an inbound grant; revoking it kills a live stream
  - revoking a peer during a live TCP stream kills it within 1 s; the same device's
    peer in another network keeps working
  - disabling network B1 deletes its interface while A1's stream keeps running

### 1.8 Deployment (repo `ansible`, its own branch there)
- `group_vars/pg`: database `wgate` + roles `wgate`, `wgate_agent`;
  `make pg-password-new ROLE=wgate` and the same for `wgate_agent`.
- Role `wgate` (defaults: version + sha256):
  - download the binary, create user `wgate` and `/var/lib/wgate`
  - render both configs from `services.vault.yml` (`no_log`)
  - `wgate migrate`, start both units
- `site.yml`: role `wgate` on the `wireguard_ui` host (tag `wgate`), after `firewall`.
- Role `firewall`:
  - `iifname "wg-*" accept` in input, `iifname/oifname "wg-*" accept` in forward
    (delegation to `inet wgate`)
  - `firewall_public_udp` + range `51800-51899` on the wireguard_ui host (51820 is
    already wg0's)
  - tests in `tests/` for the template
- `manifests/infra/services`: `service-wgate.yaml`, `endpointslice-wgate-manual-0.yaml`
  (172.19.9.10:8470), `ingress-wgate.yaml` (vpn.mmik.cz, letsencrypt-prod).
- wireguard-ui: nothing by default (no implicit wg0 → tenant access).
- DNS (web4u): `vpn.mmik.cz` A → 37.205.11.119.
- Docs:
  - README: a VPN / wgate section, the `make wgate` target
  - `.claude/CLAUDE.md`: the agent owns `table inet wgate`, so `table inet firewall` is
    not the only one
- Smoke test on the master before the first tenant: tenant `test`, network `test`
  (port 51899), a peer from the admin laptop:
  - ping 172.19.9.11 ✓, 6443 ✓, 22 on 172.19.9.2 ✗, 192.168.1.1 ✗
  - revoke → the stream drops

  Then delete the tenant.

### 1.9 Onboarding
- Tenants nexial and krcmar, a `/24` block each, one network each (`nexial`,
  `krcmar`). Ceiling and network rule:
  - `tcp 172.16.16.1/32 6443`
  - `icmp 172.19.9.10/32, .11/32, .12/32`
- Their users: a kubeconfig from `make kubeconfig-sa NS=<ns> SA=user`, unchanged
  (server `172.16.16.1:6443`).

## Phase 2 — Self-service

- Tenant OIDC from `[[tenant_oidc]]` + an `oidc_provider` row. Login:
  - email → domain → tenant, or a tenant picker
  - match `(issuer, email)` → bind `sub`; afterwards only `(issuer, sub)`
  - unknown user → 403
- Tenant-admin UI: networks inside own blocks, membership, routers, rules (within the
  ceiling), the tenant's audit log.
- User UI: my devices and peers, add to a network (server key / pasted public key),
  revoke; a per-user peer limit (default 5, editable by the tenant admin).
- Audit: every write with the actor; the global admin filters by tenant.
- Tests: integration against a mock IdP with two issuers (a user of tenant A cannot
  log in through B's IdP, cannot see or create anything in B; a tenant admin cannot
  create federations or widen the ceiling).

## Phase 3 — wg0 under wgate

- Model: `172.16.16.0/24` joins the pool as the block of tenant `miksa`; wg0 is its
  network "miksa" (port 51820, the existing hub key — the agent reads it from `/etc/wireguard`,
  never from the DB; interface name stays `wg0`). The Turris is a router peer with
  192.168.0.0/23; nodes are peers with a `node` flag.
- `wgate import-wgui /var/lib/wgui` imports the clients (names, public keys, IPs,
  allowed IPs as routed subnets; private keys are not imported) into "miksa". External
  devices are then moved per device to other tenants/networks: a new peer there (new
  IP + config handed to the owner), the old wg0 peer revoked once the new one is up.
- Ansible: `wg_peer`/`wireguard` take the hub public key + IP from `wgate export-node
  <host>`, not from the vault.
- Cutover:
  1. `wg showconf` backup
  2. stop wireguard-ui and wg-quick@wg0
  3. the agent takes over wg0
  4. check every node over wg0
  5. remove role `wireguard_ui`
  - Fallback: public SSH 22.
- The global admin sees all peers of all networks in one list (the requirement "I see
  everything").

## Phase 4 — Later (not planned in detail)

- 1:1 NETMAP of colliding routed LANs into pool blocks.
- Per-user k8s tokens (ServiceAccount per user, revoked together with the user in wgate).
- Optional Tailscale/Headscale clients.
