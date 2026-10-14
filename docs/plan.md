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
  - routed subnets: rejected when outside `routed_space` (global-admin allowlist),
    over the pool or `reserved` infrastructure, or overlapping another routed subnet
  - every conflict (tenant blocks, network ranges and slugs, peer addresses): the
    lowest id keeps it, only the newcomer fails closed
- `compile(&DesiredState) -> Compiled { peers, invalid_blocks, invalid_networks,
  skipped, dropped_routes, tenant_space, snat_source, node_cidrs }`: per peer
  `addrs`, `outbound`, `inbound` exactly per design.md → Rights (ceiling ∩ external
  rules − tenant space, rules between networks, federation, mesh, inbound grants
  clipped to outside sources + hub addresses). Peers with an unknown/invalid network,
  an invalid IP, or an address an older peer already holds are skipped with a
  `Problem`; a route outside `routed_space`, over pool/reserved, or claimed by an
  older route is dropped alone (its peer stays). A network is valid only inside its
  tenant's (winning) blocks, with a known tenant, at most /30, and with a range and
  slug no older network holds.
- Rendering:
  - `render_base` / `render_snat` / `render_network` / `render_network_purge` /
    `render_network_cutoff` (`render_all` for
    tests): `table inet wgate` per design.md as a base plus one fragment per network,
    from one compile run (disjoint peer addresses, tenant space, SNAT source and
    node networks all come from it)
  - `render_client_config(&ClientConfig { address, hub_address, private_key,
    hub_public_key, endpoint, outbound, inbound }) -> String`
- Tests: unit tests for every function; proptest (set ops match pointwise semantics,
  `intersect` commutative, elements disjoint and exact, compile never grants external
  access beyond the ceiling or tenant space beyond rules/mesh/federation); golden
  files for nft and the client config; netns: the golden ruleset loads, replaces, and
  filters real packets (veth links named `wg-*`: allowed vs. denied per chain).

### 1.3 Database + migrations (`crates/db`)
- SeaORM entities + one SQL migration for the tables in design.md → Data model. Unique:
  `tenant.slug`, `network.slug`, `network.port`, active `peer.public_key` and `peer.ip`,
  per-tenant email and OIDC subject. Exclusion constraints (GiST `inet_ops`, built in)
  keep blocks, networks and routes disjoint; CHECKs: slug syntax, port range, ≤ /30,
  "exactly one target" on `rule`, `valid_service` (icmp ⇔ NULL ports, never NULL).
- Immutable ownership columns; networks reference their block (composite FK with the
  tenant), rules reference both networks with the tenant; triggers check a network
  inside its block and a peer inside its network and tenant (immutable data only); a
  revoked peer never holds a LAN (routes reference `(peer_id, active)`: revoking
  cascades, a revoked peer cannot get one, at any isolation level). One active peer
  per (device, network); keys and IPs unique among active peers.
- The migrator records a checksum per migration and refuses a database with an
  unknown or edited migration; it re-applies the agent grants (revoke, then grant) on
  every run.
- All state writes run at READ COMMITTED (refused at the first statement otherwise)
  and never `SET CONSTRAINTS … IMMEDIATE`; TRUNCATE is refused (use DELETE); ids are
  immutable; re-revoking is a no-op. The once-per-transaction marker is the counter
  row's own xmin, and only the triggers may change that row, so no caller (not even
  the owner) can mute or rewind it. Routed LANs and tenant blocks never overlap
  (cross-table check under an advisory lock).
- `desired_state(db, &Infra)`: one REPEATABLE READ read-only snapshot, active rows →
  `core::DesiredState` (+ its revision, peer keys, owner tenants); unmappable rows are
  skipped with a warning (a load error would block revocations). Cross-tenant devices
  fail closed in `compile` (`Problem::ForeignDevice`).
- Own migrator (`wgate_migration`, one transaction under an advisory lock).
- Postgres is reached directly (5432), not through pgbouncer (transaction pooling
  breaks LISTEN).
- NOTIFY from deferred constraint triggers on the desired-state tables (only the
  columns it depends on): once per transaction, at commit, bump the counter in
  `state_revision` and `pg_notify('wgate_changed', <revision>)`. The hot row lock is
  taken last, so writers neither serialize nor deadlock on it; writes run at READ
  COMMITTED.
- Table `agent_status (applied_revision, applied_at, error)`, which the agent writes.
- Grants: `wgate` = owner; `wgate_agent` = SELECT on the tables `desired_state()`
  reads (on `app_user` only `id, tenant_id, role, disabled_at`), INSERT/UPDATE
  `hub_key` + `agent_status`; re-applied on every migrate.
- Revocation is final (un-revoking is refused); ownership columns may be rewritten
  unchanged.
- `wgate migrate` subcommand (run by ansible before the units restart).

### 1.4 `agent`
- Config `/etc/wgate/agent.toml` (`crates/agent/agent.example.toml`): `database_url`, `snat_source`
  (172.19.9.10), `node_cidrs` (172.19.9.0/24), `pool`, `routed_space`, `reserved`
  (as the server's), `keys_dir`, `state_file` (the last desired state, served when
  the hub boots without its database), `reconcile_interval_secs = 60`.
- Core: the nft rendering splits into `render_base` + `render_network` (one fragment
  per network: its chains, sets and map entries) + `render_network_purge`;
  `Compiled` lists its networks (interface, range, hub address, port).
- Loop (`LISTEN wgate_changed` or a tick):
  1. load the desired state, `core::compile` it
  2. apply the base, then SNAT as a transaction of its own; read the inventory
     (`ip -j link show type wireguard`, `nft -j list map … from_net`). A failed base
     still counts as guarding when the kernel's `tenant_space` covers the compiled
     one and the prerouting and output rules that use it are there. Otherwise, or without the full inventory
     (links and registry), nothing grows (nothing made, no peer added), but peer and
     route revocations apply, and then the fragments, cut down to what the stale
     guard covers and to what is not held (`Compiled::within_guard`); with the
     guard unknown, the kernel is left as it is (the VPN keeps running; revocations
     in the rules wait for a pass that can see)
  3. what is gone. An interface is wgate's when its alias carries the mark
     `wgate:n<id>` (set at creation; survives a flushed table and a lost key file).
     A marked interface whose network is not compiled under that name (and is not
     merely invalid this pass: that one keeps its interface, unregistered), or an
     unmarked `wgtmp-*` scratch link, is deleted; one that would not go loses its
     peers, addresses and LAN routes, frees a wanted port and holds its name until
     it goes. Map elements that are not wgate's are cleared, map by map. Registrations stay
     only for a network compiled on that name whose own interface is there or about
     to be made (a stale name of a network live elsewhere loses only its entries); any other is removed (idempotently;
     one that still fails has its chains cut off to `drop`), so nothing on that
     name keeps a network's rights. The list of links falls back to
     every link's details (`ip -j -d link show`); without either, the kernel is left
     as it is, apart from unregistering networks no longer compiled
  4. ports another network wants are freed (parked on the first free spare port,
     51900–51999, outside `PORT_RANGE`). A name held by an unmarked interface, or by a link that is not
     WireGuard, is refused. Then, for **every** network: peer removals and
     narrowings (diffed against `wg show <if> allowed-ips`, never `dump`: it carries
     private and preshared keys) and stale LAN route deletions — before any network
     grows, so nothing is held twice while it moves; what a failed command could not
     release stays held: no peer, route or right anywhere takes it this pass. A
     network whose peers cannot be read gets rules that give them nothing this pass
     (a revocation holds anyway) and no changes on its interface; one whose routes
     cannot be read still revokes, but adds no route. What either may hold (its
     compiled addresses and what its rules last gave, `n<id>_peers`) no other
     network takes. When even that cannot be read (its last rules, or a stuck
     interface's leftovers), nothing grows this pass
  5. **network by network**, every step attempted: the hub key `n<id>.key` in
     `keys_dir` first (issued only to an interface without a key, never deleted; a
     damaged or missing one for a keyed interface is an error, never a rotation; its
     public key goes to `hub_key`); a new interface made as `wgtmp-<id>`, marked,
     renamed to `wg-<slug>` (a failure stops the network); `ip addr replace`
     hub/prefix; `wg set … private-key`, then `listen-port`; up; the fragment (one that
     fails cuts the network off until it applies); if it
     applied, peer additions (`AllowedIPs` = `addrs(peer)`) and LAN routes (`ip route
     add … proto 150`, never taking over another's route)
  6. `agent_status` (applied revision, and everything `Compiled` rejected — blocks,
     networks, peers, routes — plus per-network failures as errors)
- Tools: `ip` (iproute2), `wg` (wireguard-tools), `nft`; commands go through one
  runner (each killed after 30 s), so diffs are unit-tested against fake tool output.
- Only manages interfaces carrying its mark; it never touches `wg0`. Any other `wg-*`
  interface → warn, do not delete (its traffic is dropped).
- An error in one network does not block the others; the error goes to `agent_status`
  + `tracing`.
- systemd: `User=root`, `CapabilityBoundingSet=CAP_NET_ADMIN`, `ProtectSystem=strict`,
  `ReadWritePaths=/var/lib/wgate`.

### 1.5 `server` — API + global-admin login
- Config `/etc/wgate/server.toml` (`crates/server/server.example.toml`):
  - `listen = 172.19.9.10:8470`, `database_url`, `public_url = https://vpn.mmik.cz`,
    `endpoint_host` (clients' `Endpoint`)
  - `pool`, `routed_space`, `reserved`, `snat_source`, `node_cidrs` (as the agent's:
    the server compiles the state to render client configs)
  - `[admin_oidc]` issuer (verbatim, as discovery wants it)/client_id/client_secret
  - `[[tenant_oidc]]` comes with phase 2
- OIDC login (generic, PKCE S256, nonce) for global admins only; the verified email
  matches first, then `sub` is pinned; the role comes from the DB. Bootstrap:
  `wgate admin grant <email>`. The login's state, nonce and PKCE verifier live in
  its browser (`wgate_login` cookie), so the server keeps nothing per login. Sessions in Postgres (sha256 of the token, 8 h idle,
  7 d max), cookie `HttpOnly; Secure; SameSite=Lax`, `X-CSRF-Token` on writes.
- Schema additions (in m0001): `session`, `peer.key_source`, a public
  key that rotates only while active and server-made, `network.dns`, block → network
  cascade.
- REST `/api/v1`: CRUD tenants, blocks, networks (mesh flag), users, devices, peers
  (create with a server or pasted key, routed subnets, revoke), ceilings, rules (422
  with the uncovered part / wrong tenant / overlap), federations, inbound grants;
  `GET /status` (revision vs. applied). Authorization is role-based from the start
  (global admin vs. tenant admin scoped to their tenant), even though only the global
  admin can log in until phase 2.
- Peer create with a server key: the response contains the config + a QR (SVG). The
  private key is never stored or logged (a test greps the log). `POST
  /peers/{id}/config` rotates a server key (new config, the old one dies); a pasted
  key gets a config without `PrivateKey`. Until the agent publishes the hub key, the
  config is missing and a warning says so (and the key does not rotate). A rotation
  swaps only the key it started from (a concurrent download gets 409). A peer of a
  global admin's device is the global admin's to manage.
- Routed LANs as compile wants them (routed space, clear of the pool and the
  infrastructure); no ceiling or inbound source reaches another tenant's LAN (checked
  both ways under one advisory lock). `/status` shows the agent's error text to
  global admins only.
- Deletes cascade; every write leaves an `audit` row in its transaction (`GET /audit`,
  paged with `before`/`limit`). Addresses are explicit; `free-ip`, `free-range`,
  `free-block`, `free-port` suggest. OpenAPI from the code (utoipa), committed as
  `docs/openapi.json`, a test keeps it in sync (`make golden`).
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
