# wgate — implementation plan

Architecture and decisions: [design.md](design.md). Each step = one branch + PR into
`master`. A step is done when `make lint` + `make test` are green (netns tests run in CI
under sudo).

## Phase 1 — MVP (admin manages everything)

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
- Types: `Proto`, `Rule {proto, dst: Ipv4Net, ports: Option<RangeInclusive<u16>>}`,
  `RuleSet`.
- `intersect(a, b) -> RuleSet`, `covers(ceiling, rule) -> Result<(), Uncovered>`,
  `effective(company, groups, user) -> RuleSet` exactly per design.md → Rights.
- Allocators:
  - `net_index` → `10.50.n.0/24` + port `51830+n` (n = 1..=9 for the firewall range
    51831–51839; 0 is reserved)
  - device IP = first free one in `.2–.254` (`.1` = hub)
- Rendering:
  - `render_nft(state) -> String`: the whole `table inet wgate` per design.md
  - `render_client_config(device, hub, rules, private_key: Option<_>) -> String`
- Tests: unit tests for every function, proptest (`intersect` is commutative and
  `⊆` both inputs; `effective ⊆ company`), golden files for nft and the client config.

### 1.3 Database + migrations (`server`)
- SeaORM entities + migrations for the tables in design.md → Data model. Unique:
  `company.slug`, `company.net_index`, `device.public_key`, `(company, device.ip)`,
  `(issuer, oidc_sub)`.
- Trigger-free NOTIFY: every write transaction ends with
  `SELECT pg_notify('wgate_changed', <revision>)`. `revision` is a sequence in table
  `state_revision`.
- Table `agent_status (applied_revision, applied_at, error)`, which the agent writes.
- Grants: `wgate` = owner; `wgate_agent` = SELECT on everything,
  INSERT/UPDATE `hub_key` + `agent_status`.
- `wgate migrate` subcommand (run by ansible before the units restart).

### 1.4 `agent`
- Config `/etc/wgate/agent.toml`: `database_url`, `public_ip`, `snat_source`
  (172.19.9.10), `node_cidrs` (172.19.9.0/24), `keys_dir`, `reconcile_interval = 60s`.
- Loop:
  1. `LISTEN wgate_changed` or a tick
  2. load the state
  3. per company: key in `keys_dir` (generate if missing, write `hub_key`)
  4. interface via `defguard_wireguard_rs` (create / address `10.50.n.1/24` /
     listen-port / delete a disabled one)
  5. diff peers → `remove` first, then `add`/`update`
  6. `nft -f -` with the rendered table (atomic)
  7. `agent_status`
- Only manages interfaces with the `wg-` prefix it has in its state; it never touches
  `wg0`. An unknown `wg-*` interface → warn, do not delete.
- An error in one company does not block the others; the error goes to `agent_status`
  + `tracing`.
- systemd: `User=root`, `CapabilityBoundingSet=CAP_NET_ADMIN`, `ProtectSystem=strict`,
  `ReadWritePaths=/var/lib/wgate`.

### 1.5 `server` — API + admin login
- Config `/etc/wgate/server.toml`:
  - `listen = 172.19.9.10:8470`, `database_url`, `public_url = https://vpn.mmik.cz`
  - `session_key`
  - `[admin_oidc]` issuer/client_id/client_secret + `admin_emails`
  - `[[company_oidc]]` slug/issuer/client_id/client_secret (for phase 2)
- OIDC login (PKCE) for the admin only; sessions in Postgres, cookie
  `HttpOnly; Secure; SameSite=Lax`, CSRF token on writes.
- REST `/api/v1`: CRUD companies, groups, users (+ group membership), rules (422 with
  the uncovered part when not covered), devices (create with a server or pasted key,
  revoke), `GET /status` (revision vs. applied).
- Device create with a server key: the response contains the config + a QR (SVG). The
  private key is never stored or logged (`tracing` field skip, a test greps the log).
- Errors: typed `ApiError` → JSON, no raw DB errors to the client.
- Integration tests: Postgres in a container, a mock OIDC IdP; the CRUD flows, rule
  coverage, revoke → NOTIFY arrives.

### 1.6 UI (admin)
- Pages: Companies → detail (rules, groups, users, devices), Users → detail, Audit
  (simple list), status bar "applied / pending".
- Device creation dialog: config shown once + QR + download `.conf`.

### 1.7 Netns tests (`make test-netns`)
- Script + Rust test harness:
  - namespaces `hub`, `a1` (company A), `b1` (company B), `node` (stands in for
    172.19.9.11)
  - veth links; the agent runs in `hub` against a test Postgres
- Scenarios:
  - A pings `node` (allowed) and gets a reply through SNAT
  - A → TCP 6443 on the hub allowed, TCP 22 on the hub denied
  - A → B denied; B → A denied
  - revoking A's device during a live TCP stream kills it within 1 s
  - disabling company B deletes its interface while A's stream keeps running
  - a user rule narrower than the group/company is applied as the intersection

### 1.8 Deployment (repo `ansible`, its own branch there)
- `group_vars/pg`: database `wgate` + roles `wgate`, `wgate_agent`;
  `make pg-password-new ROLE=wgate` and the same for `wgate_agent`.
- Role `wgate` (defaults: version + sha256):
  - download the binary, create user `wgate` and `/var/lib/wgate`
  - render both configs from `services.vault.yml` (`no_log`)
  - `wgate migrate`, start both units
- `site.yml`: role `wgate` on the `wireguard_ui` host (tag `wgate`), after `firewall`.
- Role `firewall`:
  - `iifname "wg-*" accept` in input (delegation to `inet wgate`)
  - `firewall_public_udp` + range `51831-51839` on the wireguard_ui host
  - tests in `tests/` for the template
- `manifests/infra/services`: `service-wgate.yaml`, `endpointslice-wgate-manual-0.yaml`
  (172.19.9.10:8470), `ingress-wgate.yaml` (vpn.mmik.cz, letsencrypt-prod).
- wireguard-ui: `WGUI_DEFAULT_CLIENT_ALLOWED_IPS` + `10.50.0.0/16`. Add it by hand to
  the admin's existing clients.
- DNS (web4u): `vpn.mmik.cz` A → 37.205.11.119.
- Docs:
  - README: a VPN / wgate section, the `make wgate` target
  - `.claude/CLAUDE.md`: the agent owns `table inet wgate`, so `table inet firewall` is
    not the only one
- Smoke test on the master before the first company: the agent creates `wg-test`
  (n=9), a device from the admin laptop:
  - ping 172.19.9.11 ✓, 6443 ✓, 22 on 172.19.9.2 ✗, 192.168.1.1 ✗
  - revoke → the stream drops

  Then delete the company.

### 1.9 Onboarding
- nexial (n=1, port 51831), krcmar (n=2, 51832). Company rule:
  - `tcp 172.16.16.1/32 6443`
  - `icmp 172.19.9.10/32, .11/32, .12/32`
- Their users: a kubeconfig from `make kubeconfig-sa NS=<ns> SA=user`, unchanged
  (server `172.16.16.1:6443`).

## Phase 2 — Self-service

- Company OIDC from `[[company_oidc]]` + a `oidc_provider` row. Login:
  - email → domain → company, or a company picker
  - match `(issuer, email)` → bind `sub`; afterwards only `(issuer, sub)`
  - unknown user → 403
- User UI: my devices, add (server key / pasted public key), revoke; a per-user device
  limit (default 5, editable by the admin).
- Audit: every write with the actor; the admin UI filters by company.
- Tests: integration against a mock IdP with two issuers (a user of company A cannot
  log in through B's IdP, cannot see or create devices in B).

## Phase 3 — wg0 under wgate

- Model: a "network" kind `infra`, one record for wg0 (172.16.16.0/24, port 51820,
  the existing hub key — the agent reads it from `/etc/wireguard`, never from the DB).
  Peers carry `extra_allowed_ips` (the Turris: 192.168.0.0/23) and a `node` flag.
- `wgate import-wgui /var/lib/wgui` imports the clients (names, public keys, IPs,
  allowed IPs; private keys are not imported).
- Ansible: `wg_peer`/`wireguard` take the hub public key + IP from `wgate export-node
  <host>`, not from the vault.
- Cutover:
  1. `wg showconf` backup
  2. stop wireguard-ui and wg-quick@wg0
  3. the agent takes over wg0
  4. check every node over wg0
  5. remove role `wireguard_ui`
  - Fallback: public SSH 22.
- The admin sees all devices of all networks in one list (the requirement "I see
  everything").

## Phase 4 — Later (not planned in detail)

- Per-user k8s tokens (ServiceAccount per user, revoked together with the user in wgate).
- Optional Tailscale/Headscale clients.
