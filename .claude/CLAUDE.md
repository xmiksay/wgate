# wgate

Multi-tenant WireGuard gateway (pool → tenants → networks → peers). Read [design](../docs/design.md) for architecture and
decisions ([enforcement](../docs/enforcement.md) for `table inet wgate`, [accounts](../docs/accounts.md) for login), [plan](../docs/plan.md) for the step you are on.

## Commands

All through the Makefile (`make help`); `CARGO_BUILD_JOBS=4` is exported there.

- `make lint` — clippy `--all-targets -D warnings`, `cargo fmt --check`, eslint
  (`--max-warnings=0`), vue-tsc, `api:check` (generated TS types current)
- `make test` — `test-unit` (lib/bin tests) + `test-int` (`tests/*.rs`; the `db` tests
  start Postgres 17 containers, so Docker must be running)
- `make lint` and `make test` first build the UI (`make web`, only when `web/` sources
  changed; needs `make deps`), so the server embeds and tests the real bundle; plain
  `cargo` embeds a stub page, and a release build without `web/dist` fails
- `make test-netns` — `#[ignore]`d root tests in `crates/agent/tests/netns*.rs`
  (kernel accepts the golden ruleset; real packets vs. the rendered ruleset over veth
  links named `wg-*`, python3 endpoints; the agent end to end against Postgres in
  Docker with real wg interfaces) and `crates/wgate/tests/netns_e2e_*.rs` (full stack:
  the API in process, the agent loop in a hub namespace, real WireGuard clients
  brought up from the downloaded configs; world in `tests/common/`);
  binaries are built as the user and run via `sudo -E` (cargo runner)
- `make release` — static musl binary + sha256 in `dist/`
- `make migrate` — `wgate migrate` with `WGATE_DATABASE_URL` (`.env.example`)
- Golden files live in `crates/core/tests/golden/`, `docs/openapi.json` and
  `web/src/api/schema.d.ts`; `make golden` rewrites them (review the diff). `ruleset.nft` is also loaded into a kernel by `make test-netns`.

Done = `make lint` + `make test` green, plus `make test-netns` when agent code, nft
rendering (`crates/core/src/nft.rs`) or the goldens changed.

## Layout

- `crates/core` — pure, no I/O: addressing/allocators, rights (`RuleSet`), `compile`
  (desired state → per-peer sets; `compile/valid.rs` decides what fails closed), nft
  + client-config rendering
- `crates/db` — SeaORM entities, the SQL migration (`migration/m0001_init.sql`: tables,
  exclusion constraints own address ranges, ownership checks; `m0001_state.sql`: the
  revision + NOTIFY triggers), `grants.sql` (agent role), `desired_state()`
  loader, `agent` (the agent's only writes: `hub_key`, `agent_status`); shared by
  server and agent
- `crates/server` — Axum + OIDC; unprivileged. `auth/` (OIDC login, sessions, `Actor`
  + CSRF), `api/` (one module per resource; `clientconf` renders configs from the
  compiled state, `openapi` lists every path), `error.rs` (`ApiError`, SQLSTATE
  mapping), `audit.rs`, `wgkey.rs` (x25519, zeroized); config
  `server.example.toml`, unit `deploy/wgate-server.service`. Tests: `tests/*.rs`
  against Postgres containers and a mock IdP (`tests/common/idp.rs`);
  `docs/openapi.json` is a golden (`make golden`; operationIds must be unique).
  `ui.rs` serves the embedded `web/dist` (staged by `build.rs`; a stub page without
  `make web`) with a strict CSP, `index.html` for client routes
- `crates/agent` — root with `CAP_NET_ADMIN` only, no HTTP listener; reconciles network
  by network through `ip`/`wg`/`nft` behind a `Runner` (faked in unit tests); who may
  hold which address this pass is one account (`reconcile/holdings.rs`); saves
  the last desired state (`state.rs`) to rebuild from when it boots without the
  database; config `agent.example.toml`, unit `deploy/wgate-agent.service`
- `crates/wgate` — binary, `server | agent | migrate`
- `web/` — Vue UI, embedded into the binary. `src/api/schema.d.ts` is generated from
  `docs/openapi.json` (`npm run api:gen`, checked by `make lint`); one typed client
  `src/api/client.ts` (CSRF header, 401 → login); no `v-html`, nothing the CSP would
  block; a server-made private key lives only in the dialog that shows it

## Rules

- Toolchain is pinned in `rust-toolchain.toml`; CI reads the channel from it. Bump
  deliberately.
- The agent owns `table inet wgate` (a base plus one atomic `nft -f` fragment per
  network) and only the interfaces carrying its mark (alias `wgate:n<id>`, set when
  it makes them) plus its scratch namespace `wgtmp-*` (where it makes them). Never
  touch `wg0` or other nft tables.
- nft interval sets reject overlapping elements: rights go through `RuleSet` (canonical,
  disjoint) before rendering — never emit raw rules into a set.
- Every packet to or from a tenant is checked against the current sets in both
  directions (replies with the tuple swapped) — no `ct state established` and no
  related-ICMP shortcut; revocation must not depend on conntrack. Conntrack only picks
  the chain via `ct direction`. Only hub-generated ICMP errors pass unchecked.
- Model: global pool → tenant blocks → networks (`wg-<slug>`, own port) → peers (a
  device's membership, own key + IP; may carry routed subnets). Default deny, even
  inside a network (`mesh` flag). Cross-tenant only via global-admin federation;
  sources outside the pool only via global-admin inbound grants. No implicit trust
  for wg0 or the master.
- All addresses (pool + routed subnets) are globally unique — the hub has one routing
  table and nft keys sets by source address. Reject overlaps; never NAT around them
  (NETMAP is a later phase).
- Hub private keys never leave `/var/lib/wgate/keys`; device private keys are never
  stored or logged.
- No raw DB errors to API clients; typed `ApiError`.
- Workspace clippy lints deny `unwrap`/`expect`/`panic`/`todo`. `clippy.toml` allows
  them inside `#[test]`/`#[cfg(test)]`; integration-test helpers and proptest
  strategies outside a `#[test]` fn need a file-level `#![allow]`.
- Workflow: one branch + PR per plan step, rebase-merge (no merge commits).
