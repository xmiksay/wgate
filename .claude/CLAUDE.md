# wgate

Multi-tenant WireGuard gateway (pool → tenants → networks → peers). Read [design](../docs/design.md) for architecture and
decisions ([enforcement](../docs/enforcement.md) for `table inet wgate`), [plan](../docs/plan.md) for the step you are on.

## Commands

All through the Makefile (`make help`); `CARGO_BUILD_JOBS=4` is exported there.

- `make lint` — clippy `--all-targets -D warnings`, `cargo fmt --check`, eslint
  (`--max-warnings=0`), vue-tsc
- `make test` — `test-unit` (lib/bin tests) + `test-int` (`tests/*.rs`; the `db` tests
  start Postgres 17 containers, so Docker must be running)
- `make test-netns` — `#[ignore]`d root tests in `crates/agent/tests/netns*.rs`
  (kernel accepts the golden ruleset; real packets vs. the rendered ruleset over veth
  links named `wg-*`, python3 endpoints; the agent end to end against Postgres in
  Docker with real wg interfaces);
  binaries are built as the user and run via `sudo -E` (cargo runner)
- `make release` — static musl binary + sha256 in `dist/`
- `make migrate` — `wgate migrate` with `WGATE_DATABASE_URL` (`.env.example`)
- Golden files live in `crates/core/tests/golden/`; `make golden` rewrites
  them (review the diff). `ruleset.nft` is also loaded into a kernel by `make test-netns`.

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
- `crates/server` — Axum + OIDC; unprivileged
- `crates/agent` — root with `CAP_NET_ADMIN` only, no HTTP listener; reconciles network
  by network through `ip`/`wg`/`nft` behind a `Runner` (faked in unit tests); who may
  hold which address this pass is one account (`reconcile/holdings.rs`); saves
  the last desired state (`state.rs`) to rebuild from when it boots without the
  database; config `agent.example.toml`, unit `deploy/wgate-agent.service`
- `crates/wgate` — binary, `server | agent | migrate`
- `web/` — Vue UI, embedded into the binary

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
