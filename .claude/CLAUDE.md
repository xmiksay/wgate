# wgate

Multi-tenant WireGuard gateway. Read [design](../docs/design.md) for architecture and
decisions, [plan](../docs/plan.md) for the step you are on.

## Commands

All through the Makefile (`make help`); `CARGO_BUILD_JOBS=4` is exported there.

- `make lint` — clippy `--all-targets -D warnings`, `cargo fmt --check`, eslint
  (`--max-warnings=0`), vue-tsc
- `make test` — `test-unit` (lib/bin tests) + `test-int` (`tests/*.rs`)
- `make test-netns` — `#[ignore]`d root tests in `crates/agent/tests/netns.rs`;
  binaries are built as the user and run via `sudo -E` (cargo runner)
- `make release` — static musl binary + sha256 in `dist/`
- Golden files live in `crates/core/tests/golden/`; `make golden` rewrites
  them (review the diff). `ruleset.nft` is also loaded into a kernel by `make test-netns`.

Done = `make lint` + `make test` green, plus `make test-netns` when agent code, nft
rendering (`crates/core/src/nft.rs`) or the goldens changed.

## Layout

- `crates/core` — pure, no I/O: rights, allocators, nft + client-config rendering
- `crates/server` — Axum + SeaORM + OIDC; unprivileged
- `crates/agent` — root with `CAP_NET_ADMIN` only, no HTTP listener
- `crates/wgate` — binary, `server | agent | migrate`
- `web/` — Vue UI, embedded into the binary

## Rules

- Toolchain is pinned in `rust-toolchain.toml`; CI reads the channel from it. Bump
  deliberately.
- The agent owns `table inet wgate` (replaced atomically) and only `wg-*` interfaces it
  has in its state. Never touch `wg0` or other nft tables.
- nft interval sets reject overlapping elements: rights go through `RuleSet` (canonical,
  disjoint) before rendering — never emit raw rules into a set.
- The tenant chain filters every packet a tenant originates — no `ct state
  established` shortcut (revocation must not depend on conntrack). The only
  exemption is `ct direction reply` + `established` for connections the hub or wg0
  opened. No related-ICMP shortcut either; replies to tenants (forward and output)
  go through `tenant_reply`, the swapped @allow check.
- Hub private keys never leave `/var/lib/wgate/keys`; device private keys are never
  stored or logged.
- No raw DB errors to API clients; typed `ApiError`.
- Workspace clippy lints deny `unwrap`/`expect`/`panic`/`todo`. `clippy.toml` allows
  them inside `#[test]`/`#[cfg(test)]`; integration-test helpers and proptest
  strategies outside a `#[test]` fn need a file-level `#![allow]`.
- Workflow: one branch + PR per plan step, rebase-merge (no merge commits).
