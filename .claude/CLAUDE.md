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

Done = `make lint` + `make test` green (+ `make test-netns` when agent code changed).

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
- The tenant chain filters every packet — no `ct state established` shortcut
  (revocation must not depend on conntrack).
- Hub private keys never leave `/var/lib/wgate/keys`; device private keys are never
  stored or logged.
- No raw DB errors to API clients; typed `ApiError`.
- Workspace clippy lints deny `unwrap`/`expect`/`panic`/`todo` outside tests;
  integration test files `#![allow]` them explicitly.
- Workflow: one branch + PR per plan step, rebase-merge (no merge commits).
