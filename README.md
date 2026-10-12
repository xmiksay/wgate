# wgate

Multi-tenant WireGuard gateway: one `wg-<slug>` interface per company, tiered rights
(company ⊇ group ⊇ user) enforced per packet in `table inet wgate`, and a portal where
users log in through their company's OIDC and add their own devices. Clients are
plain WireGuard.

- Design: [docs/design.md](docs/design.md)
- Implementation plan: [docs/plan.md](docs/plan.md)

## Layout

| Path | What |
|---|---|
| `crates/core` | Pure logic: model, rights intersection, allocators, nft/client-config rendering |
| `crates/server` | Axum REST API + embedded UI, OIDC, SeaORM + migrations |
| `crates/agent` | Root reconciler: netlink wg interfaces/peers, `nft -f` |
| `crates/wgate` | The binary: `wgate server \| agent \| migrate` |
| `web/` | Vue 3 + TS + Vite + Tailwind + Pinia UI |

## Development

Requires the Rust toolchain from `rust-toolchain.toml` (rustup picks it up) and Node
from `web/.nvmrc`.

```sh
make deps        # npm ci in web/
make lint        # clippy -D warnings, rustfmt, eslint, vue-tsc
make test        # unit + integration
make golden      # rewrite core golden files (nft ruleset, client configs)
make test-netns  # root-only tests in network namespaces (sudo, nft, wireguard module)
make release     # static x86_64 musl binary + sha256 in dist/
make help        # all targets
```

## Release

Push a `v*` tag; CI publishes `wgate-x86_64-unknown-linux-musl` + `.sha256` to the
GitHub release.
