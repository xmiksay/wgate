# wgate

Multi-tenant WireGuard gateway. Addresses come from one global pool; the admin gives
tenants blocks of it, tenants run networks (one `wg-<slug>` interface each) and put
devices into them. Access is default-deny, granted by rules between networks, tenant
ceilings for external destinations and admin federations between tenants, and enforced
per packet in `table inet wgate`. Clients are plain WireGuard.

- Design: [docs/design.md](docs/design.md)
- Implementation plan: [docs/plan.md](docs/plan.md)

## Layout

| Path | What |
|---|---|
| `crates/core` | Pure logic: model, rights intersection, allocators, nft/client-config rendering |
| `crates/db` | SeaORM entities, migrations, revision + NOTIFY, desired-state loader |
| `crates/server` | Axum REST API + embedded UI, OIDC |
| `crates/agent` | Root reconciler: wg interfaces/peers and routes via `ip`/`wg`, `nft -f` |
| `crates/wgate` | The binary: `wgate server \| agent \| migrate` |
| `web/` | Vue 3 + TS + Vite + Tailwind + Pinia UI |

## Development

Requires the Rust toolchain from `rust-toolchain.toml` (rustup picks it up) and Node
from `web/.nvmrc`.

```sh
make deps        # npm ci in web/
make lint        # clippy -D warnings, rustfmt, eslint, vue-tsc
make test        # unit + integration (Docker: the db tests start Postgres containers)
make golden      # rewrite golden files (nft ruleset, client configs, docs/openapi.json)
make test-netns  # root-only tests in network namespaces (sudo, nft, wireguard module, python3)
make release     # static x86_64 musl binary + sha256 in dist/
make help        # all targets
```

## Configuration

| Variable | Used by | What |
|---|---|---|
| `WGATE_DATABASE_URL` | `wgate migrate`, `wgate admin grant <email>` | Postgres URL of the owner role, direct to Postgres (not pgbouncer); `admin grant` makes (or re-enables) a global admin |
| `WGATE_AGENT_CONFIG` | `wgate agent` | Path of the agent config (default `/etc/wgate/agent.toml`, see `crates/agent/agent.example.toml`) |
| `WGATE_SERVER_CONFIG` | `wgate server` | Path of the server config (default `/etc/wgate/server.toml`, see `crates/server/server.example.toml`) |

The agent needs `ip` (iproute2), `wg` (wireguard-tools) and `nft` on the hub; an example
systemd unit is `deploy/wgate-agent.service`. The server runs unprivileged
(`deploy/wgate-server.service`); its API is described in `docs/openapi.json` (also
served at `/api/v1/openapi.json`).

See `.env.example`. `make migrate` applies the migrations with it.

## Release

Push a `v*` tag; CI publishes `wgate-x86_64-unknown-linux-musl` + `.sha256` to the
GitHub release.
