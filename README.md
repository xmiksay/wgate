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
| `crates/server` | Axum REST API + embedded UI, login (password + TOTP, invite/reset links, OIDC) |
| `crates/agent` | Root reconciler: wg interfaces/peers and routes via `ip`/`wg`, `nft -f` |
| `crates/wgate` | The binary: `wgate server \| agent \| migrate \| keygen \| admin grant \| user password \| user totp-reset` |
| `web/` | Vue 3 + TS + Vite + Tailwind + Pinia UI |

## Development

Requires the Rust toolchain from `rust-toolchain.toml` (rustup picks it up) and Node
from `web/.nvmrc`.

```sh
make deps        # npm ci in web/
make lint        # clippy -D warnings, rustfmt, eslint, vue-tsc
make test        # unit + integration (Docker: the db tests start Postgres containers)
make golden      # rewrite golden files (nft ruleset, client configs, docs/openapi.json)
make test-netns  # root-only tests in network namespaces (sudo, nft, wireguard module, python3, Docker)
make release     # static x86_64 musl binary + sha256 in dist/
make help        # all targets
```

The UI's API types are generated from `docs/openapi.json`: after `make golden` changes the
spec, run `cd web && npm run api:gen` (`npm run api:check` fails while
`web/src/api/schema.d.ts` is stale). `cd web && npm run dev` serves the UI with `/api`
and `/auth` proxied to a server on `127.0.0.1:8470`.

## Configuration

| Variable | Used by | What |
|---|---|---|
| `WGATE_DATABASE_URL` | `wgate migrate`, `wgate admin grant <email>`, `wgate user password <email>`, `wgate user totp-reset <email>` | Postgres URL of the owner role, direct to Postgres (not pgbouncer); `admin grant` makes (or re-enables) a global admin, `user password` sets an account's password (prompted twice, or the first line of stdin when it is not a terminal; clears its lockouts and known clients, ends its sessions), `user totp-reset` turns its TOTP off and ends its sessions |
| `WGATE_AGENT_CONFIG` | `wgate agent` | Path of the agent config (default `/etc/wgate/agent.toml`, see `crates/agent/agent.example.toml`) |
| `WGATE_SERVER_CONFIG` | `wgate server` | Path of the server config (default `/etc/wgate/server.toml`, see `crates/server/server.example.toml`) |

The agent needs `ip` (iproute2), `wg` (wireguard-tools) and `nft` on the hub; an example
systemd unit is `deploy/wgate-agent.service`. The server runs unprivileged
(`deploy/wgate-server.service`); its API is described in `docs/openapi.json` (also
served at `/api/v1/openapi.json`).

In `server.toml`, `secret_key` is required (`wgate keygen` prints one; it encrypts the
TOTP secrets: keep it). `[admin_oidc]` (the global admins' provider) is optional:
everyone can log in with a password, and admins who do set up TOTP at their first
login. Set `trusted_proxies` to the ingress's own addresses (only those:
each may name any client) so the per-client limit on login attempts (20 a minute) and
the per-client lockout see the client, not the proxy. Login
and accounts: [`docs/accounts.md`](docs/accounts.md).

See `.env.example`. `make migrate` applies the migrations with it. A host set up by hand
(test hub): [`docs/install.md`](docs/install.md).

## Release

Push a `v*` tag; CI publishes `wgate-x86_64-unknown-linux-musl` + `.sha256` to the
GitHub release.
