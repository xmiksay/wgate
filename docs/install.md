# Installing wgate by hand

For a test hub, or any host outside the `ansible` repo's `wgate` role (plan 1.8), which does
the same steps. One host runs both the server (portal, unprivileged) and the agent (root,
`CAP_NET_ADMIN`); Postgres may live elsewhere.

## 1. Host

- Debian 13 (any recent kernel has WireGuard), x86_64.
- Packages: `nftables wireguard-tools iproute2`, plus Postgres 17 if it runs here and a
  TLS reverse proxy (e.g. `caddy`).
- Forwarding on, persistently:

  ```sh
  echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/90-wgate.conf
  sysctl --system
  ```

- Your own firewall must let wgate decide for its interfaces — the agent's
  `table inet wgate` drops what its sets don't allow, but a `policy drop` in another table
  still wins. In that table:
  - input: `iifname "wg-*" accept`, `udp dport 51800-51899 accept` (the network ports you
    plan to use), `tcp dport 443 accept` for the portal
  - forward: `iifname "wg-*" accept`, `oifname "wg-*" accept`

  The agent never touches tables other than `inet wgate`, nor `wg0`.
- **Never `flush ruleset` on the hub.** Debian's `/etc/nftables.conf` starts with it, so
  reloading `nftables` would delete `table inet wgate` too — and with the accepts above,
  tenant traffic then passes unchecked until the agent's next pass (up to
  `reconcile_interval_secs`). Scope the reset to your own table instead:

  ```
  table inet filter
  flush table inet filter
  table inet filter { … }
  ```

  If it happened anyway, `systemctl restart wgate-agent` rebuilds the table at once.

## 2. Binary

```sh
v=v0.1.0
base=https://github.com/xmiksay/wgate/releases/download/$v
curl -fLO $base/wgate-x86_64-unknown-linux-musl
curl -fLO $base/wgate-x86_64-unknown-linux-musl.sha256
sha256sum -c wgate-x86_64-unknown-linux-musl.sha256
install -m 0755 wgate-x86_64-unknown-linux-musl /usr/local/bin/wgate
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin wgate
```

Or `make release` in a checkout (`dist/`). The systemd units come from the same tag:

```sh
raw=https://raw.githubusercontent.com/xmiksay/wgate/$v/deploy
curl -fL -o /etc/systemd/system/wgate-server.service $raw/wgate-server.service
curl -fL -o /etc/systemd/system/wgate-agent.service $raw/wgate-agent.service
```

## 3. Database

Two roles: `wgate` owns the schema (migrations, the server), `wgate_agent` gets only what
the agent reads and writes. Create the agent role **before** the first `wgate migrate` —
every migrate (re)applies its grants, and skips them if the role is missing.

```sql
CREATE ROLE wgate LOGIN PASSWORD '…';
CREATE ROLE wgate_agent LOGIN PASSWORD '…';
CREATE DATABASE wgate OWNER wgate;
```

Connect directly to Postgres (5432), not through pgbouncer: transaction pooling breaks the
agent's `LISTEN`. `pg_hba.conf` must admit both roles from the hub.

```sh
export WGATE_DATABASE_URL='postgres://wgate:…@127.0.0.1:5432/wgate'
wgate migrate
wgate admin grant you@example.org      # the first global admin
wgate user password you@example.org    # their password, prompted twice
```

`wgate user password` never takes the password as an argument; when stdin is not a
terminal it reads the first line of stdin instead (for scripts:
`printf '%s\n' "$PW" | wgate user password you@example.org`). It also clears the
account's lockouts and known clients and ends its sessions. A password has 12 to 256
characters.

## 4. Login provider (optional)

The password is enough to log in. To offer a provider button next to it for the global
admins, set `[admin_oidc]` in the server config and register an OIDC client (confidential, authorization code + PKCE, scopes `openid email`)
at your provider with the redirect URI `<public_url>/auth/callback`, e.g.
`https://vpn.example.org/auth/callback`. Most providers accept a plain-`http` redirect only
for `localhost`. The admin logs in with the email granted above; the provider must report
it as verified. Only the subject first seen for that email gets in afterwards.

## 5. Configs

```sh
install -d -m 0750 -o root -g wgate /etc/wgate
```

`/etc/wgate/server.toml` (`root:wgate 0640` — it holds the client secret and the DB
password) from [`server.example.toml`](../crates/server/server.example.toml), and
`/etc/wgate/agent.toml` (`root:root 0600`) from
[`agent.example.toml`](../crates/agent/agent.example.toml). The address settings — `pool`,
`routed_space`, `reserved`, `snat_source`, `node_cidrs` — must be identical in both. Both
files reject unknown keys.

| Setting | Meaning on a test host |
|---|---|
| `listen` (server) | where the proxy reaches the portal, e.g. `127.0.0.1:8470` |
| `public_url` | the portal's origin, no path: `https://vpn.example.org` |
| `endpoint_host` | the name/IP clients put in `Endpoint =` |
| `pool` | tenant address space, e.g. `10.50.0.0/16`; must not collide with the host's networks |
| `routed_space` | where routed LANs behind router peers may live |
| `reserved` | never handed out nor routed (the host's own networks) |
| `node_cidrs` | infrastructure tenants may be granted; reached SNATed |
| `snat_source` | the host's address on `node_cidrs`, used as SNAT source |
| `database_url` | `wgate` for the server, `wgate_agent` for the agent |
| `trusted_proxies` (server) | the proxies whose `X-Forwarded-For` names the client, e.g. `["127.0.0.1/32"]` behind a local Caddy; default none (the TCP peer is the client). List only the proxies themselves, never a client or pod network: every listed address may claim to be any client. Login attempts are limited and locked out per client, so behind a proxy this must be set |
| `[admin_oidc]` (server, optional) | `issuer` exactly as the provider's discovery names it (a trailing slash counts), `client_id`, `client_secret`; `name` for the login button (default the issuer's host). Without it there is no provider button |

`public_url` on `https` makes the session cookie `Secure`; on plain `http` it is not.

### Example: a lone test hub

The host `vpn.example.org` with a LAN `192.168.100.0/24` (its own address `.10`), Postgres
on the host. Tenants get `10.50.0.0/16`; the LAN is infrastructure they may be granted
(reached SNATed from `.10`), so it is also reserved — nobody may route it.

`/etc/wgate/server.toml`:

```toml
listen = "127.0.0.1:8470"
database_url = "postgres://wgate:SERVER_PASSWORD@127.0.0.1:5432/wgate"
public_url = "https://vpn.example.org"
endpoint_host = "vpn.example.org"
pool = ["10.50.0.0/16"]
routed_space = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
reserved = ["192.168.100.0/24"]
snat_source = "192.168.100.10"
node_cidrs = ["192.168.100.0/24"]
trusted_proxies = ["127.0.0.1/32"]   # Caddy on the host (step 7)

# Optional (step 4):
[admin_oidc]
issuer = "https://accounts.google.com"
client_id = "CLIENT_ID.apps.googleusercontent.com"
client_secret = "CLIENT_SECRET"
```

`/etc/wgate/agent.toml`:

```toml
database_url = "postgres://wgate_agent:AGENT_PASSWORD@127.0.0.1:5432/wgate"
pool = ["10.50.0.0/16"]
routed_space = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
reserved = ["192.168.100.0/24"]
snat_source = "192.168.100.10"
node_cidrs = ["192.168.100.0/24"]
# Defaults, shown for reference:
keys_dir = "/var/lib/wgate/keys"
state_file = "/var/lib/wgate/state.json"
reconcile_interval_secs = 60
```

```sh
chown root:wgate /etc/wgate/server.toml && chmod 0640 /etc/wgate/server.toml
chown root:root /etc/wgate/agent.toml && chmod 0600 /etc/wgate/agent.toml
```

A host with only a public address and no LAN: `node_cidrs = []`, `reserved = []`, and
`snat_source` its public address (nothing is SNATed then) — tenants reach only the peers
and routed LANs their rules grant.

## 6. Units

Installed in step 2 (or `cp deploy/*.service /etc/systemd/system/` from a checkout).

```sh
systemctl daemon-reload
systemctl enable --now wgate-agent wgate-server
journalctl -u wgate-agent -u wgate-server -f
```

The agent keeps hub private keys in `/var/lib/wgate/keys` (they never leave it) and the
last desired state in `/var/lib/wgate/state.json`, which it applies when it boots without
the database.

## 7. TLS proxy

Caddy, `/etc/caddy/Caddyfile`:

```
vpn.example.org {
    reverse_proxy 127.0.0.1:8470
}
```

## 8. Smoke test

1. Log in at `public_url` with the email and password from step 3; the status bar at the top shows `applied (rev N)`.
2. Create a tenant `test` with a block (e.g. `10.50.0.0/24`) and a ceiling (say icmp to
   one host on `node_cidrs`, e.g. `192.168.100.10/32`), a network `test` (`10.50.0.0/25`
   inside the block, port 51899) with the same rule — a rule
   outside the ceiling is refused — then a user, a device and a peer.
3. Download the config to a laptop, `wg-quick up ./test.conf`: the granted destination
   answers, anything else does not.
4. Revoke the peer: traffic stops within a second.
5. Delete the tenant; the agent removes `wg-test` and its nft fragment.

On the hub, `nft list table inet wgate` and `wg show` show what the agent applied; errors
appear under the status bar (full text for global admins) and in the agent's journal.

## Upgrading

Replace the binary, `wgate migrate` (as `wgate`), then `systemctl restart wgate-agent
wgate-server`.
