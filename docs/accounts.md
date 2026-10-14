# wgate — accounts and login

One wgate **account** per person: an email (unique across wgate, any case), a role
and tenant as before, and any mix of login methods — a local password (with TOTP), and
external **identities** from configured OpenID Connect providers linked to it. wgate
works without any external provider: the first global admin gets a password from the
CLI. Built in plan steps 1.8–1.10.

## Login methods

- **Password**: argon2id (OWASP parameters: 19 MiB, t = 2, p = 1), 12–256 characters.
  Any role may have one.
- **TOTP** (RFC 6238, SHA-1, 30 s, 6 digits, ±1 step, a code is accepted once) with 10
  single-use recovery codes (stored hashed). Optional for users; **mandatory for global
  and tenant admins** who log in with a password. A provider login skips it (the
  provider does its own MFA).
- **Identities**: `(provider, subject)` bound to an account. An account keeps at least
  one method: the last one cannot be removed.

## Providers

Rows in `oidc_provider`, managed through the API/UI; nothing in `server.toml` but the
key that encrypts their secrets.

- **Global** (`tenant_id` NULL; global admins manage them): any account may link one.
  `link_by_email` (global admins only) lets a first login bind by verified email.
- **Tenant** (a tenant admin manages their tenant's; global admins all): only that
  tenant's accounts may link or log in through it.
- One redirect URI for all: `<public_url>/auth/callback`; the `wgate_login` cookie
  carries the provider id with state, nonce and PKCE verifier. Discovery is cached per
  provider for an hour and dropped when the provider changes.

## Login flow (email first)

1. `POST /auth/options {email}` → `{ providers: [{id, name}] }`: the global providers
   plus, for an existing account in a tenant, that tenant's. An unknown email gets the
   global ones, as an account without tenant providers does — the page reveals only
   which tenant an account is in, and only when that tenant has its own provider. The
   password field is always offered.
2. Either `POST /auth/password {email, password}`, or `GET /auth/oidc/{id}` → provider →
   `/auth/callback`.
3. A provider login is matched by `(provider, subject)`. An unknown subject with a
   verified email binds to the account of that email only when it is a tenant
   provider and the account is in its tenant, or a global provider with
   `link_by_email` and the account is not a global admin. Anything else: 403, no
   auto-provisioning. Disabled accounts and accounts of disabled tenants are refused.

The session row carries a **stage**:

- `totp` — password right, the account has TOTP: only `POST /auth/totp {code}` (or a
  recovery code) is accepted; 5 minutes to finish.
- `enrol` — an admin with a password and no TOTP: only the TOTP setup endpoints and
  logout, until it is confirmed.
- `full` — everything the role allows.

and the **method** (`password`, `password_totp`, `oidc:<provider id>`) for the audit
log.

## Guessing

- Per account (Postgres, survives restarts): after 5 consecutive failures (password or
  TOTP), each further attempt waits `2^(n−5)` minutes, at most 15; a success resets it.
- Per client IP (in memory; a single server): at most 20 attempts a minute. Behind the
  ingress, the IP is taken from `X-Forwarded-For` only when the peer address is in
  `trusted_proxies` (config).
- Every reply to a failure is the same `401 invalid credentials` — unknown email,
  wrong password, locked — and an unknown email still costs one argon2 hash.
- Every attempt is audited (success, failure, lock), without the password.

## Setting and resetting credentials

- CLI on the hub: `wgate admin grant <email>` (the first global admin),
  `wgate user password <email>` (prompted twice, never an argument; clears the lockout),
  `wgate user totp-reset <email>`, `wgate keygen` (prints a new `secret_key`).
- **Invite / reset links**: an admin creates one for an account in their reach;
  the response shows `<public_url>/account/<token>` once (wgate sends no mail). Single
  use, 24 h, only the sha256 is stored; a new link voids the account's older ones.
  Following it sets a password; a reset also ends the account's sessions and clears
  its lockout.
- **Profile** (`/me`): change the password (the current one required; other sessions
  end), set up / remove TOTP (QR + the recovery codes shown once), regenerate recovery
  codes, link / unlink identities.
- Admins (global: anyone; tenant admin: their tenant's non-global accounts) can
  pre-link an identity (provider + subject), unlink one, and reset an account's TOTP.

## Secrets at rest

`server.toml` holds `secret_key` (32 random bytes, base64; `wgate keygen`). Provider
client secrets and TOTP secrets are stored as `key id (1 byte) ‖ nonce (12) ‖
AES-256-GCM ciphertext`, with the table, column and row id as associated data (a blob
copied to another row does not decrypt). Losing the key means re-entering provider
secrets and re-enrolling TOTP; the key id leaves room for a later `wgate rekey`.
Client secrets are write-only through the API.

## Schema (m0002–m0004)

```
app_user       + password_hash NULL, failed_logins, locked_until NULL,
                 totp_secret NULL (encrypted), totp_enabled_at NULL, totp_last_step NULL
                 email unique across wgate (lower(email)); oidc_sub goes (m0004)
recovery_code  id, user_id, code_hash, used_at NULL
account_token  id, user_id, token_hash (sha256), purpose (invite | reset), created_by,
               expires_at, used_at NULL
oidc_provider  id, tenant_id NULL (= global), name, issuer, client_id,
               client_secret (encrypted), link_by_email (global only), disabled_at
identity       id, user_id, provider_id, subject, created_at; unique (provider_id, subject)
session        + stage (full | totp | enrol), method
```

Upgrading from 0.1.0: m0004 drops the `oidc_sub` bindings (they name no provider);
global admins log in with a password or re-link.
