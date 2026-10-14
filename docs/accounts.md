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

1. `POST /auth/options {email}` → `{ password: true, providers: [{id, name}] }` (`id` a
   string: `admin` for `[admin_oidc]` until 1.10): the global providers
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

- `totp` — password right, the account has TOTP: only `POST /auth/totp {code}` (or
  `{recovery_code}`) is accepted; 5 minutes to finish.
- `enrol` — an admin with a password and no TOTP: only the TOTP setup endpoints
  (`/me/totp/setup`, `/me/totp/confirm`) and logout, everything else is `403
  totp_required`; 30 minutes (time to install an authenticator), until it is
  confirmed.
- `full` — everything the role allows (the only stage the API takes; a `totp` one is
  `401` there). An admin's `full` session made by a password alone (one from before
  TOTP was mandatory) counts as `enrol` while TOTP is off — setting TOTP up there
  takes the password again, and confirming it keeps the session's old expiry — and
  ends as soon as TOTP is on. Confirming TOTP ends the account's other sessions made
  by a password alone. Giving or taking an admin role ends the account's sessions.

`GET /api/v1/session` answers in every stage, with `stage` (and the CSRF token the
next step sends). When a `totp` or `enrol` login is done, the same row becomes `full`
under a **new token** (a new cookie; the CSRF token stays): a token seen before the
second factor never becomes a signed-in one.

and the **method** (`password`, `password_totp`, `oidc:<provider id>`) for the audit
log.

## Guessing

A client is an IPv4 address or an IPv6 /64 (one host holds a whole /64), behind the
ingress the right-most `X-Forwarded-For` hop not in `trusted_proxies` (config); the
header counts only when the peer address is in it.

- **Per account and client** (Postgres `login_failure`, survives restarts): after 5
  failures in a row (password or TOTP) from one client, each further attempt from it
  locks that client out of the account for `2^(n−5)` minutes, at most 15. Other
  clients — the owner's — are not held up. A success resets that client's count only.
  Rows idle for a day are dropped.
- **Known clients** (`login_known`): every client an account logged in from is
  remembered for 30 days after its last success. The owner's password change keeps
  them; `wgate user password` (a reset) forgets them with the lockouts.
- **Per account, from any clients** (the brake against distributed guessing): once
  the account has 100 failures in the hour since the first of them, it takes one
  attempt a minute from clients it does not know, whoever comes first; the hour then
  starts over. Known clients skip the brake (they keep their own lockout and limits)
  and do not use up the minute's attempt. A braked attempt still counts against its
  own client, so polling the brake locks the poller out.
- **Per client in memory** (a single server): at most 20 attempts a minute (a fixed
  window from the first), then `429` with `Retry-After`; and at most 100 a minute from
  one IPv6 /48, so one site cannot fill the hashing slots with fresh /64s — a client
  the account knows skips the /48 limit. A client already over its own limit is
  refused before the /48 counts it (one host cannot fill its /48); otherwise the /48
  is counted first, and what it refuses takes no client window, so a flood cannot
  churn other clients' windows out. At most 65 536 windows of each kind are tracked;
  a newcomer to a full table evicts the oldest.
- **Order**: the in-memory limits (this uses up one of the client's attempts), then a
  hashing slot (one per core, at least 2: an argon2 hash takes 19 MiB; none free
  within 2 s → `503 busy` with `Retry-After`, and the database counts nothing), then
  the attempt is **claimed** — counted as a failure up front under the account's row
  lock (`login_claim`, m0002), refused when locked or braked — then verified; a
  success takes the claim back (`login_succeeded`). So parallel guesses get no more
  verifies than attempts are left. Claim, verify and audit run on their own task: a
  client that hangs up mid-attempt cannot leave a failure counted without its audit
  entry, or a success without its reset.
- Every reply to a failure is the same `401 invalid credentials` — unknown email,
  wrong password, no password, disabled, locked, braked. Every failure costs the same
  round trips: the claim statement (which takes a transaction id and commits on every
  path, so every path pays a WAL flush), one argon2 verify (against a dummy hash, made
  at startup, when there is no usable one) and one audit insert.
- **A second factor is guessed like a password.** A code or recovery code at
  `/auth/totp` is claimed with `login_claim` like a password attempt (lockout, brake,
  limits, the same `401`, audited as `login.totp.*`). The right password of an account
  with TOTP does not take its own claim back: it only lifts a lockout that claim set
  (so a right password on the 5th attempt does not lock its owner out). Logging in
  with the password again therefore resets nothing, and guesses at the code run into
  the client's lockout as password guesses do (from the 5th, one per lockout). The
  right code takes both claims back. A wrong code leaves the `totp` session for
  another try, unless it locked the client out: then the session ends. A code is
  accepted once: its step (and every earlier one) is used up, atomically. An admin's
  right password without TOTP (the `enrol` stage) is treated the same: it neither
  resets the count nor makes the client known.
- **Per account, the pace of codes** (any clients together; `totp_wrong`,
  `totp_next_at` on `app_user`): every code attempt (TOTP or recovery, at
  `/auth/totp` or for new recovery codes) reserves the account's next slot up front —
  `slot = max(now, totp_next_at)`, then `totp_next_at = slot + gap(n)`, `n` the
  attempts since the last right code: `gap` is 0 for the first, then 1 s, 2 s, 4 s, …
  256 s, at most 300 s. The attempt waits for its slot (holding no connection,
  transaction or hashing slot; on its own task, so a client that hangs up still
  finishes it), then is claimed and checked. A slot more than 30 s away is a `429`
  with `Retry-After` and reserves nothing, so at most a handful of requests per
  account wait at any time. A right code (or a used recovery code) resets the pace.
  Parallel guesses from many clients are thus checked one after another: about 11 in
  the first 8½ minutes, then one every 5 minutes (288 a day). With 3 of the 10⁶ codes valid at any time
  (±1 step), even someone who has the password needs on the order of two years for an
  even chance — and the per-client lockout and the brake still apply on top.
- Re-checks on a signed-in session — the current password (change it, set up or
  remove TOTP in a `full` session), a TOTP code (new recovery codes) — are claimed the
  same way: `422` when wrong, `429` while locked out.
- Every attempt is audited (success, failure — a lockout it set is in the same entry
  as `locked_until`), with the client IP and never the password. The submitted email
  is kept only when it looks like one (an `@`, no whitespace, at most 320 characters):
  people type their password into the email box.

**Accepted residue**:

- A claim for an account with a password does a few more row writes than one for an
  unknown email; the difference is small next to the hash but not zero, and a
  patient attacker measuring many attempts might see it.
- A shared IPv4 address (CGNAT, an office NAT) is one client: whoever shares the
  owner's address shares its lockout and counts as known, so they skip the brake.
- Filling a /48 takes at least five of its /64s (each stops counting at its own 20).
  A full /48 may then ask the database whether a client is known at most 100 times a
  minute; beyond that, a known client in the same /48 as the flood waits too.
- A client the account has never logged in from (a new laptop during an attack) can
  be shut out by the brake. The way back: `wgate user password` on the hub (clears
  every lockout and the brake), or a provider login.
- Many IPv4 addresses (a botnet) are many clients: each gets its own 20 a minute, and
  together they can keep the hashing slots busy (`503` for everyone) for as long as
  the flood lasts; the per-account brake still caps their guesses at any one account.
- Every attempt writes an audit row, so a flood grows the audit table; retention is a
  later concern.
- **First enrolment**: an admin who has a password but has not set up TOTP yet can be
  enrolled by whoever has that password — they set up their own authenticator. The
  enrolment is audited (`user.totp.enrol`, with the client IP and the login method),
  and that password login neither makes the client known nor resets its count. The
  way back: `wgate user totp-reset` on the hub or a global admin's TOTP reset, and a
  new password (`wgate user password`, a reset link).
- **The code pace is per account**, so someone with the password who keeps guessing
  keeps the owner's own code attempts waiting too (`429` while the next slot is more
  than 30 s off). A new password (a reset link, a change on `/me`, `wgate user
  password`) stops them — a code attempt needs a password login first — and resets
  the pace at once, as do the next right code, a used recovery code and a TOTP
  reset.

## Setting and resetting credentials

- CLI on the hub: `wgate admin grant <email>` (the first global admin),
  `wgate user password <email>` (prompted twice, never an argument; clears the
  lockouts, the brake and the known clients, and ends the account's sessions),
  `wgate user totp-reset <email>`, `wgate keygen` (prints a new `secret_key`).
- **Invite / reset links**: an admin creates one for an account in their reach (see
  below); the response shows `<public_url>/account/<token>` once (wgate sends no
  mail). Single use, 24 h, only the sha256 is stored; a new link voids the account's
  older ones, and so do any new password (a reset, a change on `/me`, the CLI) and a
  role change. An
  invite is for an account without a password, when it is made and when it is
  followed. Following it sets a password; a reset also ends the account's sessions
  and clears its lockout. The UI pages send no `Referer` (`Referrer-Policy:
  no-referrer`): the link's token is in the path.
- **Profile** (`/me`): change the password (the current one required — a wrong one is
  a `422` and counts like a failed login from that client; other sessions end), set up / remove TOTP (QR + the recovery codes shown once), regenerate recovery
  codes, link / unlink identities. TOTP needs a password (it guards password logins
  only); setting it up in a `full` session and removing it need the password (the
  `enrol` stage just had it), and admins cannot remove theirs; new recovery codes need
  a current code.
- Recovery codes: 16 base32 characters (80 bits, `ABCD-EFGH-IJKL-MNOP`, any case),
  stored as a plain SHA-256 — 80 random bits are not guessable even offline, so a slow
  hash would buy nothing.
- **Roles**: a tenant admin creates, changes and deletes only their tenant's plain
  users; making an account an admin, taking the role away, and anything done to an
  admin account is a global admin's (or the CLI's). A role change also voids the
  account's unused links and ends its sessions, so nothing made for a user carries
  over to an admin. Invite and reset links, a TOTP reset and identities (pre-link,
  unlink) reach the same: a tenant admin their tenant's plain users, a global admin
  anyone; nobody their own account (`422`: that is `/me`).

## Secrets at rest

`server.toml` holds `secret_key` (32 random bytes, base64; `wgate keygen`). Provider
client secrets and TOTP secrets are stored as `key id (1 byte) ‖ nonce (12) ‖
AES-256-GCM ciphertext`, with the table, column and row id as associated data (a blob
copied to another row does not decrypt). Losing the key means re-entering provider
secrets and re-enrolling TOTP; the key id leaves room for a later `wgate rekey`.
Client secrets are write-only through the API.

## Schema (m0002–m0004)

```
app_user       + password_hash NULL, brake_since NULL, brake_failures, brake_last_at NULL,
                 totp_secret NULL (encrypted), totp_enabled_at NULL, totp_last_step NULL,
                 totp_wrong, totp_next_at NULL
                 email unique across wgate (lower(email)); oidc_sub goes (m0004)
recovery_code  id, user_id, code_hash, used_at NULL
account_token  id, user_id, token_hash (sha256), purpose (invite | reset), created_by,
               created_at, expires_at, used_at NULL
oidc_provider  id, tenant_id NULL (= global), name, issuer, client_id,
               client_secret (encrypted), link_by_email (global only), disabled_at
identity       id, user_id, provider_id, subject, created_at; unique (provider_id, subject)
login_failure  user_id, client (inet), failed, locked_until NULL, last_at; pk (user_id, client)
login_known    user_id, client (inet), last_ok_at; pk (user_id, client)
               + login_claim() / login_succeeded() (the owner role only)
session        + stage (full | totp | enrol), method (password | password_totp | oidc)
```

Upgrading from 0.1.0: m0004 drops the `oidc_sub` bindings (they name no provider);
global admins log in with a password or re-link.
