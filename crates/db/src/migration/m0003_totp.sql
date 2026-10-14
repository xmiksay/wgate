-- TOTP, recovery codes, and invite / reset links (plan 1.9).

-- The secret is sealed (AES-256-GCM, `secret_key`, the row as associated data). Set
-- without `totp_enabled_at` it is a setup not yet confirmed. `totp_last_step` is the
-- latest 30 s step a code was accepted for: no code of it or an earlier step again.
-- `totp_wrong` / `totp_next_at`: the account-wide pace of code attempts (any client):
-- each attempt reserves the next slot up front, the gap doubling with every attempt
-- since the last right code.
ALTER TABLE app_user
    ADD COLUMN totp_secret     bytea,
    ADD COLUMN totp_enabled_at timestamptz CHECK (isfinite(totp_enabled_at)),
    ADD COLUMN totp_last_step  bigint,
    ADD COLUMN totp_wrong      integer NOT NULL DEFAULT 0 CHECK (totp_wrong >= 0),
    ADD COLUMN totp_next_at    timestamptz CHECK (isfinite(totp_next_at)),
    ADD CONSTRAINT app_user_totp_secret CHECK (totp_enabled_at IS NULL OR totp_secret IS NOT NULL);

-- Single use: `used_at` is set, atomically, by the login that uses one.
CREATE TABLE recovery_code (
    id        bigserial PRIMARY KEY,
    user_id   bigint NOT NULL REFERENCES app_user ON DELETE CASCADE,
    code_hash bytea NOT NULL,
    used_at   timestamptz,
    UNIQUE (user_id, code_hash)
);

-- Only the token's SHA-256; the link is shown once to whoever made it.
CREATE TABLE account_token (
    id         bigserial PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES app_user ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    purpose    text NOT NULL CHECK (purpose IN ('invite', 'reset')),
    created_by bigint REFERENCES app_user ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)),
    used_at    timestamptz
);
CREATE INDEX ON account_token (user_id);
CREATE INDEX ON account_token (created_by);

-- A password login finished with a TOTP or recovery code.
ALTER TABLE session
    DROP CONSTRAINT session_method_check,
    ADD CONSTRAINT session_method_check
        CHECK (method IN ('password', 'password_totp', 'oidc'));
