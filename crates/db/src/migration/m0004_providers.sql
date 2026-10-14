-- OIDC providers in the database and identities linked to accounts (plan 1.10).

-- Nothing read these rows before 1.10 (the one provider was `[admin_oidc]`), and they
-- have no client secret to log anyone in with.
DELETE FROM oidc_provider;
-- `client_secret` is sealed (AES-256-GCM, `secret_key`, the row as associated data).
-- `link_by_email` lets a first login bind by verified email; only a global provider
-- may (a tenant's binds its own tenant's plain users by email anyway).
ALTER TABLE oidc_provider
    DROP CONSTRAINT oidc_provider_tenant_id_key,
    ADD COLUMN name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    ADD COLUMN client_secret bytea NOT NULL,
    ADD COLUMN link_by_email boolean NOT NULL DEFAULT false,
    ADD COLUMN disabled_at   timestamptz CHECK (isfinite(disabled_at)),
    ADD CONSTRAINT oidc_provider_link_by_email CHECK (NOT link_by_email OR tenant_id IS NULL);
-- Several per tenant, and several global ones; on one login page names must differ.
CREATE UNIQUE INDEX oidc_provider_name ON oidc_provider (tenant_id, lower(name))
    NULLS NOT DISTINCT;
-- A provider moved to another tenant would carry its identities across the boundary.
CREATE TRIGGER oidc_provider_immutable BEFORE UPDATE OF tenant_id ON oidc_provider
    FOR EACH ROW WHEN (OLD.tenant_id IS DISTINCT FROM NEW.tenant_id)
    EXECUTE FUNCTION immutable('tenant_id');

-- A login through `provider_id` as `subject` is account `user_id`. One subject per
-- provider binds one account, and an account has at most one identity per provider.
CREATE TABLE identity (
    id          bigserial PRIMARY KEY,
    user_id     bigint NOT NULL REFERENCES app_user ON DELETE CASCADE,
    provider_id bigint NOT NULL REFERENCES oidc_provider ON DELETE CASCADE,
    subject     text NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_id, subject),
    UNIQUE (user_id, provider_id)
);
CREATE INDEX ON identity (provider_id);

-- The `[admin_oidc]` bindings name no provider: global admins log in with a password
-- (or link again).
DROP INDEX app_user_sub;
ALTER TABLE app_user DROP COLUMN oidc_sub;

-- An OIDC session names its provider, and goes with it. The sessions made through
-- `[admin_oidc]` name none: they end here.
DELETE FROM session WHERE method = 'oidc';
ALTER TABLE session
    ALTER COLUMN method DROP DEFAULT,
    ADD COLUMN provider_id bigint REFERENCES oidc_provider ON DELETE CASCADE,
    ADD CONSTRAINT session_provider CHECK ((method = 'oidc') = (provider_id IS NOT NULL));
CREATE INDEX ON session (provider_id);
