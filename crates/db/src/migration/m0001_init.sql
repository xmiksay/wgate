-- wgate schema (docs/design.md → Data model). Address ownership is enforced here at
-- save time: exclusion constraints keep blocks, network ranges and routes disjoint,
-- so the first claim keeps a range for good; core::compile only re-checks. The GiST
-- `inet_ops` operator class is built in, so no extension is needed.

-- [a-z0-9-]{1,11}, alphanumeric at both ends: `wg-<slug>` fits IFNAMSIZ.
CREATE DOMAIN slug AS text
    CHECK (VALUE ~ '^[a-z0-9]([a-z0-9-]{0,9}[a-z0-9])?$');
CREATE DOMAIN proto AS text CHECK (VALUE IN ('tcp', 'udp', 'icmp'));

CREATE TABLE tenant (
    id          bigserial PRIMARY KEY,
    slug        slug NOT NULL UNIQUE,
    name        text NOT NULL,
    disabled_at timestamptz
);

-- Pool blocks the global admin assigned. Being inside the pool is checked by the
-- API and by compile (the pool is configuration, not data).
CREATE TABLE tenant_block (
    id        bigserial PRIMARY KEY,
    tenant_id bigint NOT NULL REFERENCES tenant ON DELETE CASCADE,
    cidr      cidr NOT NULL,
    EXCLUDE USING gist (cidr inet_ops WITH &&)
);

CREATE TABLE network (
    id          bigserial PRIMARY KEY,
    tenant_id   bigint NOT NULL REFERENCES tenant ON DELETE CASCADE,
    slug        slug NOT NULL UNIQUE,
    name        text NOT NULL,
    cidr        cidr NOT NULL CHECK (family(cidr) = 4 AND masklen(cidr) <= 30),
    port        integer NOT NULL UNIQUE
                CHECK (port BETWEEN 51800 AND 51899 AND port <> 51820),
    mesh        boolean NOT NULL DEFAULT false,
    disabled_at timestamptz,
    EXCLUDE USING gist (cidr inet_ops WITH &&)
);

-- tenant_id NULL = the global admin's provider. Client secrets live in the config.
CREATE TABLE oidc_provider (
    id        bigserial PRIMARY KEY,
    tenant_id bigint UNIQUE REFERENCES tenant ON DELETE CASCADE,
    issuer    text NOT NULL UNIQUE,
    client_id text NOT NULL
);
CREATE UNIQUE INDEX oidc_provider_global ON oidc_provider ((tenant_id IS NULL))
    WHERE tenant_id IS NULL;

CREATE TABLE app_user (
    id          bigserial PRIMARY KEY,
    tenant_id   bigint REFERENCES tenant ON DELETE CASCADE,
    email       text NOT NULL,
    oidc_sub    text,
    role        text NOT NULL CHECK (role IN ('global_admin', 'tenant_admin', 'user')),
    disabled_at timestamptz,
    CHECK ((role = 'global_admin') = (tenant_id IS NULL))
);
-- One account per email per tenant (NULL tenant = global admins), and a subject binds
-- to one account per provider.
CREATE UNIQUE INDEX app_user_email ON app_user (coalesce(tenant_id, 0), lower(email));
CREATE UNIQUE INDEX app_user_sub ON app_user (coalesce(tenant_id, 0), oidc_sub);

CREATE TABLE device (
    id         bigserial PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES app_user ON DELETE CASCADE,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE peer (
    id         bigserial PRIMARY KEY,
    device_id  bigint NOT NULL REFERENCES device ON DELETE CASCADE,
    network_id bigint NOT NULL REFERENCES network ON DELETE CASCADE,
    public_key text NOT NULL UNIQUE CHECK (public_key ~ '^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$'),
    ip         inet NOT NULL CHECK (family(ip) = 4 AND masklen(ip) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
-- An address is free again once its peer is revoked.
CREATE UNIQUE INDEX peer_ip_active ON peer (ip) WHERE revoked_at IS NULL;

-- A router's LAN. Revoking a peer deletes its routes, freeing the ranges.
CREATE TABLE peer_route (
    id      bigserial PRIMARY KEY,
    peer_id bigint NOT NULL REFERENCES peer ON DELETE CASCADE,
    cidr    cidr NOT NULL CHECK (family(cidr) = 4),
    EXCLUDE USING gist (cidr inet_ops WITH &&)
);

-- proto + ports, shared by every rule-like table: tcp/udp carry 1 <= from <= to, icmp
-- none. Never NULL: a CHECK passes on NULL, so `tcp` with NULL ports would slip by.
CREATE FUNCTION valid_service(p proto, port_from integer, port_to integer)
    RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(
        CASE WHEN p = 'icmp' THEN port_from IS NULL AND port_to IS NULL
             ELSE port_from BETWEEN 1 AND 65535 AND port_to BETWEEN port_from AND 65535
        END,
        false)
$$;

-- External destinations a tenant's networks may be granted (global admin).
CREATE TABLE ceiling (
    id        bigserial PRIMARY KEY,
    tenant_id bigint NOT NULL REFERENCES tenant ON DELETE CASCADE,
    proto     proto NOT NULL,
    dst       cidr NOT NULL CHECK (family(dst) = 4),
    port_from integer,
    port_to   integer,
    CHECK (valid_service(proto, port_from, port_to))
);

-- What members of a network may open (tenant admin): an external destination, or
-- another network of the same tenant.
CREATE TABLE rule (
    id                bigserial PRIMARY KEY,
    network_id        bigint NOT NULL REFERENCES network ON DELETE CASCADE,
    proto             proto NOT NULL,
    port_from         integer,
    port_to           integer,
    dst               cidr CHECK (family(dst) = 4),
    target_network_id bigint REFERENCES network ON DELETE CASCADE,
    comment           text NOT NULL DEFAULT '',
    CHECK (valid_service(proto, port_from, port_to)),
    CHECK ((dst IS NULL) <> (target_network_id IS NULL))
);

-- Members of `from` may open to members of `to` (global admin, cross-tenant).
CREATE TABLE federation (
    id              bigserial PRIMARY KEY,
    from_network_id bigint NOT NULL REFERENCES network ON DELETE CASCADE,
    to_network_id   bigint NOT NULL REFERENCES network ON DELETE CASCADE,
    proto           proto NOT NULL,
    port_from       integer,
    port_to         integer,
    CHECK (valid_service(proto, port_from, port_to))
);

-- Sources outside tenant space that may open to a network's members (global admin).
CREATE TABLE inbound (
    id         bigserial PRIMARY KEY,
    network_id bigint NOT NULL REFERENCES network ON DELETE CASCADE,
    source     cidr NOT NULL CHECK (family(source) = 4),
    proto      proto NOT NULL,
    port_from  integer,
    port_to    integer,
    comment    text NOT NULL DEFAULT '',
    CHECK (valid_service(proto, port_from, port_to))
);

-- Written by the agent only; the private key never leaves the hub.
CREATE TABLE hub_key (
    network_id bigint PRIMARY KEY REFERENCES network ON DELETE CASCADE,
    public_key text NOT NULL
);

CREATE TABLE audit (
    id            bigserial PRIMARY KEY,
    at            timestamptz NOT NULL DEFAULT now(),
    actor_user_id bigint REFERENCES app_user ON DELETE SET NULL,
    action        text NOT NULL,
    target        text NOT NULL,
    detail        jsonb NOT NULL DEFAULT '{}'
);

-- Bumped by every write transaction, which also NOTIFYs wgate_changed with it.
CREATE TABLE state_revision (
    id       boolean PRIMARY KEY DEFAULT true CHECK (id),
    revision bigint NOT NULL
);
INSERT INTO state_revision (revision) VALUES (0);

-- Written by the agent: what it last applied.
CREATE TABLE agent_status (
    id               boolean PRIMARY KEY DEFAULT true CHECK (id),
    applied_revision bigint NOT NULL,
    applied_at       timestamptz NOT NULL,
    error            text
);

-- The agent role reads everything and writes only what it owns. It is created by
-- ansible; a database without it (e.g. tests) simply gets no grants.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'wgate_agent') THEN
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO wgate_agent;
        GRANT INSERT, UPDATE ON hub_key, agent_status TO wgate_agent;
    END IF;
END
$$;
