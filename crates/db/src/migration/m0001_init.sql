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
-- Ownership columns never change after insert (rewriting the same value is fine): the checks below read them from
-- other rows, and a check against immutable data cannot race (unlike one that reads
-- data a concurrent transaction may still change under the caller's snapshot).
-- Moving something means delete + insert.
CREATE FUNCTION immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '%: % cannot change; delete and re-create instead', TG_TABLE_NAME, TG_ARGV[0]
        USING ERRCODE = 'check_violation';
END
$$;

CREATE TABLE tenant_block (
    id        bigserial PRIMARY KEY,
    tenant_id bigint NOT NULL REFERENCES tenant ON DELETE CASCADE,
    cidr      cidr NOT NULL CHECK (family(cidr) = 4),
    UNIQUE (id, tenant_id),
    EXCLUDE USING gist (cidr inet_ops WITH &&)
);
CREATE TRIGGER tenant_block_immutable BEFORE UPDATE OF tenant_id, cidr ON tenant_block
    FOR EACH ROW WHEN (OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.cidr IS DISTINCT FROM NEW.cidr)
    EXECUTE FUNCTION immutable('tenant_id, cidr');

-- Every entry an IPv4 host address (a CHECK cannot hold the query itself).
CREATE FUNCTION all_ipv4_hosts(addrs inet[]) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(bool_and(family(a) = 4 AND masklen(a) = 32), true) FROM unnest(addrs) a
$$;

-- A network lies inside one block of its own tenant. The (block, tenant) foreign key
-- takes the network along when its block goes, at any isolation level; the trigger
-- checks containment against the immutable block.
CREATE TABLE network (
    id          bigserial PRIMARY KEY,
    tenant_id   bigint NOT NULL REFERENCES tenant ON DELETE CASCADE,
    block_id    bigint NOT NULL,
    slug        slug NOT NULL UNIQUE,
    name        text NOT NULL,
    cidr        cidr NOT NULL CHECK (family(cidr) = 4 AND masklen(cidr) <= 30),
    port        integer NOT NULL UNIQUE
                CHECK (port BETWEEN 51800 AND 51899 AND port <> 51820),
    mesh        boolean NOT NULL DEFAULT false,
    -- Resolvers written into client configs; empty = no DNS line.
    dns         inet[] NOT NULL DEFAULT '{}' CHECK (all_ipv4_hosts(dns)),
    disabled_at timestamptz,
    FOREIGN KEY (block_id, tenant_id) REFERENCES tenant_block (id, tenant_id) ON DELETE CASCADE,
    UNIQUE (id, tenant_id),
    EXCLUDE USING gist (cidr inet_ops WITH &&)
);
-- The slug too: `wg-<slug>` is the interface (the nft chains go by the network id).
CREATE TRIGGER network_immutable BEFORE UPDATE OF tenant_id, block_id, cidr, slug ON network
    FOR EACH ROW WHEN (OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR OLD.block_id IS DISTINCT FROM NEW.block_id OR OLD.cidr IS DISTINCT FROM NEW.cidr OR OLD.slug IS DISTINCT FROM NEW.slug)
    EXECUTE FUNCTION immutable('tenant_id, block_id, cidr, slug');

CREATE FUNCTION network_in_block() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    block cidr;
BEGIN
    SELECT cidr INTO block FROM tenant_block WHERE id = NEW.block_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'block % does not exist', NEW.block_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF NOT block >>= NEW.cidr THEN
        RAISE EXCEPTION 'network % lies outside block %', NEW.cidr, NEW.block_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER network_in_block BEFORE INSERT ON network
    FOR EACH ROW EXECUTE FUNCTION network_in_block();

-- tenant_id NULL = the global admin's provider. Client secrets live in the config.
-- Issuers may repeat: tenants can share an IdP (Google, one Keycloak realm), since a
-- login first picks the tenant and matches users within it.
CREATE TABLE oidc_provider (
    id        bigserial PRIMARY KEY,
    tenant_id bigint UNIQUE NULLS NOT DISTINCT REFERENCES tenant ON DELETE CASCADE,
    issuer    text NOT NULL,
    client_id text NOT NULL
);

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
CREATE TRIGGER app_user_immutable BEFORE UPDATE OF tenant_id ON app_user
    FOR EACH ROW WHEN (OLD.tenant_id IS DISTINCT FROM NEW.tenant_id)
    EXECUTE FUNCTION immutable('tenant_id');
CREATE UNIQUE INDEX app_user_email ON app_user (tenant_id, lower(email)) NULLS NOT DISTINCT;
CREATE UNIQUE INDEX app_user_sub ON app_user (tenant_id, oidc_sub) NULLS NOT DISTINCT
    WHERE oidc_sub IS NOT NULL;

CREATE TABLE device (
    id         bigserial PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES app_user ON DELETE CASCADE,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER device_immutable BEFORE UPDATE OF user_id ON device
    FOR EACH ROW WHEN (OLD.user_id IS DISTINCT FROM NEW.user_id)
    EXECUTE FUNCTION immutable('user_id');

CREATE TABLE peer (
    id         bigserial PRIMARY KEY,
    device_id  bigint NOT NULL REFERENCES device ON DELETE CASCADE,
    network_id bigint NOT NULL REFERENCES network ON DELETE CASCADE,
    public_key text NOT NULL CHECK (public_key ~ '^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$'),
    -- Who holds the private key: the server made it (shown once, rotated on every
    -- download) or the user pasted the public key and keeps their own.
    key_source text NOT NULL DEFAULT 'pasted' CHECK (key_source IN ('server', 'pasted')),
    ip         inet NOT NULL CHECK (family(ip) = 4 AND masklen(ip) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    -- What the routes reference: revoking flips it, which cascades to the routes.
    active     boolean GENERATED ALWAYS AS (revoked_at IS NULL) STORED,
    UNIQUE (id, active)
);
CREATE TRIGGER peer_immutable BEFORE UPDATE OF device_id, network_id, ip, key_source ON peer
    FOR EACH ROW WHEN (OLD.device_id IS DISTINCT FROM NEW.device_id OR OLD.network_id IS DISTINCT FROM NEW.network_id OR OLD.ip IS DISTINCT FROM NEW.ip OR OLD.key_source IS DISTINCT FROM NEW.key_source)
    EXECUTE FUNCTION immutable('device_id, network_id, ip, key_source');
-- A key rotates (a new download of a server-key peer) only while the peer is active:
-- a revoked peer's key must never come back to life under it.
CREATE FUNCTION key_rotates_while_active() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL OR OLD.key_source <> 'server' THEN
        RAISE EXCEPTION 'peer %: only an active peer with a server key rotates', OLD.id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER key_rotates_while_active BEFORE UPDATE OF public_key ON peer
    FOR EACH ROW WHEN (OLD.public_key IS DISTINCT FROM NEW.public_key)
    EXECUTE FUNCTION key_rotates_while_active();

-- A peer address is a host of its network other than the hub address (the first
-- host), and only a global admin's device may join another tenant's network. Both
-- read immutable columns only.
CREATE FUNCTION peer_fits() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    net        cidr;
    net_tenant bigint;
    owner      bigint;
    owner_role text;
BEGIN
    SELECT cidr, tenant_id INTO net, net_tenant FROM network WHERE id = NEW.network_id;
    SELECT u.tenant_id, u.role INTO owner, owner_role
        FROM device d JOIN app_user u ON u.id = d.user_id WHERE d.id = NEW.device_id;
    IF net IS NULL OR owner_role IS NULL THEN
        RAISE EXCEPTION 'network % or device % does not exist', NEW.network_id, NEW.device_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    -- host() drops the netmask: inet equality would compare masks too.
    IF NOT (net >>= NEW.ip AND host(NEW.ip) NOT IN
            (host(network(net)), host(broadcast(net)), host(network(net) + 1))) THEN
        RAISE EXCEPTION '% is not a peer address of %', NEW.ip, net
            USING ERRCODE = 'check_violation';
    END IF;
    IF owner_role <> 'global_admin' AND owner IS DISTINCT FROM net_tenant THEN
        RAISE EXCEPTION 'device % belongs to another tenant than network %', NEW.device_id, NEW.network_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER peer_fits BEFORE INSERT ON peer FOR EACH ROW EXECUTE FUNCTION peer_fits();

-- Revoking is final: un-revoking would bring back an old key without a new grant
-- (its IP, key and LANs may already be someone else's). Disabling is the reversible
-- switch. Revoking again is a no-op (a retried or double-clicked revoke succeeds) and
-- keeps the original time.
CREATE FUNCTION revocation_is_final() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.revoked_at IS NULL THEN
        RAISE EXCEPTION 'peer % is revoked; add a new peer instead', OLD.id
            USING ERRCODE = 'check_violation';
    END IF;
    NEW.revoked_at := OLD.revoked_at;
    RETURN NEW;
END
$$;
CREATE TRIGGER revocation_is_final BEFORE UPDATE OF revoked_at ON peer
    FOR EACH ROW WHEN (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
    EXECUTE FUNCTION revocation_is_final();

-- An address and a key are free again once their peer is revoked; a device is a
-- member of a network at most once. Keys are unique across networks too: every
-- membership has its own key pair (design.md → Decisions).
CREATE UNIQUE INDEX peer_ip_active ON peer (ip) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX peer_key_active ON peer (public_key) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX peer_membership_active ON peer (device_id, network_id)
    WHERE revoked_at IS NULL;

-- A router's LAN. Only an active route holds its range. The (peer, active) foreign
-- key does the rest at any isolation level: revoking the peer cascades `active` to
-- false, freeing the LAN, and a route cannot be added as active to a revoked peer
-- (the foreign key's row locks also serialize a route insert racing a revocation).
CREATE TABLE peer_route (
    id      bigserial PRIMARY KEY,
    peer_id bigint NOT NULL,
    active  boolean NOT NULL DEFAULT true,
    cidr    cidr NOT NULL CHECK (family(cidr) = 4),
    FOREIGN KEY (peer_id, active) REFERENCES peer (id, active)
        ON UPDATE CASCADE ON DELETE CASCADE,
    EXCLUDE USING gist (cidr inet_ops WITH &&) WHERE (active)
);

-- Routed LANs never overlap tenant blocks (and so no network inside one): each
-- table's EXCLUDE only sees its own rows, so this cross-table check serializes on one
-- advisory lock and then reads what is committed (READ COMMITTED: each statement in
-- the function takes a fresh snapshot).
CREATE FUNCTION ranges_disjoint() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('wgate_ranges'));
    IF TG_TABLE_NAME = 'peer_route' THEN
        IF NEW.active AND EXISTS (SELECT FROM tenant_block WHERE cidr && NEW.cidr) THEN
            RAISE EXCEPTION 'LAN % overlaps a tenant block', NEW.cidr
                USING ERRCODE = 'exclusion_violation';
        END IF;
    ELSIF EXISTS (SELECT FROM peer_route WHERE active AND cidr && NEW.cidr) THEN
        RAISE EXCEPTION 'block % overlaps a routed LAN', NEW.cidr
            USING ERRCODE = 'exclusion_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER ranges_disjoint BEFORE INSERT ON tenant_block
    FOR EACH ROW EXECUTE FUNCTION ranges_disjoint();
CREATE TRIGGER ranges_disjoint BEFORE INSERT OR UPDATE OF cidr, active ON peer_route
    FOR EACH ROW EXECUTE FUNCTION ranges_disjoint();

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
-- Both networks of a rule belong to its tenant (composite foreign keys; a NULL
-- target skips its key): across tenants only federations exist.
CREATE TABLE rule (
    id                bigserial PRIMARY KEY,
    tenant_id         bigint NOT NULL,
    network_id        bigint NOT NULL,
    proto             proto NOT NULL,
    port_from         integer,
    port_to           integer,
    dst               cidr CHECK (family(dst) = 4),
    target_network_id bigint,
    comment           text NOT NULL DEFAULT '',
    FOREIGN KEY (network_id, tenant_id) REFERENCES network (id, tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (target_network_id, tenant_id) REFERENCES network (id, tenant_id)
        ON DELETE CASCADE,
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

-- Federations link two different tenants (so never a network to itself); inside one
-- tenant, rules do that (and are the tenant admin's). Network tenants are immutable,
-- so this cannot race.
CREATE FUNCTION federation_crosses_tenants() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (SELECT tenant_id FROM network WHERE id = NEW.from_network_id)
       = (SELECT tenant_id FROM network WHERE id = NEW.to_network_id) THEN
        RAISE EXCEPTION 'a federation links two tenants; use a rule inside one'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER federation_crosses_tenants BEFORE INSERT OR UPDATE ON federation
    FOR EACH ROW EXECUTE FUNCTION federation_crosses_tenants();

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

-- Portal sessions: only a hash of the cookie's token is stored. A session ends at
-- `expires_at` (the hard cap) or after the idle limit since `seen_at` (the server).
CREATE TABLE session (
    id         bigserial PRIMARY KEY,
    token_hash bytea NOT NULL UNIQUE,
    user_id    bigint NOT NULL REFERENCES app_user ON DELETE CASCADE,
    csrf       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    seen_at    timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

-- Foreign keys get no index by themselves; cascades and per-peer lookups need them.
CREATE INDEX ON tenant_block (tenant_id);
CREATE INDEX ON network (tenant_id);
CREATE INDEX ON network (block_id, tenant_id);
CREATE INDEX ON app_user (tenant_id);
CREATE INDEX ON device (user_id);
CREATE INDEX ON peer (device_id);
CREATE INDEX ON peer (network_id);
CREATE INDEX ON peer_route (peer_id);
CREATE INDEX ON ceiling (tenant_id);
CREATE INDEX ON session (user_id);
CREATE INDEX ON rule (network_id);
CREATE INDEX ON rule (target_network_id);
CREATE INDEX ON federation (from_network_id);
CREATE INDEX ON federation (to_network_id);
CREATE INDEX ON inbound (network_id);
CREATE INDEX ON audit (actor_user_id);
