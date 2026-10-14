-- Part of m0001 (appended to m0001_init.sql): the state revision and its NOTIFY,
-- and the agent's status.

-- Every transaction that changes the desired state bumps the revision once and
-- NOTIFYs the agent, from triggers, so no write path can forget it. Postgres delivers a NOTIFY
-- only on commit, so a rolled-back write never wakes the agent. The agent's own
-- tables (hub_key, agent_status) and audit do not count.
CREATE TABLE state_revision (
    id       boolean PRIMARY KEY DEFAULT true CHECK (id),
    revision bigint NOT NULL
);
INSERT INTO state_revision (revision) VALUES (0);

-- Only the bump below may change the counter: a direct UPDATE (even by the owner)
-- would mark the transaction as already bumped, muting it, or rewind the revision
-- past what the agent reports as applied.
CREATE FUNCTION revision_only_by_trigger() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION 'state_revision changes only through the state triggers'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER revision_only_by_trigger BEFORE UPDATE OR DELETE ON state_revision
    FOR EACH ROW EXECUTE FUNCTION revision_only_by_trigger();

-- Deferred to commit and run once per transaction: the hot state_revision row lock
-- is then the last lock a writer takes and is held only while it commits, so it can
-- neither serialize writers for their whole duration nor close a deadlock cycle
-- (writers must not `SET CONSTRAINTS ... IMMEDIATE`, which would fire it early).
-- Row-level and only for real changes of what the state depends on, so a statement
-- that changes nothing (or only a name) does not count.
-- SECURITY DEFINER: writers need no rights on the counter (none can set it to a
-- value the agent already reports as applied).
CREATE FUNCTION state_changed() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    rev bigint;
BEGIN
    -- Once per transaction: the counter row's xmin is this transaction once it has
    -- bumped it. Nothing a caller can set, unlike a session variable.
    IF (SELECT xmin FROM state_revision)::text = pg_current_xact_id()::xid::text THEN
        RETURN NULL;
    END IF;
    UPDATE state_revision SET revision = revision + 1 RETURNING revision INTO rev;
    PERFORM pg_notify('wgate_changed', rev::text);
    RETURN NULL;
END
$$;

-- At a snapshot isolation level the commit-time bump fails whenever another change
-- committed meanwhile: refuse the first statement instead, with a typed error.
CREATE FUNCTION require_read_committed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'write the wgate state at READ COMMITTED'
            USING ERRCODE = 'invalid_transaction_state';
    END IF;
    RETURN NULL;
END
$$;

-- TRUNCATE has no rows to defer on; an immediate bump would hold the hot lock for the
-- rest of the transaction. Use DELETE.
CREATE FUNCTION no_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '%: use DELETE (TRUNCATE skips the change notification)', TG_TABLE_NAME
        USING ERRCODE = 'feature_not_supported';
END
$$;

DO $$
DECLARE
    spec text[];
BEGIN
    -- table, whether inserting/deleting a row changes the state by itself, and the
    -- columns the state depends on. Users, devices and tenants matter only through
    -- their peers and networks, whose own rows (and cascades) count; names,
    -- comments, emails and roles never wake the agent. A network's dns does not matter
    -- to the agent but to client configs: a key rotation commits only on the revision
    -- its config was rendered from.
    FOREACH spec SLICE 1 IN ARRAY ARRAY[
        ['tenant', 'no', 'disabled_at'],
        ['tenant_block', 'yes', ''],
        ['network', 'yes', 'port, mesh, dns, disabled_at'],
        ['app_user', 'no', 'disabled_at'],
        ['device', 'no', ''],
        ['peer', 'yes', 'revoked_at, public_key'],
        ['peer_route', 'yes', 'peer_id, active, cidr'],
        ['ceiling', 'yes', 'tenant_id, proto, dst, port_from, port_to'],
        ['rule', 'yes', 'tenant_id, network_id, proto, port_from, port_to, dst, target_network_id'],
        ['federation', 'yes', 'from_network_id, to_network_id, proto, port_from, port_to'],
        ['inbound', 'yes', 'network_id, source, proto, port_from, port_to']
    ] LOOP
        IF spec[2] = 'yes' THEN
            EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER INSERT OR DELETE ON %I
                            DEFERRABLE INITIALLY DEFERRED
                            FOR EACH ROW EXECUTE FUNCTION state_changed()',
                           spec[1] || '_changed', spec[1]);
        END IF;
        IF spec[3] <> '' THEN
            -- Compare only those columns: a rename that also rewrites one unchanged
            -- must not count.
            EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER UPDATE OF %s ON %I
                            DEFERRABLE INITIALLY DEFERRED
                            FOR EACH ROW WHEN ((%s) IS DISTINCT FROM (%s))
                            EXECUTE FUNCTION state_changed()',
                           spec[1] || '_updated', spec[3], spec[1],
                           'OLD.' || replace(spec[3], ', ', ', OLD.'),
                           'NEW.' || replace(spec[3], ', ', ', NEW.'));
        END IF;
        -- Only writes that can bump: renames, emails and the like may run at any level.
        IF spec[2] = 'yes' OR spec[3] <> '' THEN
            EXECUTE format('CREATE TRIGGER %I BEFORE %s ON %I
                            FOR EACH STATEMENT EXECUTE FUNCTION require_read_committed()',
                           spec[1] || '_read_committed',
                           concat_ws(' OR ',
                               CASE WHEN spec[2] = 'yes' THEN 'INSERT OR DELETE' END,
                               CASE WHEN spec[3] <> '' THEN 'UPDATE OF ' || spec[3] END),
                           spec[1]);
        END IF;
        EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I
                        FOR EACH STATEMENT EXECUTE FUNCTION no_truncate()',
                       spec[1] || '_no_truncate', spec[1]);
        -- Ids are claim order (older wins) and what the agent keys on.
        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OF id ON %I
                        FOR EACH ROW WHEN (OLD.id IS DISTINCT FROM NEW.id)
                        EXECUTE FUNCTION immutable(''id'')',
                       spec[1] || '_id_immutable', spec[1]);
    END LOOP;
END
$$;

-- Written by the agent: what it last applied.
CREATE TABLE agent_status (
    id               boolean PRIMARY KEY DEFAULT true CHECK (id),
    applied_revision bigint NOT NULL,
    applied_at       timestamptz NOT NULL,
    error            text
);
