-- Part of m0001 (appended to m0001_init.sql): the state revision and its NOTIFY,
-- and the agent's status.

-- Every statement that changes the desired state bumps the revision and NOTIFYs the
-- agent, from a trigger, so no write path can forget it. Postgres delivers a NOTIFY
-- only on commit, so a rolled-back write never wakes the agent. The agent's own
-- tables (hub_key, agent_status) and audit do not count.
CREATE TABLE state_revision (
    id       boolean PRIMARY KEY DEFAULT true CHECK (id),
    revision bigint NOT NULL
);
INSERT INTO state_revision (revision) VALUES (0);

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
    -- At a snapshot isolation level this UPDATE fails whenever another change
    -- committed meanwhile; say so instead of a random serialization error.
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'write the wgate state at READ COMMITTED';
    END IF;
    -- Once per transaction. The marker is this transaction's id, so no session can
    -- preset it and switch the bumps off.
    IF current_setting('wgate.state_changed', true) = pg_current_xact_id()::text THEN
        RETURN NULL;
    END IF;
    PERFORM set_config('wgate.state_changed', pg_current_xact_id()::text, true);
    UPDATE state_revision SET revision = revision + 1 RETURNING revision INTO rev;
    PERFORM pg_notify('wgate_changed', rev::text);
    RETURN NULL;
END
$$;
DO $$
DECLARE
    spec text[];
BEGIN
    -- table, then the columns the desired state depends on ('' = none can change;
    -- names, comments, emails and the like never wake the agent).
    FOREACH spec SLICE 1 IN ARRAY ARRAY[
        ['tenant', 'disabled_at'],
        ['tenant_block', ''],
        ['network', 'slug, port, mesh, disabled_at'],
        ['app_user', 'role, disabled_at'],
        ['device', ''],
        ['peer', 'revoked_at'],
        ['peer_route', 'peer_id, active, cidr'],
        ['ceiling', 'tenant_id, proto, dst, port_from, port_to'],
        ['rule', 'tenant_id, network_id, proto, port_from, port_to, dst, target_network_id'],
        ['federation', 'from_network_id, to_network_id, proto, port_from, port_to'],
        ['inbound', 'network_id, source, proto, port_from, port_to']
    ] LOOP
        EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER INSERT OR DELETE ON %I
                        DEFERRABLE INITIALLY DEFERRED
                        FOR EACH ROW EXECUTE FUNCTION state_changed()',
                       spec[1] || '_changed', spec[1]);
        IF spec[2] <> '' THEN
            -- Compare only those columns: a rename that also rewrites one unchanged
            -- must not count.
            EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER UPDATE OF %s ON %I
                            DEFERRABLE INITIALLY DEFERRED
                            FOR EACH ROW WHEN ((%s) IS DISTINCT FROM (%s))
                            EXECUTE FUNCTION state_changed()',
                           spec[1] || '_updated', spec[2], spec[1],
                           'OLD.' || replace(spec[2], ', ', ', OLD.'),
                           'NEW.' || replace(spec[2], ', ', ', NEW.'));
        END IF;
        -- TRUNCATE has no rows; it bumps right away (an operator's tool, not a hot path).
        EXECUTE format('CREATE TRIGGER %I AFTER TRUNCATE ON %I
                        FOR EACH STATEMENT EXECUTE FUNCTION state_changed()',
                       spec[1] || '_truncated', spec[1]);
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
