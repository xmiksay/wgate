-- The agent role (root on the hub) reads only what `desired_state()` needs and
-- writes only what it owns: no emails, identities, password hashes, sessions or
-- audit trail. Applied on every `wgate migrate`, so a role created (or re-created)
-- after the first migration still gets its rights; a database without the role (e.g.
-- tests) gets none. A table a later migration adds for the loader must be added here.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'wgate_agent') THEN
        -- Start from nothing, so narrowing the list takes effect on an existing role.
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM wgate_agent;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM wgate_agent;
        GRANT SELECT ON tenant, tenant_block, ceiling, network, rule, inbound, federation,
            peer, peer_route, state_revision, hub_key, agent_status TO wgate_agent;
        GRANT SELECT (id, tenant_id, role, disabled_at) ON app_user TO wgate_agent;
        GRANT SELECT (id, user_id) ON device TO wgate_agent;
        GRANT INSERT, UPDATE ON hub_key, agent_status TO wgate_agent;
    END IF;
END
$$;
