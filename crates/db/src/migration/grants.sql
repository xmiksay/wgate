-- The agent role reads everything and writes only what it owns. Applied on every
-- `wgate migrate`, so a role created (or re-created) after the first migration still
-- gets its rights; a database without the role (e.g. tests) gets none.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'wgate_agent') THEN
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO wgate_agent;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO wgate_agent;
        GRANT INSERT, UPDATE ON hub_key, agent_status TO wgate_agent;
    END IF;
END
$$;
