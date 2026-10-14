-- Local accounts (plan 1.8): one account per email across wgate, a password, the
-- guessing brakes, and sessions that say how far a login got and how it was made.

-- Per-tenant uniqueness let one email live in two tenants; such a database needs the
-- duplicates resolved by hand first (the error names them).
DO $$
DECLARE
    dup text;
BEGIN
    SELECT string_agg(e, ', ') INTO dup
    FROM (SELECT lower(email) AS e FROM app_user GROUP BY 1 HAVING count(*) > 1) d;
    IF dup IS NOT NULL THEN
        RAISE EXCEPTION 'emails held by more than one account (keep one each): %', dup;
    END IF;
END
$$;
DROP INDEX app_user_email;
CREATE UNIQUE INDEX app_user_email ON app_user (lower(email));

-- The brake against guessing from many clients at once: the account's failures in
-- the hour from `brake_since`, and when its last attempt was let through.
ALTER TABLE app_user
    ADD COLUMN password_hash  text,
    ADD COLUMN brake_since    timestamptz CHECK (isfinite(brake_since)),
    ADD COLUMN brake_failures integer NOT NULL DEFAULT 0 CHECK (brake_failures >= 0),
    ADD COLUMN brake_last_at  timestamptz CHECK (isfinite(brake_last_at));

-- Failures in a row of one account from one client (an IPv4 address or an IPv6 /64):
-- a lockout there holds up nobody else. Rows idle for a day go.
CREATE TABLE login_failure (
    user_id      bigint NOT NULL REFERENCES app_user ON DELETE CASCADE,
    client       inet NOT NULL,
    failed       integer NOT NULL CHECK (failed > 0),
    locked_until timestamptz CHECK (isfinite(locked_until)),
    last_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client)
);
CREATE INDEX ON login_failure (last_at);

-- Clients an account logged in from (the last 30 days): the brake does not hold them
-- up, so guessing from many clients cannot shut the owner out of their usual ones.
CREATE TABLE login_known (
    user_id    bigint NOT NULL REFERENCES app_user ON DELETE CASCADE,
    client     inet NOT NULL,
    last_ok_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client)
);
CREATE INDEX ON login_known (last_ok_at);

-- `full` may use the API; `totp` and `enrol` (plan 1.9) only finish the login. Every
-- session before this came from OIDC.
ALTER TABLE session
    ADD COLUMN stage  text NOT NULL DEFAULT 'full' CHECK (stage IN ('full', 'totp', 'enrol')),
    ADD COLUMN method text NOT NULL DEFAULT 'oidc' CHECK (method IN ('password', 'oidc'));

-- One password attempt, claimed before its password is verified: counted as a failure
-- up front (a success takes it back, `login_succeeded`), refused while the client is
-- locked out or the account braked. Claiming first, under the account's row lock, is
-- what keeps parallel guesses from all passing one check before any is counted.
-- `verdict`: unknown_email | disabled | no_password | locked | braked | claimed.
-- Lock order everywhere: the app_user row, then its login_* rows.
CREATE FUNCTION login_claim(
    p_email text, p_client inet, p_lock_after int, p_lock_secs bigint[], p_brake_after int,
    OUT account bigint, OUT hash text, OUT verdict text, OUT failures int,
    OUT lock_until timestamptz, OUT wait_secs int
) LANGUAGE plpgsql AS $$
DECLARE
    u record;
    known boolean;
BEGIN
    -- Every path writes and commits like a claim does (a transaction id, a commit
    -- record): no early return is cheaper by a WAL flush.
    PERFORM pg_current_xact_id();
    <<attempt>>
    BEGIN
        -- Volatile: each statement after the lock sees the claims committed before it.
        SELECT a.id, a.password_hash,
               a.disabled_at IS NOT NULL OR t.disabled_at IS NOT NULL AS disabled,
               coalesce(a.brake_since > now() - interval '1 hour', false) AS in_window,
               a.brake_failures, a.brake_last_at
          INTO u
          FROM app_user a LEFT JOIN tenant t ON t.id = a.tenant_id
         WHERE lower(a.email) = lower(p_email)
           FOR UPDATE OF a;
        IF NOT FOUND THEN
            verdict := 'unknown_email';
            EXIT attempt;
        END IF;
        account := u.id;
        IF u.disabled THEN
            verdict := 'disabled';
            EXIT attempt;
        END IF;
        IF u.password_hash IS NULL THEN
            verdict := 'no_password';
            EXIT attempt;
        END IF;
        SELECT ceil(extract(epoch FROM lf.locked_until - now()))::int INTO wait_secs
          FROM login_failure lf
         WHERE lf.user_id = u.id AND lf.client = p_client AND lf.locked_until > now();
        IF FOUND THEN
            verdict := 'locked';
            EXIT attempt;
        END IF;
        known := EXISTS (SELECT FROM login_known k
                         WHERE k.user_id = u.id AND k.client = p_client
                           AND k.last_ok_at > now() - interval '30 days');
        IF NOT known AND u.in_window AND u.brake_failures >= p_brake_after
           AND u.brake_last_at > now() - interval '1 minute' THEN
            verdict := 'braked';
            wait_secs := ceil(extract(epoch FROM u.brake_last_at + interval '1 minute' - now()))::int;
        ELSE
            verdict := 'claimed';
            hash := u.password_hash;
            UPDATE app_user a SET
                brake_since = CASE WHEN u.in_window THEN a.brake_since ELSE now() END,
                brake_failures = CASE WHEN u.in_window THEN a.brake_failures + 1 ELSE 1 END,
                -- A known client's attempt does not take the stranger's slot.
                brake_last_at = CASE WHEN known THEN a.brake_last_at ELSE now() END
             WHERE a.id = u.id;
        END IF;
        -- A braked attempt still counts against its own client: polling the brake
        -- costs the poller its lockout.
        INSERT INTO login_failure AS lf (user_id, client, failed) VALUES (u.id, p_client, 1)
            ON CONFLICT (user_id, client)
            DO UPDATE SET failed = lf.failed + 1, last_at = now(), locked_until = NULL
            RETURNING lf.failed INTO failures;
        IF failures >= p_lock_after THEN
            UPDATE login_failure lf
               SET locked_until = now() + make_interval(secs => p_lock_secs[
                       least(failures - p_lock_after + 1, cardinality(p_lock_secs))])
             WHERE lf.user_id = u.id AND lf.client = p_client
            RETURNING lf.locked_until INTO lock_until;
        END IF;
    END attempt;
    -- Last, and never waiting: a prune must not hold rows someone else then waits
    -- for while it waits for them (set_password, an account's delete).
    DELETE FROM login_failure WHERE ctid IN (
        SELECT ctid FROM login_failure WHERE last_at < now() - interval '1 day'
        LIMIT 100 FOR UPDATE SKIP LOCKED);
    DELETE FROM login_known WHERE ctid IN (
        SELECT ctid FROM login_known WHERE last_ok_at < now() - interval '30 days'
        LIMIT 100 FOR UPDATE SKIP LOCKED);
END
$$;

-- The claimed attempt was right: it no longer counts, this client's failures start
-- over (other clients' stay), and the client is known from now on.
CREATE FUNCTION login_succeeded(p_user bigint, p_client inet) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE app_user SET brake_failures = greatest(brake_failures - 1, 0) WHERE id = p_user;
    DELETE FROM login_failure WHERE user_id = p_user AND client = p_client;
    INSERT INTO login_known (user_id, client) VALUES (p_user, p_client)
        ON CONFLICT (user_id, client) DO UPDATE SET last_ok_at = now();
END
$$;

-- Only the owner (the server) logs anyone in.
REVOKE EXECUTE ON FUNCTION login_claim(text, inet, int, bigint[], int) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION login_succeeded(bigint, inet) FROM PUBLIC;
