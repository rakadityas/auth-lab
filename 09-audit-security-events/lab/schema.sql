-- The audit log an identity team lives or dies by. Two properties matter:
--   APPEND-ONLY   — you can add events, never edit or delete them
--   TAMPER-EVIDENT — if someone edits the raw table anyway (a rogue DBA, an
--                    attacker with DB access), it must be DETECTABLE
--
-- We get tamper-evidence with a HASH CHAIN: each row's hash covers its own
-- fields PLUS the previous row's hash (like a blockchain / git history). Change
-- any past row and every hash after it stops matching -- the break points right
-- at the tampered record.

CREATE TABLE audit_events (
    seq        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- strict order
    at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- who/what/where — the questions every investigation asks
    actor      TEXT NOT NULL,          -- user id or 'system'
    action     TEXT NOT NULL,          -- 'login', 'password_changed', 'mfa_disabled', ...
    target     TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',
    -- the chain
    prev_hash  TEXT NOT NULL,          -- hash of seq-1 (or genesis for the first)
    hash       TEXT NOT NULL           -- sha256 over (seq,at,actor,action,target,ip,detail,prev_hash)
);

-- Per-user notion of "known devices", so we can detect and alert on a NEW one.
CREATE TABLE known_devices (
    user_id   TEXT NOT NULL,
    device_id TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_id)
);

-- Simple session inventory (Module 3 covered the mechanics; here it feeds the
-- "active sessions" view a user's security page shows).
CREATE TABLE sessions (
    id        TEXT PRIMARY KEY,
    user_id   TEXT NOT NULL,
    device_id TEXT NOT NULL,
    ip        TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
