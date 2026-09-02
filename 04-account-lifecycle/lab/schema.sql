-- The identity data model this whole module is about.
--
-- Three-table core: users / credentials / identities. Every serious account
-- system converges on this shape, because it keeps three different concerns
-- from being smeared into one row:
--   users        WHO exists          (one row per human, stable ID, lifecycle)
--   credentials  HOW they log in     (password today; TOTP secret, passkey later)
--   identities   WHO ELSE vouches    (Google/SAML/... federated identities)

CREATE TABLE users (
    -- The stable primary key. NEVER the email address: emails change, get
    -- recycled by providers, and differ only by case/dots. Everything else in
    -- the system (orders, documents, audit rows) points at this UUID.
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Nullable on purpose: a purged (GDPR-erased) user keeps the row as a
    -- tombstone -- foreign keys elsewhere stay valid -- but the PII is gone.
    email          TEXT,
    email_verified BOOLEAN     NOT NULL DEFAULT false,
    display_name   TEXT        NOT NULL DEFAULT '',

    -- The lifecycle state machine:
    --   pending_verification -> active -> deactivated -> active   (reversible)
    --   active/deactivated   -> soft_deleted -> purged            (one-way)
    status         TEXT        NOT NULL DEFAULT 'pending_verification'
                   CHECK (status IN ('pending_verification','active',
                                     'deactivated','soft_deleted','purged')),

    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Set when soft-deleted. The purge job uses it as the retention clock.
    deleted_at     TIMESTAMPTZ
);

-- Case-insensitive uniqueness, but ONLY among live rows: a soft-deleted or
-- purged account must not squat on the address forever. (Whether a *deleted*
-- user's email may be re-registered immediately is a product decision; the
-- partial index is where that decision lives.)
CREATE UNIQUE INDEX users_live_email ON users (lower(email))
    WHERE deleted_at IS NULL;

CREATE TABLE credentials (
    user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- One row per credential type; today only 'password'. Modules 3 and 6 add
    -- 'totp' and 'passkey' conceptually -- same table shape.
    type          TEXT        NOT NULL,
    password_hash TEXT        NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, type)
);

CREATE TABLE identities (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider       TEXT        NOT NULL,          -- 'google', 'corp-saml', ...
    -- The IdP's stable subject identifier ('sub'). THIS is the join key for
    -- federated login. Never the email the IdP reports -- see the ATO demo.
    subject        TEXT        NOT NULL,
    email          TEXT        NOT NULL,          -- what the IdP claimed, for display
    email_verified BOOLEAN     NOT NULL,          -- what the IdP claimed. A claim!
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, subject)
);

CREATE TABLE verification_tokens (
    -- Store the HASH of the token, never the token. A read-only DB leak (a
    -- backup, a replica, an injection) must not hand out live magic links.
    token_hash TEXT        PRIMARY KEY,
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose    TEXT        NOT NULL CHECK (purpose IN ('verify_email','change_email')),
    new_email  TEXT,                              -- only for change_email
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ                        -- single-use: set on redemption
);

-- Append-only. Lifecycle events are exactly the ones support and security
-- ask about later ("when did the email on this account change, and from where?").
CREATE TABLE audit_log (
    id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id UUID,                                 -- no FK: must survive a purge
    action  TEXT        NOT NULL,
    detail  TEXT        NOT NULL DEFAULT '',
    at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
