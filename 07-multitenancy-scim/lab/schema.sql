-- B2B identity: many organizations (tenants) share one deployment. The whole
-- module is about the two things that model forces you to get right:
--   1. ISOLATION  — one tenant must never see another's data
--   2. LIFECYCLE  — enterprises expect to provision AND deprovision users
--                   centrally (SSO in, SCIM out)

CREATE TABLE organizations (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    -- the email domain(s) this org claims, for home-realm discovery: a login
    -- from alice@acme.com is routed to Acme's SSO connection.
    slug       TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email      TEXT UNIQUE NOT NULL,
    -- a user is one human who may belong to SEVERAL orgs (contractor, agency).
    -- Their global identity is here; their per-org role is in memberships.
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The join table that makes multi-tenancy real. A user's rights are ALWAYS
-- scoped to (user, org): admin of Acme, member of Beta, nothing in Gamma.
CREATE TABLE memberships (
    org_id  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role    TEXT NOT NULL DEFAULT 'member',   -- 'admin' | 'member'
    -- SCIM deprovisioning flips this to false. A deactivated membership blocks
    -- login to THIS org without deleting the user's other memberships.
    active  BOOLEAN NOT NULL DEFAULT true,
    -- how the membership was created: 'invite' | 'jit' | 'scim'
    source  TEXT NOT NULL DEFAULT 'invite',
    PRIMARY KEY (org_id, user_id)
);

-- Per-tenant SSO. Each enterprise customer brings their own IdP; the connection
-- says "logins for this domain go to this org via this IdP".
CREATE TABLE sso_connections (
    org_id      UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    domain      TEXT UNIQUE NOT NULL,            -- 'acme.com' -> home-realm discovery key
    idp_name    TEXT NOT NULL,
    -- whether a first-time SSO login auto-creates the membership (JIT).
    jit_enabled BOOLEAN NOT NULL DEFAULT true,
    default_role TEXT NOT NULL DEFAULT 'member'
);

-- Invitations: the non-SSO way into an org (the admin adds you by email).
CREATE TABLE invitations (
    token_hash TEXT PRIMARY KEY,                 -- hashed, single-use (Module 4 pattern)
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email      TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'member',
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ
);

-- SCIM needs a per-org bearer token (the IdP presents it on every SCIM call).
CREATE TABLE scim_tokens (
    token_hash TEXT PRIMARY KEY,
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE
);

-- A per-tenant resource, purely so the isolation demo has something to leak.
CREATE TABLE projects (
    id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name   TEXT NOT NULL
);
