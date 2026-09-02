-- Two authorization models, side by side, over the same domain: a document
-- store with organizations, folders, and documents.
--
-- The domain objects are deliberately tiny; the interest is entirely in HOW
-- "may user U do action A on object O?" gets answered.

CREATE TABLE users (
    id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL
);

CREATE TABLE documents (
    id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title    TEXT NOT NULL,
    -- folder this doc lives in (for the ReBAC inheritance demo). Nullable = root.
    -- TEXT, not UUID: folder ids double as tuple object ids (e.g. 'eng').
    folder_id TEXT
);

CREATE TABLE folders (
    id        TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    -- folders nest; a parent's editors inherit into children.
    parent_id TEXT
);

-- ============================================================================
-- MODEL 1: RBAC (role-based). "A user has roles; a role grants permissions."
-- ============================================================================
--
-- Roles are GLOBAL here (admin, editor, viewer) — the classic, coarse model.
-- Note what it CANNOT easily say: "editor on doc X but only viewer on doc Y."
-- That limitation is the whole reason ReBAC exists.

CREATE TABLE roles (
    name TEXT PRIMARY KEY               -- 'admin', 'editor', 'viewer'
);

CREATE TABLE role_permissions (
    role       TEXT NOT NULL REFERENCES roles(name),
    permission TEXT NOT NULL,           -- 'doc:read', 'doc:write', 'doc:delete'
    PRIMARY KEY (role, permission)
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id),
    role    TEXT NOT NULL REFERENCES roles(name),
    PRIMARY KEY (user_id, role)
);

-- ============================================================================
-- MODEL 2: ReBAC (relationship-based), Google Zanzibar style.
-- ============================================================================
--
-- ONE table. Every fact is a "relation tuple":
--
--     <object>#<relation>@<subject>
--     document:readme#viewer@user:alice          -- alice is a viewer of readme
--     document:readme#parent@folder:eng          -- readme's parent is folder eng
--     folder:eng#editor@user:bob                  -- bob is an editor of eng
--     document:readme#viewer@group:staff#member   -- every member of staff can view
--
-- Permissions are DERIVED from relations by rules (in policy.go), e.g.
--   "you may view a document if you are its viewer OR editor OR owner,
--    OR you are an editor of its parent folder (inheritance)."
-- The power: per-object grants, inheritance, and groups fall out of the same
-- uniform tuple + a graph walk. No schema change to add a new sharing pattern.

CREATE TABLE relation_tuples (
    -- object being granted on, e.g. ('document','readme') or ('folder','eng')
    object_type  TEXT NOT NULL,
    object_id    TEXT NOT NULL,
    relation     TEXT NOT NULL,          -- 'owner','editor','viewer','parent','member'
    -- the subject the relation points AT: either a direct user
    --   subject_type='user', subject_id='alice', subject_relation=''
    -- or a "userset" (everyone in some relation on another object)
    --   subject_type='group', subject_id='staff', subject_relation='member'
    --   subject_type='folder', subject_id='eng',  subject_relation=''   (used by 'parent')
    subject_type     TEXT NOT NULL,
    subject_id       TEXT NOT NULL,
    subject_relation TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (object_type, object_id, relation, subject_type, subject_id, subject_relation)
);

CREATE INDEX rt_lookup ON relation_tuples (object_type, object_id, relation);
CREATE INDEX rt_reverse ON relation_tuples (subject_type, subject_id);
