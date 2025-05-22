-- Add the 'type' column to the role table
ALTER TABLE sk_role ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'UNSET';

-- set initial values based on role names
UPDATE sk_role SET type='TENANT_ADMIN' WHERE name LIKE '$!%' AND type='UNSET';
UPDATE sk_role SET type='USER_DEFAULT' WHERE name LIKE '$$%' AND type='UNSET';
UPDATE sk_role SET type='USER' WHERE type='UNSET';

-- Create an index
CREATE INDEX IF NOT EXISTS sk_role_type_idx ON sk_role (type);