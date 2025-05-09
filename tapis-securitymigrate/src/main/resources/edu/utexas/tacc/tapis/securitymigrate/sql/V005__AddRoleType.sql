-- Add the 'type' column to the role table
alter table sk_role add column "type" TEXT;

-- set initial values based on role names
update sk_role set type='TENANT_ADMIN' where name like '$!%';
update sk_role set type='USER_DEFAULT' where name like '$$%';
update sk_role set type='USER' where type is null;

-- Create an index
CREATE INDEX sk_role_type_idx ON sk_role (type);
