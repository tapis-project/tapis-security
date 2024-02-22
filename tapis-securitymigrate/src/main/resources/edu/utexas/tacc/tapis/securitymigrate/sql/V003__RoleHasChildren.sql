-- This new column allows SK to run quicker when roles are known not to have children.
ALTER TABLE sk_role ADD COLUMN IF NOT EXISTS has_children boolean NOT NULL DEFAULT FALSE;
COMMENT ON COLUMN sk_role.has_children IS 'Child role indicator';

-- Add has_children field auditing.  Replacing the funtion does not break its trigger.
CREATE OR REPLACE FUNCTION audit_sk_role() RETURNS TRIGGER AS $$
    BEGIN
        --
        -- Description fields are trimmed of whitespace at both ends and may be truncated
        -- to fit inside the audit record.
        --
        IF (TG_OP = 'DELETE') THEN
            INSERT INTO sk_role_audit (refid, refname, refcol, change, oldvalue) 
                VALUES (OLD.id, OLD.name, 'ALL', 'delete', 
                        substring(trim(both ' \b\n\r' from OLD.description) from 1 for 512));
            RETURN OLD;
        ELSIF (TG_OP = 'UPDATE') THEN
            -- We always use the OLD id and, when applicable, OLD name in update audit records, 
            -- even if those fields are among those that have changed.  Any update that changes  
            -- any field will cause an audit record to be written.  Since the updated timestamp 
            -- always changes, updates typically cause 2 or more new audit records.   
            IF OLD.id != NEW.id THEN
                INSERT INTO sk_role_audit (refid, refname, refcol, change, oldvalue, newvalue) 
                    VALUES (OLD.id, OLD.name, 'id', 'update', OLD.id::text, NEW.id::text);
            END IF;
            IF OLD.tenant != NEW.tenant THEN
                INSERT INTO sk_role_audit (refid, refname, refcol, change, oldvalue, newvalue) 
                    VALUES (OLD.id, OLD.name, 'tenant', 'update', OLD.tenant, NEW.tenant);
            END IF;
            IF OLD.name != NEW.name THEN
                INSERT INTO sk_role_audit (refid, refname, refcol, change, oldvalue, newvalue) 
                    VALUES (OLD.id, OLD.name, 'name', 'update', OLD.name, NEW.name);
            END IF;
            IF OLD.description != NEW.description THEN
                INSERT INTO sk_role_audit (refid, refname, refcol, change, oldvalue, newvalue) 
                    VALUES (OLD.id, OLD.name, 'description', 'update', 
                            substring(trim(both ' \b\n\r' from OLD.description) from 1 for 512), 
                            substring(trim(both ' \b\n\r' from NEW.description) from 1 for 512));
            END IF;
            IF OLD.owner != NEW.owner THEN
                INSERT INTO sk_role_audit (refid, refname, refcol, change, oldvalue, newvalue) 
                    VALUES (OLD.id, OLD.name, 'owner', 'update', OLD.owner, NEW.owner);
            END IF;
            IF OLD.owner_tenant != NEW.owner_tenant THEN
                INSERT INTO sk_role_audit (refid, refname, refcol, change, oldvalue, newvalue) 
                    VALUES (OLD.id, OLD.name, 'owner_tenant', 'update', OLD.owner_tenant, NEW.owner_tenant);
            END IF;
            IF OLD.createdby != NEW.createdby THEN
                INSERT INTO sk_role_audit (refid, refname, refcol, change, oldvalue, newvalue) 
                    VALUES (OLD.id, OLD.name, 'createdby', 'update', OLD.createdby, NEW.createdby);
            END IF;
            IF OLD.createdby_tenant != NEW.createdby_tenant THEN
                INSERT INTO sk_role_audit (refid, refname, refcol, change, oldvalue, newvalue) 
                    VALUES (OLD.id, OLD.name, 'createdby_tenant', 'update', OLD.createdby_tenant, NEW.createdby_tenant);
            END IF;
            IF OLD.updatedby != NEW.updatedby THEN
                INSERT INTO sk_role_audit (refid, refname, refcol, change, oldvalue, newvalue) 
                    VALUES (OLD.id, OLD.name, 'updatedby', 'update', OLD.updatedby, NEW.updatedby);
            END IF;
            IF OLD.updatedby_tenant != NEW.updatedby_tenant THEN
                INSERT INTO sk_role_audit (refid, refname, refcol, change, oldvalue, newvalue) 
                    VALUES (OLD.id, OLD.name, 'updatedby_tenant', 'update', OLD.updatedby_tenant, NEW.updatedby_tenant);
            END IF;
            IF OLD.created != NEW.created THEN
                INSERT INTO sk_role_audit (refid, refname, refcol, change, oldvalue, newvalue) 
                    VALUES (OLD.id, OLD.name, 'created', 'update', 
                            OLD.created::text, 
                            NEW.created::text);
            END IF;
            IF OLD.updated != NEW.updated THEN
                INSERT INTO sk_role_audit (refid, refname, refcol, change, oldvalue, newvalue) 
                    VALUES (OLD.id, OLD.name, 'updated', 'update', 
                            OLD.updated::text, 
                            NEW.updated::text);
            END IF;
            IF OLD.has_children != NEW.has_children THEN
                INSERT INTO sk_role_audit (refid, refname, refcol, change, oldvalue, newvalue) 
                    VALUES (OLD.id, OLD.name, 'has_children', 'update', OLD.has_children, NEW.has_children);
            END IF;

            RETURN NEW;
        ELSIF (TG_OP = 'INSERT') THEN
            INSERT INTO sk_role_audit (refid, refname, refcol, change, newvalue) 
                VALUES (NEW.id, NEW.name, 'ALL', 'insert', 
                        substring(trim(both ' \b\n\r' from NEW.description) from 1 for 512));
            RETURN NEW;
        END IF;
        RETURN NULL; -- result is ignored since this is an AFTER trigger
    END;
$$ LANGUAGE plpgsql;

