package edu.utexas.tacc.tapis.security.authz.dao.sql;

/** This class centralizes all SQL statements used in the Tapis Security Kernel 
 * for authorization.  The statements returned are ready for preparation and, 
 * when all placeholders are properly bound, execution.
 * 
 * @author rich
 *
 */
public class SqlStatements
{
  /* ---------------------------------------------------------------------- */
  /* any table:                                                             */
  /* ---------------------------------------------------------------------- */
  public static final String SELECT_1 =
      "SELECT 1 FROM :table LIMIT 1";    
    
  /* ---------------------------------------------------------------------- */
  /* sk_role:                                                               */
  /* ---------------------------------------------------------------------- */
  // Get all rows.
  public static final String SELECT_SKROLE =
	  "SELECT id, tenant, name, description, owner, owner_tenant, created, createdby, createdby_tenant, "
	  + "updated, updatedby, updatedby_tenant, has_children FROM sk_role ORDER BY tenant,name";
  
  // Role statements.
  public static final String ROLE_SELECT_BY_NAME = 
      "SELECT id, tenant, name, description FROM sk_role where tenant = ? AND name = ?";
  public static final String ROLE_SELECT_EXTENDED_BY_NAME = 
      "SELECT id, tenant, name, description, owner, owner_tenant, created, createdby, createdby_tenant, "
      + "updated, updatedby, updatedby_tenant, has_children FROM sk_role where tenant = ? AND name = ?";
  public static final String ROLE_SELECT_NAMES = 
      "SELECT name FROM sk_role where tenant = ? ORDER BY name";
  public static final String ROLE_SELECT_ID_BY_NAME =
      "SELECT id FROM sk_role where tenant = ? AND name = ?";
  public static final String ROLE_INSERT = 
      "INSERT INTO sk_role (tenant, name, description, owner, owner_tenant, createdby, createdby_tenant, updatedby, updatedby_tenant) "
      + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING";
  public static final String ROLE_DELETE_BY_ID =
      "DELETE FROM sk_role where tenant = ? AND id = ?";
  public static final String ROLE_DELETE_BY_NAME =
      "DELETE FROM sk_role where tenant = ? AND name = ?";
  public static final String ROLE_UPDATE_ROLENAME = 
      "UPDATE sk_role SET name = ?, updated = ?, updatedby = ?, updatedby_tenant = ? WHERE tenant = ? AND name = ?";
  public static final String ROLE_UPDATE_OWNER = 
      "UPDATE sk_role SET owner = ?, updated = ?, updatedby = ?, updatedby_tenant = ? WHERE tenant = ? AND name = ?";
  public static final String ROLE_UPDATE_OWNER_AND_TENANT = 
	  "UPDATE sk_role SET owner = ?, owner_tenant = ?, updated = ?, updatedby = ?, updatedby_tenant = ? WHERE tenant = ? AND name = ?";
  public static final String ROLE_UPDATE_DESCRIPTION = 
      "UPDATE sk_role SET description = ?, updated = ?, updatedby = ?, updatedby_tenant = ? WHERE tenant = ? AND name = ?";
  
  // Strict version of above commands that are not idempotent.
  public static final String ROLE_INSERT_STRICT = 
	  "INSERT INTO sk_role (tenant, name, description, owner, owner_tenant, createdby, createdby_tenant, updatedby, updatedby_tenant) "
	  + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
  
  public static final String ROLE_GET_HASCHILDREN_FOR_UPDATE =
      "SELECT has_children FROM sk_role where tenant = ? AND id = ? FOR UPDATE";	  

  public static final String ROLE_UPDATE_HASCHILDREN = 
      "UPDATE sk_role SET has_children = ? where tenant = ? AND id = ?";
  
  /* ---------------------------------------------------------------------- */
  /* sk_role_permission:                                                    */
  /* ---------------------------------------------------------------------- */
  // Get all rows.
  public static final String SELECT_ALL_PERMISSIONS =
      "SELECT id, tenant, role_id, permission, created, createdby, createdby_tenant, " 
      + "updated, updatedby, updatedby_tenant "
      + "FROM sk_role_permission "
      + "ORDER BY tenant, permission";
  
  // The following select statement grabs the role id from the sk_role table after 
  // guaranteeing that the role's tenant is the expected one.    
  public static final String ROLE_ADD_PERMISSION =
      "INSERT INTO sk_role_permission (tenant, role_id, permission, " +
                                      "createdby, createdby_tenant, updatedby, updatedby_tenant) " +
      "select ?, r.id, ?, ?, ?, ?, ? from sk_role r where r.tenant = ? and r.id = ? " +
      "ON CONFLICT DO NOTHING";        
  
  public static final String ROLE_REMOVE_PERMISSION =
      "DELETE FROM sk_role_permission where tenant = ? and role_id = ? and permission = ?";
  
  public static final String ROLE_REMOVE_PERMISSION_FROM_ALL_ROLES =
      "DELETE FROM sk_role_permission where tenant = ? and permission = ?";
      
  public static final String ROLE_REMOVE_PATH_PERMISSION_FROM_ALL_ROLES =
      "DELETE FROM sk_role_permission where tenant = ? and permission like ?";
      
  // Get rows that match a permission prefix for all roles.
  public static final String SELECT_PERMISSION_PREFIX = 
      "SELECT id, tenant, role_id, permission "
      + "FROM sk_role_permission " 
      + "WHERE tenant = ? AND permission LIKE ? "
      + "ORDER BY permission";     
      
  // Get rows that match a permission prefix with an optional role id constraint.
  public static final String SELECT_PERMISSION_PREFIX_WITH_ROLE = 
      "SELECT id, tenant, role_id, permission "
      + "FROM sk_role_permission " 
      + "WHERE tenant = ? AND permission LIKE ? AND role_id = ? "
      + "ORDER BY permission";  
  
  // Update the permission string.
  public static final String UPDATE_PERMISSION_BY_ID = 
      "UPDATE sk_role_permission SET permission = ? WHERE tenant = ? and id = ?";
  
  // Get the permission assigned directly to a role (non-transitive) in order.
  public static final String ROLE_GET_IMMEDIATE_PERMISSIONS =
      "SELECT permission "
      + "FROM sk_role_permission "
      + "WHERE tenant = ? AND role_id = ? "
      + "ORDER BY permission";

  // Get the permission assigned directly to a role (non-transitive) unordered.
  public static final String ROLE_GET_IMMEDIATE_PERMISSIONS_UNORDERED =
      "SELECT permission "
      + "FROM sk_role_permission "
      + "WHERE tenant = ? AND role_id = ? ";

  /* ---------------------------------------------------------------------- */
  /* sk_role_tree:                                                          */
  /* ---------------------------------------------------------------------- */
  // Get all rows.
  public static final String SELECT_SKROLETREE =
      "SELECT id, tenant, parent_role_id, child_role_id, created, createdby, createdby_tenant, "
      + "updated, updatedby, updatedby_tenant "
      + "FROM sk_role_tree "
      + "ORDER BY tenant, parent_role_id, child_role_id";
  
  // The following select statement only grabs the tenant and child role id from the 
  // sk_role table, but uses the parent role id, createdby and updatedby constants 
  // passed in from the caller. The parent and child tenants are guaranteed to match
  // because the last clause matches the parent role's tenant.
  public static final String ROLE_ADD_CHILD_ROLE_BY_NAME =
      "INSERT INTO sk_role_tree " +
      "(tenant, parent_role_id, child_role_id, createdby, createdby_tenant, updatedby, updatedby_tenant) " +
      "select r.tenant, ?, r.id, ?, ?, ?, ? from sk_role r where r.tenant = ? and r.name = ? " +
      "and r.tenant = (select r2.tenant from sk_role r2 where r2.id = ?) " + // enforce tenant conformance
      "ON CONFLICT DO NOTHING";
  public static final String ROLE_ADD_CHILD_ROLE_BY_ID =
      "INSERT INTO sk_role_tree " +
      "(tenant, parent_role_id, child_role_id, createdby, createdby_tenant, updatedby, updatedby_tenant) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING"; // caller guarantees same tenant for roles
  public static final String ROLE_REMOVE_CHILD_ROLE_BY_ID =
      "DELETE FROM sk_role_tree where tenant = ? and parent_role_id = ? and child_role_id = ?";
  
  // Child role name retrieval in alphabetic order.
  public static final String ROLE_GET_IMMEDIATE_CHILD_ROLE_NAMES =
      "SELECT r.name from sk_role r, sk_role_tree rt " +
      "where r.tenant = ? and r.id = rt.child_role_id and rt.parent_role_id = ? " +
      "order by r.name";
  
  // Parent role name retrieval in alphabetic order.
  public static final String ROLE_GET_IMMEDIATE_PARENT_ROLE_NAMES =
      "SELECT r.name from sk_role r, sk_role_tree rt " +
      "where r.tenant = ? and r.id = rt.parent_role_id and rt.child_role_id = ? " +
      "order by r.name";
  
  // Get the number of child roles a parent role has.
  public static final String ROLE_GET_CHILD_COUNT =
	  "SELECT count(*) FROM sk_role_tree WHERE tenant = ? AND parent_role_id = ?";
  
  // This recursive query retrieves all the roles names that are descendants
  // of the specified role (the role whose id parameter is passed in).  The
  // query returns the child names in alphabetic order.  The application  
  // guards against introducing a cycle in the graph to avoid infinite loops. 
  // Union Distinct is used to remove duplicates since as an acyclic graph, 
  // the role hierarchy allows a node to have multiple parents.
  //
  // NOTE: This postgres-specific syntax needs to be moved to
  //       a postgres file when another database is supported.
  public static final String ROLE_GET_DESCENDANT_NAMES_FOR_PARENT_ID =
      "WITH RECURSIVE children AS ( " +
      "SELECT child_role_id FROM sk_role_tree WHERE parent_role_id = ? " +
      "UNION DISTINCT " +
      "SELECT a.child_role_id FROM sk_role_tree a, children b " +
        "WHERE a.parent_role_id = b.child_role_id " +
      ") " +
      "SELECT sk_role.name FROM children, sk_role " +
        "WHERE sk_role.id = children.child_role_id " +
        "ORDER BY sk_role.name";
  
  // Given a child role id, get all its ancestor role names.
  public static final String ROLE_GET_ANCESTOR_NAMES_FOR_CHILD_ID =
      "WITH RECURSIVE children AS ( " +
      "SELECT parent_role_id FROM sk_role_tree WHERE child_role_id = ? " +
      "UNION DISTINCT " +
      "SELECT a.parent_role_id FROM sk_role_tree a, children b " +
        "WHERE a.child_role_id = b.parent_role_id " +
      ") " +
      "SELECT sk_role.name FROM children, sk_role " +
        "WHERE sk_role.id = children.parent_role_id " +
        "ORDER BY sk_role.name";
  
  // Given a role, find all permissions assigned to that role
  // and the transitive closure of all its descendants.  The 
  // WITH statement retrieves all the descendant role ids.  The
  // query that follows the WITH is a UNION.  The first part of 
  // this UNION calculates the permission values assigned to the 
  // descendant roles discovered in the preceding recursive calls.  
  // The second part of the UNION retrieves the permission values
  // assigned to the parent role.
  public static final String ROLE_GET_TRANSITIVE_PERMISSIONS =
      "WITH RECURSIVE children AS ( " +
      "SELECT child_role_id FROM sk_role_tree WHERE parent_role_id = ? " +
      "UNION DISTINCT " +
      "SELECT a.child_role_id FROM sk_role_tree a, children b " +
        "WHERE a.parent_role_id = b.child_role_id " +
      ") " +
      "SELECT DISTINCT rp1.permission AS outperm " +
        "FROM children, sk_role_permission rp1 " +
        "WHERE rp1.role_id = children.child_role_id " +
      "UNION DISTINCT " +
      "SELECT DISTINCT rp2.permission AS outperm " +
        "FROM sk_role_permission rp2 " +
        "WHERE rp2.role_id = ? " +
      "ORDER BY outperm";

  /* ---------------------------------------------------------------------- */
  /* sk_user_role:                                                          */
  /* ---------------------------------------------------------------------- */
  // Get all rows.
  public static final String SELECT_SKUSERROLE =
      "SELECT id, tenant, user_name, role_id, created, createdby, createdby_tenant, "
      + "updated, updatedby updatedby_tenant "
      + "FROM sk_user_role ORDER BY id";

  // Get all users in tenant.
  public static final String SELECT_USER_NAMES =
      "SELECT DISTINCT user_name FROM sk_user_role "
      + "WHERE tenant = ? ORDER BY user_name";
  
  // If the role's tenant does not match the passed in tenant, the insert will fail.
  // This is because users can only be assigned roles in their tenant, though those 
  // roles may be owned by services in another tenant.
  public static final String USER_ADD_ROLE_BY_ID =
      "INSERT INTO sk_user_role (tenant, user_name, role_id, createdby, createdby_tenant, " +
                                "updatedby, updatedby_tenant) " +
      "select r.tenant, ?, ?, ?, ?, ?, ? FROM sk_role r where r.tenant = ? and r.id = ? " +
      "ON CONFLICT DO NOTHING";
  
  // Strict versions of above commands that are not idempotent.
  public static final String USER_ADD_ROLE_BY_ID_STRICT =
      "INSERT INTO sk_user_role (tenant, user_name, role_id, " +
    		                    "createdby, createdby_tenant, updatedby, updatedby_tenant) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?)";

  // Strict versions of above commands that are idempotent.
  public static final String USER_ADD_ROLE_BY_ID_NOT_STRICT =
	  "INSERT INTO sk_user_role (tenant, user_name, role_id, " +
	                            "createdby, createdby_tenant, updatedby, updatedby_tenant) " +
	  "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING";

  // If the role's tenant does not match the passed in tenant, the insert will fail.
  public static final String USER_DELETE_ROLE_BY_ID =
      "DELETE FROM sk_user_role WHERE tenant = ? AND user_name = ? AND role_id = ?";

  // Get the role ids directly (non-transitively) assigned to user.
  public static final String USER_SELECT_ROLE_IDS =
      "SELECT ur.role_id, r.has_children FROM sk_user_role ur, sk_role r " +
      "WHERE ur.role_id = r.id and tenant = ? and user_name = ?";
  
  // Get the role ids and the role names directly (non-transitively) assigned to user.
  public static final String USER_SELECT_ROLE_IDS_AND_NAMES =
      "SELECT ur.role_id, r.name, r.has_children FROM sk_user_role ur, sk_role r " +
      "WHERE ur.role_id = r.id and ur.tenant = ? and ur.user_name = ?";
  
  // Get all users assigned a list of role names which are expected
  // to be the role the user is querying and all its ancestors.
  public static final String USER_SELECT_USERS_WITH_ROLE = 
      "SELECT DISTINCT u.user_name FROM sk_role r, sk_user_role u " + 
      "WHERE r.id = u.role_id AND r.tenant = ? AND r.name IN (:namelist) " +
      "ORDER BY u.user_name";

  // Get all users assigned a specific permission.  The permission can contain the
  // sql wildcard character (%), in which case the ${op} operator placeholder will 
  // be replaced with LIKE.  Otherwise, = will replace ${op}. 
  public static final String USER_SELECT_USERS_WITH_PERM = 
      "SELECT DISTINCT u.user_name FROM sk_role r, sk_user_role u, sk_role_permission pm " +
      "WHERE r.tenant = u.tenant AND r.tenant = pm.tenant " +
          "AND r.id = u.role_id AND r.id = pm.role_id " +
          "AND r.tenant = ? AND pm.permission :op ? " +
          "ORDER BY u.user_name";

  /* ---------------------------------------------------------------------- */
  /* sk_shared:                                                             */
  /* ---------------------------------------------------------------------- */
  // Get all rows.
  public static final String SELECT_SKSHARED =
      "SELECT id, tenant, grantor, grantee, resource_type, resource_id1, "
      + "resource_id2, privilege, created, createdby, createdby_tenant "
      + "FROM sk_shared ORDER BY id";
  
  public static final String SHARE_INSERT = 
      "INSERT INTO sk_shared (tenant, grantor, grantee, resource_type, resource_id1, "
      + "resource_id2, privilege, created, createdby, createdby_tenant) "
      + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING";
  
  public static final String SHARE_SELECT_BY_ID = 
      "SELECT id, tenant, grantor, grantee, resource_type, resource_id1, "
      + "resource_id2, privilege, created, createdby, createdby_tenant "
      + "FROM sk_shared WHERE tenant = ? AND id = ?";
  
  public static final String SHARE_SELECT_DYNAMIC = 
      "SELECT id, tenant, grantor, grantee, resource_type, resource_id1, "
      + "resource_id2, privilege, created, createdby, createdby_tenant "
      + "FROM sk_shared :where ORDER BY ID";
  
  public static final String SHARE_SELECT_BY_UNIQUE_KEY = 
      "SELECT id, tenant, grantor, grantee, resource_type, resource_id1, "
      + "resource_id2, privilege, created, createdby, createdby_tenant "
      + "FROM sk_shared "
      + "WHERE tenant = ? AND grantor = ? AND grantee = ? "
      + " AND resource_type = ? AND resource_id1 = ? AND resource_id2 = ? "
      + " AND privilege = ?";

  public static final String SHARE_DELETE_BY_ID = 
      "DELETE FROM sk_shared WHERE tenant = ? AND id = ? "
      + " AND createdby_tenant = ? AND createdby = ?";
  
  public static final String SHARE_DELETE_BY_SELECTOR = 
      "DELETE FROM sk_shared WHERE tenant = ? AND grantor = ? "
      + " AND grantee = ? AND resource_type = ? AND resource_id1 = ? "
      + " AND resource_id2 = ? AND privilege = ? "
      + " AND createdby_tenant = ? AND createdby = ?";
      
  public static final String SHARE_HAS_PRIVILEGE =
      "SELECT 1 FROM sk_shared "    
      + "WHERE tenant = ? AND grantee IN (:grantees) "
      + " AND resource_type = ? AND resource_id1 = ? AND resource_id2 = ? "
      + " AND privilege = ? "
      + "LIMIT 1";
}
