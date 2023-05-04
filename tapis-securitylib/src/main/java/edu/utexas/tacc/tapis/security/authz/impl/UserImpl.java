package edu.utexas.tacc.tapis.security.authz.impl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.utexas.tacc.tapis.security.authz.dao.SkRolePermissionDao;
import edu.utexas.tacc.tapis.security.authz.dao.SkUserRoleDao;
import edu.utexas.tacc.tapis.security.authz.permissions.ExtWildcardPermission;
import edu.utexas.tacc.tapis.shared.exceptions.TapisImplException;
import edu.utexas.tacc.tapis.shared.exceptions.TapisImplException.Condition;
import edu.utexas.tacc.tapis.shared.exceptions.TapisNotFoundException;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;

/** This singleton class implements the backend user APIs. 
 * 
 * Methods in this class do not depend on the caller to validate their parameters,
 * though front-end code may do parameter validation before calling methods in
 * this class.  Many methods in this class depend on the DAO methods they call for 
 * parameter validation.
 * 
 * Methods in this class should only expose their clients to Tapis exceptions.
 * For example, SQL errors are wrapped in TapisExceptions.
 * 
 * @author rcardone
 */
public final class UserImpl
 extends BaseImpl
{
    /* ********************************************************************** */
    /*                               Constants                                */
    /* ********************************************************************** */
    // Tracing.
    private static final Logger _log = LoggerFactory.getLogger(UserImpl.class);
    
    /* **************************************************************************** */
    /*                                     Enums                                    */
    /* **************************************************************************** */
    // Logical operations applied during authentication.
    public enum AuthOperation {ANY, ALL}
    
    /* ********************************************************************** */
    /*                                Fields                                  */
    /* ********************************************************************** */
    // Singleton instance of this class.
    private static UserImpl _instance;
    
    /* ********************************************************************** */
    /*                             Constructors                               */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* constructor:                                                           */
    /* ---------------------------------------------------------------------- */
    private UserImpl() {}
    
    /* ********************************************************************** */
    /*                             Public Methods                             */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* getInstance:                                                           */
    /* ---------------------------------------------------------------------- */
    public static UserImpl getInstance()
    {
        // Create the singleton instance if necessary.
        if (_instance == null) {
            synchronized (UserImpl.class) {
                if (_instance == null) _instance = new UserImpl();
            }
        }
        return _instance;
    }
    
    /* ---------------------------------------------------------------------------- */
    /* createAndAssignRole:                                                         */
    /* ---------------------------------------------------------------------------- */
    public int createAndAssignRole(String roleName, String roleTenant, String description,
                                    String grantee, String granteeTenant,
                                    String grantor, String grantorTenant, boolean strict) 
     throws TapisImplException
    {
        // Get the dao.
        SkUserRoleDao userDao = null;
        try {userDao = getSkUserRoleDao();}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("DB_DAO_ERROR", "userRoles");
                _log.error(msg, e);
                throw new TapisImplException(e.getMessage(), e, Condition.INTERNAL_SERVER_ERROR); 
            }

        // Create and assign the role.
        int rows = 0;
        try {rows = userDao.createAndAssignRole(roleName, roleTenant, description, 
        		                                grantee, granteeTenant, 
        		                                grantor, grantorTenant, strict);}
            catch (Exception e) {
                // Interpret all errors as client request problems.
                throw new TapisImplException(e.getMessage(), Condition.BAD_REQUEST);
            }
        return rows;
    }
    
    /* ---------------------------------------------------------------------- */
    /* getUserNames:                                                          */
    /* ---------------------------------------------------------------------- */
    public List<String> getUserNames(String tenant) throws TapisImplException
    {
        // Get the dao.
        SkUserRoleDao dao = null;
        try {dao = getSkUserRoleDao();}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("DB_DAO_ERROR", "userRoles");
                _log.error(msg, e);
                throw new TapisImplException(msg, e, Condition.INTERNAL_SERVER_ERROR);
            }
    
        // Get the names.
        List<String> users = null;
        try {users = dao.getUserNames(tenant);}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("SK_USER_GET_NAMES_ERROR", 
                                             tenant, e.getMessage());
                _log.error(msg, e);
                throw new TapisImplException(msg, e, Condition.BAD_REQUEST);
        }
    
        return users;
    }

    /* ---------------------------------------------------------------------- */
    /* getUserPerms:                                                          */
    /* ---------------------------------------------------------------------- */
    public List<String> getUserPerms(String tenant, String user, String implies,
                                     String impliedBy) 
     throws TapisImplException
    {
        // Get the dao.
        SkUserRoleDao dao = null;
        try {dao = getSkUserRoleDao();}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("DB_DAO_ERROR", "userRoles");
                _log.error(msg, e);
                throw new TapisImplException(msg, e, Condition.INTERNAL_SERVER_ERROR);            
            }

        // Get the names.
        List<String> perms = null;
        try {perms = dao.getUserPermissions(tenant, user);}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("SK_USER_GET_PERMISSIONS_ERROR", 
                                             tenant, user, e.getMessage());
                _log.error(msg, e);
                throw new TapisImplException(msg, e, Condition.BAD_REQUEST);            
            }

        // Optionally filter the list of permissions.
        if (!StringUtils.isBlank(implies)) filterImpliesPermissions(perms, implies);
        if (!StringUtils.isBlank(impliedBy)) filterImpliedByPermissions(perms, impliedBy);
        
        return perms;
    }

    /* ---------------------------------------------------------------------- */
    /* grantRole:                                                             */
    /* ---------------------------------------------------------------------- */
    public int grantRole(String tenant, String user, String roleName, 
    		             String requestor, String requestorTenant) 
      throws TapisImplException, TapisNotFoundException
    {
        // Get the role id.
        int roleId = 0;
        try {roleId = getRoleId(tenant, roleName);}
            catch (TapisNotFoundException e) {
                _log.error(e.getMessage());
                throw e;
            }
            catch (Exception e) {
                _log.error(e.getMessage());
                throw new TapisImplException(e.getMessage(), e, Condition.INTERNAL_SERVER_ERROR);            
            }

        // Get the dao.
        SkUserRoleDao dao = null;
        try {dao = getSkUserRoleDao();}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("DB_DAO_ERROR", "userRoles");
                _log.error(msg, e);
                throw new TapisImplException(msg, e, Condition.INTERNAL_SERVER_ERROR);
            }
        
        // Assign the role to the user.
        int rows = 0;
        try {rows = dao.assignUserRole(user, tenant, roleId, requestor, requestorTenant);}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("SK_ADD_USER_ROLE_ERROR", requestor, 
                                             requestorTenant, roleId, user, tenant);
                _log.error(msg, e);
                throw new TapisImplException(msg, e, Condition.BAD_REQUEST);            
            }
        
        return rows;
    }

    /* ---------------------------------------------------------------------- */
    /* revokeUserRole:                                                        */
    /* ---------------------------------------------------------------------- */
    public int revokeUserRole(String tenant, String user, String roleName) 
      throws TapisImplException, TapisNotFoundException
    {
        // Get the role id.
        int roleId = 0;
        try {roleId = getRoleId(tenant, roleName);}
            catch (TapisNotFoundException e) {
                _log.error(e.getMessage());
                throw e;
            }
            catch (Exception e) {
                _log.error(e.getMessage());
                throw new TapisImplException(e.getMessage(), e, Condition.INTERNAL_SERVER_ERROR);            
            }

        // Get the dao.
        SkUserRoleDao dao = null;
        try {dao = getSkUserRoleDao();}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("DB_DAO_ERROR", "userRoles");
                _log.error(msg, e);
                throw new TapisImplException(msg, e, Condition.INTERNAL_SERVER_ERROR);
            }

        // Assign the role to the user.
        int rows = 0;
        try {rows = dao.removeUserRole(tenant, user, roleId);}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("SK_REMOVE_USER_ROLE_ERROR",  
                                             tenant, roleId, user, e.getMessage());
                _log.error(msg, e);
                throw new TapisImplException(msg, e, Condition.BAD_REQUEST);            
            }
        
        return rows;
    }
    
    /* ---------------------------------------------------------------------- */
    /* grantUserPermission:                                                   */
    /* ---------------------------------------------------------------------- */
    /** Grant a permission by assigning the permission to the user's default
     * role, creating and granting that role to the user if it doesn't already
     * exist.
     * 
     * @param grantee the user receiving the permission
     * @param granteeTenant the grantee's tenant
     * @param permSpec the permission specification
     * @param grantor the grantor
     * @param grantorTenant the grantor's tenant
     * 
     * @return the number of database updates
     * @throws TapisImplException on general errors
     */
    public int grantUserPermission(String grantee, String granteeTenant, String permSpec, 
    		                       String grantor, String grantorTenant)
        throws TapisImplException
    {
        // Check user name length before using it to construct the user's default role.
        if (grantee.length() > MAX_USER_NAME_LEN) {
            String msg = MsgUtils.getMsg("SK_USER_NAME_LEN", granteeTenant, grantee, MAX_USER_NAME_LEN);
            _log.error(msg);
            throw new TapisImplException(msg, Condition.BAD_REQUEST);
        }
        
        // Construct the user's default role name.
        String roleName = getUserDefaultRolename(grantee);
        
        // Perform an optimistic assignment that works only if the user's 
        // default role exists and has already been assigned to the user.
        // If the first attempt fails, we try one more time after creating
        // and assigning the user's default role.
        final boolean strict = true;
        int rows = 0;
        for (int i = 0; i < 2; i++) {
            try {
                // See if we can assign the permission to the role.
                rows += grantRoleWithPermission(roleName, granteeTenant, permSpec,  
                		                        grantee, granteeTenant, 
                		                        grantor, grantorTenant);
                
                // This try worked!
                break;
            } 
            catch (TapisNotFoundException e) {
                // The role does not exist, so let's create it and
                // assign it to the user in one atomic operation.
                // Any failure here aborts the whole operation.
            	String desc = "Default role for user " + grantee;
                rows = createAndAssignRole(roleName, granteeTenant, desc, 
                		                   grantee, granteeTenant,
                		                   grantor, grantorTenant, strict);
            }
        }
        
        return rows;
    }
    
    /* ---------------------------------------------------------------------- */
    /* grantRoleWithPermission:                                               */
    /* ---------------------------------------------------------------------- */
    /** Grant an existing role to a user after inserting the permission into the
     * role.
     * 
     * @param roleName the role to receive the permission
     * @param roleTenant the role's tenant
     * @param permSpec the permission specification
     * @param grantee the user receiving the permission
     * @param granteeTenant the grantee's tenant
     * @param grantor the grantor
     * @param grantorTenant the grantor's tenant
     * @return the number of database updates
     * @throws TapisImplException on general errors
     * @throws TapisNotFoundException the role does not exist
     */
    public int grantRoleWithPermission(String roleName, String roleTenant, String permSpec,
    		                           String grantee, String granteeTenant,  
                                       String grantor, String grantorTenant)
        throws TapisImplException, TapisNotFoundException
    {
        // ******************* Insert Permission into Role ********************
        // --------------------------------------------------------------------
        // Get the role id.
        int roleId = 0;
        try {roleId = getRoleId(granteeTenant, roleName);}
            catch (TapisNotFoundException e) {
                _log.error(e.getMessage());
                throw e;
            }
            catch (Exception e) {
                _log.error(e.getMessage());
                throw new TapisImplException(e.getMessage(), e, Condition.INTERNAL_SERVER_ERROR);           
            }

        // Get the dao.
        SkRolePermissionDao rolePermDao = null;
        try {rolePermDao = getSkRolePermissionDao();}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("DB_DAO_ERROR", "rolePermission");
                _log.error(msg, e);
                throw new TapisImplException(msg, e, Condition.INTERNAL_SERVER_ERROR);
            }
        
        // Assign the permission.
        int rows = 0;
        try {
            rows = rolePermDao.assignPermission(roleTenant, roleId, permSpec, grantor, grantorTenant);
        } catch (TapisNotFoundException e) {
            // This only occurs when the role name is not found.
            String msg = MsgUtils.getMsg("SK_ADD_PERMISSION_ERROR", grantor, granteeTenant,
            		                     permSpec, roleName, roleTenant);
            _log.error(msg, e);
            throw e;
        } catch (Exception e) {
            // We assume a bad request for all other errors.
            String msg = MsgUtils.getMsg("SK_ADD_PERMISSION_ERROR", grantor, granteeTenant,
                                         permSpec, roleName, roleTenant);
            _log.error(msg, e);
            throw new TapisImplException(msg, e, Condition.BAD_REQUEST);        
        }
       
        // ************************ Assign Role to User ***********************
        // --------------------------------------------------------------------
        // Get the dao.
        SkUserRoleDao userDao = null;
        try {userDao = getSkUserRoleDao();}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("DB_DAO_ERROR", "userRoles");
                _log.error(msg, e);
                throw new TapisImplException(e.getMessage(), e, Condition.INTERNAL_SERVER_ERROR);            }

        // Assign the role to the user.
        try {rows += userDao.assignUserRole(grantee, granteeTenant, roleId, grantor, granteeTenant);}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("SK_ADD_USER_ROLE_ERROR", grantor, 
                                             grantorTenant, roleId, grantee, granteeTenant);
                _log.error(msg, e);
                throw new TapisImplException(msg, e, Condition.BAD_REQUEST);
            }
        
        return rows;
    }
    
    /* ---------------------------------------------------------------------- */
    /* getUserRoleNames:                                                      */
    /* ---------------------------------------------------------------------- */
    public List<String> getUserRoleNames(String tenant, String user) 
     throws TapisImplException
    {
        // Get the dao.
        SkUserRoleDao dao = null;
        try {dao = getSkUserRoleDao();}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("DB_DAO_ERROR", "userRoles");
                _log.error(msg, e);
                throw new TapisImplException(e.getMessage(), e, Condition.INTERNAL_SERVER_ERROR);             }

        // Get the user's role names including those assigned transitively.
        List<String> roles = null;
        try {roles = dao.getUserRoleNames(tenant, user);}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("SK_USER_GET_ROLE_NAMES_ERROR", 
                                             tenant, user, e.getMessage());
                _log.error(msg, e);
                throw new TapisImplException(msg, e, Condition.BAD_REQUEST);            }
        
        return roles;
    }
    
    /* ---------------------------------------------------------------------- */
    /* getUserRoleIdsAndNames:                                                */
    /* ---------------------------------------------------------------------- */
    /** Get the role id and name for all roles directly assigned to a user.
     * This method does not perform transitive role process--only the roles
     * immediately assigned to the user are returned.
     * 
     * @param tenant user's tenant
     * @param user user id
     * @return pairs of <roleId, roleName> for each role directly assigned to user
     * @throws TapisImplException
     */
    public List<Pair<Integer,String>> getUserRoleIdsAndNames(String tenant, String user) 
     throws TapisImplException
    {
        // Get the dao.
        SkUserRoleDao dao = null;
        try {dao = getSkUserRoleDao();}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("DB_DAO_ERROR", "userRoles");
                _log.error(msg, e);
                throw new TapisImplException(e.getMessage(), e, Condition.INTERNAL_SERVER_ERROR);             }

        // Get the user's role names including those assigned transitively.
        List<Pair<Integer,String>> pairs = null;
        try {pairs = dao.getUserRoleIdsAndNames(tenant, user);}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("SK_USER_GET_ROLE_NAMES_ERROR", 
                                             tenant, user, e.getMessage());
                _log.error(msg, e);
                throw new TapisImplException(msg, e, Condition.BAD_REQUEST);            }
        
        return pairs;
    }
    
    /* ---------------------------------------------------------------------- */
    /* getUsersWithRole:                                                      */
    /* ---------------------------------------------------------------------- */
    public List<String> getUsersWithRole(String tenant, String roleName) 
     throws TapisImplException, TapisNotFoundException
    {
        // Get the dao.
        SkUserRoleDao dao = null;
        try {dao = getSkUserRoleDao();}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("DB_DAO_ERROR", "userRoles");
                _log.error(msg, e);
                throw new TapisImplException(e.getMessage(), e, Condition.INTERNAL_SERVER_ERROR); 
            }

        // Assign the role to the user.
        List<String> users = null;
        try {users = dao.getUsersWithRole(tenant, roleName);}
            catch (TapisNotFoundException e) {
                _log.error(e.getMessage());
                throw e;
            }
            catch (Exception e) {
                _log.error(e.getMessage());
                throw new TapisImplException(e.getMessage(), e, Condition.INTERNAL_SERVER_ERROR);
            }
        
        return users;
    }
    
    /* ---------------------------------------------------------------------- */
    /* getUsersWithPermission:                                                */
    /* ---------------------------------------------------------------------- */
    public List<String> getUsersWithPermission(String tenant, String permSpec) 
     throws TapisImplException
    {
        // Get the dao.
        SkUserRoleDao dao = null;
        try {dao = getSkUserRoleDao();}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("DB_DAO_ERROR", "userRoles");
                _log.error(msg, e);
                throw new TapisImplException(e.getMessage(), e, Condition.INTERNAL_SERVER_ERROR);
            }

        // Assign the role to the user.
        List<String> users = null;
        try {users = dao.getUsersWithPermission(tenant, permSpec);}
            catch (Exception e) {
                _log.error(e.getMessage());
                throw new TapisImplException(e.getMessage(), e, Condition.INTERNAL_SERVER_ERROR);
            }
        
        return users;
    }
    
    /* ---------------------------------------------------------------------- */
    /* hasRole:                                                               */
    /* ---------------------------------------------------------------------- */
    public boolean hasRole(String tenant, String user, String[] roleNames, AuthOperation op) 
     throws TapisImplException
    {
        // Check inputs not checked by called routines.
        if (op == null) {
            String msg = MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "hasRole", "op");            
            _log.error(msg);
            throw new TapisImplException(msg, Condition.BAD_REQUEST);            
        }
        if (roleNames == null || (roleNames.length == 0)) {
            String msg = MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "hasRole", "roleNames");
            _log.error(msg);
            throw new TapisImplException(msg, Condition.BAD_REQUEST);  
        }
        
        // Get the user's roles.  An exception can be thrown here.
        List<String> roles = getUserRoleNames(tenant, user);
        
        // Initialize the result based on the operation.
        // ANY starts out as false, ALL starts as true.
        boolean authorized = (op == AuthOperation.ANY) ? false : true;
        
        // Iterate through the list of user-suppled role names.
        for (String curRole : roleNames) {
            // Search for the role in the list whose elements are sorted in ascending order.
            int position = Collections.binarySearch(roles, curRole);
            
            // We stop processing ANY constraints as soon as we find the first match.
            if (op == AuthOperation.ANY) {
                if (position >= 0) {
                    authorized = true;
                    break;
                }
            }
            // We stop processing ALL constraints as soon as we find the first non-match.
            else {
                if (position < 0) {
                    authorized = false;
                    break;
                }
            }
        }
        
        return authorized;
    }
    
    /* ---------------------------------------------------------------------- */
    /* getUserPermissions:                                                    */
    /* ---------------------------------------------------------------------- */
    public List<String> getUserPermissions(String tenant, String user) 
     throws TapisImplException
    {
        // Get the dao.
        SkUserRoleDao dao = null;
        try {dao = getSkUserRoleDao();}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("DB_DAO_ERROR", "userRoles");
                _log.error(msg, e);
                throw new TapisImplException(e.getMessage(), e, Condition.INTERNAL_SERVER_ERROR); 
            }

        // Get the names.
        List<String> assignedPerms = null;
        try {assignedPerms = dao.getUserPermissions(tenant, user);}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("SK_USER_GET_ROLE_NAMES_ERROR", 
                                             tenant, user, e.getMessage());
                _log.error(msg, e);
                throw new TapisImplException(msg, e, Condition.BAD_REQUEST);            
            }
        
        return assignedPerms;
    }
    
    /* ---------------------------------------------------------------------- */
    /* isPermitted:                                                           */
    /* ---------------------------------------------------------------------- */
    public boolean isPermitted(String tenant, String user, String[] permSpecs, 
                               AuthOperation op) 
     throws TapisImplException
    {
        // Check inputs not checked by called routines.
        if (op == null) {
            String msg = MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "isPermitted", "op");            
            _log.error(msg);
            throw new TapisImplException(msg, Condition.BAD_REQUEST);            
        }
        if (permSpecs == null || (permSpecs.length == 0)) {
            String msg = MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "isPermitted", "permSpecs");
            _log.error(msg);
            throw new TapisImplException(msg, Condition.BAD_REQUEST);  
        }
        
        // Get all permissions assigned to user include those assigned transitively.
        // This call can throw an exception.
        List<String> assignedPerms = getUserPermissions(tenant, user);
        
        // Maybe it's already obvious that the user does not have permission.
        if (assignedPerms.isEmpty()) return false;
        
        // Initialize the result based on the operation.
        // ANY starts out as false, ALL starts as true.
        boolean authorized = (op == AuthOperation.ANY) ? false : true;
        
        // Create a permission cache that allows us to allocate at most
        // one wildcard object for each assigned permission.  The cache
        // is only useful if more than 1 permSpec might get tested.
        HashMap<String,ExtWildcardPermission> assignedPermMap;
        if (permSpecs.length > 1) 
            assignedPermMap = new HashMap<>(1 + 2 * assignedPerms.size());
          else assignedPermMap = null;
        
        // Iterate through the list of user-suppled role names.
        for (String curPermSpec : permSpecs) 
        {
            // Match the current user-supplied permission with those assigned to the user.
            boolean matched = matchPermission(curPermSpec, assignedPerms, assignedPermMap);
            
            // We stop processing ANY constraints as soon as we find the first match.
            if (op == AuthOperation.ANY) {
                if (matched) {
                    authorized = true;
                    break;
                }
            }
            // We stop processing ALL constraints as soon as we find the first non-match.
            else {
                if (!matched) {
                    authorized = false;
                    break;
                }
            }
        }
        
        return authorized;
    }

    /* ---------------------------------------------------------------------- */
    /* grantAdminRoleInternal:                                                */
    /* ---------------------------------------------------------------------- */
    /** Grant the administrator role to the user without checking whether the
     * requestor is also an administrator.  This method should only be used
     * by SK code, never by clients.
     * 
     * @param tenant the tenant id
     * @param requestor the caller's name
     * @param user the user being grant the admin role
     * @return the number of rows changed
     * @throws TapisImplException on error
     * @throws TapisNotFoundException if the role is not found
     */
    public int grantAdminRoleInternal(String grantee, String granteeTenant,
                                      String grantor, String grantorTenant) 
      throws TapisImplException, TapisNotFoundException
    {
        // The tenant admin role.
        String desc = "Administrator role for tenant " + granteeTenant;
        return grantRoleInternal(ADMIN_ROLE_NAME, granteeTenant, desc,
        		                 grantee, granteeTenant, grantor, grantorTenant);
    }

    /* ---------------------------------------------------------------------- */
    /* grantRoleInternal:                                                     */
    /* ---------------------------------------------------------------------- */
    /** Grant the internal-use role to the user without checking whether the
     * requestor is also an administrator.  This method should only be used
     * by SK code, never by clients.
     * 
     * @param tenant the tenant id
     * @param requestor the caller's name
     * @param user the user being grant the role
     * @param roleName the role to be created
     * @param desc the role's description
     * @return the number of rows changed
     * @throws TapisImplException on error
     * @throws TapisNotFoundException if the role is not found
     */
    public int grantRoleInternal(String roleName, String roleTenant, String description,
    		                     String grantee, String granteeTenant,
    		                     String grantor, String grantorTenant)
      throws TapisImplException, TapisNotFoundException
    {
        // Get the dao.
        SkUserRoleDao userDao = null;
        try {userDao = getSkUserRoleDao();}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("DB_DAO_ERROR", "userRoles");
                _log.error(msg, e);
                throw new TapisImplException(e.getMessage(), e, Condition.INTERNAL_SERVER_ERROR); 
            }
        
        // Create and assign the role.
        boolean strict = false;
        int rows = 0;
        try {rows = userDao.createAndAssignRole(roleName, roleTenant, description, 
        		                                grantee, granteeTenant, 
        		                                grantor, grantorTenant, strict);}
            catch (Exception e) {
                // Interpret all errors as client request problems.
                throw new TapisImplException(e.getMessage(), Condition.BAD_REQUEST);
            }
        
        return rows;
    }

    /* ---------------------------------------------------------------------- */
    /* revokeAdminRole:                                                       */
    /* ---------------------------------------------------------------------- */
    /** Only admins can revoke admin privileges.  This method will not remove
     * the admin role from the last administrator.  The database calls made in
     * this method are in separate transactions, but that shouldn't lead to 
     * inconsistencies in practice.
     * 
     * @param tenant the tenant id
     * @param requestor the admin that is removing the role from user
     * @param user the user that will no longer be an admin
     * @return the number of rows affected (0 or 1)
     * @throws TapisImplException on error
     * @throws TapisNotFoundException if the role is not found
     */
    public int revokeAdminRole(String tenant, String requestor, String user) 
      throws TapisImplException, TapisNotFoundException
    {
        // Check inputs not checked by called routines.
        if (StringUtils.isBlank(requestor)) {
            String msg = MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "revokeAdminRole", "requestor");            
            _log.error(msg);
            throw new TapisImplException(msg, Condition.BAD_REQUEST);            
        }
        if (StringUtils.isBlank(user)) {
            String msg = MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "revokeAdminRole", "user");            
            _log.error(msg);
            throw new TapisImplException(msg, Condition.BAD_REQUEST);            
        }
        
        // The tenant admin role.
        final String roleName = ADMIN_ROLE_NAME;
        
        // Get all the users with the admin role.  Exceptions already logged.
        List<String> admins = getUsersWithRole(tenant, roleName);
        
        // Make sure the requestor is an admin.  Null checks are performed here.
        if (!admins.contains(requestor)) {
            String msg = MsgUtils.getMsg("SK_REQUESTOR_NOT_ADMIN", tenant, requestor);
            _log.error(msg);
            throw new TapisImplException(msg, Condition.BAD_REQUEST); 
        }
              
        // There's nothing to do if the user is not an admin.
        if (!admins.contains(user)) return 0;
        
        // Make sure we don't delete the last administrator (requestor could equal user).
        if (admins.size() < 2) {
            String msg = MsgUtils.getMsg("SK_REVOKE_LAST_ADMIN_ERROR", tenant, user);
            _log.error(msg);
            throw new TapisImplException(msg, Condition.BAD_REQUEST); 
        }

        // Get the role id.
        int roleId = 0;
        try {roleId = getRoleId(tenant, roleName);}
            catch (TapisNotFoundException e) {
                _log.error(e.getMessage());
                throw e;
            }
            catch (Exception e) {
                _log.error(e.getMessage());
                throw new TapisImplException(e.getMessage(), e, Condition.INTERNAL_SERVER_ERROR);            
            }

        // Get the dao.
        SkUserRoleDao dao = null;
        try {dao = getSkUserRoleDao();}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("DB_DAO_ERROR", "userRoles");
                _log.error(msg, e);
                throw new TapisImplException(msg, e, Condition.INTERNAL_SERVER_ERROR);
            }

        // Assign the role to the user.
        int rows = 0;
        try {rows = dao.removeUserRole(tenant, user, roleId);}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("SK_REMOVE_USER_ROLE_ERROR",  
                                             tenant, roleId, user, e.getMessage());
                _log.error(msg, e);
                throw new TapisImplException(msg, e, Condition.BAD_REQUEST);            
            }
        
        return rows;
    }
    
    /* ********************************************************************** */
    /*                             Private Methods                            */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------------- */
    /* matchPermission:                                                             */
    /* ---------------------------------------------------------------------------- */
    /** Perform the extended Shiro-base permission checking.  All permission checking
     * is case-sensitive.  Exceptions are logged and not rethrown. 
     * 
     * The caller may provide a map to use as a cache for permission objects.  A cache 
     * will reduce the number of objects created when this method is called with 
     * different reqPermStr's in a row, all using the same set of assignedPermStrs.
     * 
     * @param reqPermStr the spec to be matched on a user request
     * @param assignedPermStrs the user's assigned permissions
     * @param assignedPermMap the optional cache of permission strings to objects
     * @return true if permSpec matches one of the perms, false otherwise
     */
    private boolean matchPermission(String reqPermStr, List<String> assignedPermStrs,
                                    HashMap<String,ExtWildcardPermission> assignedPermMap)
    {
        // Create a case-sensitive request permission.
        ExtWildcardPermission reqPerm;
        try {reqPerm = new ExtWildcardPermission(reqPermStr, true);}
            catch (Exception e) {
                String msg = MsgUtils.getMsg("SK_PERM_CREATE_ERROR", reqPermStr,
                                             e.getMessage());            
                _log.error(msg, e);
                return false;
            }
        
        // See if any of the user's assigned permissions match the request spec.
        for (String curAssignedPermStr : assignedPermStrs) 
        {
            // Declare the current perm object.
            ExtWildcardPermission curAssignedPerm;
            
            // If caching is activated, determine if we've already created a 
            // perm object for this assigned perm string.
            try {
                if (assignedPermMap != null) {
                    curAssignedPerm = assignedPermMap.get(curAssignedPermStr);
                    if (curAssignedPerm == null) {
                        // Create and cache the perm object.
                        curAssignedPerm = new ExtWildcardPermission(curAssignedPermStr, true);
                        assignedPermMap.put(curAssignedPermStr, curAssignedPerm);
                    }
                }
                else curAssignedPerm = new ExtWildcardPermission(curAssignedPermStr, true);
            }
            catch (Exception e) {
                String msg = MsgUtils.getMsg("SK_PERM_CREATE_ERROR", curAssignedPermStr,
                                             e.getMessage());            
                _log.error(msg, e);
                continue;
            }
            
            // Check the request permission and return as soon 
            // as we find a match. Runtime exceptions can be thrown.
            try {if (curAssignedPerm.implies(reqPerm)) return true;}
                catch (Exception e) {
                    // Just log the exception.
                    String msg = MsgUtils.getMsg("SK_PERM_MATCH_ERROR", curAssignedPermStr,
                                                 reqPermStr, e.getMessage());            
                    _log.error(msg, e);
                }
        }
        
        // No match if we get here.
        return false;
    }
    
    /* ---------------------------------------------------------------------------- */
    /* filterImpliesPermissions:                                                    */
    /* ---------------------------------------------------------------------------- */
    /** Remove permissions from the list that are not implied by the implies 
     * permission parameter.  The result is a possibly altered permissions list.
     * 
     * @param perms List of permissions to be filtered
     * @param implies a permission string that implies each entry in the final perms list
     */
    private void filterImpliesPermissions(List<String> perms, String implies)
    {
        // Is there anything to do?
        if (perms.isEmpty()) return;
        
        // Put the match filter in a list.
        var impliesList = new ArrayList<String>(1);
        impliesList.add(implies);
        
        // Create a permission cache that allows us to allocate at most
        // one wildcard object for the match permission.  The cache
        // is only useful if more than 1 permission might get tested.
        HashMap<String,ExtWildcardPermission> impliesPermMap;
        if (perms.size() > 1) impliesPermMap = new HashMap<>(3);
          else impliesPermMap = null;
        
        // Iterate through the list removing permissions that don't match.
        var it = perms.listIterator();
        while (it.hasNext()) {
            String curPerm = it.next();
            if (!matchPermission(curPerm, impliesList, impliesPermMap)) it.remove();
        }
    }
    
    /* ---------------------------------------------------------------------------- */
    /* filterImpliedByPermissions:                                                  */
    /* ---------------------------------------------------------------------------- */
    /** Remove permissions from the list that don't imply the impliedBy permission
     * parameter.  The result is a possibly altered permissions list.  
     * 
     * Note that no caching of permission objects occurs on this path. If this becomes
     * a problem, we should only create the impliedBy permission object once. 
     * 
     * @param perms List of permissions to be filtered
     * @param impliedBy a permission string that is implied by each entry in the final perms list
     */
    private void filterImpliedByPermissions(List<String> perms, String impliedBy)
    {
        // Is there anything to do?
        if (perms.isEmpty()) return;
        
        // For each permission in the perms list, see if it implies 
        // the impliedBy permission parameter.
        var impliesList = new ArrayList<String>(1);  
        var it = perms.listIterator();
        while (it.hasNext()) {
            String curPerm = it.next();
            impliesList.clear();
            impliesList.add(curPerm);
            if (!matchPermission(impliedBy, impliesList, null)) it.remove();
        }
    }
}
