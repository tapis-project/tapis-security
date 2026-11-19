package edu.utexas.tacc.tapis.security.authz.permissions;

import java.util.List;
import java.util.Set;

import edu.utexas.tacc.tapis.security.authz.model.SkRoleType;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;

import edu.utexas.tacc.tapis.security.authz.impl.RoleImpl;
import edu.utexas.tacc.tapis.security.authz.impl.UserImpl;
import edu.utexas.tacc.tapis.shared.exceptions.TapisImplException;
import edu.utexas.tacc.tapis.shared.exceptions.TapisNotFoundException;

@Test(groups={"integration"})
public class UserPermsTest 
{
    // Fields.
    private UserImpl _userImpl;
    private RoleImpl _roleImpl;
    
    /* ---------------------------------------------------------------------- */
    /* setup:                                                                 */
    /* ---------------------------------------------------------------------- */
    @BeforeSuite
    public void setup()
    {
        // Disable vault so we only test the db login.
        System.setProperty("tapis.sk.vault.disable", "true");
        
        // Access requires a database connection.
        _userImpl = UserImpl.getInstance();
        _roleImpl = RoleImpl.getInstance();
    }
    
//    public int grantUserPermission(String tenant, String requestor, 
//            String user, String permSpec)
    
//    public int grantUserPermission(String grantee, String granteeTenant, String permSpec, 
//            String grantor, String grantorTenant)
    /* ---------------------------------------------------------------------- */
    /* permsTest:                                                             */
    /* ---------------------------------------------------------------------- */
    public void permsTest() throws TapisImplException, TapisNotFoundException
    {
        // Add a bunch of permissions to user bobby.
        _userImpl.grantUserPermission("bobby", "dev", "stream:dev:read:project1", "admin", "dev");
        _userImpl.grantUserPermission("bobby", "dev", "stream:dev:read,write:project1", "admin", "dev");
        _userImpl.grantUserPermission("bobby", "dev", "stream:dev:read,write,exec:project1", "admin", "dev");
        
        // List all of bobby's permissions.
        List<String> perms = _userImpl.getUserPerms("dev", "bobby", Set.of(SkRoleType.USER, SkRoleType.USER_DEFAULT), null, null);
        System.out.println("All permissions:");
        for (String perm : perms) System.out.println("    " + perm);
        
        // List a subset of bobby's permissions.
        perms = _userImpl.getUserPerms("dev", "bobby", Set.of(SkRoleType.USER, SkRoleType.USER_DEFAULT), "stream:dev:*:project1", null);
        System.out.println("\n\"stream:dev:*:project1\" IMPLIES:");
        for (String perm : perms) System.out.println("    " + perm);
        
        // List a subset of bobby's permissions.
        perms = _userImpl.getUserPerms("dev", "bobby", Set.of(SkRoleType.USER, SkRoleType.USER_DEFAULT), "stream:dev:write:project1", null);
        System.out.println("\n\"stream:dev:write:project1\" IMPLIES:");
        for (String perm : perms) System.out.println("    " + perm);
        
        // List a subset of bobby's permissions.
        perms = _userImpl.getUserPerms("dev", "bobby", Set.of(SkRoleType.USER, SkRoleType.USER_DEFAULT), null, "stream:dev:*:project1");
        System.out.println("\n\"stream:dev:*:project1\" IMPLIED BY:");
        for (String perm : perms) System.out.println("    " + perm);
        
        // List a subset of bobby's permissions.
        perms = _userImpl.getUserPerms("dev", "bobby", Set.of(SkRoleType.USER, SkRoleType.USER_DEFAULT), null, "stream:dev:write:project1");
        System.out.println("\n\"stream:dev:write:project1\" IMPLIED BY:");
        for (String perm : perms) System.out.println("    " + perm);

        // Optional clean up.
//        _roleImpl.removeRolePermission("dev", "$$bobby", "stream:dev:read:project1");
//        _roleImpl.removeRolePermission("dev", "$$bobby", "stream:dev:read,write:project1");
//        _roleImpl.removeRolePermission("dev", "$$bobby", "stream:dev:read,write,exec:project1");
    }
}
