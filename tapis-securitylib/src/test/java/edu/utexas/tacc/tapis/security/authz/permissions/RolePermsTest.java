package edu.utexas.tacc.tapis.security.authz.permissions;

import edu.utexas.tacc.tapis.security.authz.impl.RoleImpl;
import edu.utexas.tacc.tapis.security.authz.impl.UserImpl;
import edu.utexas.tacc.tapis.security.authz.model.SkRoleDescriptor;
import edu.utexas.tacc.tapis.security.authz.model.SkRoleType;
import edu.utexas.tacc.tapis.shared.exceptions.TapisImplException;
import org.testng.Assert;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;

import java.util.List;
import java.util.UUID;
import java.util.function.Predicate;

@Test(groups={"integration"})
public class RolePermsTest {
    private UserImpl _userImpl;
    private RoleImpl _roleImpl;

    private static final String TEST_TENANT = "TestTenant";
    private static final String TEST_USER = "TestUser";
    private static final String TEST_USER_ROLE_NAME = "TestUserRoleName";
    private static final SkRoleDescriptor TEST_USER_ROLE_DESCRIPTOR;
    private static final String TEST_USER_DEFAULT_ROLE_NAME = "TestUserDefaultRoleName";
    private static final SkRoleDescriptor TEST_USER_DEFAULT_ROLE_DESCRIPTOR;
    private static final String TEST_RESTRICTED_SERVICE_ROLE_NAME = "TestRestrictedServiceRoleName";
    private static final SkRoleDescriptor TEST_RESTRICTED_SERVICE_ROLE_DESCRIPTOR;
    private static final String TEST_SITE_ADMIN_ROLE_NAME = "TestSiteAdminRoleName";
    private static final SkRoleDescriptor TEST_SITE_ADMIN_ROLE_DESCRIPTOR;
    private static final String TEST_TENANT_ADMIN_ROLE_NAME = "TestTenantAdminRoleName";
    private static final SkRoleDescriptor TEST_TENANT_ADMIN_ROLE_DESCRIPTOR;

    static {
        TEST_USER_ROLE_DESCRIPTOR = SkRoleDescriptor.newSkRoleDescriptor(TEST_USER_ROLE_NAME, SkRoleType.USER);
        TEST_USER_DEFAULT_ROLE_DESCRIPTOR = SkRoleDescriptor.newSkRoleDescriptor(TEST_USER_DEFAULT_ROLE_NAME, SkRoleType.USER_DEFAULT);
        TEST_RESTRICTED_SERVICE_ROLE_DESCRIPTOR = SkRoleDescriptor.newSkRoleDescriptor(TEST_RESTRICTED_SERVICE_ROLE_NAME, SkRoleType.RESTRICTED_SVC);
        TEST_SITE_ADMIN_ROLE_DESCRIPTOR = SkRoleDescriptor.newSkRoleDescriptor(TEST_SITE_ADMIN_ROLE_NAME, SkRoleType.SITE_ADMIN);
        TEST_TENANT_ADMIN_ROLE_DESCRIPTOR = SkRoleDescriptor.newSkRoleDescriptor(TEST_TENANT_ADMIN_ROLE_NAME, SkRoleType.TENANT_ADMIN);
    };

    @BeforeSuite
    public void setup() throws Exception {
        // Disable vault so we only test the db login.
        System.setProperty("tapis.sk.vault.disable", "true");

        // Access requires a database connection.
        _userImpl = UserImpl.getInstance();
        _roleImpl = RoleImpl.getInstance();
    }

    public void addPermsUserTest() throws Exception {
        // role may or may not exist - create then verifiy
        _roleImpl.createRole(TEST_USER_ROLE_DESCRIPTOR,
                TEST_TENANT, "Test Role", TEST_USER, TEST_TENANT);
        var user_role = _roleImpl.getRoleByName(TEST_TENANT, TEST_USER_ROLE_DESCRIPTOR);
        Assert.assertNotNull(user_role);

        String user_permission = UUID.randomUUID().toString();
        Assert.assertEquals(_roleImpl.addRolePermission(TEST_TENANT, TEST_USER_ROLE_DESCRIPTOR, user_permission, TEST_USER, TEST_TENANT), 1);
        List<String> perms = _roleImpl.getRolePermissions(TEST_TENANT, TEST_USER_ROLE_DESCRIPTOR, true);
        Assert.assertListContains(perms, Predicate.isEqual(user_permission), "List should contain the new permission");
    }

    public void addPermsSiteAdminTest() throws Exception {
        // role may or may not exist - create then verifiy
        _roleImpl.createRole(TEST_SITE_ADMIN_ROLE_DESCRIPTOR,
                TEST_TENANT, "Test Role", TEST_USER, TEST_TENANT);
        var site_admin_role = _roleImpl.getRoleByName(TEST_TENANT, TEST_SITE_ADMIN_ROLE_DESCRIPTOR);
        Assert.assertNotNull(site_admin_role);

        String site_admin_permission = UUID.randomUUID().toString();
        Assert.assertEquals(_roleImpl.addRolePermission(TEST_TENANT, TEST_SITE_ADMIN_ROLE_DESCRIPTOR, site_admin_permission, TEST_USER, TEST_TENANT), 1);
        List<String> perms = _roleImpl.getRolePermissions(TEST_TENANT, TEST_SITE_ADMIN_ROLE_DESCRIPTOR, true);
        Assert.assertListContains(perms, Predicate.isEqual(site_admin_permission), "List should contain the new permission");
    }

    public void addPermsUserDefaultTest() throws Exception {
        // role may or may not exist - create then verifiy
        _roleImpl.createRole(TEST_USER_DEFAULT_ROLE_DESCRIPTOR,
                TEST_TENANT, "Test Role", TEST_USER, TEST_TENANT);
        var user_default_role = _roleImpl.getRoleByName(TEST_TENANT, TEST_USER_DEFAULT_ROLE_DESCRIPTOR);
        Assert.assertNotNull(user_default_role);

        String user_default_permission = UUID.randomUUID().toString();
        Assert.assertEquals(_roleImpl.addRolePermission(TEST_TENANT, TEST_USER_DEFAULT_ROLE_DESCRIPTOR, user_default_permission, TEST_USER, TEST_TENANT), 1);
        List<String> perms = _roleImpl.getRolePermissions(TEST_TENANT, TEST_USER_DEFAULT_ROLE_DESCRIPTOR, true);
        Assert.assertListContains(perms, Predicate.isEqual(user_default_permission), "List should contain the new permission");
    }

    public void addPermsRestrictedServiceTest() throws Exception {
        // role may or may not exist - create then verifiy
        _roleImpl.createRole(TEST_RESTRICTED_SERVICE_ROLE_DESCRIPTOR,
                TEST_TENANT, "Test Role", TEST_USER, TEST_TENANT);
        var restricted_service_role = _roleImpl.getRoleByName(TEST_TENANT, TEST_RESTRICTED_SERVICE_ROLE_DESCRIPTOR);
        Assert.assertNotNull(restricted_service_role);

        String restricted_service_permission = UUID.randomUUID().toString();
        Assert.assertEquals(_roleImpl.addRolePermission(TEST_TENANT, TEST_RESTRICTED_SERVICE_ROLE_DESCRIPTOR, restricted_service_permission, TEST_USER, TEST_TENANT), 1);
        List<String> perms = _roleImpl.getRolePermissions(TEST_TENANT, TEST_RESTRICTED_SERVICE_ROLE_DESCRIPTOR, true);
        Assert.assertListContains(perms, Predicate.isEqual(restricted_service_permission), "List should contain the new permission");
    }

    @Test(expectedExceptions = TapisImplException.class, expectedExceptionsMessageRegExp = "Cannot add role permissions for tenant admin roles")
    public void addPermsTenantAdminTest() throws Exception {
        // role may or may not exist - create then verifiy
        _roleImpl.createRole(TEST_TENANT_ADMIN_ROLE_DESCRIPTOR,
                TEST_TENANT, "Test Role", TEST_USER, TEST_TENANT);
        var tenant_admin_role = _roleImpl.getRoleByName(TEST_TENANT, TEST_TENANT_ADMIN_ROLE_DESCRIPTOR);
        Assert.assertNotNull(tenant_admin_role);

        String tenant_admin_permission = UUID.randomUUID().toString();
        Assert.assertEquals(_roleImpl.addRolePermission(TEST_TENANT, TEST_TENANT_ADMIN_ROLE_DESCRIPTOR, tenant_admin_permission, TEST_USER, TEST_TENANT), 1);
        List<String> perms = _roleImpl.getRolePermissions(TEST_TENANT, TEST_TENANT_ADMIN_ROLE_DESCRIPTOR, true);
        Assert.assertListContains(perms, Predicate.isEqual(tenant_admin_permission), "List should contain the new permission");
    }
}
