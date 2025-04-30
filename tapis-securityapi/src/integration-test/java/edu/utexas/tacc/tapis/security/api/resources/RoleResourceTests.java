package edu.utexas.tacc.tapis.security.api.resources;

import edu.utexas.tacc.tapis.security.authz.dao.SkRoleDao;
import edu.utexas.tacc.tapis.security.authz.model.SkRole;
import edu.utexas.tacc.tapis.security.authz.model.SkRoleDescriptor;
import edu.utexas.tacc.tapis.security.authz.model.SkRoleType;
import edu.utexas.tacc.tapis.shared.utils.TapisGsonUtils;
import edu.utexas.tacc.tapis.sharedapi.responses.RespNameArray;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.ws.rs.core.Response;
import java.util.Arrays;
import java.util.UUID;
import java.util.function.Predicate;

@Test
public class RoleResourceTests {

    private SkRoleDao roleDao;

    private static final String userToken = IntegrationTestUtils.getTokenForUser(IntegrationTestUtils.TEST_USER_1, IntegrationTestUtils.TEST_TENANT_1);
    private static final String tenantAdminToken = IntegrationTestUtils.getTokenForUser(IntegrationTestUtils.TEST_TENANT_ADMIN_USER, IntegrationTestUtils.TEST_TENANT_1);
    private static final String siteAdminToken = IntegrationTestUtils.getTokenForUser(IntegrationTestUtils.TEST_SITE_ADMIN_USER, IntegrationTestUtils.TEST_ADMIN_TENANT);

    @BeforeClass
    public void beforeClass() throws Exception {
        roleDao = new SkRoleDao();
        RoleResourceTestUtils.cleanupAllTestRoles(new SkRoleDao(), IntegrationTestUtils.TEST_TENANT_1, SkRoleType.ALL_TYPES);
        RoleResourceTestUtils.cleanupAllTestRoles(new SkRoleDao(), IntegrationTestUtils.TEST_TENANT_2, SkRoleType.ALL_TYPES);
    }

    @Test
    public void testCreateRole() throws Exception {
        // try as a regular user
        doTestCreateRole(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, 401);
        doTestCreateRole(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER_DEFAULT, 401);
        doTestCreateRole(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.RESTRICTED_SVC, 401);
        doTestCreateRole(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.TENANT_ADMIN, 401);
        doTestCreateRole(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.SITE_ADMIN, 401);

        // try as a tenant admin user - same Tenant
        doTestCreateRole(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, 201);
        doTestCreateRole(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER_DEFAULT, 401);
        doTestCreateRole(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.RESTRICTED_SVC, 401);
        doTestCreateRole(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.TENANT_ADMIN, 401);
        doTestCreateRole(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.SITE_ADMIN, 401);

        // try as a tenant admin user - different Tenant
        doTestCreateRole(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.USER, 400);
        doTestCreateRole(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.USER_DEFAULT, 400);
        doTestCreateRole(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.RESTRICTED_SVC, 400);
        doTestCreateRole(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.TENANT_ADMIN, 400);
        doTestCreateRole(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.SITE_ADMIN, 400);

        // try as a site admin user - same Tenant
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, 201);
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER_DEFAULT, 201);
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.RESTRICTED_SVC, 201);
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.TENANT_ADMIN, 201);
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.SITE_ADMIN, 201);

        // try as a site admin user - different Tenant
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.USER, 201);
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.USER_DEFAULT, 201);
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.RESTRICTED_SVC, 201);
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.TENANT_ADMIN, 201);
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.SITE_ADMIN, 201);
    }

    private void doTestCreateRole(String token, String roleTenant, SkRoleType roleType, int expectedResult) throws Exception {
        // Create the role with a random name
        String roleName = RoleResourceTestUtils.createRandomRoleName();
        Response response = RoleResourceTestUtils.createRole(token, roleTenant, roleType, roleName, "Integration Test Role");

        // verify that the response
        Assert.assertEquals(response.getStatus(), expectedResult);
        SkRoleDescriptor roleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(roleName, roleType);

        // verify that the role was really created (or not created)
        SkRole role = roleDao.getRole(roleTenant, roleDescriptor);
        if((expectedResult >= 200) && (expectedResult < 300)) {
            Assert.assertNotNull(role);
            Assert.assertEquals(role.getType(), roleType);
            Assert.assertEquals(role.getName(), roleDescriptor.getRoleFullName());
        } else {
            Assert.assertNull(role);
        }
    }

    @Test
    public void testAddChildRole() throws Exception {
        // regular user - owns both roles
        doTestAddChildRole(userToken, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_1, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_1, IntegrationTestUtils.TEST_TENANT_1, 200);

        // regular user - owns parent role but not child
        doTestAddChildRole(userToken, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_1, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_2, IntegrationTestUtils.TEST_TENANT_1, 401);

        // regular user - owns child role but not parent
        doTestAddChildRole(userToken, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_2, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_1, IntegrationTestUtils.TEST_TENANT_1, 401);

        // regular user - doesnt own either role
        doTestAddChildRole(userToken, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_2, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_2, IntegrationTestUtils.TEST_TENANT_1, 401);

        // tenant admin user - owns both roles
        doTestAddChildRole(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_TENANT_ADMIN_USER, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_TENANT_ADMIN_USER, IntegrationTestUtils.TEST_TENANT_1, 200);

        // tenant admin user - owns parent role but not child
        doTestAddChildRole(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_TENANT_ADMIN_USER, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_1, IntegrationTestUtils.TEST_TENANT_1, 200);

        // tenant admin user - owns child role but not parent
        doTestAddChildRole(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_2, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_TENANT_ADMIN_USER, IntegrationTestUtils.TEST_TENANT_1, 200);

        // tenant admin user - doesnt own either role
        doTestAddChildRole(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_1, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_1, IntegrationTestUtils.TEST_TENANT_1, 200);
/*

// site admin can't really do these things - the issue is that the tenant is taken from the jwt token, and for site admin, that's the primary site admin tenant
        // site admin user - both roles owned by same user
        doTestAddChildRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_1, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_1, IntegrationTestUtils.TEST_TENANT_1, 200);

        // site admin user - roles owned by different user
        doTestAddChildRole(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_2, IntegrationTestUtils.TEST_TENANT_1,
                IntegrationTestUtils.TEST_USER_1, IntegrationTestUtils.TEST_TENANT_1, 200);
 */
    }

    private void doTestAddChildRole(String token, String tokenTenant,
                                          String parentRoleOwner, String parentRoleTenant,
                                          String childRoleOwner, String childRoleTenant,
                                          int expectedResult) throws Exception {

        // create a parent role
        String parentRoleName = createRole(parentRoleTenant, SkRoleType.USER, parentRoleOwner);

        // create a child role
        String childRoleName = createRole(childRoleTenant, SkRoleType.USER, childRoleOwner);

        Response response = RoleResourceTestUtils.addChildRole(token, tokenTenant, parentRoleName, childRoleName);
        Assert.assertEquals(response.getStatus(), expectedResult);

        // verify that the role was really added
        if((expectedResult >= 200) && (expectedResult < 300)) {
            SkRoleDescriptor parentRoleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(parentRoleName, SkRoleType.USER);
            SkRoleDescriptor childRoleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(childRoleName, SkRoleType.USER);
            SkRole parentRole = roleDao.getRole(tokenTenant, parentRoleDescriptor);
            SkRole childRole = roleDao.getRole(tokenTenant, childRoleDescriptor);
            Assert.assertNotNull(parentRole);
            Assert.assertNotNull(childRole);
            Assert.assertTrue(parentRole.hasChildren());
            Assert.assertTrue(childRole.getAncestorRoleNames().contains(parentRoleName));
            Assert.assertTrue(parentRole.getDescendantRoleNames().contains(childRoleName));
        }

    }

    @Test
    public void testAddRolePermissions() throws Exception {
        doTestAddAndRetrieveRolePermissions(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
        doTestAddAndRetrieveRolePermissions(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_2, 401);
        doTestAddAndRetrieveRolePermissions(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER_DEFAULT, IntegrationTestUtils.TEST_USER_1, 401);
        doTestAddAndRetrieveRolePermissions(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER_DEFAULT, IntegrationTestUtils.TEST_USER_2, 401);

        doTestAddAndRetrieveRolePermissions(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_TENANT_ADMIN_USER, 200);
        doTestAddAndRetrieveRolePermissions(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
//        doTestAddAndRetrieveRolePermissions(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER_DEFAULT, IntegrationTestUtils.TEST_TENANT_ADMIN_USER, 200);
//        doTestAddAndRetrieveRolePermissions(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER_DEFAULT, IntegrationTestUtils.TEST_USER_1, 200);

        doTestAddAndRetrieveRolePermissions(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
        doTestAddAndRetrieveRolePermissions(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_SITE_ADMIN_USER, 200);
//        doTestAddAndRetrieveRolePermissions(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER_DEFAULT, IntegrationTestUtils.TEST_USER_1, 200);
//        doTestAddAndRetrieveRolePermissions(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER_DEFAULT, IntegrationTestUtils.TEST_SITE_ADMIN_USER, 200);
    }

    private void doTestAddAndRetrieveRolePermissions(String token, String roleTenant, SkRoleType roleType, String roleOwner, int expectedResult) throws Exception {
        // crate a role
        String roleName = createRole(roleTenant, roleType, roleOwner);
        String permSpec1 = "integration.test1";
        String permSpec2 = "integration.test2";
        String permSpec3 = "integration.test1,test2";

        // add permissions
        Response response = RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleName, permSpec1);
        Assert.assertEquals(response.getStatus(), expectedResult);

        if((expectedResult >= 200) && (expectedResult < 300)) {
            // get role, and make sure it's correct
            response = RoleResourceTestUtils.getRolePermissions(token, roleTenant, SkRoleType.USER, roleName, true);
            Assert.assertEquals(response.getStatus(), 200);
            String jsonString = response.readEntity(String.class);
            RespNameArray nameArray = TapisGsonUtils.getGson().fromJson(jsonString, RespNameArray.class);
            Assert.assertNotNull(nameArray);
            Assert.assertListContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec1), "Permission " + permSpec1 + " not found for role " + roleName);
            Assert.assertListNotContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec2), "Permission " + permSpec3 + " not found for role " + roleName);
            Assert.assertListNotContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec3), "Permission " + permSpec3 + " not found for role " + roleName);

            // add permissions
            response = RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleName, permSpec2);
            Assert.assertEquals(response.getStatus(), expectedResult);
            // get role, and make sure it's correct
            response = RoleResourceTestUtils.getRolePermissions(token, roleTenant, SkRoleType.USER, roleName, true);
            Assert.assertEquals(response.getStatus(), 200);
            jsonString = response.readEntity(String.class);
            nameArray = TapisGsonUtils.getGson().fromJson(jsonString, RespNameArray.class);
            Assert.assertNotNull(nameArray);

            Assert.assertListContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec1), "Permission " + permSpec1 + " not found for role " + roleName);
            Assert.assertListContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec2), "Permission " + permSpec2 + " not found for role " + roleName);
            Assert.assertListNotContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec3), "Permission " + permSpec3 + " not found for role " + roleName);

            // add permissions
            response = RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleName, permSpec3);
            Assert.assertEquals(response.getStatus(), expectedResult);

            // get role, and make sure it's correct
            response = RoleResourceTestUtils.getRolePermissions(token, roleTenant, SkRoleType.USER, roleName, true);
            Assert.assertEquals(response.getStatus(), 200);
            jsonString = response.readEntity(String.class);
            nameArray = TapisGsonUtils.getGson().fromJson(jsonString, RespNameArray.class);
            Assert.assertNotNull(nameArray);

            Assert.assertListContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec1), "Permission " + permSpec1 + " not found for role " + roleName);
            Assert.assertListContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec2), "Permission " + permSpec2 + " not found for role " + roleName);
            Assert.assertListContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec3), "Permission " + permSpec3 + " not found for role " + roleName);
        } else {
            // get role, and make sure it's correct
            response = RoleResourceTestUtils.getRolePermissions(token, roleTenant, roleType, roleName, true);
            Assert.assertEquals(response.getStatus(), 200);
            String jsonString = response.readEntity(String.class);
            RespNameArray nameArray = TapisGsonUtils.getGson().fromJson(jsonString, RespNameArray.class);
            Assert.assertNotNull(nameArray);
            Assert.assertListNotContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec1), "Permission " + permSpec1 + " not found for role " + roleName);
            Assert.assertListNotContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec2), "Permission " + permSpec3 + " not found for role " + roleName);
            Assert.assertListNotContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec3), "Permission " + permSpec3 + " not found for role " + roleName);
        }
    }

    @Test
    public void testGetRoleByName() {

    }

    private void doTestGetRoleByName() {
//        String roleName = createRole(roleTenant, roleType, roleOwner)
    }

    private String createRole(String roleTenant, SkRoleType roleType, String roleOwner) throws Exception {
        String roleName = RoleResourceTestUtils.createRandomRoleName();
        Response response = RoleResourceTestUtils.createRole(siteAdminToken , roleTenant, roleType, roleName, "Integration Test Role");
        Assert.assertEquals(response.getStatus(), 201, "Create parent role failed");
        response = RoleResourceTestUtils.updateOwner(siteAdminToken, roleTenant, roleType, roleName, roleTenant, roleOwner);
        Assert.assertEquals(response.getStatus(), 200);
        SkRoleDescriptor roleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(roleName, roleType);
        SkRole role = roleDao.getRole(roleTenant, roleDescriptor);
        Assert.assertEquals(role.getName(), roleDescriptor.getRoleFullName());
        Assert.assertEquals(role.getType(), roleDescriptor.getRoleType());
        Assert.assertEquals(role.getOwner(), roleOwner);
        return roleName;
    }

}
