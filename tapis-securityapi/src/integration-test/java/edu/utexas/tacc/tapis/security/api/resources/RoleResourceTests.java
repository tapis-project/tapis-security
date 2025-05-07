package edu.utexas.tacc.tapis.security.api.resources;

import edu.utexas.tacc.tapis.security.api.responses.RespPathPrefixes;
import edu.utexas.tacc.tapis.security.api.responses.RespRole;
import edu.utexas.tacc.tapis.security.authz.dao.SkRoleDao;
import edu.utexas.tacc.tapis.security.authz.model.SkRole;
import edu.utexas.tacc.tapis.security.authz.model.SkRoleDescriptor;
import edu.utexas.tacc.tapis.security.authz.model.SkRoleType;
import edu.utexas.tacc.tapis.security.authz.permissions.PermissionTransformer;
import edu.utexas.tacc.tapis.shared.utils.SkConstants;
import edu.utexas.tacc.tapis.shared.utils.TapisGsonUtils;
import edu.utexas.tacc.tapis.sharedapi.responses.RespChangeCount;
import edu.utexas.tacc.tapis.sharedapi.responses.RespNameArray;
import edu.utexas.tacc.tapis.sharedapi.responses.results.ResultChangeCount;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
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

    @BeforeTest
    public void beforeTest() throws Exception {
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
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.TENANT_ADMIN, 401);
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.SITE_ADMIN, 401);

        // try as a site admin user - different Tenant
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.USER, 201);
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.USER_DEFAULT, 201);
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.RESTRICTED_SVC, 201);
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.TENANT_ADMIN, 401);
        doTestCreateRole(siteAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.SITE_ADMIN, 401);
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
        doTestAddAndRetrieveRolePermissions(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER_DEFAULT, IntegrationTestUtils.TEST_USER_SK, 401);

        doTestAddAndRetrieveRolePermissions(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_TENANT_ADMIN_USER, 200);
        doTestAddAndRetrieveRolePermissions(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
        doTestAddAndRetrieveRolePermissions(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER_DEFAULT, IntegrationTestUtils.TEST_USER_SK, 401);

        doTestAddAndRetrieveRolePermissions(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
        doTestAddAndRetrieveRolePermissions(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_SITE_ADMIN_USER, 200);
        doTestAddAndRetrieveRolePermissions(siteAdminToken, IntegrationTestUtils.TEST_ADMIN_TENANT, SkRoleType.RESTRICTED_SVC, IntegrationTestUtils.TEST_SITE_ADMIN_USER, 200);
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
        Response response = RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName, permSpec1);
        Assert.assertEquals(response.getStatus(), expectedResult);

        if((expectedResult >= 200) && (expectedResult < 300)) {
            // get role, and make sure it's correct
            response = RoleResourceTestUtils.getRolePermissions(token, roleTenant, roleType, roleName, true);
            Assert.assertEquals(response.getStatus(), 200);
            String jsonString = response.readEntity(String.class);
            RespNameArray nameArray = TapisGsonUtils.getGson().fromJson(jsonString, RespNameArray.class);
            Assert.assertNotNull(nameArray);
            Assert.assertListContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec1), "Permission " + permSpec1 + " not found for role " + roleName);
            Assert.assertListNotContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec2), "Permission " + permSpec3 + " not found for role " + roleName);
            Assert.assertListNotContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec3), "Permission " + permSpec3 + " not found for role " + roleName);

            // add permissions
            response = RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName, permSpec2);
            Assert.assertEquals(response.getStatus(), expectedResult);
            // get role, and make sure it's correct
            response = RoleResourceTestUtils.getRolePermissions(token, roleTenant, roleType, roleName, true);
            Assert.assertEquals(response.getStatus(), 200);
            jsonString = response.readEntity(String.class);
            nameArray = TapisGsonUtils.getGson().fromJson(jsonString, RespNameArray.class);
            Assert.assertNotNull(nameArray);

            Assert.assertListContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec1), "Permission " + permSpec1 + " not found for role " + roleName);
            Assert.assertListContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec2), "Permission " + permSpec2 + " not found for role " + roleName);
            Assert.assertListNotContains(Arrays.asList(nameArray.result.names), Predicate.isEqual(permSpec3), "Permission " + permSpec3 + " not found for role " + roleName);

            // add permissions
            response = RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName, permSpec3);
            Assert.assertEquals(response.getStatus(), expectedResult);

            // get role, and make sure it's correct
            response = RoleResourceTestUtils.getRolePermissions(token, roleTenant, roleType, roleName, true);
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
    public void testGetRoleByName() throws Exception {
        String userRoleName_1 = createRole(IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1);
        String userRoleName_2 = createRole(IntegrationTestUtils.TEST_TENANT_2, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1);
        String userDefaultRoleName_1 = createRole(IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER_DEFAULT, IntegrationTestUtils.TEST_USER_1);
        String restrictedServiceRoleName_1 = createRole(IntegrationTestUtils.TEST_TENANT_1, SkRoleType.RESTRICTED_SVC, IntegrationTestUtils.TEST_USER_1);

        doTestGetRoleByName(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, userRoleName_1, 200);
        doTestGetRoleByName(userToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.USER, userRoleName_2, 400);
        doTestGetRoleByName(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER_DEFAULT, userDefaultRoleName_1, 200);
        doTestGetRoleByName(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.TENANT_ADMIN, SkConstants.ADMIN_ROLE_NAME, 401);
        doTestGetRoleByName(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.RESTRICTED_SVC, restrictedServiceRoleName_1, 200);
        doTestGetRoleByName(userToken, IntegrationTestUtils.TEST_ADMIN_TENANT, SkRoleType.SITE_ADMIN, SkConstants.SK_PRIMARY_SITE_ADMIN_ROLE, 400);

        doTestGetRoleByName(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, userRoleName_1, 200);
        doTestGetRoleByName(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.USER, userRoleName_2, 400);
        doTestGetRoleByName(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER_DEFAULT, userDefaultRoleName_1, 200);
        doTestGetRoleByName(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.TENANT_ADMIN, SkConstants.ADMIN_ROLE_NAME, 401);
        doTestGetRoleByName(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.RESTRICTED_SVC, restrictedServiceRoleName_1, 200);
        doTestGetRoleByName(tenantAdminToken, IntegrationTestUtils.TEST_ADMIN_TENANT, SkRoleType.SITE_ADMIN, SkConstants.SK_PRIMARY_SITE_ADMIN_ROLE, 400);

        doTestGetRoleByName(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, userRoleName_1, 200);
        doTestGetRoleByName(siteAdminToken, IntegrationTestUtils.TEST_TENANT_2, SkRoleType.USER, userRoleName_2, 200);
        doTestGetRoleByName(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER_DEFAULT, userDefaultRoleName_1, 200);
        doTestGetRoleByName(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.TENANT_ADMIN, SkRoleType.getRoleShortName(SkConstants.ADMIN_ROLE_NAME), 200);
        doTestGetRoleByName(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.RESTRICTED_SVC, restrictedServiceRoleName_1, 200);
        doTestGetRoleByName(siteAdminToken, IntegrationTestUtils.TEST_ADMIN_TENANT, SkRoleType.SITE_ADMIN, SkRoleType.getRoleShortName(SkConstants.SK_PRIMARY_SITE_ADMIN_ROLE), 200);
    }

    private void  doTestGetRoleByName(String token, String tenant, SkRoleType roleType, String roleName, int expectedResult) throws Exception {
        Response response = RoleResourceTestUtils.getRoleByName(token, tenant, roleType, roleName);
        Assert.assertEquals(response.getStatus(), expectedResult);

        String jsonString = response.readEntity(String.class);
        RespRole roleResponse = TapisGsonUtils.getGson().fromJson(jsonString, RespRole.class);
        SkRole role = roleResponse.result;


        if((expectedResult >= 200) && (expectedResult < 300)) {
            Assert.assertEquals(roleName, role.getName());
            Assert.assertEquals(roleType, role.getType());
        }
    }

    @Test
    public void testDeleteRoleByName() throws Exception {
        doTestDeleteRoleByName(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
        doTestDeleteRoleByName(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_2, 401);
        doTestDeleteRoleByName(userToken, IntegrationTestUtils.TEST_ADMIN_TENANT, SkRoleType.RESTRICTED_SVC, IntegrationTestUtils.TEST_USER_1, 400);
        doTestDeleteRoleByName(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.TENANT_ADMIN, null, 401);
        doTestDeleteRoleByName(userToken, IntegrationTestUtils.TEST_ADMIN_TENANT, SkRoleType.SITE_ADMIN, null, 400);

        doTestDeleteRoleByName(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
        doTestDeleteRoleByName(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_2, 200);
        doTestDeleteRoleByName(tenantAdminToken, IntegrationTestUtils.TEST_ADMIN_TENANT, SkRoleType.RESTRICTED_SVC, IntegrationTestUtils.TEST_USER_1, 400);
        doTestDeleteRoleByName(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.TENANT_ADMIN, null, 401);
        doTestDeleteRoleByName(tenantAdminToken, IntegrationTestUtils.TEST_ADMIN_TENANT, SkRoleType.SITE_ADMIN, null, 400);

        doTestDeleteRoleByName(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
        doTestDeleteRoleByName(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_2, 200);
        doTestDeleteRoleByName(siteAdminToken, IntegrationTestUtils.TEST_ADMIN_TENANT, SkRoleType.RESTRICTED_SVC, IntegrationTestUtils.TEST_USER_1, 200);
        doTestDeleteRoleByName(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.TENANT_ADMIN, null, 401);
        doTestDeleteRoleByName(siteAdminToken, IntegrationTestUtils.TEST_ADMIN_TENANT, SkRoleType.SITE_ADMIN, null, 401);

    }

    private void doTestDeleteRoleByName(String token, String roleTenant, SkRoleType roleType, String roleOwner, int expectedResult) throws Exception {
        // create roles to delete
        String roleName = null;
        switch (roleType) {
            case USER -> roleName = createRole(roleTenant, roleType, roleOwner);
            case USER_DEFAULT -> roleName = createRole(roleTenant, roleType, roleOwner);
            case RESTRICTED_SVC -> roleName = createRole(roleTenant, roleType, roleOwner);
            case TENANT_ADMIN -> roleName = SkConstants.ADMIN_ROLE_NAME;
            case SITE_ADMIN -> roleName = SkConstants.SK_PRIMARY_SITE_ADMIN_ROLE;
        }


        Response response = RoleResourceTestUtils.deleteRoleByName(token, roleTenant, roleType, roleName);
        Assert.assertEquals(response.getStatus(), expectedResult);

        String jsonString = response.readEntity(String.class);
        RespChangeCount rowCountResponse = TapisGsonUtils.getGson().fromJson(jsonString, RespChangeCount.class);
        ResultChangeCount changeCount = rowCountResponse.result;

        if((expectedResult >= 200) && (expectedResult < 300)) {
            Assert.assertEquals(1, changeCount.changes);
        }
    }

    @Test
    public void testPathPrefix() throws Exception {
        doTestPathPrefix(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, "files:dev:READ:system_a:/home/user_a",
                "files", "system_a", "system_a", "/home/user_a", "/home/user_b", 200, 401, "files:dev:READ:system_a:/home/user_b");
        doTestPathPrefix(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, "files:dev:READ:system_a:/home/user_a",
                "files", "system_a", "system_a", "/home/user_a", "/home/user_b", 200, 200, "files:dev:READ:system_a:/home/user_b");
        doTestPathPrefix(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, "files:dev:READ:system_a:/home/user_a",
                "files", "system_a", "system_a", "/home/user_a", "/home/user_b", 200, 200, "files:dev:READ:system_a:/home/user_b");
    }

    private void doTestPathPrefix(String token, String roleTenant, SkRoleType roleType, String roleOwner,
                                  String initialPermission, String schema,
                                  String oldSystemId, String newSystemId, String oldPrefix,
                                  String newPrefix, int expectedPreviewResult, int expectedReplaceResult,
                                  String expectedNewPermission) throws Exception {
        String roleName = createRole(roleTenant, roleType, roleOwner);
        RoleResourceTestUtils.addRolePermissions(siteAdminToken, roleTenant, roleType, roleName, initialPermission);

        // test preview
        Response response = RoleResourceTestUtils.previewPathPrefix(token, roleTenant, roleType, roleName, schema, oldSystemId, newSystemId, oldPrefix, newPrefix);
        String jsonString = response.readEntity(String.class);
        RespPathPrefixes prefixesResponse = TapisGsonUtils.getGson().fromJson(jsonString, RespPathPrefixes.class);
        Assert.assertEquals(response.getStatus(), expectedPreviewResult);
        if((expectedPreviewResult >= 200) && (expectedPreviewResult < 300)) {
            PermissionTransformer.Transformation[] result = prefixesResponse.result;
            Assert.assertEquals(result.length, 1);
            Assert.assertEquals(result[0].oldPerm, initialPermission);
            Assert.assertEquals(result[0].newPerm, expectedNewPermission);
        }
        // Now test replace
        response = RoleResourceTestUtils.replacePathPrefix(token, roleTenant, roleType, roleName, schema, oldSystemId, newSystemId, oldPrefix, newPrefix);
        jsonString = response.readEntity(String.class);
        RespChangeCount respChangeCount = TapisGsonUtils.getGson().fromJson(jsonString, RespChangeCount.class);
        Assert.assertEquals(response.getStatus(), expectedReplaceResult);
        ResultChangeCount result = respChangeCount.result;
        if((expectedReplaceResult >= 200) && (expectedReplaceResult < 300)) {
            Assert.assertEquals(result.changes, 1);
        }
    }

    @Test
    public void testUpdateRoleName() throws Exception {
        doTestUpdateRoleName(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
        doTestUpdateRoleName(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_2, 401);

        doTestUpdateRoleName(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
        doTestUpdateRoleName(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_2, 200);

        doTestUpdateRoleName(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
        doTestUpdateRoleName(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_2, 200);
    }

    private void doTestUpdateRoleName(String token, String roleTenant, SkRoleType roleType, String roleOwner, int expectedResult) throws Exception {
        String roleName = createRole(roleTenant, roleType, roleOwner);
        String newRoleName = RoleResourceTestUtils.createRandomRoleName();
        Response response = RoleResourceTestUtils.updateRoleName(token, roleTenant, roleType, roleName, newRoleName);
        Assert.assertEquals(response.getStatus(), expectedResult);
        if((expectedResult >= 200) && (expectedResult < 300)) {
            SkRole newNameRole = roleDao.getRole(roleTenant, SkRoleDescriptor.newSkRoleDescriptor(newRoleName, roleType));
            Assert.assertEquals(newNameRole.getName(), newRoleName);
        } else {
            SkRole newNameRole = roleDao.getRole(roleTenant, SkRoleDescriptor.newSkRoleDescriptor(roleName, roleType));
            Assert.assertEquals(newNameRole.getName(), roleName);
        }
    }

    @Test
    public void testUpdateRoleDescription() throws Exception {
        doTestUpdateRoleDescription(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
        doTestUpdateRoleDescription(userToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_2, 401);

        doTestUpdateRoleDescription(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
        doTestUpdateRoleDescription(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_2, 200);

        doTestUpdateRoleDescription(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
        doTestUpdateRoleDescription(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1, SkRoleType.USER, IntegrationTestUtils.TEST_USER_2, 200);
    }

    private void doTestUpdateRoleDescription(String token, String roleTenant, SkRoleType roleType, String roleOwner, int expectedResult) throws Exception {
        String roleName = createRole(roleTenant, roleType, roleOwner);
        String newRoleDescription = "My New Description";
        Response response = RoleResourceTestUtils.updateRoleDescription(token, roleTenant, roleType, roleName, newRoleDescription);
        Assert.assertEquals(response.getStatus(), expectedResult);
        if((expectedResult >= 200) && (expectedResult < 300)) {
            SkRole newDescriptionRole = roleDao.getRole(roleTenant, SkRoleDescriptor.newSkRoleDescriptor(roleName, roleType));
            Assert.assertEquals(newDescriptionRole.getName(), roleName);
            Assert.assertEquals(newDescriptionRole.getDescription(), newRoleDescription);
        } else {
            SkRole role = roleDao.getRole(roleTenant, SkRoleDescriptor.newSkRoleDescriptor(roleName, roleType));
            Assert.assertEquals(role.getName(), roleName);
            Assert.assertNotEquals(role.getDescription(), newRoleDescription);
        }
    }

    @Test
    public void testRemovePermissionFromAllRoles() throws Exception {
        testRemovePermissionFromAllRoles(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1,
                SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 401);
        testRemovePermissionFromAllRoles(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1,
                SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
    }

    private void testRemovePermissionFromAllRoles(String token, String roleTenant, SkRoleType roleType,
                                                   String roleOwner, int expectedResult) throws  Exception {
        String roleName1 = createRole(roleTenant, roleType, roleOwner);
        String roleName2 = createRole(roleTenant, roleType, roleOwner);
        String roleName3 = createRole(roleTenant, roleType, roleOwner);

        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "I:1:a");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "I:1:b");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "I:1:a:b");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "I:1:aother");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "I:2:a");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "I:2:b");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "I:2:a:b");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "I:2:aother");

        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName2, "I:1:a");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName2, "I:1:b");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "I:1:a:b");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "I:1:aother");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName2, "I:3:a");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName2, "I:3:b");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "I:3:a:b");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "I:3:aother");

        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName3, "II:1:a");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName3, "II:1:b");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "II:1:a:b");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "II:1:aother");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName3, "II:3:a");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName3, "II:3:b");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "II:3:a:b");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "II:3:aother");

        Response response = RoleResourceTestUtils.removePermissionsFromAllRoles(token, roleTenant, "I:1:a");
        String jsonString = response.readEntity(String.class);
        System.out.println(jsonString);
        Assert.assertEquals(response.getStatus(), expectedResult);
        if((expectedResult >= 200) && (expectedResult < 300)) {
            RespChangeCount changeCountResponse = TapisGsonUtils.getGson().fromJson(jsonString, RespChangeCount.class);
            Assert.assertEquals(changeCountResponse.result.changes, 2);
        }

        // cleanup roles - must clean between each invocation since it affects all roles with permission
        beforeTest();
    }

    @Test
    public void testRemovePathPermissionFromAllRoles() throws Exception {
        doTestRemovePathPermissionFromAllRoles(tenantAdminToken, IntegrationTestUtils.TEST_TENANT_1,
                SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 401);
        doTestRemovePathPermissionFromAllRoles(siteAdminToken, IntegrationTestUtils.TEST_TENANT_1,
                SkRoleType.USER, IntegrationTestUtils.TEST_USER_1, 200);
    }

    private void  doTestRemovePathPermissionFromAllRoles(String token, String roleTenant, SkRoleType roleType,
                                                         String roleOwner, int expectedResult) throws  Exception {
        String roleName1 = createRole(roleTenant, roleType, roleOwner);
        String roleName2 = createRole(roleTenant, roleType, roleOwner);
        String roleName3 = createRole(roleTenant, roleType, roleOwner);

        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "files:dev:READ:system1:/user/home/usera");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "files:dev:READ:system1:/user/home/userb");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "files:dev:READ:system1:/user/home/usera/subdir");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "files:dev:READ:system1:/user/home/usera_other");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "files:dev:READ:system2:/user/home/usera");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "files:dev:READ:system2:/user/home/userb");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "files:dev:READ:system2:/user/home/usera/subdir");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName1, "files:dev:READ:system2:/user/home/usera_other");

        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName2, "files:dev:READ:system1:/user/home/usera");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName2, "files:dev:READ:system1:/user/home/userb");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName2, "files:dev:READ:system1:/user/home/usera/subdir");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName2, "files:dev:READ:system1:/user/home/usera_other");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName2, "files:dev:READ:system3:/user/home/usera");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName2, "files:dev:READ:system3:/user/home/userb");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName2, "files:dev:READ:system3:/user/home/usera/subdir");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName2, "files:dev:READ:system3:/user/home/usera_other");

        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName3, "files:other:READ:system1:/user/home/usera");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName3, "files:other:READ:system1:/user/home/userb");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName3, "files:other:READ:system1:/user/home/usera/subdir");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName3, "files:other:READ:system1:/user/home/usera_other");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName3, "files:other:READ:system3:/user/home/usera");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName3, "files:other:READ:system3:/user/home/userb");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName3, "files:other:READ:system3:/user/home/usera/subdir");
        RoleResourceTestUtils.addRolePermissions(token, roleTenant, roleType, roleName3, "files:other:READ:system3:/user/home/usera_other");

        Response response = RoleResourceTestUtils.removePathPermissionsFromAllRoles(token, roleTenant, "files:dev:READ:system1:/user/home/usera");
        String jsonString = response.readEntity(String.class);
        Assert.assertEquals(response.getStatus(), expectedResult);
        if((expectedResult >= 200) && (expectedResult < 300)) {
            RespChangeCount changeCountResponse = TapisGsonUtils.getGson().fromJson(jsonString, RespChangeCount.class);
            // NOTE - files:dev:READ:system1:/user/home/usera is like files:dev:READ:system1:/user/home/usera* (i.e usera_thing and usera:thing)
            Assert.assertEquals(changeCountResponse.result.changes, 6);
        }

        // cleanup roles - must clean between each invocation since it affects all roles with permission
        beforeTest();
    }

    private String createRole(String roleTenant, SkRoleType roleType, String roleOwner) throws Exception {
        String roleName = RoleResourceTestUtils.createRandomRoleName();
        Response response = RoleResourceTestUtils.createRole(siteAdminToken , roleTenant, roleType, roleName, "Integration Test Role");
        Assert.assertEquals(response.getStatus(), 201, "Create parent role failed");
        response = RoleResourceTestUtils.updateRoleOwner(siteAdminToken, roleTenant, roleType, roleName, roleTenant, roleOwner);
        Assert.assertEquals(response.getStatus(), 200);
        SkRoleDescriptor roleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(roleName, roleType);
        SkRole role = roleDao.getRole(roleTenant, roleDescriptor);
        Assert.assertEquals(role.getName(), roleDescriptor.getRoleFullName());
        Assert.assertEquals(role.getType(), roleDescriptor.getRoleType());
        Assert.assertEquals(role.getOwner(), roleOwner);
        return roleName;
    }

}
