package edu.utexas.tacc.tapis.security.api.resources;

import edu.utexas.tacc.tapis.security.api.requestBody.ReqAddChildRole;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqAddRolePermission;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqCreateRole;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqRemoveChildRole;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqRemoveRolePermission;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqUpdateRoleOwner;
import edu.utexas.tacc.tapis.security.authz.dao.SkRoleDao;
import edu.utexas.tacc.tapis.security.authz.model.SkRole;
import edu.utexas.tacc.tapis.security.authz.model.SkRoleDescriptor;
import edu.utexas.tacc.tapis.security.authz.model.SkRoleType;
import edu.utexas.tacc.tapis.shared.exceptions.TapisException;
import edu.utexas.tacc.tapis.shared.utils.TapisGsonUtils;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class RoleResourceTestUtils {
    public static final String CREATE_ROLE_PATH = "role";
    public static final String ADD_CHILD_ROLE_PATH = "role/addChild";
    public static final String UPDATE_ROLE_OWNER = "role/updateOwner";
    public static final String ADD_ROLE_PERMISSIONS = "role/addPerm";


    public static final String TEST_PREFIX_ROLE_NAME = "integration_test_role_";

    public static Response createRole(String token, String roleTenant,
                                      SkRoleType roleType, String roleName, String description) throws TapisException {
        ReqCreateRole reqCreateRole = new ReqCreateRole();
        reqCreateRole.roleTenant = roleTenant;
        reqCreateRole.roleType = roleType.name();
        reqCreateRole.roleName = roleName;
        reqCreateRole.description = description;
        String jsonString = TapisGsonUtils.getGson().toJson(reqCreateRole);
        Response response = ClientBuilder.newClient()
                .target(IntegrationTestUtils.getBaseUrl())
                .path(CREATE_ROLE_PATH)
                .request(MediaType.APPLICATION_JSON)
                .header("X-Tapis-Token", token)
                .post(Entity.json(jsonString));
        return response;
    }

    public static Response updateOwner(String token,
                                        String roleTenant, SkRoleType roleType, String roleName,
                                        String newTenant, String newOwner) throws TapisException {
        ReqUpdateRoleOwner reqUpdateRoleOwner = new ReqUpdateRoleOwner();
        reqUpdateRoleOwner.newOwner = newOwner;
        reqUpdateRoleOwner.newTenant = newTenant;
        reqUpdateRoleOwner.roleTenant = roleTenant;
        reqUpdateRoleOwner.roleType = roleType.name();
        String jsonString = TapisGsonUtils.getGson().toJson(reqUpdateRoleOwner);
        Response response = ClientBuilder.newClient()
                .target(IntegrationTestUtils.getBaseUrl())
                .path(UPDATE_ROLE_OWNER + "/" + roleName)
                .request(MediaType.APPLICATION_JSON)
                .header("X-Tapis-Token", token)
                .post(Entity.json(jsonString));
        return response;
    }

    public static Response addChildRole(String token, String roleTenant,
                                        String parentRoleName, String childRoleName) throws TapisException {
        ReqAddChildRole reqAddChildRole = new ReqRemoveChildRole();
        reqAddChildRole.childRoleName = childRoleName;
        reqAddChildRole.parentRoleName = parentRoleName;
        reqAddChildRole.roleTenant = roleTenant;
        String jsonString = TapisGsonUtils.getGson().toJson(reqAddChildRole);
        Response response = ClientBuilder.newClient()
                .target(IntegrationTestUtils.getBaseUrl())
                .path(ADD_CHILD_ROLE_PATH)
                .request(MediaType.APPLICATION_JSON)
                .header("X-Tapis-Token", token)
                .post(Entity.json(jsonString));
        return response;
    }

    public static Response addRolePermissions(String token, String roleTenant,
                                        String roleName, String permSpec) throws TapisException {
        ReqAddRolePermission reqAddRolePermission = new ReqRemoveRolePermission();
        reqAddRolePermission.roleTenant = roleTenant;
        reqAddRolePermission.roleName = roleName;
        reqAddRolePermission.permSpec = permSpec;

        String jsonString = TapisGsonUtils.getGson().toJson(reqAddRolePermission);
        Response response = ClientBuilder.newClient()
                .target(IntegrationTestUtils.getBaseUrl())
                .path(ADD_ROLE_PERMISSIONS)
                .request(MediaType.APPLICATION_JSON)
                .header("X-Tapis-Token", token)
                .post(Entity.json(jsonString));
        return response;
    }

    public static Response getRolePermissions(String token, String roleTenant,
                                              SkRoleType roleType, String roleName,
                                              boolean immediate) throws TapisException {
        Response response = ClientBuilder.newClient()
                .target(IntegrationTestUtils.getBaseUrl())
                .queryParam("tenant", roleTenant)
                .queryParam("roleType", roleType.name())
                .queryParam("immediate", Boolean.valueOf(immediate).toString())
                .path("role/" + roleName  + "/perms")
                .request(MediaType.APPLICATION_JSON)
                .header("X-Tapis-Token", token)
                .get();
        return response;
    }

    public static void cleanupAllTestRoles(SkRoleDao roleDao, String tenant, Set<SkRoleType> roleTypesToDelete) throws Exception {
        for(var roleType : roleTypesToDelete) {
            List<String> roleNames = roleDao.getRoleNames(tenant, EnumSet.of(roleType));
            for(var roleName : roleNames) {
                if(roleName.startsWith(TEST_PREFIX_ROLE_NAME)) {
                    roleDao.deleteRole(tenant, SkRoleDescriptor.newSkRoleDescriptor(roleName, roleType));
                }
            }
        }
    }

    public static String createRandomRoleName() {
        String roleName = UUID.randomUUID().toString();
        return TEST_PREFIX_ROLE_NAME + roleName.replace('-', '_');
    }

}
