package edu.utexas.tacc.tapis.security.api.resources;

import edu.utexas.tacc.tapis.security.api.requestBody.ReqAddChildRole;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqAddRolePermission;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqCreateRole;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqPreviewPathPrefix;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqRemoveChildRole;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqRemovePermissionFromAllRoles;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqRemoveRolePermission;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqReplacePathPrefix;
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
                .path("role")
                .request(MediaType.APPLICATION_JSON)
                .header("X-Tapis-Token", token)
                .post(Entity.json(jsonString));
        return response;
    }

    public static Response updateRoleOwner(String token,
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
                .path("role/updateOwner" + "/" + roleName)
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
                .path("role/addChild")
                .request(MediaType.APPLICATION_JSON)
                .header("X-Tapis-Token", token)
                .post(Entity.json(jsonString));
        return response;
    }
/*
    public static Response removePathPermissionsFromAllRoles(String token, String roleTenant,
                                        SkRoleType roleType, String permSpec) throws TapisException {
        ReqRemovePermissionFromAllRoles reqRemovePermissionFromAllRoles = new ReqRemovePermissionFromAllRoles();
        reqRemovePermissionFromAllRoles.tenant = roleTenant;
        reqRemovePermissionFromAllRoles.roleType = roleType.name();
        reqRemovePermissionFromAllRoles.permSpec = permSpec;
        String jsonString = TapisGsonUtils.getGson().toJson(reqRemovePermissionFromAllRoles);
        Response response = ClientBuilder.newClient()
                .target(IntegrationTestUtils.getBaseUrl())
                .path("role/removePathPermissionFromAllRoles")
                .request(MediaType.APPLICATION_JSON)
                .header("X-Tapis-Token", token)
                .post(Entity.json(jsonString));
        return response;
    }
*/
    public static Response addRolePermissions(String token, String roleTenant, SkRoleType roleType,
                                        String roleName, String permSpec) throws TapisException {
        ReqAddRolePermission reqAddRolePermission = new ReqRemoveRolePermission();
        reqAddRolePermission.roleTenant = roleTenant;
        reqAddRolePermission.roleType = roleType.name();
        reqAddRolePermission.roleName = roleName;
        reqAddRolePermission.permSpec = permSpec;

        String jsonString = TapisGsonUtils.getGson().toJson(reqAddRolePermission);
        Response response = ClientBuilder.newClient()
                .target(IntegrationTestUtils.getBaseUrl())
                .path("role/addPerm")
                .request(MediaType.APPLICATION_JSON)
                .header("X-Tapis-Token", token)
                .post(Entity.json(jsonString));
        return response;
    }

    public static Response previewPathPrefix(String token, String roleTenant, SkRoleType roleType, String roleName,
                                             String schema, String oldSystemId, String newSystemId,
                                             String oldPrefix, String newPrefix) throws TapisException {
        ReqPreviewPathPrefix reqPreviewPathPrefix = new ReqPreviewPathPrefix();
        reqPreviewPathPrefix.tenant = roleTenant;
        reqPreviewPathPrefix.roleType = roleType.name();
        reqPreviewPathPrefix.schema = schema;
        reqPreviewPathPrefix.roleName = roleName;
        reqPreviewPathPrefix.oldSystemId = oldSystemId;
        reqPreviewPathPrefix.newSystemId = newSystemId;
        reqPreviewPathPrefix.oldPrefix = oldPrefix;
        reqPreviewPathPrefix.newPrefix = newPrefix;

        String jsonString = TapisGsonUtils.getGson().toJson(reqPreviewPathPrefix);
        Response response = ClientBuilder.newClient()
                .target(IntegrationTestUtils.getBaseUrl())
                .path("role/previewPathPrefix")
                .request(MediaType.APPLICATION_JSON)
                .header("X-Tapis-Token", token)
                .post(Entity.json(jsonString));
        return response;
    }

    public static Response replacePathPrefix(String token, String roleTenant, SkRoleType roleType, String roleName,
                                             String schema, String oldSystemId, String newSystemId,
                                             String oldPrefix, String newPrefix) throws TapisException {
        ReqReplacePathPrefix reqReplacePathPrefix = new ReqReplacePathPrefix();
        reqReplacePathPrefix.tenant = roleTenant;
        reqReplacePathPrefix.roleType = roleType.name();
        reqReplacePathPrefix.schema = schema;
        reqReplacePathPrefix.roleName = roleName;
        reqReplacePathPrefix.oldSystemId = oldSystemId;
        reqReplacePathPrefix.newSystemId = newSystemId;
        reqReplacePathPrefix.oldPrefix = oldPrefix;
        reqReplacePathPrefix.newPrefix = newPrefix;

        String jsonString = TapisGsonUtils.getGson().toJson(reqReplacePathPrefix);
        Response response = ClientBuilder.newClient()
                .target(IntegrationTestUtils.getBaseUrl())
                .path("role/replacePathPrefix")
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

    public static Response getRoleByName(String token, String roleTenant,
                                              SkRoleType roleType, String roleName) throws TapisException {
        Response response = ClientBuilder.newClient()
                .target(IntegrationTestUtils.getBaseUrl())
                .queryParam("tenant", roleTenant)
                .queryParam("roleType", roleType.name())
                .path("role/" + roleName)
                .request(MediaType.APPLICATION_JSON)
                .header("X-Tapis-Token", token)
                .get();
        return response;
    }

    public static Response deleteRoleByName(String token, String roleTenant,
                                         SkRoleType roleType, String roleName) throws TapisException {
        Response response = ClientBuilder.newClient()
                .target(IntegrationTestUtils.getBaseUrl())
                .queryParam("tenant", roleTenant)
                .queryParam("roleType", roleType.name())
                .path("role/" + roleName)
                .request(MediaType.APPLICATION_JSON)
                .header("X-Tapis-Token", token)
                .delete();
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
