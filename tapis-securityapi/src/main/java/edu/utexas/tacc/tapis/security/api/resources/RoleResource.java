package edu.utexas.tacc.tapis.security.api.resources;

import java.io.InputStream;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import javax.annotation.security.PermitAll;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.UriInfo;

import edu.utexas.tacc.tapis.security.api.requestBody.ReqRolePermits;
import edu.utexas.tacc.tapis.security.authz.model.SkRoleDescriptor;
import edu.utexas.tacc.tapis.security.authz.model.SkRoleType;
import edu.utexas.tacc.tapis.sharedapi.responses.RespAuthorized;
import edu.utexas.tacc.tapis.sharedapi.responses.results.ResultAuthorized;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.utexas.tacc.tapis.security.api.requestBody.ReqAddChildRole;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqAddRolePermission;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqCreateRole;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqPreviewPathPrefix;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqRemoveChildRole;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqRemovePermissionFromAllRoles;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqRemoveRolePermission;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqReplacePathPrefix;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqUpdateRoleDescription;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqUpdateRoleName;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqUpdateRoleOwner;
import edu.utexas.tacc.tapis.security.api.responses.RespPathPrefixes;
import edu.utexas.tacc.tapis.security.api.responses.RespRole;
import edu.utexas.tacc.tapis.security.api.utils.SKApiUtils;
import edu.utexas.tacc.tapis.security.api.utils.SKCheckAuthz;
import edu.utexas.tacc.tapis.security.authz.impl.RoleImpl;
import edu.utexas.tacc.tapis.security.authz.model.SkRole;
import edu.utexas.tacc.tapis.security.authz.permissions.PermissionTransformer.Transformation;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import edu.utexas.tacc.tapis.shared.threadlocal.TapisThreadLocal;
import edu.utexas.tacc.tapis.sharedapi.responses.RespChangeCount;
import edu.utexas.tacc.tapis.sharedapi.responses.RespName;
import edu.utexas.tacc.tapis.sharedapi.responses.RespNameArray;
import edu.utexas.tacc.tapis.sharedapi.responses.RespResourceUrl;
import edu.utexas.tacc.tapis.sharedapi.responses.results.ResultChangeCount;
import edu.utexas.tacc.tapis.sharedapi.responses.results.ResultName;
import edu.utexas.tacc.tapis.sharedapi.responses.results.ResultNameArray;
import edu.utexas.tacc.tapis.sharedapi.responses.results.ResultResourceUrl;
import edu.utexas.tacc.tapis.sharedapi.utils.TapisRestUtils;

@Path("/role")
public final class RoleResource 
 extends AbstractResource
{
    /* **************************************************************************** */
    /*                                   Constants                                  */
    /* **************************************************************************** */
    // Local logger.
    private static final Logger _log = LoggerFactory.getLogger(RoleResource.class);
    
    // Json schema resource files.
    private static final String FILE_SK_CREATE_ROLE_REQUEST = 
        "/edu/utexas/tacc/tapis/security/api/jsonschema/CreateRoleRequest.json";
    private static final String FILE_SK_UPDATE_ROLE_NAME_REQUEST = 
            "/edu/utexas/tacc/tapis/security/api/jsonschema/UpdateRoleNameRequest.json";
    private static final String FILE_SK_UPDATE_ROLE_OWNER_REQUEST = 
            "/edu/utexas/tacc/tapis/security/api/jsonschema/UpdateRoleOwnerRequest.json";
    private static final String FILE_SK_UPDATE_ROLE_DESCRIPTION_REQUEST = 
            "/edu/utexas/tacc/tapis/security/api/jsonschema/UpdateRoleDescriptionRequest.json";
    private static final String FILE_SK_ADD_ROLE_PERM_REQUEST = 
            "/edu/utexas/tacc/tapis/security/api/jsonschema/AddRolePermissionRequest.json";
    private static final String FILE_SK_ADD_CHILD_ROLE_REQUEST = 
            "/edu/utexas/tacc/tapis/security/api/jsonschema/AddChildRoleRequest.json";
    private static final String FILE_SK_REMOVE_ROLE_PERM_REQUEST = 
            "/edu/utexas/tacc/tapis/security/api/jsonschema/RemoveRolePermissionRequest.json";
    private static final String FILE_SK_REMOVE_PERM_FROM_ALL_ROLES_REQUEST = 
            "/edu/utexas/tacc/tapis/security/api/jsonschema/RemovePermissionFromAllRolesRequest.json";
    private static final String FILE_SK_REMOVE_CHILD_ROLE_REQUEST = 
            "/edu/utexas/tacc/tapis/security/api/jsonschema/RemoveChildRoleRequest.json";
    private static final String FILE_SK_PREVIEW_PATH_PREFIX_REQUEST = 
            "/edu/utexas/tacc/tapis/security/api/jsonschema/PreviewPathPrefixRequest.json";
    private static final String FILE_SK_REPLACE_PATH_PREFIX_REQUEST = 
            "/edu/utexas/tacc/tapis/security/api/jsonschema/ReplacePathPrefixRequest.json";
    private static final String FILE_SK_ROLE_PERMITS_REQUEST =
            "/edu/utexas/tacc/tapis/security/api/jsonschema/RolePermitsRequest.json";
    public static final Set<SkRoleType> ALL_ROLES = EnumSet.allOf(SkRoleType.class);
    public static final Set<SkRoleType> ADMIN_ROLES = EnumSet.of(SkRoleType.TENANT_ADMIN, SkRoleType.SITE_ADMIN);
    public static final Set<SkRoleType> USER_ROLES = EnumSet.of(SkRoleType.USER);
    public static final Set<SkRoleType> NON_ADMIN_ROLES = EnumSet.of(SkRoleType.USER, SkRoleType.USER_DEFAULT, SkRoleType.RESTRICTED_SVC);
    public static final Set<SkRoleType> NON_SITE_ADMIN_ROLES = EnumSet.of(SkRoleType.USER, SkRoleType.USER_DEFAULT, SkRoleType.RESTRICTED_SVC, SkRoleType.TENANT_ADMIN);
    public static final Set<SkRoleType> NO_ROLES = Collections.emptySet();

    /* **************************************************************************** */
    /*                                    Fields                                    */
    /* **************************************************************************** */
    /* Jax-RS context dependency injection allows implementations of these abstract
     * types to be injected (ch 9, jax-rs 2.0):
     * 
     *      javax.ws.rs.container.ResourceContext
     *      javax.ws.rs.core.Application
     *      javax.ws.rs.core.HttpHeaders
     *      javax.ws.rs.core.Request
     *      javax.ws.rs.core.SecurityContext
     *      javax.ws.rs.core.UriInfo
     *      javax.ws.rs.core.Configuration
     *      javax.ws.rs.ext.Providers
     * 
     * In a servlet environment, Jersey context dependency injection can also 
     * initialize these concrete types (ch 3.6, jersey spec):
     * 
     *      javax.servlet.HttpServletRequest
     *      javax.servlet.HttpServletResponse
     *      javax.servlet.ServletConfig
     *      javax.servlet.ServletContext
     *
     * Inject takes place after constructor invocation, so fields initialized in this
     * way can not be accessed in constructors.
     */ 
     @Context
     private HttpHeaders        _httpHeaders;
  
     @Context
     private Application        _application;
  
     @Context
     private UriInfo            _uriInfo;
  
     @Context
     private SecurityContext    _securityContext;
  
     @Context
     private ServletContext     _servletContext;
  
     @Context
     private HttpServletRequest _request;
    
     /* **************************************************************************** */
     /*                                Public Methods                                */
     /* **************************************************************************** */
     /* ---------------------------------------------------------------------------- */
     /* getRoleNames:                                                                */
     /* ---------------------------------------------------------------------------- */
     @GET
     @Produces(MediaType.APPLICATION_JSON)
     public Response getRoleNames(@QueryParam("tenant") String tenant,
                                  @DefaultValue("USER") @QueryParam("roleType") String roleTypeName)
       {
         SkRoleType type = SkRoleType.getRoleTypeFromStringIgnoreCase(roleTypeName);

         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "getRoleNames", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         if (StringUtils.isBlank(tenant)) {
             String msg = MsgUtils.getMsg("SK_MISSING_PARAMETER", "tenant");
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }

         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, null).check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Create the role.
         List<String> list = null;
         try {
             list = getRoleImpl().getRoleNames(tenant, EnumSet.of(type));
         } catch (Exception e) {
             String msg = MsgUtils.getMsg("SK_ROLE_GET_NAMES_ERROR", tenant, 
                                          TapisThreadLocal.tapisThreadContext.get().getJwtUser());
             return getExceptionResponse(e, msg);
         }
         
         // Assign result.
         ResultNameArray names = new ResultNameArray();
         names.names = list.stream().map( name -> SkRoleType.getRoleShortName(name)).toArray(String[]::new);
         RespNameArray r = new RespNameArray(names);

         // ---------------------------- Success ------------------------------- 
         // Success means we found the tenant's role names.
         int cnt = names.names.length;
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_FOUND", "Roles", cnt + " items"), r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* getRoleByName:                                                               */
     /* ---------------------------------------------------------------------------- */
     @GET
     @Path("/{roleName}")
     @Produces(MediaType.APPLICATION_JSON)
     public Response getRoleByName(@PathParam("roleName") String roleName,
                                   @QueryParam("tenant") String tenant,
                                   @DefaultValue("USER") @QueryParam("roleType") String roleTypeName)
     {
         SkRoleDescriptor roleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(roleName, roleTypeName);

         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "getRoleByName", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         if (StringUtils.isBlank(tenant)) {
             String msg = MsgUtils.getMsg("SK_MISSING_PARAMETER", "tenant");
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }

         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, null)
                 .setRoleTypeRestrictions(roleDescriptor.getRoleType(), NON_ADMIN_ROLES, NON_ADMIN_ROLES, ALL_ROLES)
                 .check();
         if (resp != null) return resp;

         // ------------------------ Request Processing ------------------------
         // Get the role.
         SkRole role = null;
         try {
             role = getRoleImpl().getRoleByName(tenant, roleDescriptor);
         } catch (Exception e) {
             String msg = MsgUtils.getMsg("SK_ROLE_GET_ERROR", tenant,
                                          TapisThreadLocal.tapisThreadContext.get().getJwtUser(), 
                                          roleName);
             return getExceptionResponse(e, msg);
         }

         // Adjust status based on whether we found the role.
         if (role == null) {
             ResultName missingName = new ResultName();
             missingName.name = roleName;
             RespName r = new RespName(missingName);
             return Response.status(Status.NOT_FOUND).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg("TAPIS_NOT_FOUND", "Role", roleName), r)).build();
         }
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         RespRole r = new RespRole(role);
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_FOUND", "Role", roleName), r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* createRole:                                                                  */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response createRole(InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "createRole", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         ReqCreateRole payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_CREATE_ROLE_REQUEST, 
                                   ReqCreateRole.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "createRole", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg, false)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant  = payload.roleTenant;
         String description = payload.description;
         SkRoleDescriptor roleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(payload.roleName, payload.roleType);

         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                         .setCheckServiceIsAllowed()
                         .setCheckIsSiteAdmin()
                         .setCheckIsTenantAdmin()
                         .setPreventForeignTenantUpdate()
                         .setRoleTypeRestrictions(roleDescriptor.getRoleType(), USER_ROLES, USER_ROLES, NON_ADMIN_ROLES)
                         .check();

         if (resp != null) {
             return resp;
         }

         // ------------------------ Request Processing ------------------------
         // The threadlocal object has been validated by now.
         String owner = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
         String ownerTenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();

         // Create the role.
         int rows = 0;
         try {rows = getRoleImpl().createRole(roleDescriptor, roleTenant, description, owner, ownerTenant);}
         catch (Exception e) {
             String msg = MsgUtils.getMsg("SK_ROLE_CREATE_ERROR", roleDescriptor.getRoleName(), roleDescriptor.getRoleType(), roleTenant, owner, ownerTenant);
             return getExceptionResponse(e, msg);
         }
         
         // NOTE: We need to assign a location header as well.
         //       See https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9.5.
         ResultResourceUrl respUrl = new ResultResourceUrl();
         respUrl.url = SKApiUtils.constructTenantURL(roleTenant, _request.getRequestURI(), roleDescriptor.getRoleFullName());
         RespResourceUrl r = new RespResourceUrl(respUrl);
         
         // ---------------------------- Success ------------------------------- 
         // No new rows means the role exists. 
         if (rows == 0)
             return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg("TAPIS_EXISTED", "Role", roleDescriptor.getRoleFullName()+"@"+roleTenant), false, r)).build();
         else 
             return Response.status(Status.CREATED).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg("TAPIS_CREATED", "Role", roleDescriptor.getRoleFullName()+"@"+roleTenant), false, r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* deleteRoleByName:                                                            */
     /* ---------------------------------------------------------------------------- */
     @DELETE
     @Path("/{roleName}")
     @Produces(MediaType.APPLICATION_JSON)
     public Response deleteRoleByNameAndType(@PathParam("roleName") String roleName,
                                      @QueryParam("tenant") String tenant,
                                      @DefaultValue("USER") @QueryParam("roleType") String roleTypeName)
     {
         SkRoleDescriptor roleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(roleName, roleTypeName);
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "deleteRoleByName", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         if (StringUtils.isBlank(tenant)) {
             String msg = MsgUtils.getMsg("SK_MISSING_PARAMETER", "tenant");
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, null)
                 .addOwnedRole(roleDescriptor)
                 .setCheckIsTenantAdmin()
                 .setCheckIsSiteAdmin()
                 .setRoleTypeRestrictions(roleDescriptor.getRoleType(), USER_ROLES, USER_ROLES, NON_ADMIN_ROLES)
                 .check();

         if (resp != null) {
             return resp;
         }

         // ------------------------ Request Processing ------------------------
         // Delete the role.
         int rows = 0;
         try {rows =  getRoleImpl().deleteRoleByNameAndType(tenant, roleDescriptor);}
         catch (Exception e) {
        	 // The threadlocal value has been validated.
             String msg = MsgUtils.getMsg("SK_ROLE_DELETE_ERROR", tenant, 
            		                      TapisThreadLocal.tapisThreadContext.get().getJwtUser(), 
            		                      roleName);
             return getExceptionResponse(e, msg);
         }
         
         // Return the number of row affected.
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we deleted the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_DELETED", "Role", roleName), r)).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* getRolePermissions:                                                          */
     /* ---------------------------------------------------------------------------- */
     @GET
     @Path("/{roleName}/perms")
     @Produces(MediaType.APPLICATION_JSON)
     public Response getRolePermissions(@PathParam("roleName") String roleName,
                                        @QueryParam("tenant") String tenant,
                                        @DefaultValue("USER") @QueryParam("roleType") String roleTypeName,
                                        @DefaultValue("false") @QueryParam("immediate") boolean immediate)
     {
         SkRoleDescriptor roleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(roleName, roleTypeName);

         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "getRolePermissions", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         if (StringUtils.isBlank(tenant)) {
             String msg = MsgUtils.getMsg("SK_MISSING_PARAMETER", "tenant");
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }

         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, null)
                 .setRoleTypeRestrictions(roleDescriptor.getRoleType(), NON_ADMIN_ROLES, NON_ADMIN_ROLES, ALL_ROLES)
                 .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Create the role.
         List<String> list = null;
         try {
             list = getRoleImpl().getRolePermissions(tenant, roleDescriptor, immediate);
         } catch (Exception e) {
             String msg = MsgUtils.getMsg("SK_ROLE_GET_PERMISSIONS_ERROR",tenant, 
                                          TapisThreadLocal.tapisThreadContext.get().getJwtUser(), 
                                          roleName);
             return getExceptionResponse(e, msg);
         }

         // Assign result.
         ResultNameArray names = new ResultNameArray();
         names.names = list.toArray(new String[list.size()]);
         RespNameArray r = new RespNameArray(names);

         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         int cnt = names.names.length;
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_FOUND", "Permissions", cnt + " permissions"), r)).build();
     }

     @POST
     @Path("/{roleName}/permits")
     @Produces(MediaType.APPLICATION_JSON)
     public Response rolePermits(@PathParam("roleName") String roleName,
                                 @DefaultValue("false") @QueryParam("immediate") boolean immediate,
                                 InputStream payloadStream) {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(),
                     "permits", _request.getRequestURL());
             _log.trace(msg);
         }

         // ------------------------- Input Processing -------------------------
         // Make sure the existing role name is not reserved.
         if (!SKApiUtils.isValidName(roleName)) {
             String msg = MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "updateRoleName", "roleName",
                     roleName);
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }

         // Parse and validate the json in the request payload, which must exist.
         ReqRolePermits payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_ROLE_PERMITS_REQUEST,
                 ReqRolePermits.class);
         }
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR",
                     "updateRoleName", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }

         String tenant = payload.roleTenant;
         SkRoleDescriptor roleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(roleName, payload.roleType);
         String requestedPermissionString = payload.permSpec;

         boolean authorized = false;

         try {
             authorized = getRoleImpl().roleHasPermission(tenant, roleDescriptor, requestedPermissionString, immediate);
         } catch (Exception ex) {
             String msg = MsgUtils.getMsg("SK_ROLE_CHECK_PERMISSIONS",
                     roleDescriptor.getRoleType(), roleDescriptor.getRoleName(), tenant, ex.getMessage());
             return getExceptionResponse(ex, msg);
         }

         // Set the result payload.
         ResultAuthorized authResp = new ResultAuthorized();
         authResp.isAuthorized = authorized;
         RespAuthorized r = new RespAuthorized(authResp);

         // Set the response message.
         String resultCode;
         if (authorized) {
             resultCode = "TAPIS_AUTHORIZED";
         } else {
             resultCode = "TAPIS_NOT_AUTHORIZED";
         }

         // ---------------------------- Success -------------------------------
         // Success means we found the role.
         String respMsg = roleName + " authorized: " + authorized;
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg(resultCode, "Role", respMsg), r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* updateRoleName:                                                              */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/updateName/{roleName}")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response updateRoleName(@PathParam("roleName") String roleName,
                                    InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "updateRoleName", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Make sure the existing role name is not reserved.
         if (!SKApiUtils.isValidName(roleName)) {
             String msg = MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "updateRoleName", "roleName",
                                          roleName);
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         
         // Parse and validate the json in the request payload, which must exist.
         ReqUpdateRoleName payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_UPDATE_ROLE_NAME_REQUEST, 
                                   ReqUpdateRoleName.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "updateRoleName", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant  = payload.roleTenant;
         String newRoleName = payload.newRoleName;
         SkRoleDescriptor roleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(roleName, payload.roleType);

         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsTenantAdmin()
                             .setCheckIsSiteAdmin()
                             .addOwnedRole(roleDescriptor)
                             .setRoleTypeRestrictions(roleDescriptor.getRoleType(),
                                     USER_ROLES, NON_ADMIN_ROLES, NON_ADMIN_ROLES)
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // The threadlocal object has been validated by now.
         String requestor = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
         String requestorTenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();
         
         // Create the role.
         int rows = 0;
         try {
             rows = getRoleImpl().updateRoleName(roleTenant, roleDescriptor, newRoleName,
            		                             requestor, requestorTenant);
         } catch (Exception e) {
             String msg = MsgUtils.getMsg("SK_ROLE_UPDATE_ERROR", roleTenant, roleName, 
            		                      requestor, requestorTenant);
             return getExceptionResponse(e, msg, "Role");
         }

         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Role", roleName))).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* updateRoleOwner:                                                             */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/updateOwner/{roleName}")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response updateRoleOwner(@PathParam("roleName") String roleName,
                                     InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "updateRoleOwner", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Make sure the existing role name is not reserved.
         if (!SKApiUtils.isValidName(roleName)) {
             String msg = MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "updateRoleName", "roleName",
                                          roleName);
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         
         // Parse and validate the json in the request payload, which must exist.
         ReqUpdateRoleOwner payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_UPDATE_ROLE_OWNER_REQUEST, 
                                   ReqUpdateRoleOwner.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "updateRoleOwner", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant = payload.roleTenant;
         String newOwner   = payload.newOwner;
         String newTenant  = payload.newTenant; // optional, can be null or empty

         SkRoleDescriptor roleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(roleName, payload.roleType);
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsTenantAdmin()
                             .addOwnedRole(roleDescriptor)
                             .setCheckIsSiteAdmin()
                             .setPreventInvalidOwnerAssignment(newTenant)
                             .setRoleTypeRestrictions(roleDescriptor.getRoleType(),
                                     NO_ROLES, NON_ADMIN_ROLES, NON_ADMIN_ROLES)
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // The threadlocal object has been validated by now.
         String requestor = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
         String requestorTenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();
         
         // Create the role.
         int rows = 0;
         try {
        	 // The new tenant can be null.
             rows = getRoleImpl().updateRoleOwner(roleTenant, roleDescriptor, newOwner, newTenant,
            		                              requestor, requestorTenant);
         } catch (Exception e) {
             String msg = MsgUtils.getMsg("SK_ROLE_UPDATE_ERROR", roleTenant, roleName, 
                                          requestor, requestorTenant);
             return getExceptionResponse(e, msg, "Role");
         }
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Role", roleName))).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* updateRoleDescription:                                                       */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/updateDesc/{roleName}")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response updateRoleDescription(
                                @PathParam("roleName") String roleName,
                                InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "updateRoleDescription", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Make sure the existing role name is not reserved.
         if (!SKApiUtils.isValidName(roleName)) {
             String msg = MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "updateRoleName", "roleName",
                                          roleName);
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         
         // Parse and validate the json in the request payload, which must exist.
         ReqUpdateRoleDescription payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_UPDATE_ROLE_DESCRIPTION_REQUEST, 
                                   ReqUpdateRoleDescription.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "updateRoleName", e.getMessage());
              _log.error(msg, e);
              return Response.status(Status.BAD_REQUEST).
                entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant     = payload.roleTenant;
         String newDescription = payload.newDescription;
         SkRoleDescriptor roleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(roleName, payload.roleType);

         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsTenantAdmin()
                             .setCheckIsSiteAdmin()
                             .addOwnedRole(roleDescriptor)
                             .setRoleTypeRestrictions(roleDescriptor.getRoleType(),
                                     USER_ROLES, NON_ADMIN_ROLES, NON_ADMIN_ROLES)
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // The threadlocal object has been validated by now.
         String requestor = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
         String requestorTenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();
         
         // Create the role.
         int rows = 0;
         try {
             rows = getRoleImpl().updateRoleDescription(roleTenant, roleDescriptor, newDescription,
            		                                    requestor, requestorTenant);
         } catch (Exception e) {
             String msg = MsgUtils.getMsg("SK_ROLE_UPDATE_ERROR", roleTenant, roleDescriptor.getRoleFullName(),
                                          requestor, requestorTenant);
             return getExceptionResponse(e, msg, "Role");
         }
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Role", roleName))).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* addRolePermission:                                                           */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/addPerm")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response addRolePermission(InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "addRolePermission", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         ReqAddRolePermission payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_ADD_ROLE_PERM_REQUEST, 
                                   ReqAddRolePermission.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "addRolePermission", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
                entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant = payload.roleTenant;
         String permSpec   = payload.permSpec;
         SkRoleDescriptor roleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(payload.roleName, payload.roleType);

                 // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                 .setCheckIsTenantAdmin()
                 .setCheckIsSiteAdmin()
                 .addOwnedRole(roleDescriptor)
                 .setRoleTypeRestrictions(roleDescriptor.getRoleType(),
                         USER_ROLES, USER_ROLES, NON_ADMIN_ROLES)
                 .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // The threadlocal object has been validated by now.
         String requestor = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
         String requestorTenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();
         
         // Add permission to role.
         int rows = 0;
         try {
             rows = getRoleImpl().addRolePermission(roleTenant, roleDescriptor, permSpec, requestor, requestorTenant);
         } catch (Exception e) {
             // This only occurs when the role name is not found.
             String msg = MsgUtils.getMsg("SK_ADD_PERMISSION_ERROR", requestor, requestorTenant, permSpec, 
            		                      roleDescriptor.getRoleFullName(), roleTenant);
             return getExceptionResponse(e, msg, "Role", roleDescriptor.getRoleFullName());
         }

         // Report the number of rows changed.
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Role", roleDescriptor.getRoleFullName()), r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* removeRolePermission:                                                        */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/removePerm")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response removeRolePermission(InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "removeRolePermission", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         ReqRemoveRolePermission payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_REMOVE_ROLE_PERM_REQUEST, 
                                   ReqRemoveRolePermission.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "removeRolePermission", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant = payload.roleTenant;
         String permSpec   = payload.permSpec;
         SkRoleDescriptor roleDescriptor   = SkRoleDescriptor.newSkRoleDescriptor(payload.roleName, payload.roleType);

         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsSiteAdmin()
                             .setCheckIsTenantAdmin()
                             .setRoleTypeRestrictions(roleDescriptor.getRoleType(),
                                     USER_ROLES, NON_ADMIN_ROLES, NON_ADMIN_ROLES)
                             .addOwnedRole(roleDescriptor)
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Remove the permission from the role.
         int rows = 0;
         try {rows = getRoleImpl().removeRolePermission(roleTenant, roleDescriptor, permSpec);}
         catch (Exception e) {
             // Role not found is an error in this case.
             String requestor = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
             String requestorTenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();
             String msg = MsgUtils.getMsg("SK_REMOVE_PERMISSION_ERROR", requestor,
            		                      requestorTenant, permSpec, roleDescriptor.getRoleFullName(), roleTenant);
             return getExceptionResponse(e, msg, "Role", roleDescriptor.getRoleFullName());
         }

         // Report the number of rows changed.
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Role", roleDescriptor.getRoleFullName()), r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* addChildRole:                                                                */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/addChild")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response addChildRole(InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "addChildRole", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         ReqAddChildRole payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_ADD_CHILD_ROLE_REQUEST, 
                                   ReqAddChildRole.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "addChildRole", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant     = payload.roleTenant; 
         String parentRoleName = payload.parentRoleName;
         String childRoleName  = payload.childRoleName;

         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsTenantAdmin()
                             .addOwnedRole(parentRoleName, SkRoleType.USER)
                             .addOwnedRole(childRoleName, SkRoleType.USER)
                             .setCheckIsSiteAdmin()
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // The requestor will always be non-null after the above check. 
         String user = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
         String tenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();
         
         // Add the child role to the parent.
         int rows = 0;
         try {
             rows = getRoleImpl().addChildRole(tenant, user, roleTenant, parentRoleName, childRoleName);
         } catch (Exception e) {
             String msg = MsgUtils.getMsg("SK_ADD_CHILD_ROLE_ERROR", tenant, user, 
            		                      childRoleName, parentRoleName, roleTenant);
             return getExceptionResponse(e, msg, "Role");
         }

         // Report the number of rows changed.
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Role", parentRoleName), r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* removeChildRole:                                                             */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/removeChild")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response removeChildRole(InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "removeChildRole", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         ReqRemoveChildRole payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_REMOVE_CHILD_ROLE_REQUEST, 
                                   ReqRemoveChildRole.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "removeChildRole", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant     = payload.roleTenant;
         String parentRoleName = payload.parentRoleName;
         String childRoleName  = payload.childRoleName;
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsTenantAdmin()
                             .addOwnedRole(parentRoleName, SkRoleType.USER)
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Create the role.
         int rows = 0;
         try {
             rows = getRoleImpl().removeChildRole(roleTenant, parentRoleName, childRoleName);
         } catch (Exception e) {
             String user = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
             String tenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();
             String msg = MsgUtils.getMsg("SK_DELETE_CHILD_ROLE_ERROR", 
                                          tenant, user, childRoleName, parentRoleName);
             return getExceptionResponse(e, msg, "Role");
         }

         // Report the number of rows changed.
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Role", parentRoleName), r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* previewPathPrefix:                                                           */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/previewPathPrefix")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response previewPathPrefix(InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "previewPathPrefix", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         ReqPreviewPathPrefix payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_PREVIEW_PATH_PREFIX_REQUEST, 
                                   ReqPreviewPathPrefix.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "previewPathPrefix", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
                entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
             
         // Fill in the parameter fields.
         String tenant = payload.tenant;
         String schema = payload.schema;
         String oldSystemId = payload.oldSystemId;
         String newSystemId = payload.newSystemId;
         String oldPrefix = payload.oldPrefix;
         String newPrefix = payload.newPrefix;
         SkRoleDescriptor roleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(payload.roleName, payload.roleType);

         // Canonicalize blank prefix values.
         if (StringUtils.isBlank(oldPrefix)) oldPrefix = "";
         if (StringUtils.isBlank(newPrefix)) newPrefix = "";
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, null)
                 .setRoleTypeRestrictions(roleDescriptor.getRoleType(),
                         NON_ADMIN_ROLES, NON_ADMIN_ROLES, NON_ADMIN_ROLES)
                 .check();
         if (resp != null) {
             return resp;
         }
         
        // ------------------------ Request Processing ------------------------
         // Get the list of transformations that would be appled by replacePathPrefix.
         List<Transformation> transList = null;
         try {
                 transList = getRoleImpl().previewPathPrefix(schema, roleDescriptor,
                                                             oldSystemId, newSystemId, 
                                                             oldPrefix, newPrefix, 
                                                             tenant);
             }
             catch (Exception e) {
                 String msg = MsgUtils.getMsg("SK_PERM_TRANSFORM_FAILED", schema, roleDescriptor.getRoleFullName(),
                                              oldSystemId, oldPrefix, newSystemId, newPrefix,
                                              tenant);
                 _log.error(msg);
                 return Response.status(Status.BAD_REQUEST).
                         entity(TapisRestUtils.createErrorResponse(msg)).build();
             }
         
         // Create the result object with a properly sized transformation array.
         var transArray = new Transformation[transList.size()];
         transArray = transList.toArray(transArray);
         RespPathPrefixes pathPrefixes = new RespPathPrefixes(transArray);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we calculated zero or more transformations. 
         String s = oldSystemId + ":" + oldPrefix;
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_READ", "Permission", s), pathPrefixes)).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* replacePathPrefix:                                                           */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/replacePathPrefix")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response replacePathPrefix(InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "replacePathPrefix", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         ReqReplacePathPrefix payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_REPLACE_PATH_PREFIX_REQUEST, 
                                   ReqReplacePathPrefix.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "replacePathPrefix", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
                entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
             
         // Fill in the parameter fields.
         String tenant = payload.tenant;
         String schema = payload.schema;
         String oldSystemId = payload.oldSystemId;
         String newSystemId = payload.newSystemId;
         String oldPrefix = payload.oldPrefix;
         String newPrefix = payload.newPrefix;
         SkRoleDescriptor roleDescriptor = SkRoleDescriptor.newSkRoleDescriptor(payload.roleName, payload.roleType);
         
         // Canonicalize blank prefix values.
         if (StringUtils.isBlank(oldPrefix)) oldPrefix = "";
         if (StringUtils.isBlank(newPrefix)) newPrefix = "";
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, null)
                             .setCheckIsTenantAdmin()
                             .setCheckIsSiteAdmin()
                             .setCheckIsFilesService()
                             .setRoleTypeRestrictions(roleDescriptor.getRoleType(),
                                     NO_ROLES,
                                     EnumSet.of(SkRoleType.USER, SkRoleType.USER_DEFAULT),
                                     NON_ADMIN_ROLES)
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Calculate the permissions that need to change and apply changes.
         int rows = 0;
         try {
                 rows = getRoleImpl().replacePathPrefix(schema, roleDescriptor,
                                                        oldSystemId, newSystemId, 
                                                        oldPrefix, newPrefix, 
                                                        tenant);
             }
             catch (Exception e) {
                 String msg = MsgUtils.getMsg("SK_PERM_UPDATE_FAILED", schema, roleDescriptor.getRoleFullName(),
                                              oldSystemId, oldPrefix, newSystemId, newPrefix,
                                              tenant, e.getMessage());
                 _log.error(msg);
                 return Response.status(Status.BAD_REQUEST).
                         entity(TapisRestUtils.createErrorResponse(msg)).build();
             }
         
         // ---------------------------- Success ------------------------------- 
         // Success means we updated zero or more permissions. 
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         String s = oldSystemId + ":" + oldPrefix;
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Permission", s), r)).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* getDefaultUserRole:                                                          */
     /* ---------------------------------------------------------------------------- */
     @Deprecated // This is no longer needed.  A default role always has the user's name, and a type of USER_DEFAULT.
     @GET
     @Path("/defaultRole/{user}")
     @Produces(MediaType.APPLICATION_JSON)
     @PermitAll
     public Response getDefaultUserRole(@PathParam("user") String user)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "getDefaultUserRole", _request.getRequestURL());
             _log.trace(msg);
         }

         // ------------------------- Input Processing -------------------------
         // Check input.
         if (StringUtils.isBlank(user)) {
             String msg = MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "getDefaultUserRole", "user");
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         if (user.length() > RoleImpl.MAX_USER_NAME_LEN) {
             String msg = MsgUtils.getMsg("SK_USER_NAME_LEN", "anyTenant", 
                                          user, RoleImpl.MAX_USER_NAME_LEN);
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         
         // ------------------------ Request Processing ------------------------
         // Construct the role name.
         SkRoleDescriptor roleDescriptor = null;
         try {
             roleDescriptor = getUserImpl().getUserDefaultRolename(user);
         } catch (Exception e) {
             return getExceptionResponse(e, null);
         }
         
         // Fill in the response.
         ResultName dftName = new ResultName();
         dftName.name = roleDescriptor.getRoleFullName();
         RespName r = new RespName(dftName);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the tenant's role names.
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_FOUND", "Role", roleDescriptor.getRoleFullName()), r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* removePermissionFromAllRoles:                                                */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/removePermFromAllRoles")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response removePermissionFromAllRoles(InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "removePermissionFromAllRoles", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         ReqRemovePermissionFromAllRoles payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_REMOVE_PERM_FROM_ALL_ROLES_REQUEST, 
                                   ReqRemovePermissionFromAllRoles.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "removeRolePermission", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
             
         // Fill in the parameter fields.
         String reqTenant = payload.tenant;
         String permSpec  = payload.permSpec;
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(reqTenant, null)
                             .setCheckIsSiteAdmin()
                             .setCheckServiceIsAllowed()
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Remove the permission from the role.
         int rows = 0;
         try {rows = getRoleImpl().removePermissionFromRoles(reqTenant, permSpec);} 
         catch (Exception e) {
             // Role not found is an error in this case.
             String requestor = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
             String requestorTenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();
             String msg = MsgUtils.getMsg("SK_REMOVE_PERMISSION_FROM_ROLES_ERROR", requestor,
                                          requestorTenant, permSpec, reqTenant, e.getMessage());
             return getExceptionResponse(e, msg, "Permission", permSpec);
         }

         // Report the number of rows changed.
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Permission", permSpec), r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* removePathPermissionFromAllRoles:                                             */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/removePathPermFromAllRoles")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response removePathPermissionFromAllRoles(InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "removePathPermissionFromAllRoles", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         ReqRemovePermissionFromAllRoles payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_REMOVE_PERM_FROM_ALL_ROLES_REQUEST, 
                                   ReqRemovePermissionFromAllRoles.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "removeRolePermission", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
             
         // Fill in the parameter fields.
         String reqTenant = payload.tenant;
         String permSpec  = payload.permSpec;
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(reqTenant, null)
                             .setCheckIsSiteAdmin()
                             .setCheckIsFilesService()
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Remove the permission from the role.
         int rows = 0;
         try {rows = getRoleImpl().removePathPermissionFromRoles(reqTenant, permSpec);} 
         catch (Exception e) {
             // Role not found is an error in this case.
             String requestor = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
             String requestorTenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();
             String msg = MsgUtils.getMsg("SK_REMOVE_PERMISSION_FROM_ROLES_ERROR", requestor,
                                          requestorTenant, permSpec, reqTenant, e.getMessage());
             return getExceptionResponse(e, msg, "Permission", permSpec);
         }

         // Report the number of rows changed.
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Permission", permSpec), r)).build();
     }
}
