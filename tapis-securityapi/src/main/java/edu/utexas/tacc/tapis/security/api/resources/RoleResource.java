package edu.utexas.tacc.tapis.security.api.resources;

import java.io.InputStream;
import java.util.List;

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
                                  @DefaultValue("false") @QueryParam("pretty") boolean prettyPrint)
     {
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
                     entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }

         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, null).check(prettyPrint);
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Create the role.
         List<String> list = null;
         try {
             list = getRoleImpl().getRoleNames(tenant);
         } catch (Exception e) {
             String msg = MsgUtils.getMsg("SK_ROLE_GET_NAMES_ERROR", tenant, 
                                          TapisThreadLocal.tapisThreadContext.get().getJwtUser());
             return getExceptionResponse(e, msg, prettyPrint);
         }
         
         // Assign result.
         ResultNameArray names = new ResultNameArray();
         names.names = list.toArray(new String[list.size()]);
         RespNameArray r = new RespNameArray(names);

         // ---------------------------- Success ------------------------------- 
         // Success means we found the tenant's role names.
         int cnt = names.names.length;
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_FOUND", "Roles", cnt + " items"), prettyPrint, r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* getRoleByName:                                                               */
     /* ---------------------------------------------------------------------------- */
     @GET
     @Path("/{roleName}")
     @Produces(MediaType.APPLICATION_JSON)
     public Response getRoleByName(@PathParam("roleName") String roleName,
                                   @QueryParam("tenant") String tenant,
                                   @DefaultValue("false") @QueryParam("pretty") boolean prettyPrint)
     {
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
                     entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }

         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, null).check(prettyPrint);
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Get the role.
         SkRole role = null;
         try {
             role = getRoleImpl().getRoleByName(tenant, roleName);
         } catch (Exception e) {
             String msg = MsgUtils.getMsg("SK_ROLE_GET_ERROR", tenant,
                                          TapisThreadLocal.tapisThreadContext.get().getJwtUser(), 
                                          roleName);
             return getExceptionResponse(e, msg, prettyPrint);
         }

         // Adjust status based on whether we found the role.
         if (role == null) {
             ResultName missingName = new ResultName();
             missingName.name = roleName;
             RespName r = new RespName(missingName);
             return Response.status(Status.NOT_FOUND).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg("TAPIS_NOT_FOUND", "Role", roleName), prettyPrint, r)).build();
         }
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         RespRole r = new RespRole(role);
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_FOUND", "Role", roleName), prettyPrint, r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* createRole:                                                                  */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response createRole(@DefaultValue("false") @QueryParam("pretty") boolean prettyPrint,
                                InputStream payloadStream)
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
               entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant  = payload.roleTenant;
         String roleName    = payload.roleName;
         String description = payload.description;
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsService()
                             .setCheckIsAdmin()
                             .setPreventForeignTenantUpdate()
                             .check(prettyPrint);
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // The threadlocal object has been validated by now.
         String owner = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
         String ownerTenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();

         // Create the role.
         int rows = 0;
         try {rows = getRoleImpl().createRole(roleName, roleTenant, description, owner, ownerTenant);}
         catch (Exception e) {
             String msg = MsgUtils.getMsg("SK_ROLE_CREATE_ERROR", roleName, roleTenant, owner, ownerTenant);
             return getExceptionResponse(e, msg, prettyPrint);
         }
         
         // NOTE: We need to assign a location header as well.
         //       See https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9.5.
         ResultResourceUrl respUrl = new ResultResourceUrl();
         respUrl.url = SKApiUtils.constructTenantURL(roleTenant, _request.getRequestURI(), roleName);
         RespResourceUrl r = new RespResourceUrl(respUrl);
         
         // ---------------------------- Success ------------------------------- 
         // No new rows means the role exists. 
         if (rows == 0)
             return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg("TAPIS_EXISTED", "Role", roleName+"@"+roleTenant), prettyPrint, r)).build();
         else 
             return Response.status(Status.CREATED).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg("TAPIS_CREATED", "Role", roleName+"@"+roleTenant), prettyPrint, r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* deleteRoleByName:                                                            */
     /* ---------------------------------------------------------------------------- */
     @DELETE
     @Path("/{roleName}")
     @Produces(MediaType.APPLICATION_JSON)
     public Response deleteRoleByName(@PathParam("roleName") String roleName,
                                      @QueryParam("tenant") String tenant,
                                      @DefaultValue("false") @QueryParam("pretty") boolean prettyPrint)
     {
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
                     entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, null)
                             .setCheckIsAdmin()
                             .addOwnedRole(roleName)
                             .check(prettyPrint);
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Delete the role.
         int rows = 0;
         try {rows =  getRoleImpl().deleteRoleByName(tenant, roleName);}
         catch (Exception e) {
        	 // The threadlocal value has been validated.
             String msg = MsgUtils.getMsg("SK_ROLE_DELETE_ERROR", tenant, 
            		                      TapisThreadLocal.tapisThreadContext.get().getJwtUser(), 
            		                      roleName);
             return getExceptionResponse(e, msg, prettyPrint);
         }
         
         // Return the number of row affected.
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we deleted the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_DELETED", "Role", roleName), prettyPrint, r)).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* getRolePermissions:                                                          */
     /* ---------------------------------------------------------------------------- */
     @GET
     @Path("/{roleName}/perms")
     @Produces(MediaType.APPLICATION_JSON)
     public Response getRolePermissions(@PathParam("roleName") String roleName,
                                        @QueryParam("tenant") String tenant,
                                        @DefaultValue("false") @QueryParam("immediate") boolean immediate,
                                        @DefaultValue("false") @QueryParam("pretty") boolean prettyPrint)
     {
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
                     entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, null).check(prettyPrint);
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Create the role.
         List<String> list = null;
         try {
             list = getRoleImpl().getRolePermissions(tenant, roleName, immediate);
         } catch (Exception e) {
             String msg = MsgUtils.getMsg("SK_ROLE_GET_PERMISSIONS_ERROR",tenant, 
                                          TapisThreadLocal.tapisThreadContext.get().getJwtUser(), 
                                          roleName);
             return getExceptionResponse(e, msg, prettyPrint);
         }

         // Assign result.
         ResultNameArray names = new ResultNameArray();
         names.names = list.toArray(new String[list.size()]);
         RespNameArray r = new RespNameArray(names);

         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         int cnt = names.names.length;
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_FOUND", "Permissions", cnt + " permissions"), prettyPrint, r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* updateRoleName:                                                              */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/updateName/{roleName}")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response updateRoleName(@PathParam("roleName") String roleName,
                                    @DefaultValue("false") @QueryParam("pretty") boolean prettyPrint,
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
               entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
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
               entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant  = payload.roleTenant;
         String newRoleName = payload.newRoleName;
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsAdmin()
                             .addOwnedRole(roleName)
                             .check(prettyPrint);
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // The threadlocal object has been validated by now.
         String requestor = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
         String requestorTenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();
         
         // Create the role.
         int rows = 0;
         try {
             rows = getRoleImpl().updateRoleName(roleTenant, roleName, newRoleName, 
            		                             requestor, requestorTenant);
         } catch (Exception e) {
             String msg = MsgUtils.getMsg("SK_ROLE_UPDATE_ERROR", roleTenant, roleName, 
            		                      requestor, requestorTenant);
             return getExceptionResponse(e, msg, prettyPrint, "Role");
         }

         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Role", roleName), prettyPrint)).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* updateRoleOwner:                                                             */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/updateOwner/{roleName}")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response updateRoleOwner(@PathParam("roleName") String roleName,
                                     @DefaultValue("false") @QueryParam("pretty") boolean prettyPrint,
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
               entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
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
               entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant = payload.roleTenant;
         String newOwner   = payload.newOwner;
         String newTenant  = payload.newTenant; // optional, can be null or empty
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsAdmin()
                             .addOwnedRole(roleName)
                             .setPreventInvalidOwnerAssignment(newTenant)
                             .check(prettyPrint);
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // The threadlocal object has been validated by now.
         String requestor = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
         String requestorTenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();
         
         // Create the role.
         int rows = 0;
         try {
        	 // The new tenant can be null.
             rows = getRoleImpl().updateRoleOwner(roleTenant, roleName, newOwner, newTenant,
            		                              requestor, requestorTenant);
         } catch (Exception e) {
             String msg = MsgUtils.getMsg("SK_ROLE_UPDATE_ERROR", roleTenant, roleName, 
                                          requestor, requestorTenant);
             return getExceptionResponse(e, msg, prettyPrint, "Role");
         }
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Role", roleName), prettyPrint)).build();
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
                                @DefaultValue("false") @QueryParam("pretty") boolean prettyPrint,
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
               entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
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
                entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant     = payload.roleTenant;
         String newDescription = payload.newDescription;
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsAdmin()
                             .addOwnedRole(roleName)
                             .check(prettyPrint);
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // The threadlocal object has been validated by now.
         String requestor = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
         String requestorTenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();
         
         // Create the role.
         int rows = 0;
         try {
             rows = getRoleImpl().updateRoleDescription(roleTenant, roleName, newDescription,
            		                                    requestor, requestorTenant);
         } catch (Exception e) {
             String msg = MsgUtils.getMsg("SK_ROLE_UPDATE_ERROR", roleTenant, roleName, 
                                          requestor, requestorTenant);
             return getExceptionResponse(e, msg, prettyPrint, "Role");
         }
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Role", roleName), prettyPrint)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* addRolePermission:                                                           */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/addPerm")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response addRolePermission(@DefaultValue("false") @QueryParam("pretty") boolean prettyPrint,
                                       InputStream payloadStream)
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
                entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant = payload.roleTenant;
         String roleName   = payload.roleName;
         String permSpec   = payload.permSpec;
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsAdmin()
                             .addOwnedRole(roleName)
                             .check(prettyPrint);
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // The threadlocal object has been validated by now.
         String requestor = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
         String requestorTenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();
         
         // Add permission to role.
         int rows = 0;
         try {
             rows = getRoleImpl().addRolePermission(roleTenant, roleName, permSpec, requestor, requestorTenant);
         } catch (Exception e) {
             // This only occurs when the role name is not found.
             String msg = MsgUtils.getMsg("SK_ADD_PERMISSION_ERROR", requestor, requestorTenant, permSpec, 
            		                      roleName, roleTenant);
             return getExceptionResponse(e, msg, prettyPrint, "Role", roleName);
         }

         // Report the number of rows changed.
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Role", roleName), prettyPrint, r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* removeRolePermission:                                                        */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/removePerm")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response removeRolePermission(@DefaultValue("false") @QueryParam("pretty") boolean prettyPrint,
                                          InputStream payloadStream)
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
               entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant = payload.roleTenant;
         String roleName   = payload.roleName;
         String permSpec   = payload.permSpec;
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsAdmin()
                             .addOwnedRole(roleName)
                             .check(prettyPrint);
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Remove the permission from the role.
         int rows = 0;
         try {rows = getRoleImpl().removeRolePermission(roleTenant, roleName, permSpec);} 
         catch (Exception e) {
             // Role not found is an error in this case.
             String requestor = TapisThreadLocal.tapisThreadContext.get().getJwtUser();
             String requestorTenant = TapisThreadLocal.tapisThreadContext.get().getJwtTenantId();
             String msg = MsgUtils.getMsg("SK_REMOVE_PERMISSION_ERROR", requestor,
            		                      requestorTenant, permSpec, roleName, roleTenant);
             return getExceptionResponse(e, msg, prettyPrint, "Role", roleName);
         }

         // Report the number of rows changed.
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Role", roleName), prettyPrint, r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* addChildRole:                                                                */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/addChild")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response addChildRole(@DefaultValue("false") @QueryParam("pretty") boolean prettyPrint,
                                  InputStream payloadStream)
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
               entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant     = payload.roleTenant; 
         String parentRoleName = payload.parentRoleName;
         String childRoleName  = payload.childRoleName;
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsAdmin()
                             .addOwnedRole(parentRoleName)
                             .addOwnedRole(childRoleName)
                             .check(prettyPrint);
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
             return getExceptionResponse(e, msg, prettyPrint, "Role");
         }

         // Report the number of rows changed.
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Role", parentRoleName), prettyPrint, r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* removeChildRole:                                                             */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/removeChild")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response removeChildRole(@DefaultValue("false") @QueryParam("pretty") boolean prettyPrint,
                                     InputStream payloadStream)
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
               entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant     = payload.roleTenant;
         String parentRoleName = payload.parentRoleName;
         String childRoleName  = payload.childRoleName;
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsAdmin()
                             .addOwnedRole(parentRoleName)
                             .check(prettyPrint);
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
             return getExceptionResponse(e, msg, prettyPrint, "Role");
         }

         // Report the number of rows changed.
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Role", parentRoleName), prettyPrint, r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* previewPathPrefix:                                                           */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/previewPathPrefix")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response previewPathPrefix(@DefaultValue("false") @QueryParam("pretty") boolean prettyPrint,
                                       InputStream payloadStream)
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
                entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
             
         // Fill in the parameter fields.
         String tenant = payload.tenant;
         String schema = payload.schema;
         String roleName = payload.roleName;
         String oldSystemId = payload.oldSystemId;
         String newSystemId = payload.newSystemId;
         String oldPrefix = payload.oldPrefix;
         String newPrefix = payload.newPrefix;
         
         // Canonicalize blank prefix values.
         if (StringUtils.isBlank(oldPrefix)) oldPrefix = "";
         if (StringUtils.isBlank(newPrefix)) newPrefix = "";
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, null).check(prettyPrint);
         if (resp != null) return resp;
         
        // ------------------------ Request Processing ------------------------
         // Get the list of transformations that would be appled by replacePathPrefix.
         List<Transformation> transList = null;
         try {
                 transList = getRoleImpl().previewPathPrefix(schema, roleName, 
                                                             oldSystemId, newSystemId, 
                                                             oldPrefix, newPrefix, 
                                                             tenant);
             }
             catch (Exception e) {
                 String msg = MsgUtils.getMsg("SK_PERM_TRANSFORM_FAILED", schema, roleName,
                                              oldSystemId, oldPrefix, newSystemId, newPrefix,
                                              tenant);
                 _log.error(msg);
                 return Response.status(Status.BAD_REQUEST).
                         entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
             }
         
         // Create the result object with a properly sized transformation array.
         var transArray = new Transformation[transList.size()];
         transArray = transList.toArray(transArray);
         RespPathPrefixes pathPrefixes = new RespPathPrefixes(transArray);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we calculated zero or more transformations. 
         String s = oldSystemId + ":" + oldPrefix;
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_READ", "Permission", s), prettyPrint, pathPrefixes)).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* replacePathPrefix:                                                           */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/replacePathPrefix")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response replacePathPrefix(@DefaultValue("false") @QueryParam("pretty") boolean prettyPrint,
                                       InputStream payloadStream)
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
                entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
             
         // Fill in the parameter fields.
         String tenant = payload.tenant;
         String schema = payload.schema;
         String roleName = payload.roleName;
         String oldSystemId = payload.oldSystemId;
         String newSystemId = payload.newSystemId;
         String oldPrefix = payload.oldPrefix;
         String newPrefix = payload.newPrefix;
         
         // Canonicalize blank prefix values.
         if (StringUtils.isBlank(oldPrefix)) oldPrefix = "";
         if (StringUtils.isBlank(newPrefix)) newPrefix = "";
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, null)
                             .setCheckIsAdmin()
                             .setCheckIsFilesService()
                             .check(prettyPrint);
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Calculate the permissions that need to change and apply changes.
         int rows = 0;
         try {
                 rows = getRoleImpl().replacePathPrefix(schema, roleName, 
                                                        oldSystemId, newSystemId, 
                                                        oldPrefix, newPrefix, 
                                                        tenant);
             }
             catch (Exception e) {
                 String msg = MsgUtils.getMsg("SK_PERM_UPDATE_FAILED", schema, roleName,
                                              oldSystemId, oldPrefix, newSystemId, newPrefix,
                                              tenant, e.getMessage());
                 _log.error(msg);
                 return Response.status(Status.BAD_REQUEST).
                         entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
             }
         
         // ---------------------------- Success ------------------------------- 
         // Success means we updated zero or more permissions. 
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         String s = oldSystemId + ":" + oldPrefix;
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Permission", s), prettyPrint, r)).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* getDefaultUserRole:                                                          */
     /* ---------------------------------------------------------------------------- */
     @GET
     @Path("/defaultRole/{user}")
     @Produces(MediaType.APPLICATION_JSON)
     @PermitAll
     public Response getDefaultUserRole(@PathParam("user") String user,
                                        @DefaultValue("false") @QueryParam("pretty") boolean prettyPrint)
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
                     entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
         if (user.length() > RoleImpl.MAX_USER_NAME_LEN) {
             String msg = MsgUtils.getMsg("SK_USER_NAME_LEN", "anyTenant", 
                                          user, RoleImpl.MAX_USER_NAME_LEN);
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
         
         // ------------------------ Request Processing ------------------------
         // Construct the role name.
         String name = null;
         try {name = getUserImpl().getUserDefaultRolename(user);}
         catch (Exception e) {
             return getExceptionResponse(e, null, prettyPrint);
         }
         
         // Fill in the response.
         ResultName dftName = new ResultName();
         dftName.name = name;
         RespName r = new RespName(dftName);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the tenant's role names.
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_FOUND", "Role", name), prettyPrint, r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* removePermissionFromAllRoles:                                                */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/removePermFromAllRoles")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response removePermissionFromAllRoles(@DefaultValue("false") @QueryParam("pretty") boolean prettyPrint,
                                                  InputStream payloadStream)
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
               entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
             
         // Fill in the parameter fields.
         String reqTenant = payload.tenant;
         String permSpec  = payload.permSpec;
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(reqTenant, null)
                             .setCheckIsService()
                             .check(prettyPrint);
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
             return getExceptionResponse(e, msg, prettyPrint, "Permission", permSpec);
         }

         // Report the number of rows changed.
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Permission", permSpec), prettyPrint, r)).build();
     }

     /* ---------------------------------------------------------------------------- */
     /* removePathPermissionFromAllRoles:                                             */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/removePathPermFromAllRoles")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response removePathPermissionFromAllRoles(@DefaultValue("false") @QueryParam("pretty") boolean prettyPrint,
                                                      InputStream payloadStream)
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
               entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
             
         // Fill in the parameter fields.
         String reqTenant = payload.tenant;
         String permSpec  = payload.permSpec;
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(reqTenant, null)
                             .setCheckIsFilesService()
                             .check(prettyPrint);
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
             return getExceptionResponse(e, msg, prettyPrint, "Permission", permSpec);
         }

         // Report the number of rows changed.
         ResultChangeCount count = new ResultChangeCount();
         count.changes = rows;
         RespChangeCount r = new RespChangeCount(count);
         
         // ---------------------------- Success ------------------------------- 
         // Success means we found the role. 
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
             MsgUtils.getMsg("TAPIS_UPDATED", "Permission", permSpec), prettyPrint, r)).build();
     }
}
