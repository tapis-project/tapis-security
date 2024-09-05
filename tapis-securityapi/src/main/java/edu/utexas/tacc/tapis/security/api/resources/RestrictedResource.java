package edu.utexas.tacc.tapis.security.api.resources;

import java.io.InputStream;
import java.util.List;

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

import edu.utexas.tacc.tapis.security.api.requestBody.ReqAddServiceRolePermission;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqCreateServiceRole;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqRemoveServiceRolePermission;
import edu.utexas.tacc.tapis.security.api.responses.RespRole;
import edu.utexas.tacc.tapis.security.api.utils.SKApiUtils;
import edu.utexas.tacc.tapis.security.api.utils.SKCheckAuthz;
import edu.utexas.tacc.tapis.security.authz.model.SkRole;
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
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

/** This class implements the restricted service API. The API restrict what a service can 
 * do by limiting its runtime access to these resources:
 *
 *  tenant - what tenants the new service can access
 *
 *  user - what users can the new service execute on behalf of (user@tenant)
 *
 *  service - what other services can the new service communicate with
 *
 *  action - what actions can the new service take
 *
 * 
 * @author rcardone
 */
@Path("/restricted/role")
public final class RestrictedResource 
 extends AbstractResource 
{
    /* **************************************************************************** */
    /*                                   Constants                                  */
    /* **************************************************************************** */
    // Local logger.
    private static final Logger _log = LoggerFactory.getLogger(RestrictedResource.class);
    
    // Json schema resource files.
    private static final String FILE_SK_CREATE_ROLE_REQUEST = 
    		"/edu/utexas/tacc/tapis/security/api/jsonschema/CreateRoleRequest.json";
    private static final String FILE_SK_ADD_ROLE_PERM_REQUEST = 
            "/edu/utexas/tacc/tapis/security/api/jsonschema/AddRolePermissionRequest.json";
    private static final String FILE_SK_REMOVE_ROLE_PERM_REQUEST = 
            "/edu/utexas/tacc/tapis/security/api/jsonschema/RemoveRolePermissionRequest.json";

    // The prefix that identifies all restricted service role names.
    private static final String RESTRICTED_SVC_ROLENAME_PREFIX = "$#service_";
    
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
     /* getServiceRoleNames:                                                         */
     /* ---------------------------------------------------------------------------- */
     @GET
     @Path("/{adminTenant}")
     @Produces(MediaType.APPLICATION_JSON)
     @Operation(
             description = "Get the names of all restricted service roles in a site-admin "
             		 + "tenant in alphabetic order.  Restricted service role names have "
             		 + "the format !#service_<service> and are only defined in site-admin "
             		 + "tenants.  The tenant is a required path parameter and must be a "
             		 + "site-admin tenant.\n\n"
                     + ""
                     + "The requestor must be an authenticated user in the tenant or a service."
                     + "",
             tags = "restricted",
             security = {@SecurityRequirement(name = "TapisJWT")},
             responses = 
                 {@ApiResponse(responseCode = "200", description = "List of role names returned.",
                     content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespNameArray.class))),
                  @ApiResponse(responseCode = "400", description = "Input error.",
                     content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class))),
                  @ApiResponse(responseCode = "401", description = "Not authorized.",
                     content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class))),
                  @ApiResponse(responseCode = "500", description = "Server error.",
                     content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class)))}
         )
     public Response getServiceRoleNames(@PathParam("adminTenant") String tenant,
                                         @DefaultValue("false") @QueryParam("pretty") boolean prettyPrint)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "getServiceRoleNames", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         if (!SKApiUtils.isValidName(tenant)) {
        	 String msg = MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "getServiceRoleNames", "tenant", tenant);
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
            		 entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, null)
        		 					 .setPreventNonSiteAdminTenant()
        		 					 .check(prettyPrint);
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Get the rolename list.
         List<String> list = null;
         try {
             list = getRoleImpl().getRestrictedSvcRoleNames(tenant);
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
     /* getServiceRole:                                                              */
     /* ---------------------------------------------------------------------------- */
     @GET
     @Path("/{adminTenant}/{serviceName}")
     @Produces(MediaType.APPLICATION_JSON)
     @Operation(
         description = "Get a restricted service's role given the site-admin tenant in "
         			   + "which the role is defined and the service name.  Restricted "
         			   + "service role names have the format !#service_<service> and are "
         			   + "only defined in site-admin tenants.\n\n"
                       + ""
                       + "The requestor must be an authenticated user in the tenant or a service."
                       + "",
         tags = "restricted",
         security = {@SecurityRequirement(name = "TapisJWT")},
         responses = 
             {@ApiResponse(responseCode = "200", description = "Named role returned.",
               content = @Content(schema = @Schema(
                   implementation = edu.utexas.tacc.tapis.security.api.responses.RespRole.class))),
              @ApiResponse(responseCode = "400", description = "Input error.",
               content = @Content(schema = @Schema(
                  implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class))),
              @ApiResponse(responseCode = "401", description = "Not authorized.",
               content = @Content(schema = @Schema(
                  implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class))),
              @ApiResponse(responseCode = "404", description = "Named role not found.",
                content = @Content(schema = @Schema(
                   implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespName.class))),
              @ApiResponse(responseCode = "500", description = "Server error.",
                content = @Content(schema = @Schema(
                   implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class)))}
     )
     public Response getServiceRole(@PathParam("adminTenant") String tenant,
    		                        @PathParam("serviceName") String serviceName,
                                    @DefaultValue("false") @QueryParam("pretty") boolean prettyPrint)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "getServiceRole", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         if (!SKApiUtils.isValidName(tenant)) {
        	 String msg = MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "getServiceRole", "tenant", tenant);
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
            		 entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }

         // Make sure the restricted service role name conforms to the required format.
         if (!SKApiUtils.isValidName(serviceName)) {
             String msg = MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "getServiceRole", "roleName", serviceName);
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, null)
        		 					 .setPreventNonSiteAdminTenant()
        		 					 .check(prettyPrint);
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Construct the restricted service role name using the service name.
         var roleName = RESTRICTED_SVC_ROLENAME_PREFIX + serviceName;
         
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
     /* getServiceRolePermissions:                                                   */
     /* ---------------------------------------------------------------------------- */
     @GET
     @Path("/{adminTenant}/{serviceName}/perms")
     @Produces(MediaType.APPLICATION_JSON)
     @Operation(
         description = "Get the restricted service role's permissions.\n\n"
                 + ""
                 + "The requestor must be an authenticated user in the tenant or a service."
                 + "",
         tags = "restricted",
         security = {@SecurityRequirement(name = "TapisJWT")},
         responses = 
             {@ApiResponse(responseCode = "200", description = "Named role returned.",
               content = @Content(schema = @Schema(
                   implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespNameArray.class))),
              @ApiResponse(responseCode = "400", description = "Input error.",
               content = @Content(schema = @Schema(
                  implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class))),
              @ApiResponse(responseCode = "401", description = "Not authorized.",
               content = @Content(schema = @Schema(
                  implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class))),
              @ApiResponse(responseCode = "404", description = "Named role not found.",
                content = @Content(schema = @Schema(
                   implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespName.class))),
              @ApiResponse(responseCode = "500", description = "Server error.",
                content = @Content(schema = @Schema(
                   implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class)))}
     )
     public Response getServiceRolePermissions(@PathParam("adminTenant") String tenant,
    		 								   @PathParam("serviceName") String serviceName,
                                               @DefaultValue("false") @QueryParam("pretty") boolean prettyPrint)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "getServiceRolePermissions", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         if (!SKApiUtils.isValidName(tenant)) {
        	 String msg = MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "getServiceRolePermissions", "tenant", tenant);
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
            		 entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }

         // Make sure the restricted service role name conforms to the required format.
         if (!SKApiUtils.isValidName(serviceName)) {
             String msg = MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "getServiceRolePermissions", "roleName", serviceName);
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, null)
        		 					 .setPreventNonSiteAdminTenant()
        		 					 .check(prettyPrint);
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Construct the restricted service role name using the service name.
         var roleName = RESTRICTED_SVC_ROLENAME_PREFIX + serviceName;
         
         // Create the role.
         List<String> list = null;
         try {
        	 final boolean immediate = true;
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
     /* createServiceRole:                                                           */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     @Operation(
             description = "Create a role for a restricted service.  "
             			   + "Parameters include the standard serviceName; the adminTenant, "
             			   + "which is the name of a site-admin tenant; and a description.  "
             			   + "This endpoint will construct a standard restricted "
             			   + "service role name using the serviceName parameter.  Restricted "
             			   + "service role names have the format !#service_<service> and are "
            			   + "only defined in site-admin tenants.\n\n"
             			   + ""
                           + "The desciption can be no more than 2048 characters long.  "
                           + "If the role already exists, this request has no effect.\n\n"
                           + ""
                           + "For the request to be authorized, the requestor must be "
                           + "the administrator in the site-admin tenant."
                           + "",
             tags = "restricted",
             security = {@SecurityRequirement(name = "TapisJWT")},
             requestBody = 
                 @RequestBody(
                     required = true,
                     content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.security.api.requestBody.ReqCreateRole.class))),
             responses = 
                 {@ApiResponse(responseCode = "200", description = "Role existed.",
                      content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespResourceUrl.class))),
                  @ApiResponse(responseCode = "201", description = "Role created.",
                      content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespResourceUrl.class))),
                  @ApiResponse(responseCode = "400", description = "Input error.",
                      content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class))),
                  @ApiResponse(responseCode = "401", description = "Not authorized.",
                      content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class))),
                  @ApiResponse(responseCode = "500", description = "Server error.",
                      content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class)))}
         )
     public Response createServiceRole(@DefaultValue("false") @QueryParam("pretty") boolean prettyPrint,
                                       InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "createServiceRole", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         ReqCreateServiceRole payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_CREATE_ROLE_REQUEST, 
                                   ReqCreateServiceRole.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "createServiceRole", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant  = payload.adminTenant;
         String roleName    = RESTRICTED_SVC_ROLENAME_PREFIX + payload.serviceName;
         String description = payload.description;
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned. The caller must 
         // be an admin in the same tenant as specified in the payload.
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsAdmin()
                             .setPreventDifferentJwtAndReqTenants()
                             .setPreventNonSiteAdminTenant()
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
     /* deleteServiceRoleByName:                                                     */
     /* ---------------------------------------------------------------------------- */
     @DELETE
     @Path("/{adminTenant}/{serviceName}")
     @Produces(MediaType.APPLICATION_JSON)
     @Operation(
         description = "Delete the named role. A valid site admin-tenant and service name "
         			   + "must be provided.\n\n"
                       + ""
                       + "This request is authorized only if the authenticated user is the "
                       + "tenant administrator.\n\n"
                       + "",
         tags = "restricted",
         security = {@SecurityRequirement(name = "TapisJWT")},
         responses = 
             {@ApiResponse(responseCode = "200", description = "Role deleted.",
                 content = @Content(schema = @Schema(
                     implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespChangeCount.class))),
              @ApiResponse(responseCode = "400", description = "Input error.",
                 content = @Content(schema = @Schema(
                     implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class))),
              @ApiResponse(responseCode = "401", description = "Not authorized.",
                 content = @Content(schema = @Schema(
                     implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class))),
              @ApiResponse(responseCode = "500", description = "Server error.",
                 content = @Content(schema = @Schema(
                     implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class)))}
     )
     public Response deleteServiceRoleByName(@PathParam("adminTenant") String tenant,
                                             @PathParam("serviceName") String serviceName,
                                             @DefaultValue("false") @QueryParam("pretty") boolean prettyPrint)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "deleteServiceRoleByName", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Make sure the restricted service role name conforms to the required format.
         if (!SKApiUtils.isValidName(serviceName)) {
             String msg = MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "deleteServiceRoleByName", 
            		                      "serviceName", serviceName);
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
         
         // Construct role name.
         var roleName = RESTRICTED_SVC_ROLENAME_PREFIX + serviceName;
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned. The caller must 
         // be an admin in the same tenant as specified in the query parameter.
         Response resp = SKCheckAuthz.configure(tenant, null)
                             .setCheckIsAdmin()
                             .setPreventDifferentJwtAndReqTenants()
                             .setPreventNonSiteAdminTenant()
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
     /* addServiceRolePermission:                                                    */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/addPerm")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     @Operation(
             description = "Add a resticted service permission to an existing role.  "
                         + "If the exact same permission already exists, "
                         + "then the request has no effect and the change count returned is "
                         + "zero. Otherwise, the permission is added and the change count is one.\n\n"
                         + ""
                         + "In general, permissions are case-sensitive strings that follow the format "
                         + "defined by Apache Shiro (https://shiro.apache.org/permissions.html).  "
                         + "This format defines colon-separated (:) parts, with the "
                         + "possible use of asterisks (*) as wildcards and commas (,) as "
                         + "aggregators.  See the Shiro documentation for further details.\n\n"
                         + ""
                         + "Restricted service permissions must adhere to specific formats "
                         + "that convey well-defined authorization semantics.  The four 'allow' formats "
                         + "are as follows, where the fields enclosed in angle brackets represent "
                         + "user supplied values:\n\n"
                         + ""
                         + "  - service:allow:tenant:<tenant_name>\n"
                         + "  - service:allow:user:<tenant>:<user_name>\n"
                         + "  - service:allow:service:<tenant>:<service_name>\n"
                         + "  - service:allow:action:<tenant>:<target_service>:<action_name>\n\n"
                         + ""
                         + "The first permission type limits the tenants in which a service can "
                         + "run.  The second limits the users on whose behalf the service can "
                         + "operate.  The third specifies the services with which the restricted "
                         + "service can interact.  The fourth limits what actions the restricted service "
                         + "is authorized to request of a target service.\n\n"
                         + ""
                         + "At least one instance of each of the four above permission types need to be "
                         + "defined for a restricted service to successfully make requests.  "
                         + "This fail-safe approach means that restricted services must be fully "
                         + "configured to partipate in a Tapis deployment.\n\n"
                         + ""
                         + "In addition to the above 'allow' permission, there is a complimentary set "
                         + "of 'deny' permission with the same formats, except the second element "
                         + "in each permission string is 'deny' rather than 'allow'.  At runtime, deny "
                         + "permissions are evaluated first and if a match is found, the request is "
                         + "immediately rejected even if an allow permission would have authorized the "
                         + "request." 
                         + ""
                         + "For the request to be authorized, the requestor must be "
                         + "the administrator in the site-admin tenant."
                         + "",
             tags = "restricted",
             security = {@SecurityRequirement(name = "TapisJWT")},
             requestBody = 
                 @RequestBody(
                     required = true,
                     content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.security.api.requestBody.ReqAddRolePermission.class))),
             responses = 
                 {@ApiResponse(responseCode = "200", description = "Permission assigned to role.",
                     content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespChangeCount.class))),
                  @ApiResponse(responseCode = "400", description = "Input error.",
                     content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class))),
                  @ApiResponse(responseCode = "401", description = "Not authorized.",
                     content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class))),
                  @ApiResponse(responseCode = "404", description = "Named role not found.",
                     content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespName.class))),
                  @ApiResponse(responseCode = "500", description = "Server error.",
                     content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class)))}
         )
     public Response addServiceRolePermission(@DefaultValue("false") @QueryParam("pretty") boolean prettyPrint,
                                              InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "addServiceRolePermission", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         ReqAddServiceRolePermission payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_ADD_ROLE_PERM_REQUEST, 
                                   ReqAddServiceRolePermission.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "addServiceRolePermission", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
                entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant = payload.adminTenant;
         String roleName   = RESTRICTED_SVC_ROLENAME_PREFIX + payload.serviceName;
         String permSpec   = payload.permSpec;  // format already validated
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned. The caller must 
         // be an admin in the same tenant as specified in the payload
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsAdmin()
                             .setPreventDifferentJwtAndReqTenants()
                             .setPreventNonSiteAdminTenant()
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
     /* removeServiceRolePermission:                                                 */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/removePerm")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     @Operation(
             description = "Remove a permission from a role.  "
                     + "A valid serviceName, adminTenant and permission must be "
                     + "specified in the request body.\n\n"
                     + ""
                     + "For the request to be authorized, the requestor must be "
                     + "the administrator in the site-admin tenant."
                     + "",
             tags = "restricted",
             security = {@SecurityRequirement(name = "TapisJWT")},
             requestBody = 
                 @RequestBody(
                     required = true,
                     content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.security.api.requestBody.ReqRemoveRolePermission.class))),
             responses = 
                 {@ApiResponse(responseCode = "200", description = "Permission removed from role.",
                      content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespChangeCount.class))),
                  @ApiResponse(responseCode = "400", description = "Input error.",
                     content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class))),
                  @ApiResponse(responseCode = "401", description = "Not authorized.",
                     content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class))),
                  @ApiResponse(responseCode = "404", description = "Named role not found.",
                      content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespName.class))),
                  @ApiResponse(responseCode = "500", description = "Server error.",
                      content = @Content(schema = @Schema(
                         implementation = edu.utexas.tacc.tapis.sharedapi.responses.RespBasic.class)))}
         )
     public Response removeServiceRolePermission(@DefaultValue("false") @QueryParam("pretty") boolean prettyPrint,
                                                 InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "removeServiceRolePermission", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         ReqRemoveServiceRolePermission payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_REMOVE_ROLE_PERM_REQUEST, 
        		 				   ReqRemoveServiceRolePermission.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "removeServiceRolePermission", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
         }
             
         // Fill in the parameter fields.
         String roleTenant = payload.adminTenant;
         String roleName   = RESTRICTED_SVC_ROLENAME_PREFIX + payload.serviceName;
         String permSpec   = payload.permSpec; // format already validated
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned. The caller must 
         // be an admin in the same tenant as specified in the payload
         Response resp = SKCheckAuthz.configure(roleTenant, null)
                             .setCheckIsAdmin()
                             .setPreventDifferentJwtAndReqTenants()
                             .setPreventNonSiteAdminTenant()
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
}
