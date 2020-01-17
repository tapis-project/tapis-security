package edu.utexas.tacc.tapis.systems.api.resources;

import com.google.gson.JsonObject;

import edu.utexas.tacc.tapis.shared.exceptions.TapisJSONException;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import edu.utexas.tacc.tapis.shared.schema.JsonValidator;
import edu.utexas.tacc.tapis.shared.schema.JsonValidatorSpec;
import edu.utexas.tacc.tapis.shared.threadlocal.TapisThreadContext;
import edu.utexas.tacc.tapis.shared.threadlocal.TapisThreadLocal;
import edu.utexas.tacc.tapis.shared.utils.TapisGsonUtils;
import edu.utexas.tacc.tapis.sharedapi.responses.RespBasic;
import edu.utexas.tacc.tapis.sharedapi.responses.RespNameArray;
import edu.utexas.tacc.tapis.sharedapi.utils.RestUtils;
import edu.utexas.tacc.tapis.sharedapi.utils.TapisRestUtils;
import edu.utexas.tacc.tapis.systems.api.requests.ReqCreateCredential;
import edu.utexas.tacc.tapis.systems.api.responses.RespCredential;
import edu.utexas.tacc.tapis.systems.api.utils.ApiUtils;
import edu.utexas.tacc.tapis.systems.model.Credential;
import edu.utexas.tacc.tapis.systems.service.SystemsService;
import edu.utexas.tacc.tapis.systems.service.SystemsServiceImpl;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

/*
 * JAX-RS REST resource for Tapis System credentials
 * Contains annotations which generate the OpenAPI specification documents.
 * Annotations map HTTP verb + endpoint to method invocation.
 * Secrets are stored in the Security Kernel
 *
 */
@Path("/credential")
public class CredentialResource
{
  // ************************************************************************
  // *********************** Constants **************************************
  // ************************************************************************
  // Local logger.
  private static final Logger _log = LoggerFactory.getLogger(CredentialResource.class);

  // Json schema resource files.
  private static final String FILE_CRED_REQUEST = "/edu/utexas/tacc/tapis/systems/api/jsonschema/CredentialCreateRequest.json";

  // ************************************************************************
  // *********************** Fields *****************************************
  // ************************************************************************
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
  private HttpHeaders _httpHeaders;
  @Context
  private Application _application;
  @Context
  private UriInfo _uriInfo;
  @Context
  private SecurityContext _securityContext;
  @Context
  private ServletContext _servletContext;
  @Context
  private HttpServletRequest _request;

  // **************** Inject Services ****************
//  @com.google.inject.Inject
  private SystemsService systemsService = null;

  // ************************************************************************
  // *********************** Public Methods *********************************
  // ************************************************************************

  /**
   * Store or update credential for given system and user.
   * @param prettyPrint - pretty print the output
   * @param payloadStream - request body
   * @return basic response
   */
  @POST
  @Path("/{systemName}/user/{userName}")
  @Produces(MediaType.APPLICATION_JSON)
  @Consumes(MediaType.APPLICATION_JSON)
  @Operation(
    summary = "Create or update access credential in the Security Kernel for given system and user",
    description =
        "Create or update access credential in the Security Kernel for given system and user using a request body. " +
        " Requester must be owner of the system.",
    tags = "credentials",
    requestBody =
      @RequestBody(
        description = "A JSON object specifying a credential.",
        required = true,
        content = @Content(schema = @Schema(implementation = ReqCreateCredential.class))
      ),
    responses = {
      @ApiResponse(responseCode = "200", description = "Credential updated.",
        content = @Content(schema = @Schema(implementation = RespBasic.class))),
      @ApiResponse(responseCode = "400", description = "Input error. Invalid JSON.",
        content = @Content(schema = @Schema(implementation = RespBasic.class))),
      @ApiResponse(responseCode = "401", description = "Not authorized.",
        content = @Content(schema = @Schema(implementation = RespBasic.class))),
      @ApiResponse(responseCode = "500", description = "Server error.",
        content = @Content(schema = @Schema(implementation = RespBasic.class)))
    }
  )
  public Response createUserCredential(@PathParam("systemName") String systemName,
                                       @PathParam("userName") String userName,
                                       @QueryParam("pretty") @DefaultValue("false") boolean prettyPrint,
                                       InputStream payloadStream)
  {
    systemsService = getSystemsService();
    String msg;
    TapisThreadContext threadContext = TapisThreadLocal.tapisThreadContext.get(); // Local thread context

    // Trace this request.
    if (_log.isTraceEnabled())
    {
      msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), "createUserCredential",
                                   "  " + _request.getRequestURL());
      _log.trace(msg);
    }

    // Check that we have all we need from the context, tenant name and apiUserId
    // Utility method returns null if all OK and appropriate error response if there was a problem.
    Response resp = ApiUtils.checkContext(threadContext, prettyPrint);
    if (resp != null) return resp;

    // Get tenant and apiUserId from context
    String tenantName = threadContext.getTenantId();
    String apiUserId = threadContext.getUser();

    // ------------------------- Check authorization -------------------------
    // ------------------------- Check prerequisites -------------------------
    // Check that the system exists and that requester is owner
    resp = ApiUtils.checkSystemAndOwner(systemsService, tenantName, systemName, userName, prettyPrint, apiUserId,
                                "createUserCredential", true);
    if (resp != null) return resp;

    // ------------------------- Extract and validate payload -------------------------
    // Read the payload into a string.
    String json;
    try { json = IOUtils.toString(payloadStream, StandardCharsets.UTF_8); }
    catch (Exception e)
    {
      msg = ApiUtils.getMsg("SYSAPI_CRED_JSON_ERROR", systemName, userName, e.getMessage());
      _log.error(msg, e);
      return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
    }
    // Create validator specification and validate the json against the schema
    JsonValidatorSpec spec = new JsonValidatorSpec(json, FILE_CRED_REQUEST);
    try { JsonValidator.validate(spec); }
    catch (TapisJSONException e)
    {
      msg = ApiUtils.getMsg("SYSAPI_CRED_JSON_INVALID", systemName, userName, e.getMessage());
      _log.error(msg, e);
      return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
    }

    // Populate credential from payload
    char[] password, privateKey, publicKey, cert, accessKey, accessSecret;
    JsonObject credObj = TapisGsonUtils.getGson().fromJson(json, JsonObject.class);
    // Extract credential attributes from the request body
    password = ApiUtils.getValS(credObj.get("password"), "").toCharArray();
    privateKey = ApiUtils.getValS(credObj.get("privateKey"), "").toCharArray();
    publicKey = ApiUtils.getValS(credObj.get("publicKey"), "").toCharArray();
    cert = ApiUtils.getValS(credObj.get("sshCert"), "").toCharArray();
    accessKey = ApiUtils.getValS(credObj.get("accessKey"), "").toCharArray();
    accessSecret = ApiUtils.getValS(credObj.get("accessSecret"), "").toCharArray();
    Credential credential = new Credential(null, null, null, null, null,
            password, privateKey, publicKey, cert, accessKey, accessSecret);

    // TODO It would be good to collect and report as many errors as possible so they can all be fixed before next attempt
//    msg = null;
//    // Check values. We should have at least one permission
////    if (perms == null || perms.size() <= 0)
////    {
////      msg = ApiUtils.getMsg("SYSAPI_PERMS_NOPERMS", systemName, userName);
////    }
//    // If validation failed log error message and return response
//    if (msg != null)
//    {
//      _log.error(msg);
//      return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
//    }

    // ------------------------- Perform the operation -------------------------
    // Make the service call to create or update the credential
    try
    {
      systemsService.createUserCredential(tenantName, systemName, userName, credential);
    }
    catch (Exception e)
    {
      msg = ApiUtils.getMsg("SYSAPI_CRED_ERROR", null, systemName, userName, e.getMessage());
      _log.error(msg, e);
      return Response.status(Status.INTERNAL_SERVER_ERROR).entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
    }

    // ---------------------------- Success -------------------------------
    RespBasic resp1 = new RespBasic();
    return Response.status(Status.CREATED)
      .entity(TapisRestUtils.createSuccessResponse(ApiUtils.getMsg("SYSAPI_CRED_UPDATED", null, systemName, userName),
                                                   prettyPrint, resp1))
      .build();
  }

  /**
   * getUserCredential
   * @param prettyPrint - pretty print the output
   * @return Response
   */
  @GET
  @Path("/{systemName}/user/{userName}")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      summary = "Retrieve credential for given system and user",
      description = "Retrieve credential for given system and user. Requester must be owner of the system.",
      tags = "credentials",
      responses = {
          @ApiResponse(responseCode = "200", description = "Success.",
            content = @Content(schema = @Schema(implementation = RespNameArray.class))),
          @ApiResponse(responseCode = "400", description = "Input error.",
            content = @Content(schema = @Schema(implementation = RespBasic.class))),
          @ApiResponse(responseCode = "404", description = "System not found.",
            content = @Content(schema = @Schema(implementation = RespBasic.class))),
          @ApiResponse(responseCode = "401", description = "Not authorized.",
            content = @Content(schema = @Schema(implementation = RespBasic.class))),
          @ApiResponse(responseCode = "500", description = "Server error.",
            content = @Content(schema = @Schema(implementation = RespBasic.class)))
      }
  )
  public Response getUserCredential(@PathParam("systemName") String systemName,
                                    @PathParam("userName") String userName,
                                    @QueryParam("pretty") @DefaultValue("false") boolean prettyPrint)
  {
    systemsService = getSystemsService();
    String msg;
    TapisThreadContext threadContext = TapisThreadLocal.tapisThreadContext.get(); // Local thread context

    // Trace this request.
    if (_log.isTraceEnabled())
    {
      msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), "getUserCredential",
                                   "  " + _request.getRequestURL());
      _log.trace(msg);
    }

    // Check that we have all we need from the context, the tenant name and apiUserId
    // Utility method returns null if all OK and appropriate error response if there was a problem.
    Response resp = ApiUtils.checkContext(threadContext, prettyPrint);
    if (resp != null) return resp;

    // Get tenant and apiUserId from context
    String tenantName = threadContext.getTenantId();
    String apiUserId = threadContext.getUser();

    // ------------------------- Check prerequisites -------------------------
    // Check that the system exists and that requester is owner
    resp = ApiUtils.checkSystemAndOwner(systemsService, tenantName, systemName, userName, prettyPrint, apiUserId,
                                "getUserCredential", true);
    if (resp != null) return resp;

    // ------------------------- Perform the operation -------------------------
    // Make the service call to get the permissions
    Credential credential;
    try { credential = systemsService.getUserCredential(tenantName, systemName, userName); }
    catch (Exception e)
    {
      msg = ApiUtils.getMsg("SYSAPI_CRED_ERROR", null, systemName, userName, e.getMessage());
      _log.error(msg, e);
      return Response.status(RestUtils.getStatus(e)).entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
    }

    // Resource was not found.
    if (credential == null)
    {
      msg = ApiUtils.getMsg("SYSAPI_CRED_NOT_FOUND", null, systemName, userName);
      _log.warn(msg);
      return Response.status(Status.NOT_FOUND).entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
    }

    // ---------------------------- Success -------------------------------
    // Success means we retrieved the information.
    RespCredential resp1 = new RespCredential(credential);
    return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
            ApiUtils.getMsg("SYSAPI_CRED_FOUND", systemName, userName), prettyPrint, resp1)).build();
  }

  /**
   * Remove credential for given system and user.
   * @param prettyPrint - pretty print the output
   * @return basic response
   */
  @DELETE
  @Path("/{systemName}/user/{userName}")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
    summary = "Remove credential in the Security Kernel for given system and user",
    description =
      "Remove credential from the Security Kernel for given system and user. Requester must be owner of the system.",
    tags = "credentials",
    responses = {
      @ApiResponse(responseCode = "200", description = "Permission revoked.",
        content = @Content(schema = @Schema(implementation = RespBasic.class))),
      @ApiResponse(responseCode = "400", description = "Input error. Invalid JSON.",
        content = @Content(schema = @Schema(implementation = RespBasic.class))),
      @ApiResponse(responseCode = "401", description = "Not authorized.",
        content = @Content(schema = @Schema(implementation = RespBasic.class))),
      @ApiResponse(responseCode = "500", description = "Server error.",
        content = @Content(schema = @Schema(implementation = RespBasic.class)))
    }
  )
  public Response removeUserCredential(@PathParam("systemName") String systemName,
                                       @PathParam("userName") String userName,
                                       @QueryParam("pretty") @DefaultValue("false") boolean prettyPrint)
  {
    systemsService = getSystemsService();
    String msg;
    TapisThreadContext threadContext = TapisThreadLocal.tapisThreadContext.get(); // Local thread context

    // Trace this request.
    if (_log.isTraceEnabled())
    {
      msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), "removeUserCredential",
                            "  " + _request.getRequestURL());
      _log.trace(msg);
    }

    // Check that we have all we need from the context, tenant name and apiUserId
    // Utility method returns null if all OK and appropriate error response if there was a problem.
    Response resp = ApiUtils.checkContext(threadContext, prettyPrint);
    if (resp != null) return resp;

    // Get tenant and apiUserId from context
    String tenantName = threadContext.getTenantId();
    String apiUserId = threadContext.getUser();

    // ------------------------- Check authorization -------------------------
    // ------------------------- Check prerequisites -------------------------
    // Check that the system exists and that requester is owner
    resp = ApiUtils.checkSystemAndOwner(systemsService, tenantName, systemName, userName, prettyPrint, apiUserId,
                                       "removeUserCredential", true);
    if (resp != null) return resp;

    // ------------------------- Perform the operation -------------------------
    // Make the service call to remove the credential
    try
    {
      systemsService.deleteUserCredential(tenantName, systemName, userName);
    }
    catch (Exception e)
    {
      msg = ApiUtils.getMsg("SYSAPI_PERMS_ERROR", null, systemName, userName, e.getMessage());
      _log.error(msg, e);
      return Response.status(Status.INTERNAL_SERVER_ERROR).entity(TapisRestUtils.createErrorResponse(msg, prettyPrint)).build();
    }

    // ---------------------------- Success -------------------------------
    RespBasic resp1 = new RespBasic();
    return Response.status(Status.CREATED)
      .entity(TapisRestUtils.createSuccessResponse(ApiUtils.getMsg("SYSAPI_CRED_DELETED", null, systemName,
                                                                   userName), prettyPrint, resp1))
      .build();
  }

  // ************************************************************************
  // *********************** Private Methods ********************************
  // ************************************************************************

  private SystemsService getSystemsService()
  {
    if (systemsService != null) return systemsService;
    return new SystemsServiceImpl();
  }
}
