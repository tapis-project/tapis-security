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

import edu.utexas.tacc.tapis.security.api.requestBody.ReqShareResource;
import edu.utexas.tacc.tapis.security.api.responses.RespShare;
import edu.utexas.tacc.tapis.security.api.responses.RespShareList;
import edu.utexas.tacc.tapis.security.api.utils.SKApiUtils;
import edu.utexas.tacc.tapis.security.api.utils.SKCheckAuthz;
import edu.utexas.tacc.tapis.security.authz.model.SkShare;
import edu.utexas.tacc.tapis.security.authz.model.SkShareDeleteSelector;
import edu.utexas.tacc.tapis.security.authz.model.SkShareInputFilter;
import edu.utexas.tacc.tapis.security.authz.model.SkShareList;
import edu.utexas.tacc.tapis.security.authz.model.SkSharePrivilegeSelector;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import edu.utexas.tacc.tapis.shared.threadlocal.TapisThreadLocal;
import edu.utexas.tacc.tapis.sharedapi.responses.RespBasic;
import edu.utexas.tacc.tapis.sharedapi.responses.RespBoolean;
import edu.utexas.tacc.tapis.sharedapi.responses.RespChangeCount;
import edu.utexas.tacc.tapis.sharedapi.responses.RespResourceUrl;
import edu.utexas.tacc.tapis.sharedapi.responses.results.ResultBoolean;
import edu.utexas.tacc.tapis.sharedapi.responses.results.ResultChangeCount;
import edu.utexas.tacc.tapis.sharedapi.responses.results.ResultResourceUrl;
import edu.utexas.tacc.tapis.sharedapi.utils.TapisRestUtils;

@Path("/share")
public class ShareResource 
  extends AbstractResource
{
   /* **************************************************************************** */
   /*                                   Constants                                  */
   /* **************************************************************************** */
   // Local logger.
   private static final Logger _log = LoggerFactory.getLogger(ShareResource.class);
   
   // Json schema resource files.
   private static final String FILE_SK_SHARE_RESOURCE_REQUEST = 
       "/edu/utexas/tacc/tapis/security/api/jsonschema/ShareResourceRequest.json";
   
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
    /* shareResource:                                                               */
    /* ---------------------------------------------------------------------------- */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response shareResource(InputStream payloadStream)
    {
        // Trace this request.
        if (_log.isTraceEnabled()) {
            String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                         "shareResource", _request.getRequestURL());
            _log.trace(msg);
        }
        
        // ------------------------- Input Processing -------------------------
        // Parse and validate the json in the request payload, which must exist.
        ReqShareResource payload = null;
        try {payload = getPayload(payloadStream, FILE_SK_SHARE_RESOURCE_REQUEST, 
                                  ReqShareResource.class);
        } 
        catch (Exception e) {
            String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                         "shareResource", e.getMessage());
            _log.error(msg, e);
            return Response.status(Status.BAD_REQUEST).
              entity(TapisRestUtils.createErrorResponse(msg)).build();
        }
            
        // Fill in the parameter fields.
        var skShare = new SkShare();
        skShare.setGrantor(payload.grantor);
        skShare.setGrantee(payload.grantee);
        skShare.setTenant(payload.tenant);
        skShare.setResourceType(payload.resourceType);
        skShare.setResourceId1(payload.resourceId1);
        skShare.setResourceId2(payload.resourceId2);
        skShare.setPrivilege(payload.privilege);
        
        // The threadlocal object has not been validated yet, but it's never null.
        // Note that the obo values are null on a user token. This isn't a problem
        // because the first authz check detects non-service tokens before the
        // obo tenant and user are referenced.  JWTValidateRequestFilter guarantees 
        // that service tokens always have both obo values assigned. 
        var threadContext = TapisThreadLocal.tapisThreadContext.get();
        skShare.setCreatedBy(threadContext.getJwtUser());
        skShare.setCreatedByTenant(threadContext.getJwtTenantId());
        var oboUser   = threadContext.getOboUser();
        var oboTenant = threadContext.getOboTenantId();
        
        // ------------------------- Check Authz ------------------------------
        // Authorization passed if a null response is returned.
        Response resp = SKCheckAuthz.configure(oboTenant, oboUser)
                            .setCheckServiceIsAllowed()
                            .check();
        if (resp != null) return resp;
        
        // ------------------------ Request Processing ------------------------
        // Create the share in the database.  The share object's id, created, 
        // createdBy and createdByTenant are updated by the called code.  This
        // includes cases where the share existed or not.
        int rows = 0;
        try {rows = getShareImpl().shareResource(skShare);}
        catch (Exception e) {
            String msg = MsgUtils.getMsg("SK_SHARE_CREATE_ERROR", skShare.getGrantor(), skShare.getTenant(),
                            skShare.getGrantee(), skShare.getResourceType(), skShare.printResource(), 
                            skShare.getPrivilege());
            return getExceptionResponse(e, msg);
        }
        
        // NOTE: We need to assign a location header as well.
        //       See https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9.5.
        ResultResourceUrl respUrl = new ResultResourceUrl();
        respUrl.url = SKApiUtils.constructTenantURL(skShare.getCreatedByTenant(), _request.getRequestURI(), 
                                                    Integer.toString(skShare.getId()));
        RespResourceUrl r = new RespResourceUrl(respUrl);
        
        // ---------------------------- Success ------------------------------- 
        // No new rows means the role exists. 
        if (rows == 0)
            return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
                MsgUtils.getMsg("TAPIS_EXISTED", "Share", skShare.getId()), r)).build();
        else 
            return Response.status(Status.CREATED).entity(TapisRestUtils.createSuccessResponse(
                MsgUtils.getMsg("TAPIS_CREATED", "Share", skShare.getId()), r)).build();
    }

    /* ---------------------------------------------------------------------------- */
    /* getShares:                                                                   */
    /* ---------------------------------------------------------------------------- */
    @GET
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getShares(@DefaultValue("") @QueryParam("grantor")         String grantor,
                              @DefaultValue("") @QueryParam("grantee")         String grantee,
                              @DefaultValue("") @QueryParam("tenant")          String tenant,  // required
                              @DefaultValue("") @QueryParam("resourceType")    String resourceType,
                              @DefaultValue("") @QueryParam("resourceId1")     String resourceId1,
                              @DefaultValue("") @QueryParam("resourceId2")     String resourceId2,
                              @DefaultValue("") @QueryParam("privilege")       String privilege,
                              @DefaultValue("") @QueryParam("createdBy")       String createdBy,
                              @DefaultValue("") @QueryParam("createdByTenant") String createdByTenant,
                              @DefaultValue("true")  @QueryParam("includePublicGrantees") boolean includePublicGrantees,
                              @DefaultValue("true")  @QueryParam("requireNullId2")        boolean requireNullId2,
                              @DefaultValue("0")     @QueryParam("id")         int id)
    {
        // Trace this request.
        if (_log.isTraceEnabled()) {
            String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                         "getShares", _request.getRequestURL());
            _log.trace(msg);
        }
        
        // ------------------------- Input Processing -------------------------
        // Get obo information.
        var threadContext = TapisThreadLocal.tapisThreadContext.get();
        var oboTenant = threadContext.getOboTenantId();
        var oboUser   = threadContext.getOboUser();
        
        // Convert empty strings to null and sanitize input.
        var inputFilter = new SkShareInputFilter();
        inputFilter.setGrantor(StringUtils.stripToNull(grantor));
        inputFilter.setGrantee(StringUtils.stripToNull(grantee));
        inputFilter.setTenant(StringUtils.stripToNull(tenant));  // checked for null below
        inputFilter.setResourceType(StringUtils.stripToNull(resourceType));
        inputFilter.setResourceId1(StringUtils.stripToNull(resourceId1));
        inputFilter.setResourceId2(StringUtils.stripToNull(resourceId2));
        inputFilter.setPrivilege(StringUtils.stripToNull(privilege));
        inputFilter.setCreatedBy(StringUtils.stripToNull(createdBy));
        inputFilter.setCreatedByTenant(StringUtils.stripToNull(createdByTenant));
        inputFilter.setIncludePublicGrantees(includePublicGrantees);
        inputFilter.setRequireNullId2(requireNullId2);
        inputFilter.setId(id);

        // We don't allow cross tenant queries.
        if (inputFilter.getTenant() == null) {
            var r = new RespBasic("Missing input parameter: tenant");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "hasPrivilege", "tenant"), r)).build();
        }
        // ------------------------- Check Authz ------------------------------
        // Authorization passed if a null response is returned.
        Response resp = SKCheckAuthz.configure(oboTenant, oboUser)
                            .setCheckServiceIsAllowed()
                            .check();
        if (resp != null) return resp;
        
        // ------------------------ Request Processing ------------------------
        // Retrieve the shared resource objects that meet the filter criteria.
        // A non-null list is always returned unless there's an exception.
        List<SkShare> list = null;
        try {list = getShareImpl().getShares(inputFilter);}
        catch (Exception e) {
            String msg = MsgUtils.getMsg("SK_SHARE_RETRIEVAL_ERROR", oboTenant, oboUser,
                                         threadContext.getJwtTenantId(), threadContext.getJwtUser(),
                                         inputFilter.getTenant());
            return getExceptionResponse(e, msg);
        }
        
        // Package the list for the response.
        var skShares = new SkShareList();
        skShares.shares = list;
        
        // ---------------------------- Success ------------------------------- 
        // Success means zero or more shares were found. 
        RespShareList r = new RespShareList(skShares);
        return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
            MsgUtils.getMsg("TAPIS_FOUND", "Shares", skShares.shares.size()), r)).build();
    }

    /* ---------------------------------------------------------------------------- */
    /* getShare:                                                                    */
    /* ---------------------------------------------------------------------------- */
    @GET
    @Path("/{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getShare(@PathParam("id") int id,
                             @DefaultValue("") @QueryParam("tenant") String tenant)
    {
        // Trace this request.
        if (_log.isTraceEnabled()) {
            String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                         "getShares", _request.getRequestURL());
            _log.trace(msg);
        }
        
        // ------------------------- Input Processing -------------------------
        // The id must be greater than zero.
        if (id <= 0) {
            var r = new RespBasic("Invalid share id: " + id + ".");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "Share", id), r)).build();
        }
        
        // Make sure we have an actual tenant string.
        tenant = StringUtils.stripToNull(tenant);
        if (tenant == null) {
            var r = new RespBasic("Missing tenant query parameter.");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "Share", "tenant"), r)).build();
        }
        
        // Get obo information.
        var threadContext = TapisThreadLocal.tapisThreadContext.get();
        var oboTenant = threadContext.getOboTenantId();
        var oboUser   = threadContext.getOboUser();

        // ------------------------- Check Authz ------------------------------
        // Authorization passed if a null response is returned.
        Response resp = SKCheckAuthz.configure(oboTenant, oboUser)
                            .setCheckServiceIsAllowed()
                            .check();
        if (resp != null) return resp;
        
        // ------------------------ Request Processing ------------------------
        // Retrieve the shared resource objects that meet the filter criteria.
        // A non-null list is always returned unless there's an exception.
        SkShare skShare = null;
        try {skShare = getShareImpl().getShare(tenant, id);}
        catch (Exception e) {
            String msg = MsgUtils.getMsg("SK_SHARE_RETRIEVAL_ERROR", oboTenant, oboUser,
                                         threadContext.getJwtTenantId(), threadContext.getJwtUser(),
                                         tenant);
            return getExceptionResponse(e, msg);
        }
        
        // Surface not found as an error.
        if (skShare == null) {
            var r = new RespBasic("No share with id " + id + " was found.");
            return Response.status(Status.NOT_FOUND).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "Share", id), r)).build();
        }
                
        // ---------------------------- Success ------------------------------- 
        // Success means zero or more shares were found. 
        RespShare r = new RespShare(skShare);
        return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
            MsgUtils.getMsg("TAPIS_FOUND", "Shares", id), r)).build();
    }

    /* ---------------------------------------------------------------------------- */
    /* deleteShareById:                                                             */
    /* ---------------------------------------------------------------------------- */
    @DELETE
    @Path("/{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteShareById(@PathParam("id") int id,
                                    @DefaultValue("") @QueryParam("tenant") String tenant)
    {
        // Trace this request.
        if (_log.isTraceEnabled()) {
            String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                         "deleteSharesById", _request.getRequestURL());
            _log.trace(msg);
        }
        
        // ------------------------- Input Processing -------------------------
        // The id must be greater than zero.
        if (id <= 0) {
            var r = new RespBasic("Invalid share id: " + id + ".");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "deleteShare", id), r)).build();
        }
        
        // Make sure we have an actual tenant string.
        tenant = StringUtils.stripToNull(tenant);
        if (tenant == null) {
            var r = new RespBasic("Missing tenant query parameter.");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "Share", "tenant"), r)).build();
        }
        
        // Get obo information.
        var threadContext = TapisThreadLocal.tapisThreadContext.get();
        var oboTenant = threadContext.getOboTenantId();
        var oboUser   = threadContext.getOboUser();
        var jwtTenant = threadContext.getJwtTenantId();
        var jwtUser   = threadContext.getJwtUser();

        // ------------------------- Check Authz ------------------------------
        // Authorization passed if a null response is returned.
        Response resp = SKCheckAuthz.configure(oboTenant, oboUser)
                            .setCheckServiceIsAllowed()
                            .check();
        if (resp != null) return resp;
        
        // ------------------------ Request Processing ------------------------
        // Retrieve the shared resource objects that meet the filter criteria.
        // A non-null list is always returned unless there's an exception.
        int rows = 0;
        try {rows = getShareImpl().deleteShare(tenant, id, jwtTenant, jwtUser);}
        catch (Exception e) {
            String msg = MsgUtils.getMsg("SK_SHARE_DELETE_BY_ID_ERROR", oboTenant, oboUser,
                                         jwtTenant, jwtUser, id, tenant);
            return getExceptionResponse(e, msg);
        }
        
        // Package the count.
        var resultCount = new ResultChangeCount();
        resultCount.changes = rows;
        var r = new RespChangeCount(resultCount);
        
        // This call is idempotent but returns a different response message when ID not found.
        if (rows < 1) {
            return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "deleteShare", id), r)).build();
        }
                
        // ---------------------------- Success ------------------------------- 
        // Success means zero or more shares were found. 
        return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
            MsgUtils.getMsg("TAPIS_FOUND", "deleteShare", id), r)).build();
    }

    /* ---------------------------------------------------------------------------- */
    /* deleteShare:                                                                 */
    /* ---------------------------------------------------------------------------- */
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteShare(@DefaultValue("") @QueryParam("grantor")      String grantor,
                                @DefaultValue("") @QueryParam("grantee")      String grantee,
                                @DefaultValue("") @QueryParam("tenant")       String tenant,
                                @DefaultValue("") @QueryParam("resourceType") String resourceType,
                                @DefaultValue("") @QueryParam("resourceId1")  String resourceId1,
                                @DefaultValue("") @QueryParam("resourceId2")  String resourceId2,
                                @DefaultValue("") @QueryParam("privilege")    String privilege)
    {
        // Trace this request.
        if (_log.isTraceEnabled()) {
            String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                         "deleteShares", _request.getRequestURL());
            _log.trace(msg);
        }
        
        // ------------------------- Input Processing -------------------------        
        // Get obo information.
        var threadContext = TapisThreadLocal.tapisThreadContext.get();
        var oboTenant = threadContext.getOboTenantId();
        var oboUser   = threadContext.getOboUser();
        var jwtTenant = threadContext.getJwtTenantId();
        var jwtUser   = threadContext.getJwtUser();

        // Package input parameters. 
        var sel = new SkShareDeleteSelector();
        sel.setGrantor(StringUtils.stripToNull(grantor));
        sel.setGrantee(StringUtils.stripToNull(grantee));
        sel.setTenant(StringUtils.stripToNull(tenant));
        sel.setResourceType(StringUtils.stripToNull(resourceType));
        sel.setResourceId1(StringUtils.stripToNull(resourceId1));
        sel.setResourceId2(StringUtils.stripToNull(resourceId2)); 
        sel.setPrivilege(StringUtils.stripToNull(privilege));
        sel.setCreatedBy(jwtUser);
        sel.setCreatedByTenant(jwtTenant);
        
        // Validate inputs. Only id2 can be null.
        if (sel.getGrantor() == null) {
            var r = new RespBasic("Missing input parameter: grantor");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "hasPrivilege", "grantor"), r)).build();
        }
        if (sel.getGrantee() == null) {
            var r = new RespBasic("Missing input parameter: grantee");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "hasPrivilege", "grantee"), r)).build();
        }
        if (sel.getTenant() == null) {
            var r = new RespBasic("Missing input parameter: tenant");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "hasPrivilege", "tenant"), r)).build();
        }
        if (sel.getResourceType() == null) {
            var r = new RespBasic("Missing input parameter: resourceType");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "hasPrivilege", "resourceType"), r)).build();
        }
        if (sel.getResourceId1() == null) {
            var r = new RespBasic("Missing input parameter: resourceId1");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "hasPrivilege", "resourceId1"), r)).build();
        }
        if (sel.getPrivilege() == null) {
            var r = new RespBasic("Missing input parameter: privilege");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "hasPrivilege", "privilege"), r)).build();
        }
        
        // ------------------------- Check Authz ------------------------------
        // Authorization passed if a null response is returned.
        Response resp = SKCheckAuthz.configure(oboTenant, oboUser)
                            .setCheckServiceIsAllowed()
                            .check();
        if (resp != null) return resp;
        
        // ------------------------ Request Processing ------------------------
        // Retrieve the shared resource objects that meet the filter criteria.
        // A non-null list is always returned unless there's an exception.
        int rows = 0;
        try {rows = getShareImpl().deleteShare(sel);}
        catch (Exception e) {
            String msg = MsgUtils.getMsg("SK_SHARE_DELETE_ERROR", oboTenant, oboUser,
                                         jwtTenant, jwtUser, grantee, grantor, tenant);
            return getExceptionResponse(e, msg);
        }
        
        // Package the count.
        var resultCount = new ResultChangeCount();
        resultCount.changes = rows;
        var r = new RespChangeCount(resultCount);
        
        // This call is idempotent but returns a different response message when ID not found.
        if (rows < 1) {
            return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "deleteShare", grantee), r)).build();
        }
                
        // ---------------------------- Success ------------------------------- 
        // Success means zero or more shares were found. 
        return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
            MsgUtils.getMsg("TAPIS_FOUND", "deleteShare", grantee), r)).build();
    }

    /* ---------------------------------------------------------------------------- */
    /* hasPrivilege:                                                                */
    /* ---------------------------------------------------------------------------- */
    @GET
    @Path("/hasPrivilege")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response hasPrivilege(@DefaultValue("") @QueryParam("grantee") String grantee,
                                 @DefaultValue("") @QueryParam("tenant") String tenant,
                                 @DefaultValue("") @QueryParam("resourceType") String resourceType,
                                 @DefaultValue("") @QueryParam("resourceId1")  String resourceId1,
                                 @DefaultValue("") @QueryParam("resourceId2")  String resourceId2,
                                 @DefaultValue("") @QueryParam("privilege")    String privilege,
                                 @DefaultValue("false") @QueryParam("excludePublic") boolean excludePublic,
                                 @DefaultValue("false") @QueryParam("excludePublicNoAuthn") boolean excludePublicNoAuthn)
    {
        // Trace this request.
        if (_log.isTraceEnabled()) {
            String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                         "hasPrivilege", _request.getRequestURL());
            _log.trace(msg);
        }
        
        // ------------------------- Input Processing -------------------------        
        // Get obo information.
        var threadContext = TapisThreadLocal.tapisThreadContext.get();
        var oboTenant = threadContext.getOboTenantId();
        var oboUser   = threadContext.getOboUser();

        // Package input parameters. 
        var sel = new SkSharePrivilegeSelector();
        sel.setGrantee(StringUtils.stripToNull(grantee));
        sel.setTenant(StringUtils.stripToNull(tenant));
        sel.setResourceType(StringUtils.stripToNull(resourceType));
        sel.setResourceId1(StringUtils.stripToNull(resourceId1));
        sel.setResourceId2(StringUtils.stripToNull(resourceId2)); 
        sel.setPrivilege(StringUtils.stripToNull(privilege));
        
        // Validate inputs. Only id2 can be null.
        if (sel.getGrantee() == null) {
            var r = new RespBasic("Missing input parameter: grantee");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "hasPrivilege", "grantee"), r)).build();
        }
        if (sel.getTenant() == null) {
            var r = new RespBasic("Missing input parameter: tenant");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "hasPrivilege", "tenant"), r)).build();
        }
        if (sel.getResourceType() == null) {
            var r = new RespBasic("Missing input parameter: resourceType");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "hasPrivilege", "resourceType"), r)).build();
        }
        if (sel.getResourceId1() == null) {
            var r = new RespBasic("Missing input parameter: resourceId1");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "hasPrivilege", "resourceId1"), r)).build();
        }
        if (sel.getPrivilege() == null) {
            var r = new RespBasic("Missing input parameter: privilege");
            return Response.status(Status.BAD_REQUEST).entity(TapisRestUtils.createErrorResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "hasPrivilege", "privilege"), r)).build();
        }
        
        // ------------------------- Check Authz ------------------------------
        // Authorization passed if a null response is returned.
        Response resp = SKCheckAuthz.configure(oboTenant, oboUser)
                            .setCheckServiceIsAllowed()
                            .check();
        if (resp != null) return resp;
        
        // ------------------------ Request Processing ------------------------
        // Retrieve the shared resource objects that meet the filter criteria.
        // A non-null list is always returned unless there's an exception.
        boolean hasPrivilege = false;
        try {hasPrivilege = getShareImpl().hasPrivilege(sel);}
        catch (Exception e) {
            String msg = MsgUtils.getMsg("SK_SHARE_RETRIEVAL_ERROR", oboTenant, oboUser,
                                         threadContext.getJwtTenantId(), threadContext.getJwtUser(),
                                         sel.getTenant());
            return getExceptionResponse(e, msg);
        }
        
        // Create the response.
        var resultBoolean = new ResultBoolean();
        resultBoolean.aBool = hasPrivilege;
        var r = new RespBoolean(resultBoolean);
        
        // Surface not found as an error.
        if (!hasPrivilege) {
            return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
                    MsgUtils.getMsg("TAPIS_NOT_FOUND", "hasPrivilege", sel.getPrivilege()), r)).build();
        }
                
        // ---------------------------- Success ------------------------------- 
        // Success means zero or more shares were found. 
        return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
            MsgUtils.getMsg("TAPIS_FOUND", "hasPrivilege", sel.getPrivilege()), r)).build();
    }
}
