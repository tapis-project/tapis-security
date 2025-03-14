package edu.utexas.tacc.tapis.security.api.resources;

import edu.utexas.tacc.tapis.security.api.requestBody.ReqAdminReinitialize;
import edu.utexas.tacc.tapis.security.api.utils.TenantInit;
import edu.utexas.tacc.tapis.security.config.RuntimeParameters;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import edu.utexas.tacc.tapis.shared.security.TenantManager;
import edu.utexas.tacc.tapis.sharedapi.utils.TapisRestUtils;
import edu.utexas.tacc.tapis.tenants.client.gen.model.Tenant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.UriInfo;
import java.io.InputStream;
import java.util.Map;

@Path("/admin")
public class AdminResource extends AbstractResource {
    private static final Logger _log = LoggerFactory.getLogger(AdminResource.class);
    private static final String FILE_SK_GRANT_TENANT_ADMIN_ROLE =
            "/edu/utexas/tacc/tapis/security/api/jsonschema/GrantTenantAdminRole.json";
    private static final String FILE_SK_REVOKE_TENANT_ADMIN_ROLE =
            "/edu/utexas/tacc/tapis/security/api/jsonschema/RevokeTenantAdminRole.json";
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


    @POST
    @Path("reinitialize")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response reinitialize(InputStream payloadStream) {
        // Trace this request.
        if (_log.isTraceEnabled()) {
            String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(),
                    "reinitialize", _request.getRequestURL());
            _log.trace(msg);
        }

        // ------------------------- Input Processing -------------------------
        // Parse and validate the json in the request payload, which must exist.
        ReqAdminReinitialize reinitializeRequest = null;
        try {reinitializeRequest = getPayload(payloadStream, FILE_SK_GRANT_TENANT_ADMIN_ROLE,
                ReqAdminReinitialize.class);
        }
        catch (Exception e) {
            String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR",
                    "grantTenantAdminRole", e.getMessage());
            _log.error(msg, e);
            return Response.status(Response.Status.BAD_REQUEST).
                    entity(TapisRestUtils.createErrorResponse(msg, true)).build();
        }

        if(reinitializeRequest.doReinitialize) {
            var tenantMap = getTenantMap();
            try {
                TenantInit.initializeTenants(tenantMap);
            } catch (Exception e) {
                // TODO: make this something reasonable - log message or whatever
                _log.error("**** FAILURE TO INITIALIZE: tapis-securityapi TenantInit ****\n" + e.getMessage());

                // TODO: return an HTTP error
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            }
            // TODO: return HTTP success
            return Response.status(Response.Status.OK).build();
        }
        // TODO: return HTTP sucess ... or error? Or maybe remove the doReinitialize payload



        // TODO: Temporary
        return Response.status(Response.Status.OK).build();
    }

    private static Map<String, Tenant> getTenantMap() {
        Map<String, Tenant> tenantMap = null;
        try {
            // The base url of the tenants service is a required input parameter.
            // We actually retrieve the tenant list from the tenant service now
            // to fail fast if we can't access the list.
            String url = RuntimeParameters.getInstance().getTenantBaseUrl();
            tenantMap = TenantManager.getInstance(url).getTenants();
        } catch (Exception e) {
            // We don't depend on the logging subsystem.
            errors.add("**** FAILURE TO INITIALIZE: tapis-securityapi TenantManager ****\n" + e.getMessage());
            e.printStackTrace();
        }
        if (tenantMap != null) {
            System.out.println("**** SUCCESS:  " + tenantMap.size() + " tenants retrieved ****");
            String s = "Tenants:\n";
            for (String tenant : tenantMap.keySet()) s += "  " + tenant + "\n";
            System.out.println(s);

            System.out.println("\nLocal site: " + RuntimeParameters.getInstance().getSiteId());
            System.out.println("Primary site: " + TenantManager.getInstance().getPrimarySiteId());
        } else {
            System.out.println("**** FAILURE TO INITIALIZE: tapis-securityapi TenantManager - No Tenants ****");
        }

        return tenantMap;
    }
}
