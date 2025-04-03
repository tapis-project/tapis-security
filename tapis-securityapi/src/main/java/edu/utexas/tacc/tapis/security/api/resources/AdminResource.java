package edu.utexas.tacc.tapis.security.api.resources;

import edu.utexas.tacc.tapis.security.api.utils.SKCheckAuthz;
import edu.utexas.tacc.tapis.security.api.utils.TenantInit;
import edu.utexas.tacc.tapis.security.config.RuntimeParameters;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import edu.utexas.tacc.tapis.shared.security.TenantManager;
import edu.utexas.tacc.tapis.shared.threadlocal.TapisThreadLocal;
import edu.utexas.tacc.tapis.shared.utils.SkConstants;
import edu.utexas.tacc.tapis.sharedapi.utils.TapisRestUtils;
import edu.utexas.tacc.tapis.tenants.client.gen.model.Tenant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.UriInfo;
import java.util.Map;

@Path("/admin")
public class AdminResource extends AbstractResource {
    private static final Logger _log = LoggerFactory.getLogger(AdminResource.class);
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

    private static final String primarySiteAdminTenantId = TenantManager.getInstance().getPrimarySite().getSiteAdminTenantId();

    @GET
    @Path("reinitialize")
    @Produces(MediaType.APPLICATION_JSON)
    public Response reinitialize() {
        // Trace this request.
        if (_log.isTraceEnabled()) {
            String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(),
                    "reinitialize", _request.getRequestURL());
            _log.trace(msg);
        }

        String jwtUser = TapisThreadLocal.tapisThreadContext.get().getJwtUser();

        Response resp = SKCheckAuthz.configure(primarySiteAdminTenantId, jwtUser)
                .addRequiredRole(SkConstants.SK_PRIMARY_SITE_ADMIN_ROLE).check();
        if(resp != null) {
            return resp;
        }

        try {
            var tenantMap = getTenantMap();
            TenantInit.initializeTenants(tenantMap);
        } catch (Exception e) {
            String msg = MsgUtils.getMsg("SK_SITE_ADMIN_REINIT_ERROR", jwtUser, e.getMessage());
            return getExceptionResponse(e, msg);
        }
        return Response.status(Response.Status.OK)
                .entity(TapisRestUtils.createSuccessResponse("Reinitialized Successfully", true))
                .build();
    }

    private static Map<String, Tenant> getTenantMap() throws Exception {
        Map<String, Tenant> tenantMap = null;
        tenantMap = TenantManager.getInstance().refreshTenants();
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
