package edu.utexas.tacc.tapis.security.api.resources;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

import javax.annotation.security.PermitAll;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.utexas.tacc.tapis.security.api.responses.RespProbe;
import edu.utexas.tacc.tapis.security.secrets.VaultManager;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import edu.utexas.tacc.tapis.shared.security.TenantManager;
import edu.utexas.tacc.tapis.shared.utils.CallSiteToggle;
import edu.utexas.tacc.tapis.sharedapi.responses.RespBasic;
import edu.utexas.tacc.tapis.sharedapi.utils.TapisRestUtils;

@Path("/")
public final class SecurityResource
 extends AbstractResource
{
    /* **************************************************************************** */
    /*                                   Constants                                  */
    /* **************************************************************************** */
    // Local logger.
    private static final Logger _log = LoggerFactory.getLogger(SecurityResource.class);
    
    // Database check timeouts.
    private static final long DB_READY_TIMEOUT_MS  = 6000;   // 6 seconds.
    private static final long DB_HEALTH_TIMEOUT_MS = 60000;  // 1 minute.
    
    // The table we query during readiness checks.
    private static final String QUERY_TABLE = "sk_role";
    
    // Keep track of the last db monitoring outcome.
    private static final CallSiteToggle _lastQueryDBSucceeded = new CallSiteToggle();
    private static final CallSiteToggle _lastQueryTenantsSucceeded = new CallSiteToggle();
    
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
     
     // Count the number of healthchecks requests received.
     private static final AtomicLong _healthChecks = new AtomicLong();
    
     // Count the number of healthchecks requests received.
     private static final AtomicLong _readyChecks = new AtomicLong();
     
  /* **************************************************************************** */
  /*                                Public Methods                                */
  /* **************************************************************************** */
  /* ---------------------------------------------------------------------------- */
  /* healthcheck:                                                                 */
  /* ---------------------------------------------------------------------------- */
  /** This method does no logging and is expected to be as lightwieght as possible.
   * It's intended as the endpoint that monitoring applications can use to check
   * the liveness (i.e, no deadlocks) of the application.  In particular, 
   * kubernetes can use this endpoint as part of its pod health check.
   * 
   * Note that no JWT is required on this call.
   * 
   * A good synopsis of the difference between liveness and readiness checks:
   * 
   * ---------
   * The probes have different meaning with different results:
   * 
   *    - failing liveness probes  -> restart pod
   *    - failing readiness probes -> do not send traffic to that pod
   *    
   * See https://stackoverflow.com/questions/54744943/why-both-liveness-is-needed-with-readiness
   * ---------
   * 
   * @return a success response if all is ok
   */
  @GET
  @Path("/healthcheck")
  @Produces(MediaType.APPLICATION_JSON)
  @PermitAll
  public Response checkHealth()
  {
      var skProbe = new SkHealthProbe();
      skProbe.checkNum = _healthChecks.incrementAndGet();

      // Create the response object.
      RespProbe r = new RespProbe(skProbe);

      // ---------------------------- Success -------------------------------
      // Create the response payload.
      return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
              MsgUtils.getMsg("TAPIS_HEALTHY", "Security Kernel"), false, r)).build();
  }

  /* ---------------------------------------------------------------------------- */
  /* readycheck:                                                                       */
  /* ---------------------------------------------------------------------------- */
  /** This method does no logging and is expected to be as lightwieght as possible.
   * It's intended as the endpoint that monitoring applications can use to check
   * whether the application is ready to accept traffic.  In particular, kubernetes 
   * can use this endpoint as part of its pod readiness check.
   * 
   * Note that no JWT is required on this call.
   * 
   * A good synopsis of the difference between liveness and readiness checks:
   * 
   * ---------
   * The probes have different meaning with different results:
   * 
   *    - failing liveness probes  -> restart pod
   *    - failing readiness probes -> do not send traffic to that pod
   *    
   * See https://stackoverflow.com/questions/54744943/why-both-liveness-is-needed-with-readiness
   * ---------
   * 
   * @return a success response if all is ok
   */
  @GET
  @Path("/readycheck")
  @Produces(MediaType.APPLICATION_JSON)
  @PermitAll
  public Response readycheck()
  {
      // Assign the current check count to the probe result object.
      var skProbe = new SkReadyProbe();
      skProbe.checkNum = _readyChecks.incrementAndGet();

      // Check the database.
      if (queryDB(DB_READY_TIMEOUT_MS)) skProbe.databaseAccess = true; 
      
      // Check the tenant manager.
      if (queryTenants()) skProbe.tenantsAccess = true;
      
      // Check the readiness of vault.
      var vaultMgr = VaultManager.getInstance(true);
      if (vaultMgr != null && vaultMgr.isReady()) skProbe.vaultAccess = true;
      
      // Create the response object.
      RespProbe r = new RespProbe(skProbe);
      
      // Failure case.
      if (skProbe.failed()) {
        String msg = MsgUtils.getMsg("TAPIS_NOT_READY", "Security Kernel");
        return Response.status(Status.SERVICE_UNAVAILABLE).
            entity(TapisRestUtils.createErrorResponse(msg, false, r)).build();
      }
      
      // ---------------------------- Success -------------------------------
      // Create the response payload.
      return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
          MsgUtils.getMsg("TAPIS_READY", "Security Kernel"), false, r)).build();
  }

  /* **************************************************************************** */
  /*                               Private Methods                                */
  /* **************************************************************************** */
  /* ---------------------------------------------------------------------------- */
  /* queryDB:                                                                     */
  /* ---------------------------------------------------------------------------- */
  /** Probe the database with a simple database query and minimal logging.
   * 
   * @param timeoutMillis millisecond limit for success
   * @return true for success, false otherwise
   */
  private boolean queryDB(long timeoutMillis)
  {
      // Start optimistically.
      boolean success = true;
      
      // Any db error or a time expiration fails the connectivity check.
      try {
          // Try to run a simple query.
          long startTime = Instant.now().toEpochMilli();
          int result = getRoleImpl().queryDB(QUERY_TABLE);
          
          // Did the query take too long?
          long elapsed = Instant.now().toEpochMilli() - startTime;
          if (elapsed > timeoutMillis) {
              if (_lastQueryDBSucceeded.toggleOff()) {
                  String msg = MsgUtils.getMsg("TAPIS_PROBE_ERROR", "Security Kernel", 
                                               "Excessive query time (" + elapsed + " milliseconds)");
                  _log.error(msg);
              }
              success = false;
          } else if (_lastQueryDBSucceeded.toggleOn())
              _log.info(MsgUtils.getMsg("TAPIS_PROBE_ERROR_CLEARED", "Security Kernel", "database"));
      }
      catch (Exception e) {
          // Any exception causes us to report failure on first recent occurrence.
          if (_lastQueryDBSucceeded.toggleOff()) {
              String msg = MsgUtils.getMsg("TAPIS_PROBE_ERROR", "Security Kernel", e.getMessage());
              _log.error(msg, e);
          }
          success = false;
      }
      
      return success;
  }
  
  /* ---------------------------------------------------------------------------- */
  /* queryTenants:                                                                */
  /* ---------------------------------------------------------------------------- */
  /** Retrieve the cached tenants map.
   * 
   * @return true if the map is not null, false otherwise
   */
  private boolean queryTenants()
  {
      // Start optimistically.
      boolean success = true;
      
      try {
          // Make sure the cached tenants map is not null.
          var tenantMap = TenantManager.getInstance().getTenants();
          if (tenantMap == null) {
              if (_lastQueryTenantsSucceeded.toggleOff()) {
                  String msg = MsgUtils.getMsg("TAPIS_PROBE_ERROR", "Security Kernel", 
                                               "Null tenants map.");
                  _log.error(msg);
              }
              success = false;
          } else if (_lastQueryTenantsSucceeded.toggleOn())
              _log.info(MsgUtils.getMsg("TAPIS_PROBE_ERROR_CLEARED", "Security Kernel", "tenants"));
      } catch (Exception e) {
          if (_lastQueryTenantsSucceeded.toggleOff()) {
              String msg = MsgUtils.getMsg("TAPIS_PROBE_ERROR", "Security Kernel", 
                                           e.getMessage());
              _log.error(msg, e);
          }
          success = false;
      }
      
      return success;
  }
  
  /* **************************************************************************** */
  /*                                    Fields                                    */
  /* **************************************************************************** */
  // Simple class to collect probe results.
  public static class SkProbe {
      public long checkNum;
  }

  public final static class SkHealthProbe extends SkProbe {
  }

  public final static class SkReadyProbe extends SkProbe {
      public boolean databaseAccess;
      public boolean vaultAccess;
      public boolean tenantsAccess;
      
      public boolean failed() {return !(databaseAccess && vaultAccess && tenantsAccess);}
  }
}
