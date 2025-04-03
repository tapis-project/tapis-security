package edu.utexas.tacc.tapis.security.api.resources;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
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

import edu.utexas.tacc.tapis.security.api.requestBody.ReqValidateServicePwd;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqVersions;
import edu.utexas.tacc.tapis.security.api.requestBody.ReqWriteSecret;
import edu.utexas.tacc.tapis.security.api.responses.RespSecret;
import edu.utexas.tacc.tapis.security.api.responses.RespSecretList;
import edu.utexas.tacc.tapis.security.api.responses.RespSecretMeta;
import edu.utexas.tacc.tapis.security.api.responses.RespSecretVersionMetadata;
import edu.utexas.tacc.tapis.security.api.responses.RespVersions;
import edu.utexas.tacc.tapis.security.api.utils.SKCheckAuthz;
import edu.utexas.tacc.tapis.security.authz.model.SkSecret;
import edu.utexas.tacc.tapis.security.authz.model.SkSecretList;
import edu.utexas.tacc.tapis.security.authz.model.SkSecretMetadata;
import edu.utexas.tacc.tapis.security.authz.model.SkSecretVersionMetadata;
import edu.utexas.tacc.tapis.security.secrets.SecretPathMapper.SecretPathMapperParms;
import edu.utexas.tacc.tapis.security.secrets.SecretType;
import edu.utexas.tacc.tapis.shared.exceptions.TapisImplException;
import edu.utexas.tacc.tapis.shared.exceptions.TapisImplException.Condition;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import edu.utexas.tacc.tapis.sharedapi.responses.RespAuthorized;
import edu.utexas.tacc.tapis.sharedapi.responses.RespBasic;
import edu.utexas.tacc.tapis.sharedapi.responses.results.ResultAuthorized;
import edu.utexas.tacc.tapis.sharedapi.utils.TapisRestUtils;

/** Endpoints that communicate with Hashicorp Vault.
 * 
 *  Driver enhancements:
 *      1. Add secrets v2 options object to create (write).
 *      2. Add readMeta 
 *      3. Add updateMeta
 *      4. deleteLast - soft delete of latest version 
 * 
 * @author rcardone
 */
@Path("/vault")
public final class VaultResource
 extends AbstractResource
{
    /* **************************************************************************** */
    /*                                   Constants                                  */
    /* **************************************************************************** */
    // Local logger.
    private static final Logger _log = LoggerFactory.getLogger(VaultResource.class);

    // Json schema resource files.
    private static final String FILE_SK_WRITE_SECRET_REQUEST = 
        "/edu/utexas/tacc/tapis/security/api/jsonschema/WriteSecretRequest.json";
    private static final String FILE_SK_SECRET_VERSION_REQUEST = 
        "/edu/utexas/tacc/tapis/security/api/jsonschema/SecretVersionRequest.json";
    private static final String FILE_SK_VALIDATE_SERVICE_PWD_REQUEST = 
        "/edu/utexas/tacc/tapis/security/api/jsonschema/ValidateServicePwdRequest.json";
    
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
     
     // Map of url secret type text to secret type enum.
     private static final HashMap<String,SecretType> _secretTypeMap = initSecretTypeMap();
    
     /* **************************************************************************** */
     /*                                Public Methods                                */
     /* **************************************************************************** */
     /* ---------------------------------------------------------------------------- */
     /* readSecret:                                                                  */
     /* ---------------------------------------------------------------------------- */
     @GET
     @Path("/secret/{secretType}/{secretName}")
     @Produces(MediaType.APPLICATION_JSON)
     public Response readSecret(@PathParam("secretType") String secretType,
                                @PathParam("secretName") String secretName,
                                @QueryParam("tenant") String tenant,
                                @QueryParam("user") String user,
                                @DefaultValue("0") @QueryParam("version") int version,
                                /* Query parameters used to construct the secret path in vault */
                                @QueryParam("sysid")      String sysId,
                                @QueryParam("sysuser")    String sysUser,
                                @DefaultValue("sshkey") @QueryParam("keytype") String keyType,
                                @QueryParam("dbhost")     String dbHost,
                                @QueryParam("dbname")     String dbName,
                                @QueryParam("dbservice")  String dbService)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "readSecret", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         if (StringUtils.isBlank(tenant)) {
             String msg = MsgUtils.getMsg("SK_MISSING_PARAMETER", "tenant");
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         if (StringUtils.isBlank(user)) {
             String msg = MsgUtils.getMsg("SK_MISSING_PARAMETER", "user");
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         
         // ------------------------- Path Processing --------------------------
         // Null response means the secret type and its required parameters are present.
         SecretPathMapperParms secretPathParms;
         try {secretPathParms = getSecretPathParms(secretType, secretName, sysId, sysUser,
                                                   keyType, dbHost, dbName, dbService);}
             catch (Exception e) {
                 _log.error(e.getMessage(), e);
                 return getExceptionResponse(e, e.getMessage());
             }
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, user, secretPathParms)
                             .setCheckSecrets()
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Issue the vault call.
         SkSecret skSecret = null;
         try {
             skSecret = getVaultImpl().secretRead(tenant, user, secretPathParms, version);
         } catch (Exception e) {
             _log.error(e.getMessage(), e);
             return getExceptionResponse(e, e.getMessage());
         }
         
         // ------------------------ Request Output ----------------------------
         // Create the response object.
         var respSecret = new RespSecret(skSecret);
         
         // Success.
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg("TAPIS_READ", "Secret", secretPathParms.getSecretName()), 
                                 respSecret)).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* writeSecret:                                                                */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/secret/{secretType}/{secretName}")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response writeSecret(@PathParam("secretType") String secretType,
                                 @PathParam("secretName") String secretName,
                                 /* Query parameters used to construct the secret path in vault */
                                 @QueryParam("sysid")      String sysId,
                                 @QueryParam("sysuser")    String sysUser,
                                 @DefaultValue("sshkey") @QueryParam("keytype") String keyType,
                                 @QueryParam("dbhost")     String dbHost,
                                 @QueryParam("dbname")     String dbName,
                                 @QueryParam("dbservice")  String dbService,
                                 InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "writeSecret", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         // Note that the secret values in the payload will only be string values,
         // which is more restrictive typing than Vault.
         ReqWriteSecret payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_WRITE_SECRET_REQUEST, 
                                   ReqWriteSecret.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "writeSecret", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         
         // Unpack the payload.
         String tenant = payload.tenant;
         String user   = payload.user;
         var secretMap = new HashMap<String,Object>();
         if (payload.data != null) secretMap.putAll(payload.data);
         
         // ------------------------- Path Processing --------------------------
         // Null response means the secret type and its required parameters are present.
         SecretPathMapperParms secretPathParms;
         try {secretPathParms = getSecretPathParms(secretType, secretName, sysId, sysUser,
                                                   keyType, dbHost, dbName, dbService);}
             catch (Exception e) {
                 _log.error(e.getMessage(), e);
                 return getExceptionResponse(e, e.getMessage());
             }
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, user, secretPathParms)
                             .setCheckSecrets()
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Issue the vault call.
         SkSecretMetadata skSecretMeta = null;
         try {
             skSecretMeta = getVaultImpl().secretWrite(tenant, user, secretPathParms, secretMap);
         } catch (Exception e) {
             _log.error(e.getMessage(), e);
             return getExceptionResponse(e, e.getMessage());
         }
         
         // Return the data portion of the vault response.
         RespSecretMeta r = new RespSecretMeta(skSecretMeta);
         return Response.status(Status.CREATED).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg("TAPIS_CREATED", "Secret", secretPathParms.getSecretName()), 
                                 r)).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* deleteSecret:                                                                */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/secret/delete/{secretType}/{secretName}")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response deleteSecret(@PathParam("secretType") String secretType,
                                  @PathParam("secretName") String secretName,
                                  /* Query parameters used to construct the secret path in vault */
                                  @QueryParam("sysid")      String sysId,
                                  @QueryParam("sysuser")    String sysUser,
                                  @DefaultValue("sshkey") @QueryParam("keytype") String keyType,
                                  @QueryParam("dbhost")     String dbHost,
                                  @QueryParam("dbname")     String dbName,
                                  @QueryParam("dbservice")  String dbService,
                                  InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "deleteSecret", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         ReqVersions payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_SECRET_VERSION_REQUEST, 
                                   ReqVersions.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "deleteSecret", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         
         // Massage the input.
         String tenant = payload.tenant;
         String user   = payload.user;
         List<Integer> versions = 
             payload.versions != null ? payload.versions : new ArrayList<>(); 
         
         // ------------------------- Path Processing --------------------------
         // Null response means the secret type and its required parameters are present.
         SecretPathMapperParms secretPathParms;
         try {secretPathParms = getSecretPathParms(secretType, secretName, sysId, sysUser,
                                                   keyType, dbHost, dbName, dbService);}
             catch (Exception e) {
                 _log.error(e.getMessage(), e);
                 return getExceptionResponse(e, e.getMessage());
             }
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, user, secretPathParms)
                             .setCheckSecrets()
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Issue the vault call.
         List<Integer> deletedVersions = null;
         try {
             deletedVersions = getVaultImpl().secretDelete(tenant, user, secretPathParms, 
                                                           versions);
         } catch (Exception e) {
             _log.error(e.getMessage(), e);
             return getExceptionResponse(e, e.getMessage());
         }
         
         // Return the data portion of the vault response.
         RespVersions r = new RespVersions(deletedVersions);
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg("TAPIS_DELETED", "Secret", secretPathParms.getSecretName()), 
                                 r)).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* undeleteSecret:                                                              */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/secret/undelete/{secretType}/{secretName}")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response undeleteSecret(@PathParam("secretType") String secretType,
                                    @PathParam("secretName") String secretName,
                                    /* Query parameters used to construct the secret path in vault */
                                    @QueryParam("sysid")      String sysId,
                                    @QueryParam("sysuser")    String sysUser,
                                    @DefaultValue("sshkey") @QueryParam("keytype") String keyType,
                                    @QueryParam("dbhost")     String dbHost,
                                    @QueryParam("dbname")     String dbName,
                                    @QueryParam("dbservice")  String dbService,
                                    InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "undeleteSecret", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // Parse and validate the json in the request payload, which must exist.
         ReqVersions payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_SECRET_VERSION_REQUEST, 
                                   ReqVersions.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "undeleteSecret", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         
         // Massage the input.
         String tenant = payload.tenant;
         String user   = payload.user;
         List<Integer> versions = 
             payload.versions != null ? payload.versions : new ArrayList<>(); 
         
         // ------------------------- Path Processing --------------------------
         // Null response means the secret type and its required parameters are present.
         SecretPathMapperParms secretPathParms;
         try {secretPathParms = getSecretPathParms(secretType, secretName, sysId, sysUser,
                                                   keyType, dbHost, dbName, dbService);}
             catch (Exception e) {
                 _log.error(e.getMessage(), e);
                 return getExceptionResponse(e, e.getMessage());
             }
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, user, secretPathParms)
                             .setCheckSecrets()
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Issue the vault call.
         List<Integer> undeletedVersions = null;
         try {
             undeletedVersions = getVaultImpl().secretUndelete(tenant, user, secretPathParms, 
                                                               versions);
         } catch (Exception e) {
             _log.error(e.getMessage(), e);
             return getExceptionResponse(e, e.getMessage());
         }
         
         // Return the data portion of the vault response.
         RespVersions r = new RespVersions(undeletedVersions);
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg("TAPIS_UNDELETED", "Secret", secretPathParms.getSecretName()), 
                                 r)).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* destroySecret:                                                               */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/secret/destroy/{secretType}/{secretName}")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response destroySecret(@PathParam("secretType") String secretType,
                                   @PathParam("secretName") String secretName,
                                   /* Query parameters used to construct the secret path in vault */
                                   @QueryParam("sysid")      String sysId,
                                   @QueryParam("sysuser")    String sysUser,
                                   @DefaultValue("sshkey") @QueryParam("keytype") String keyType,
                                   @QueryParam("dbhost")     String dbHost,
                                   @QueryParam("dbname")     String dbName,
                                   @QueryParam("dbservice")  String dbService,
                                   InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "destroySecret", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         ReqVersions payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_SECRET_VERSION_REQUEST, 
                                   ReqVersions.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "destroySecret", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         
         // Massage the input.
         String tenant = payload.tenant;
         String user   = payload.user;
         List<Integer> versions = 
             payload.versions != null ? payload.versions : new ArrayList<>(); 
         
         // ------------------------- Path Processing --------------------------
         // Null response means the secret type and its required parameters are present.
         SecretPathMapperParms secretPathParms;
         try {secretPathParms = getSecretPathParms(secretType, secretName, sysId, sysUser,
                                                   keyType, dbHost, dbName, dbService);}
             catch (Exception e) {
                 _log.error(e.getMessage(), e);
                 return getExceptionResponse(e, e.getMessage());
             }
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, user, secretPathParms)
                             .setCheckSecrets()
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Issue the vault call.
         List<Integer> destroyedVersions = null;
         try {
             destroyedVersions = getVaultImpl().secretDestroy(tenant, user, secretPathParms, 
                                                              versions);
         } catch (Exception e) {
             _log.error(e.getMessage(), e);
             return getExceptionResponse(e, e.getMessage());
         }
         
         // Return the data portion of the vault response.
         RespVersions r = new RespVersions(destroyedVersions);
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg("TAPIS_DELETED", "Secret", secretPathParms.getSecretName()), 
                                 r)).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* readSecretMetadata:                                                          */
     /* ---------------------------------------------------------------------------- */
     @GET
     @Path("/secret/read/meta/{secretType}/{secretName}")
     @Produces(MediaType.APPLICATION_JSON)
     public Response readSecretMeta(@PathParam("secretType") String secretType,
                                    @PathParam("secretName") String secretName,
                                    @QueryParam("tenant") String tenant,
                                    @QueryParam("user")   String user,
                                    /* Query parameters used to construct the secret path in vault */
                                    @QueryParam("sysid")      String sysId,
                                    @QueryParam("sysuser")    String sysUser,
                                    @DefaultValue("sshkey") @QueryParam("keytype")  String keyType,
                                    @QueryParam("dbhost")     String dbHost,
                                    @QueryParam("dbname")     String dbName,
                                    @QueryParam("dbservice")  String dbService)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "readSecretMeta", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         if (StringUtils.isBlank(tenant)) {
             String msg = MsgUtils.getMsg("SK_MISSING_PARAMETER", "tenant");
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         if (StringUtils.isBlank(user)) {
             String msg = MsgUtils.getMsg("SK_MISSING_PARAMETER", "user");
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         
         // ------------------------- Path Processing --------------------------
         // Null response means the secret type and its required parameters are present.
         SecretPathMapperParms secretPathParms;
         try {secretPathParms = getSecretPathParms(secretType, secretName, sysId, sysUser,
                                                   keyType, dbHost, dbName, dbService);}
             catch (Exception e) {
                 _log.error(e.getMessage(), e);
                 return getExceptionResponse(e, e.getMessage());
             }
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, user, secretPathParms)
                             .setCheckSecrets()
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Issue the vault call.
         SkSecretVersionMetadata info = null;
         try {
             info = getVaultImpl().secretReadMeta(tenant, user, secretPathParms);
         } catch (Exception e) {
             _log.error(e.getMessage(), e);
             return getExceptionResponse(e, e.getMessage());
         }
         
         // Return the data portion of the vault response.
         var r = new RespSecretVersionMetadata(info);
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg("TAPIS_READ", "Secret", secretPathParms.getSecretName()), 
                                 r)).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* listSecretMeta:                                                              */
     /* ---------------------------------------------------------------------------- */
     @GET
     @Path("/secret/list/meta/{secretType}")
     @Produces(MediaType.APPLICATION_JSON)
     public Response listSecretMeta(@PathParam("secretType") String secretType,
                                    @QueryParam("tenant") String tenant,
                                    @QueryParam("user")   String user,
                                    /* Query parameters used to construct the secret path in vault */
                                    @QueryParam("sysid")      String sysId,
                                    @QueryParam("sysuser")    String sysUser,
                                    @DefaultValue("sshkey") @QueryParam("keytype") String keyType,
                                    @QueryParam("dbhost")     String dbHost,
                                    @QueryParam("dbname")     String dbName,
                                    @QueryParam("dbservice")  String dbService)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "listSecretMeta", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         if (StringUtils.isBlank(tenant)) {
             String msg = MsgUtils.getMsg("SK_MISSING_PARAMETER", "tenant");
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         if (StringUtils.isBlank(user)) {
             String msg = MsgUtils.getMsg("SK_MISSING_PARAMETER", "user");
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         
         // ------------------------- Path Processing --------------------------
         // Null response means the secret type and its required parameters are present.
         SecretPathMapperParms secretPathParms;
         try {secretPathParms = getSecretPathParms(secretType, null, sysId, sysUser,
                                                   keyType, dbHost, dbName, dbService);}
             catch (Exception e) {
                 _log.error(e.getMessage(), e);
                 return getExceptionResponse(e, e.getMessage());
             }
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, user, secretPathParms)
                             .setCheckSecrets()
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Issue the vault call.
         SkSecretList info = null;
         try {
             info = getVaultImpl().secretListMeta(tenant, user, secretPathParms);
         } catch (Exception e) {                  
             _log.error(e.getMessage(), e);
             return getExceptionResponse(e, e.getMessage());
         }
         
         // Return the data portion of the vault response.
         var r = new RespSecretList(info);
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg("TAPIS_READ", "Secret", info.secretPath), r)).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* destroySecretMeta:                                                           */
     /* ---------------------------------------------------------------------------- */
     @DELETE
     @Path("/secret/destroy/meta/{secretType}/{secretName}")
     @Produces(MediaType.APPLICATION_JSON)
     public Response destroySecretMeta(@PathParam("secretType") String secretType,
                                       @PathParam("secretName") String secretName,
                                       @QueryParam("tenant") String tenant,
                                       @QueryParam("user")   String user,
                                       /* Query parameters used to construct the secret path in vault */
                                       @QueryParam("sysid")      String sysId,
                                       @QueryParam("sysuser")    String sysUser,
                                       @DefaultValue("sshkey") @QueryParam("keytype") String keyType,
                                       @QueryParam("dbhost")     String dbHost,
                                       @QueryParam("dbname")     String dbName,
                                       @QueryParam("dbservice")  String dbService)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "readSecretMeta", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         if (StringUtils.isBlank(tenant)) {
             String msg = MsgUtils.getMsg("SK_MISSING_PARAMETER", "tenant");
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         if (StringUtils.isBlank(user)) {
             String msg = MsgUtils.getMsg("SK_MISSING_PARAMETER", "user");
             _log.error(msg);
             return Response.status(Status.BAD_REQUEST).
                     entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         
         // ------------------------- Path Processing --------------------------
         // Null response means the secret type and its required parameters are present.
         SecretPathMapperParms secretPathParms;
         try {secretPathParms = getSecretPathParms(secretType, secretName, sysId, sysUser,
                                                   keyType, dbHost, dbName, dbService);}
             catch (Exception e) {
                 _log.error(e.getMessage(), e);
                 return getExceptionResponse(e, e.getMessage());
             }
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, user, secretPathParms)
                             .setCheckSecrets()
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Issue the vault call.
         try {
             getVaultImpl().secretDestroyMeta(tenant, user, secretPathParms);
         } catch (Exception e) {
             _log.error(e.getMessage(), e);
             return getExceptionResponse(e, e.getMessage());
         }
         
         // Return the data portion of the vault response.
         var r = new RespBasic();
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg("TAPIS_DELETED", "Secret", secretPathParms.getSecretName()), 
                                 r)).build();
     }
     
     /* ---------------------------------------------------------------------------- */
     /* validateServicePassword:                                                     */
     /* ---------------------------------------------------------------------------- */
     @POST
     @Path("/secret/validateServicePassword/{secretName}")
     @Consumes(MediaType.APPLICATION_JSON)
     @Produces(MediaType.APPLICATION_JSON)
     public Response validateServicePassword(@PathParam("secretName") String secretName,
                         InputStream payloadStream)
     {
         // Trace this request.
         if (_log.isTraceEnabled()) {
             String msg = MsgUtils.getMsg("TAPIS_TRACE_REQUEST", getClass().getSimpleName(), 
                                          "writeSecret", _request.getRequestURL());
             _log.trace(msg);
         }
         
         // ------------------------- Input Processing -------------------------
         // Parse and validate the json in the request payload, which must exist.
         // Note that the secret values in the payload will only be string values,
         // which is more restrictive typing than Vault.
         ReqValidateServicePwd payload = null;
         try {payload = getPayload(payloadStream, FILE_SK_VALIDATE_SERVICE_PWD_REQUEST, 
                                   ReqValidateServicePwd.class);
         } 
         catch (Exception e) {
             String msg = MsgUtils.getMsg("NET_REQUEST_PAYLOAD_ERROR", 
                                          "validateServicePassword", e.getMessage());
             _log.error(msg, e);
             return Response.status(Status.BAD_REQUEST).
               entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         
         // Extract input values.
         String tenant = payload.tenant;
         String user   = payload.user;
         
         // Support secret name paths by replacing the escape characters (+) with
         // slashes.  This is typically handled in SecretPathMapperParms. 
         if (secretName != null) secretName = secretName.replace('+', '/');
         
         // Log payload info.
         if (_log.isDebugEnabled()) 
        	 _log.debug(MsgUtils.getMsg("SK_VALIDATING_PASSWORD", tenant, user, secretName));
         
         // ------------------------- Check Authz ------------------------------
         // Authorization passed if a null response is returned.
         Response resp = SKCheckAuthz.configure(tenant, user)
                             .setValidatePassword()
                             .check();
         if (resp != null) return resp;
         
         // ------------------------ Request Processing ------------------------
         // Get the names.
         boolean authorized;
         try {authorized = getVaultImpl().validateServicePwd(tenant, user, secretName, 
                                                             payload.password);}
             catch (Exception e) {
                 // Already logged.
                 return getExceptionResponse(e, e.getMessage());
             }
         
         // Password was not matched.
         if (!authorized) {
             String msg = MsgUtils.getMsg("SK_INVALID_SERVICE_PASSWORD", 
                                          tenant, user, secretName);
             _log.warn(msg);
             return Response.status(Status.FORBIDDEN).
                 entity(TapisRestUtils.createErrorResponse(msg)).build();
         }
         
         // Set the result payload on success.
         ResultAuthorized authResp = new ResultAuthorized();
         authResp.isAuthorized = true;
         RespAuthorized r = new RespAuthorized(authResp);
         
         // Return the data portion of the vault response.
         return Response.status(Status.OK).entity(TapisRestUtils.createSuccessResponse(
                 MsgUtils.getMsg("TAPIS_AUTHORIZED", "Service", secretName), r)).build();
     }
     
     /* **************************************************************************** */
     /*                               Private Methods                                */
     /* **************************************************************************** */
     /* ---------------------------------------------------------------------------- */
     /* getSecretPathParms:                                                          */
     /* ---------------------------------------------------------------------------- */
     /** Wrap all possible input optional parameters into a single object.  Convert
      * any plus signs (+) in the secretName parameter to slashes (/) as defined on 
      * the client interface.
      * 
      * @return a single parameter object
      * @throws TapisImplException on an invalid secret type
      */
     private SecretPathMapperParms getSecretPathParms(String secretType, String secretName, 
                                         String sysId, String sysUser, String keyType, 
                                         String dbHost, String dbName, String dbService) 
      throws TapisImplException
     {
         // Assign the secret type.
         var secretTypeEnum = _secretTypeMap.get(secretType.toLowerCase());
         if (secretTypeEnum == null) {
             var typeArray = new ArrayList<String>(_secretTypeMap.keySet());
             Collections.sort(typeArray);
             
             // Throw the exception.
             String msg = MsgUtils.getMsg("TAPIS_SECURITY_INVALID_SECRET_TYPE",
                                          secretType, typeArray.toString());
             _log.error(msg);
             throw new TapisImplException(msg, Condition.BAD_REQUEST);
         }

         // Create the parm container object.
         SecretPathMapperParms parms = new SecretPathMapperParms(secretTypeEnum);
         
         // Translate the "+" sign into slashes to allow for vault subdirectories.
         if (secretName != null) secretName = secretName.replace('+', '/');
         
         // Assign the rest of the parm fields.
         parms.setSecretName(secretName);
         parms.setSysId(sysId);
         parms.setSysUser(sysUser);
         parms.setKeyType(keyType);
         parms.setDbHost(dbHost);
         parms.setDbName(dbName);
         parms.setDbService(dbService);
         
         return parms;
     }

     /* ---------------------------------------------------------------------------- */
     /* initSecretTypeMap:                                                           */
     /* ---------------------------------------------------------------------------- */
     /** Initialize a map with key secret type url text and value SecretType enumeration. 
      * 
      * @return the map of text to enum
      */
     private static HashMap<String,SecretType> initSecretTypeMap()
     {
         // Get a map of secret type text to secret type enum. The secret
         // type text is what should appear in url paths.
         SecretType[] types = SecretType.values();
         var map = new HashMap<String,SecretType>(1 + types.length * 2);
         for (int i = 0; i < types.length; i++) map.put(types[i].getUrlText(), types[i]);
         return map;
     }
}
