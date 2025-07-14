package edu.utexas.tacc.tapis.security.commands.aux.utility;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import com.google.gson.JsonObject;
import edu.utexas.tacc.tapis.security.secrets.SecretPathMapper;
import edu.utexas.tacc.tapis.security.secrets.SecretType;
import edu.utexas.tacc.tapis.shared.utils.TapisGsonUtils;

/*
 * Support various actions for maintaining SK secrets.
 * Actions to take are determined by the options specified.
 *
 * Dockerfile for image is at deployment/tapis-securityutility/Dockerfile
 *
 * To build the utility image run the jenkins job https://jenkins-cic.tacc.utexas.edu/job/TapisJava/job/3_ManualBuildDeploy/job/sk
 *   The job will run the script at deployment/build-securityutility.sh which creates docker image tapis/securityutility
 *   The job also tags the image as tapis/securityutility:dev and pushes to docker hub.
 *
 * To build and push a "dev" version of the image from a laptop:
 *   mvn clean install
 *   mvn -f tapis-securitylib/shaded-pom.xml package
 *   export TAPIS_ENV=dev
 *   ./deployment/build-securityutility.sh
 *   docker push tapis/securityutility:dev
 *
 * Here is an example of running the utility from the TACC Tapis DEV k8s environment
     export VT="$VAULT_TOKEN"
     export SP="-vtok $VT -vurl http://vault:8200 -v -tenant dev -sys_export_meta"
     kubectl run skutility -i --tty --image-pull-policy="Always" \
                              --pod-running-timeout 7m0s \
                             --image=tapis/securityutility:dev --restart=Never --rm --env="SKUTILITY_PARMS=$SP"
 * Example command to output all secret metadata in CSV format.
 *    export SP="-vtok $VT -vurl http://vault:8200 -o -csv -sys_export_meta"
 *    kubectl run skutility -i --tty --image-pull-policy="Always" \
 *                             --pod-running-timeout 7m0s \
 *                             --image=tapis/securityutility:dev --restart=Never --rm --env="SKUTILITY_PARMS=$SP" \
 *             > /tmp/tapis_sys_cred_info_init.csv
 *
 * If no actions are specified then only the check of the vault status is performed
 *   and the tenants under path tapis/tenant are retrieved.
 *
 * Actions:
 *   -sys_cleanup : Removes orphaned Systems secrets.
 *   -sys_export_meta : Exports metadata for all systems secrets
 *
 * sys_cleanup:
 *   Initial version of Systems service stored secrets using a path of the format:
 *     secret/tapis/tenant/<tenant_id>/system/<system_id>/user/<target_user>/<key_type>/S1
 *   Later this was changed in order to distinguish static versus dynamic secrets.
 *     secret/tapis/tenant/<tenant_id>/system/<system_id>/user/<static|dynamic>+<target_user>/<key_type>/S1
 *   This resulted in Systems secrets in SK becoming orphaned. Systems will never look for secrets
 *     using the older path format.
 *   This action will find and remove all Systems secrets matching the old path format
 *
 *  sys_export_meta:
 *    This will output metadata for System secrets. This can be used to initialize the Systems table
 *    that tracks credential metadata. The table was introduced as part of Systems version 1.9.0
 *    The metadata will be output for each path, either static or dynamic, i.e., paths in the form:
 *      secret/tapis/tenant/<tenant_id>/system/<system_id>/user/static+<target_user>
 *    or
 *      secret/tapis/tenant/<tenant_id>/system/<system_id>/user/dynamic+<target_user>
 *    Each metadata record will output as json. For example, for the path
 *      secret/tapis/tenant/dev/test-system/user/static+testuser1
 *    the output would be similar to the following:
 *    {
 *      "tenant_id": "dev",
 *      "system_id": "test-system",
 *      "target_user": "testuser1",
 *      "is_static": true,
 *      "has_password": false,
 *      "has_pki_keys": true,
 *      "has_access_key": false,
 *      "has_token": false
 *    }
 *
 *   Based on SkExport utility written by @rcardone
 */
public class SkUtility
{
  /* ********************************************************************** */
  /*                               Constants                                */
  /* ********************************************************************** */
  // Base URL path for walking tree to find Tapis meta records.
  private static final String VAULT_BASE_URL_META = "v1/secret/metadata";
  // Base URL path for walking tree to find Tapis data records.
  private static final String VAULT_BASE_URL_DATA = "v1/secret/data";
  // Root of the tapis secrets subtree.
  private static final String TAPIS_ROOT = "tapis";
  // Path element for tenants.
  private static final String TENANT_ROOT = String.format("%s/tenant", TAPIS_ROOT);
  // Path element for systems.
  private static final String SYSTEM_ELEMENT = "system";
  // Path element for systems secret suffix.
  private static final String SYSTEM_SECRET_SUFFIX = "S1";
  // Path element for users.
  private static final String USER_ELEMENT = "user";

  // Constants used when generating text output
  private static final String START_SECRETS = "[";
  private static final int    START_SECRETS_LEN = START_SECRETS.length();
  private static final String END_SECRETS  = "]";
  private static final int    OUTPUT_BUFLEN = 8192;

  // We split vault paths on slashes.
  private static final Pattern SPLIT_SLASH_PATTERN = Pattern.compile("/");
  // Delimiter for user field is +
  private static final Pattern SPLIT_PLUS_PATTERN = Pattern.compile("\\+");

  public enum AuthnMethod {PASSWORD, PKI_KEYS, ACCESS_KEY, TOKEN, CERT, TMS_KEYS}

  /* ********************************************************************** */
  /*                                 Fields                                 */
  /* ********************************************************************** */
  // User input.
  private final SkUtilityParameters _parms;

  // The client used for all http calls.
  private final HttpClient           _httpClient;

 /* ********************************************************************** */
 /*                                 Records                                */
 /*    {
 *      "tenant_id": "dev",
 *      "system_id": "test-system",
 *      "target_user": "testuser1",
 *      "is_static": true,
 *      "has_password": false,
 *      "has_pki_keys": true,
 *      "has_access_key": false,
 *      "has_token": false
 *    } */
  /* ********************************************************************** */
  // Wrapper for secret info metadata.
  private record SecretMetaInfo(String tenantId, String systemId, String targetUser, boolean isStatic,
                                boolean hasPassword, boolean hasPkiKeys, boolean hasAccessKey, boolean hasToken,
                                boolean hasTmsKeys) {}

  // Wrapper for processed SecretInfo records.
  private record SecretOutput(String key, String value) {}

  /* ********************************************************************** */
  /*                              Constructors                              */
  /* ********************************************************************** */
  public SkUtility(SkUtilityParameters parms)
  {
    // Parameters cannot be null.
    if (parms == null)
    {
      String msg = "SkUtility requires a parameter object.";
      throw new IllegalArgumentException(msg);
    }

    // Initialize final fields.
    _parms = parms;
    _httpClient  = HttpClient.newHttpClient();
  }

  /* ********************************************************************** */
  /*                             Public Methods                             */
  /* ********************************************************************** */
  /**
   * Main
   *
   * @param args the command line parameters
   * @throws Exception on error
   */
  public static void main(String[] args) throws Exception
  {
    // Parse the command line parameters.
    SkUtilityParameters parms = new SkUtilityParameters(args);
    // Run the utility
    SkUtility skUtility = new SkUtility(parms);
    skUtility.run();
  }

  /**
   * Execute the actions requested
   * @throws Exception on error
   */
  public void run() throws Exception
  {
    List<String> tenants = new ArrayList<>();
    boolean allSystems = true;
    AuthnMethod authnMethod = null;
    int totalSystemsProcessed = 0;
    int totalUsersProcessed = 0;

    // Check status of Vault.
    info("Checking status of Vault");
    checkVaultStatus();

    // If authnMethod specified then validate it
    if (!StringUtils.isBlank(_parms.authnMethod))
    {
      authnMethod =  AuthnMethod.valueOf(_parms.authnMethod.toUpperCase());
    }
    // Figure out tenants and systems to process
    if (!StringUtils.isBlank(_parms.tenant))
    {
      tenants.add(_parms.tenant);
      info("Processing single tenant: " + _parms.tenant);
      // Check for specified list of systems
      if (_parms.systemList != null && !_parms.systemList.isEmpty())
      {
        info("Processing specified list of systems");
        allSystems = false;
      }
    }
    else if (_parms.tenantList != null && !_parms.tenantList.isEmpty())
    {
      info("Processing specified list of tenants");
      tenants.addAll(_parms.tenantList);
    }
    else
    {
      // Get all tenants under tapis/tenant
      info("Processing all tenants");
      tenants = getAllTenants();
    }

    info("******** Tenants Count: " + tenants.size() + " ********");

    // If writing output as CSV then output a header
    if (_parms.csv_output)
    {
      out("===============================================");
      out("Tenant, System, User, isStatic, AuthnMethod");
      out("===============================================");
    }
    // Iterate over tenants
    for (String tenant: tenants)
    {
      debug("Processing tenant: " + tenant);
      // Figure out systems to process
      List<String> systems;
      if (allSystems) systems = getAllSystemsForTenant(tenant);
      else systems = new ArrayList<>(_parms.systemList);
      debug(" ******** Systems Count: " + systems.size() + " ********");
      totalSystemsProcessed += systems.size();
      // Iterate over systems
      for (String system : systems)
      {
        debug(String.format("Found system. Tenant: %s System: %s", tenant, system));
        // Get all users under system
        List<String> users = getUsers(tenant, system);
        debug("******** Users Count: " + users.size() + " ********");
        totalUsersProcessed += users.size();
        // Iterate over users
        for(String user :users)
        {
          if (_parms.sysCleanup) sysCleanupForTenant(tenant, system, user);
          if (_parms.sysExportMeta) sysExportMetadataForTenant(tenant, system, user, authnMethod);
        }
      }
      info("******** Total Tenants Processed: " + tenants.size() + " ********");
      info("******** Total Systems Processed: " + totalSystemsProcessed + " ********");
      info("******** Total Users Processed  : " + totalUsersProcessed + " ********");
    }
  }

  /* ********************************************************************** */
  /*                             Private Methods                            */
  /* ********************************************************************** */

  /*
   * getTenants
   * A LIST on tapis/tenant will yield a list of all tenants under that path
   * Exit with a 1 on error.
   * If we cannot get tenants then it is an unrecoverable error.
   */
  private List<String> getAllTenants() throws Exception
  {
    List<String> tenants = new ArrayList<>();
    // Build the full path
    String fullPath = String.format("%s/%s/%s",_parms.vurl,VAULT_BASE_URL_META,TENANT_ROOT);
    // Make the request to list
    HttpResponse<String> resp = sendListRequest(fullPath);
    // Check return code.
    int rc = resp.statusCode();
    debug("Received HTTP status code: " + rc);
    if (rc == 404)
    {
      // This should never happen. It means no tenants.
      warn("No tenants found");
      return tenants;
    }
    else if (rc >= 300)
    {
      // Looks like an error.
      errorExit("Received http status code " + rc + " on LIST request to vault. FullPath: " + fullPath);
    }

    // Intermediate node. Response body should look like this: {"data": {"keys": ["foo", "foo/"]}}.
    // Parse the response to get the keys
    tenants = getKeysFromResponse(resp);
    return tenants;
  }

  /*
   * getSystems
   * A LIST on tapis/tenant/<tenant_id>/system will yield a list of all systems under that path
   */
  private List<String> getAllSystemsForTenant(String tenant) throws Exception
  {
    List<String> systems = new ArrayList<>();
    // Build the full path
    String fullPath = String.format("%s/%s/%s/%s/%s",_parms.vurl,VAULT_BASE_URL_META,TENANT_ROOT,tenant,SYSTEM_ELEMENT);
    // Make the request to list
    HttpResponse<String> resp = sendListRequest(fullPath);
    // Check return code.
    int rc = resp.statusCode();
    debug("Received HTTP status code: " + rc);
    if (rc == 404)
    {
      // Indicates no systems for this tenant. This could happen.
      warn("No systems found for tenant. Tenant: " + tenant);
      return systems;
    }
    else if (rc >= 300)
    {
      // Looks like an error.
      errorExit("Received http status code " + rc + " on LIST request to vault. FullPath: " + fullPath);
    }
    // Intermediate node. Response body should look like this: {"data": {"keys": ["foo", "foo/"]}}.
    // Parse the response to get the keys
    systems = getKeysFromResponse(resp);
    debug("Number of systems: " + systems.size());
    return systems;
  }

  /*
   * getUsers
   * A LIST on tapis/tenant/<tenant_id>/system/<system_id>/user will yield a list of all users under that path
   */
    private List<String> getUsers(String tenant, String system) throws Exception
    {
        List<String> users = new ArrayList<>();
        // Build the full path
        String fullPath =
            String.format("%s/%s/%s/%s/%s/%s/%s/",
                          _parms.vurl,VAULT_BASE_URL_META,TENANT_ROOT,tenant,SYSTEM_ELEMENT,system,USER_ELEMENT);
        // Make the request to list
        HttpResponse<String> resp = sendListRequest(fullPath);
        // Check return code.
        int rc = resp.statusCode();
        debug("Received HTTP status code: " + rc);
        if (rc == 404)
        {
            // Indicates no systems for this tenant. This could happen.
            warn("No systems found for tenant. Tenant: " + tenant);
            return users;
        }
        else if (rc >= 300)
        {
            // Looks like an error.
            errorExit("Received http status code " + rc + " on LIST request to vault. FullPath: " + fullPath);
        }
        // Intermediate node. Response body should look like this: {"data": {"keys": ["foo", "foo/"]}}.
        // Parse the response to get the keys
        users = getKeysFromResponse(resp);
        debug("Number of users: " + users.size());
        return users;
    }

  /**
   * Run sysCleanup action for a single tenant.
   *TODO Remove legacy orphaned secrets
   *TODO  This action will find and remove all Systems secrets matching the old path format
   * Initial version of Systems service stored secrets using a path of the format:
   *   secret/tapis/tenant/<tenant_id>/system/<system_id>/user/<target_user>/<key_type>/S1
   * Later this was changed in order to distinguish static versus dynamic secrets.
   *   secret/tapis/tenant/<tenant_id>/system/<system_id>/user/static+<target_user>/<key_type>/S1
   *   or
   *   secret/tapis/tenant/<tenant_id>/system/<system_id>/user/dynamic+<target_user>/<key_type>/S1
   * This resulted in Systems secrets in SK becoming orphaned. Systems will never look for secrets
   *   using the older path format.
   * For given tenant walk the tree looking for System type records that do not match the format of
   *   the current implementation of system secrets.
   * If a path does contain "dynamic+" or "static+" in the expected location then it is a legacy record
   *   and can be removed.
   * @param tenant tenant to process
   * @throws Exception on error
   */
  private void sysCleanupForTenant(String tenant, String system, String user) throws Exception
  {
    debug(String.format("Executing action: SysCleanup for tenant: %s system: %s user: %s.", tenant, system, user));
//    // TODO If user does not begin with static+ or dynamic+ then it is a legacy record and is removed.
//    if (!StringUtils.startsWith(user,"static+") && !StringUtils.startsWith(user,"dynamic+"))
//    {
//      debug(String.format("Found legacy record. Tenant: %s System: %s User: %s", tenant, system, user));
//    }
    // TODO If user does not begin with static+ or dynamic+ then it is a legacy record and is removed.
    if (StringUtils.startsWith(user,"static+") || StringUtils.startsWith(user,"dynamic+"))
    {
      String userName = SPLIT_PLUS_PATTERN.split(user, 2)[1];
      debug(String.format("Found non-legacy record. Tenant: %s System: %s User field: %s Username: %s",
                          tenant, system, user, userName));
    }
  }

  /**
   * Run sysExportMetadata action for a single tenant.
   * The metadata will be output for each path, either static or dynamic,
   * Vault paths are in the form:
   *      secret/tapis/tenant/<tenant_id>/system/<system_id>/user/static+<target_user>
   *    or
   *      secret/tapis/tenant/<tenant_id>/system/<system_id>/user/dynamic+<target_user>
   * Vault paths for Systems secrets always end with <secret_type>/S1
   *   where secret_type is password, sshkey, accesskey or
   * @param tenant tenant to process
   * @param system system to process
   * @param userField field with user data, static/dynamic plus username
   * @param authnMethod authn method if filtering by specific AuthnMethod
   * @throws Exception on error
   */
  private void sysExportMetadataForTenant(String tenant, String system, String userField, AuthnMethod authnMethod) throws Exception
  {
    debug(String.format("Executing action: SysExportMetadata for tenant: %s system: %s user: %s authnMethod: %s.",
                        tenant, system, userField, authnMethod));
    boolean isStatic;
    String userName;

    // If user field begins with static+ or dynamic+ then it is a non-legacy record we process it
    if (StringUtils.startsWith(userField,"static+"))
    {
      isStatic = true;
      userName = SPLIT_PLUS_PATTERN.split(userField, 2)[1];
    }
    else if (StringUtils.startsWith(userField,"dynamic+"))
    {
      isStatic = false;
      userName = SPLIT_PLUS_PATTERN.split(userField, 2)[1];
      debug(String.format("Found dynamic record. Tenant: %s System: %s User field: %s Username: %s",
                          tenant, system, userField, userName));
    }
    else
    {
      // It is a legacy record. Ignore it.
      return;
    }
    debug(String.format("Found record. Tenant: %s System: %s TargetUsername: %s isStatic: %b",
                        tenant, system, userName, isStatic));
    // Determine metadata for this user as a java record
    SecretMetaInfo secretMetadata = getSecretMetadata(tenant, system, userField, userName, isStatic);
    debug("Found secret metadata: " + secretMetadata);

    // If not asked to log only specific authnMethod records, then always log the record
    boolean logIt;
    if (authnMethod == null) logIt = true;
    else
    {
      // Only log if record has requested type of secret.
      logIt =
            switch (authnMethod)
            {
              case PASSWORD -> secretMetadata.hasPassword;
              case PKI_KEYS -> secretMetadata.hasPkiKeys;
              case ACCESS_KEY -> secretMetadata.hasAccessKey;
              case TOKEN -> secretMetadata.hasToken;
              case TMS_KEYS -> secretMetadata.hasTmsKeys;
              default -> false;
            };
    }
    if (logIt)
    {
      if (_parms.csv_output)
      {
        out(String.format("%s,%s,%s,%b,%s", tenant, system, secretMetadata.targetUser, isStatic, authnMethod));
      }
      else
      {
        out(String.format("Found secret. Tenant: %s System: %s TargetUsername: %s isStatic: %b, KeyType: %s",
                          tenant, system, secretMetadata.targetUser, isStatic, authnMethod));
      }
    }
  }

  /*
   * getSecretMetadata
   * Determine secret metadata by making calls to vault under path v1/secret/data/
   */
  private SecretMetaInfo getSecretMetadata(String tenant, String system, String userField, String targetUser, boolean isStatic)
          throws Exception
  {
    // Build the base path for secret data
    String baseSecretDataPath = String.format("%s/%s/%s/%s/%s/%s/%s/%s",
                   _parms.vurl,VAULT_BASE_URL_DATA,TENANT_ROOT,tenant,SYSTEM_ELEMENT,system,USER_ELEMENT,userField);
    // For each secret type build the path and attempt to check for data
    boolean hasPassword = checkSecretData(baseSecretDataPath, SecretPathMapper.KeyType.password);
    boolean hasPkiKeys = checkSecretData(baseSecretDataPath, SecretPathMapper.KeyType.sshkey);
    boolean hasAccessKey = checkSecretData(baseSecretDataPath, SecretPathMapper.KeyType.accesskey);
    boolean hasToken = checkSecretData(baseSecretDataPath, SecretPathMapper.KeyType.token);
    boolean hasTmsKeys = checkSecretData(baseSecretDataPath, SecretPathMapper.KeyType.tmskey);
    return new SecretMetaInfo(tenant, system, targetUser, isStatic, hasPassword, hasPkiKeys, hasAccessKey, hasToken, hasTmsKeys);
  }

  /*
   * checkSecretData
   * Determine if secret of given type is present.
   */
  private boolean checkSecretData(String baseSecretDataPath, SecretPathMapper.KeyType keytype)
          throws Exception
  {
    // Build the full path to the secret
    String fullPath = String.format("%s/%s/%s", baseSecretDataPath, keytype.toString(), SYSTEM_SECRET_SUFFIX);

    // Make the GET request
    // Parse the response body and return the value of the data object.
    // The secrets should look like:  "data": {"data": {"foo": "bar"}, "metadata": {..}}
    HttpRequest request;
    HttpResponse<String> resp;
    var reqUri = new URI(fullPath);
    debug("Sending GET request to: " + reqUri);
    request = HttpRequest.newBuilder().uri(reqUri)
            .headers("X-Vault-Token", _parms.vtok, "Accept", "application/json",
                     "Content-Type", "application/json")
            .build();
    resp = _httpClient.send(request, HttpResponse.BodyHandlers.ofString());

    // Check return code.
    int rc = resp.statusCode();
    String headers = resp.headers().toString();
    String respStr = resp.toString();
    var location = resp.headers().firstValue("location");
    warn(String.format("Received HTTP status code: %d location: %s Headers: %s Response: %s", rc, location, headers, respStr));
    // If not found then no secret data, so return false
    if (rc == 404) return false;
    // For error status code log an error and return false
    if (rc >= 300)
    {
      warn("Received http status code " + rc + " on GET request to " + reqUri);
      debug(String.format("Received HTTP status code: %d location: %s Headers: %s Response: %s", rc, location, headers, respStr));
      return false;
    }

    // Parse the response body and return the value of the data object.
    // The secrets look like:  "data": {"data": {"foo": "bar"}, "metadata": {..}}
    JsonObject jsonObj =  TapisGsonUtils.getGson().fromJson(resp.body(), JsonObject.class);
    if (jsonObj == null)
    {
        error("Unable to create Json object from response.");
        return false;
    }
    var dataObj = jsonObj.get("data");
    if (dataObj == null)
    {
      error("Did not find data field in json object from response.");
      return false;
    }
    var dataJsonObj = dataObj.getAsJsonObject();

    if (dataJsonObj == null)
    {
      error("Unable to get dataJsonObj from response.");
      return false;
    }
    // Log if found
    debug(String.format("Found secret. KeyType: %s reqUri: %s", SecretPathMapper.KeyType.sshkey, reqUri));
    return true;
  }

  // Print out error message and exit
  private void errorExit(String s) { System.out.printf("ERROR: %s%n", s); System.exit(1); }
  // Print out error message
  private void error(String s) { System.out.printf("ERROR: %s%n", s); }
  // Print warning message
  private void warn(String s) { if (_parms.verbose) System.out.println("WARN: " + s); }
  // Print info message
  private void info(String s) { if (!_parms.quiet) System.out.println("INFO: " + s); }
  // Print debug message
  private void debug(String s) { if (_parms.verbose) System.out.println("DEBUG: " + s); }
  // Print trace message
  private void trace(String s) { if (_parms.verbose) System.out.println("TRACE: " + s); }

  // Output result
  private void out(String s) { if (_parms.output) System.out.println(s); }

    /* ---------------------------------------------------------------------- */
    /* checkVaultStatus:                                                      */
    /* ---------------------------------------------------------------------- */
    private void checkVaultStatus() throws Exception
    {
        // Get vault information.
        String baseUrl = _parms.vurl;
        String tok = _parms.vtok;
        
        // Issue request.
        HttpRequest request = HttpRequest.newBuilder()
            .uri(new URI(baseUrl + "/v1/sys/health"))
            .headers("X-Vault-Token", tok, "Accept", "application/json", 
                     "Content-Type", "application/json")
            .GET()
            .build();
        HttpResponse<String> resp = _httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        // Check status code.
        int rc = resp.statusCode();
        if (rc >= 300) {
            String msg = "Received http status code " + rc + " on request to " +
                         "vault: " + request.uri().toString() + ".";
            throw new RuntimeException(msg);
        }
        
        // Parse the response body.
        var jsonObj = TapisGsonUtils.getGson().fromJson(resp.body(), JsonObject.class);
        if (jsonObj == null) {
            String msg = "Received http status code " + rc + " and no response content " +
                         "on request to vault: " + request.uri().toString() + ".";
            throw new RuntimeException(msg);
        }
        boolean sealed = jsonObj.get("sealed").getAsBoolean();
        String version = jsonObj.get("version").getAsString();
        info("Vault at " + baseUrl + " is at version " + version +
            " and is " + (sealed ? "" : "not ") + "sealed.");
        if (sealed) {
            String msg = "Unable to continue because vault at " + baseUrl + " is sealed.";
            throw new RuntimeException(msg);
        }
    }

    /* ---------------------------------------------------------------------- */
    /* writeJsonOutput:                                                       */
    /* ---------------------------------------------------------------------- */
    private String writeJsonOutput(List<SecretOutput> olist)
    {
        // Initialize result json string.
        var secrets = new StringBuilder(OUTPUT_BUFLEN);
        secrets.append(START_SECRETS);
        
        // Write each path/secret pair as json. The secret is itself a json object
        // so the result is that secret is nested in the result object. When raw
        // output is requested, the result objects end up looking like this:
        //
        // {
        //    "key": "tapis/service/postgres/dbhost/sk-postgres/dbname/tapissecdb/dbuser/tapis/credentials/passwords",
        //    "value": { "password": "abcdefg" }
        // }
        //
        // When raw output is not requested, the key is converted into a string derived 
        // from the raw path and appropriate for use as an environment variable name. 
        for (var rec: olist) {
            // Format the json payload.
            if (secrets.length() != START_SECRETS_LEN) secrets.append(",");
            secrets.append("\n{\"key\": \"");
            secrets.append(rec.key());
            secrets.append("\",\"value\":");
            secrets.append(rec.value());
            secrets.append("}");
        }
        
        // Close the secrets outer json object and return.
        secrets.append(END_SECRETS);
        return secrets.toString();
    }

    /* ********************************************************************** */
    /*                             Private Methods                            */
    /* ********************************************************************** */
    // Temporary holder for a secret type.
    private static final class SecretTypeWrapper {
        private SecretType _secretType;
    }

  /**
   * Send http LIST request
   * @param fullPath - url for request
   * @return http response
   */
  private HttpResponse<String> sendListRequest(String fullPath)
          throws URISyntaxException, IOException, InterruptedException
  {
    var reqUri = new URI(fullPath);
    debug("Sending LIST request to: " + reqUri);
    HttpRequest request = HttpRequest.newBuilder().uri(reqUri)
            .headers("X-Vault-Token", _parms.vtok, "Accept", "application/json",
                     "Content-Type", "application/json")
            .method("LIST", BodyPublishers.noBody())
            .build();
    return _httpClient.send(request, HttpResponse.BodyHandlers.ofString());
  }

  /**
   * Get keys from http LIST response
   * @param resp - response from request
   * @return List of keys as strings with trailig slash (/) removed
   */
  private List<String> getKeysFromResponse(HttpResponse<String> resp)
  {
    List<String> keysAsString = new ArrayList<>();
    var jsonObj = TapisGsonUtils.getGson().fromJson(resp.body(), JsonObject.class);
    if (jsonObj == null) errorExit("Unable to create Json object from response.");
    var dataObj = jsonObj.get("data");
    if (dataObj == null) errorExit("Did not find data field in json object from response.");
    var data = dataObj.getAsJsonObject();
    var keysObj = data.get("keys");
    if (keysObj == null) errorExit("Did not find keys field in json object from response.");
    var keys = data.get("keys").getAsJsonArray();
    // Create the list of keys
    for (int i = 0; i < keys.size(); i++)
    {
      String keyStr = StringUtils.removeEnd(keys.get(i).getAsString(), "/");
      keysAsString.add(keyStr);
    }
    return keysAsString;
  }
}
