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
import java.util.TreeSet;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import com.google.gson.JsonObject;
import edu.utexas.tacc.tapis.security.secrets.SecretPathMapper;
import edu.utexas.tacc.tapis.security.secrets.SecretType;
import edu.utexas.tacc.tapis.security.secrets.SecretTypeDetector;
import edu.utexas.tacc.tapis.shared.utils.TapisGsonUtils;

/**
 * Support various actions for maintaining SK secrets.
 * Actions to take are determined by the options specified.
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
 *    This will output metadata for System secrets. This is used to initialize the Systems table
 *    that tracks credential metadata. The table was introduced as part of Systems version TODO/TBD 1.?.?
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
 *   Based on SKExport utility written by @rcardone
 */
public class SkUtility
{
  /* ********************************************************************** */
  /*                               Constants                                */
  /* ********************************************************************** */
  // Base URL path for walking tree to find Tapis meta records.
  private static final String VAULT_BASE_URL_META = "v1/secret/metadata";
  // Base URL path for walking tree to find Tapis data records.
  private static final String VAULT_BASE_URL_DATA = "v1/secret/data/";
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

  // We sanitize by removing all characters not in this character class.
  private static final Pattern SANITIZER = Pattern.compile("[^a-zA-Z0-9_]");

  /* ********************************************************************** */
  /*                                 Fields                                 */
  /* ********************************************************************** */
  // User input.
  private final SkUtilityParameters _parms;

  // The client used for all http calls.
  private final HttpClient           _httpClient;

  // Metadata records for secrets
  private final ArrayList<SecretInfo> _secretRecords;

  // Progress counters.
  private int _numListings;
  private int _numReads;
  private int _numUnknownPaths;

  // Result reporting lists.
  private final TreeSet<String> _failedReads;   // Secrets paths that could not be read.

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
  private record SecretInfo(SecretType type, String path, String secret) {} // TODO remove
  private record SecretMetaInfo(String tenantId, String systemId, String targetUser, boolean isStatic,
                                boolean hasPassword, boolean hasPkiKeys, boolean hasAccessKey, boolean hasToken) {}

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
    _failedReads = new TreeSet<String>();
    _secretRecords = new ArrayList<>(256);
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
    // Check status of Vault.
    debug("Checking status of Vault");
    checkVaultStatus();

    // Get all tenants under tapis/tenant
    debug("Retrieving tenants");
    List<String> tenants = getTenants();
    debug("******** Tenants Count: " + tenants.size() + " ********");
    for (String tenant: tenants)
    {
      debug("Processing tenant: " + tenant);
      if (_parms.sysCleanup) sysCleanupForTenant(tenant);
      if (_parms.sysExportMeta) sysExportMetadataForTenant(tenant);
    }

//    {
//      debug("Execuing SysCleanup action");
//      executeSysCleanup(tenants);
//    }

//TODO if (_parms.sysExportMeta) executeSysExportMeta();
    // Walk the Vault source tree and discover all tapis secrets.
//TODO    processSourceTree(TAPIS_SECRET_ROOT);
        
    // Put all secrets into a list of records.
//TODO    var outputRecs = calculateOutputRecs();
        
    // Put the raw data into the user-specified output format.
//TODO    writeResults(outputRecs);
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
  private List<String> getTenants() throws Exception
  {
    List<String> tenants = new ArrayList<>();
    // Build the full path
    String fullPath = String.format("%s%s/%s/",_parms.vurl,VAULT_BASE_URL_META,TENANT_ROOT);
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
  private List<String> getSystems(String tenant) throws Exception
  {
    List<String> systems = new ArrayList<>();
    // Build the full path
    String fullPath = String.format("%s%s/%s/%s/%s",_parms.vurl,VAULT_BASE_URL_META,TENANT_ROOT,tenant,SYSTEM_ELEMENT);
    // Make the request to list
    HttpResponse<String> resp = sendListRequest(fullPath);
    // Check return code.
    int rc = resp.statusCode();
    System.out.println("Received HTTP status code: " + rc);
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
            String.format("%s%s/%s/%s/%s/%s/%s/",
                          _parms.vurl,VAULT_BASE_URL_META,TENANT_ROOT,tenant,SYSTEM_ELEMENT,system,USER_ELEMENT);
        // Make the request to list
        HttpResponse<String> resp = sendListRequest(fullPath);
        // Check return code.
        int rc = resp.statusCode();
        System.out.println("Received HTTP status code: " + rc);
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
  private void sysCleanupForTenant(String tenant) throws Exception
  {
    // TODO/TBD If all actions require iterating over systems and users,
    //   then probably makes sense to refactor and place the loops outside the individual action methods,
    //   i.e. in SkUtility.run()
    debug("Executing action: SysCleanup for tenant. Tenant: " + tenant);
    // Get all systems under the tenant
    List<String> systems = getSystems(tenant);
    debug("******** Systems Count: " + systems.size() + " ********");
    for (String system : systems)
    {
      debug(String.format("Found system. Tenant: %s System: %s", tenant, system));
      // Get all users under system
      List<String> users = getUsers(tenant, system);
      debug("******** Users Count: " + users.size() + " ********");
      for (String user : users)
      {
//        debug(String.format("Found system user. Tenant: %s System: %s User: %s", tenant, system, user));
//        // TODO If user does not begin with static+ or dynamic+ then it is a legacy record and is removed.
//        if (!StringUtils.startsWith(user,"static+") && !StringUtils.startsWith(user,"dynamic+"))
//        {
//          debug(String.format("Found legacy record. Tenant: %s System: %s User: %s", tenant, system, user));
//        }
        // TODO If user does not begin with static+ or dynamic+ then it is a legacy record and is removed.
        if (StringUtils.startsWith(user,"static+") || StringUtils.startsWith(user,"dynamic+"))
        {
          String userName = SPLIT_PLUS_PATTERN.split(user, 2)[1];
          debug(String.format("Found non-legacy record. Tenant: %s System: %s User field: %s Username: %s",
                              tenant, system, user, userName));
        }
      }
    }
  }

  /**
   * Run sysExportMetadata action for a single tenant.
   * The metadata will be output for each path, either static or dynamic,
   * Vault paths are in the form:
   *      secret/tapis/tenant/<tenant_id>/system/<system_id>/user/static+<target_user>
   *    or
   *      secret/tapis/tenant/<tenant_id>/system/<system_id>/user/dynamic+<target_user>
   * Metadata is under TODO ???
   * and data is under TODO ???
   * Vault paths for Systems secrets always end with <secret_type>/S1
   *   where secret_type is password, sshkey, accesskey or
   * TODO
   * @param tenant tenant to process
   * @throws Exception on error
   */
  private void sysExportMetadataForTenant(String tenant) throws Exception
  {
    // TODO/TBD If all actions require iterating over systems and users,
    //   then probably makes sense to refactor and place the loops outside the individual action methods,
    //   i.e. in SkUtility.run()
    debug("Executing action: SysExportMetadata for tenant. Tenant: " + tenant);
    // Get all systems under the tenant
    List<String> systems = getSystems(tenant);
    debug("******** Systems Count: " + systems.size() + " ********");
    for (String system : systems)
    {
      boolean isStatic;
      String userName;
      debug(String.format("Found system. Tenant: %s System: %s", tenant, system));
      // Get all users under system
      List<String> users = getUsers(tenant, system);
      debug("******** Users Count: " + users.size() + " ********");
      for (String userField : users)
      {
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
          continue;
        }
        debug(String.format("Found record. Tenant: %s System: %s TargetUsername: %s isStatic: %b",
                            tenant, system, userName, isStatic));
        // TODO determine metadata for this user as a java record
        var secretMetadata = getSecretMetadata(tenant, system, userField, userName, isStatic);
        outputSecretMetadata(secretMetadata);
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
    // Build the base path for secret dta
    String baseSecretDataPath = String.format("%s%s/%s/%s/%s/%s/%s/%s/",
                   _parms.vurl,VAULT_BASE_URL_DATA,TENANT_ROOT,tenant,SYSTEM_ELEMENT,system,USER_ELEMENT,userField);
    // For each secret type build the path and attempt to check for data
    boolean hasPassword = checkSecretData(baseSecretDataPath, SecretPathMapper.KeyType.password);
    boolean hasPkiKeys = checkSecretData(baseSecretDataPath, SecretPathMapper.KeyType.sshkey);
    boolean hasAccessKey = checkSecretData(baseSecretDataPath, SecretPathMapper.KeyType.accesskey);
    boolean hasToken = checkSecretData(baseSecretDataPath, SecretPathMapper.KeyType.token);
    return new SecretMetaInfo(tenant, system, targetUser, isStatic, hasPassword, hasPkiKeys, hasAccessKey, hasToken);
  }

  /*
   * checkSecretData
   * Determine if secret of given type is present.
   */
  private boolean checkSecretData(String baseSecretDataPath, SecretPathMapper.KeyType keytype)
          throws Exception
  {
    // Build the full path to the secret
    String fullPath = String.format("%s/%s/%s/", baseSecretDataPath, keytype.toString(), SYSTEM_SECRET_SUFFIX);

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
    System.out.println("Received HTTP status code: " + rc);
    // If not found then no secret data, so return false
    if (rc == 404) return false;
    // For error status code log an error and return false
    if (rc >= 300)
    {
      warn("Received http status code " + rc + " on GET request to " + reqUri);
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
    // TODO For given keytype (password, sshkeys, etc) check that all fields present and valid
    return checkSecretDataForKeytype(keytype, dataJsonObj);
  }

  // Print debug message
  private void debug(String s) { if (_parms.verbose) System.out.println("DEBUG: " + s); }
  // Print warning message
  private void warn(String s) { if (_parms.verbose) System.out.println("WARN: " + s); }
  // Print out error message
  private void error(String s) { System.out.printf("ERROR: %s%n", s); }
  // Print out error message and exit
  private void errorExit(String s) { System.out.printf("ERROR: %s%n", s); System.exit(1); }

  /** TODO remove
   * processSourceTree
   * The first call to this recursive method starts at the root of the tapis hierarchy in Vault.
   *
   * @param curpath the path to explore depth-first
   */
  private void processSourceTree(String curpath) throws Exception
  {
      // Increment listing counter.
        _numListings++;

        // Make the request to list the curpath.
        HttpRequest request;
        HttpResponse<String> resp;
        try {
            request = HttpRequest.newBuilder()
                .uri(new URI(_parms.vurl + "v1/secret/metadata/" + curpath))
                .headers("X-Vault-Token", _parms.vtok, "Accept", "application/json",
                         "Content-Type", "application/json")
                .method("LIST", BodyPublishers.noBody())
                .build();
            resp = _httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            // Record read failure and display error message.
            recordFailedRead(_parms.vurl + "v1/secret/metadata/" + curpath);
            out(e.getClass().getSimpleName() + ": " + e.getMessage());
            return;
        }

        // Check return code.
        int rc = resp.statusCode();
        if (rc == 404) {
            // We probably discovered a secret (i.e., leaf node).
            copySecret(curpath);
            return;
        }
        else if (rc >= 300) {
            // Looks like an error.
            recordFailedRead(_parms.vurl + "v1/secret/metadata/" + curpath);
            out("Received http status code " + rc + " on LIST request to " +
                "source vault: " + request.uri().toString() + ".");
            return;
        } else {
            // Intermediate node. Parse the response body that looks something like this:
            // {"data": {"keys": ["foo", "foo/"]}}
            var jsonObj = TapisGsonUtils.getGson().fromJson(resp.body(), JsonObject.class);
            var data    = jsonObj.get("data").getAsJsonObject();
            var keys    = data.get("keys").getAsJsonArray();
            int numKeys = keys.size();
            for (int i = 0; i < numKeys; i++) {
               String key = keys.get(i).getAsString();
               processSourceTree(curpath + key);
            }
        }
    }
    
    /* ---------------------------------------------------------------------- */
    /* copySecret:                                                            */
    /* ---------------------------------------------------------------------- */
    private void copySecret(String curpath)
    {
        // Get the secret from the source vault.
        var secretText = readSecret(curpath);
        if (secretText == null) return;
        
        // Do we care about this path?
        // We may not need to export all secrets.
        var typeWrapper = new SecretTypeWrapper(); 
        if (skipStore(curpath, typeWrapper)) return;
        
        // Collect the path and secret.
        var r = new SecretInfo(typeWrapper._secretType, curpath, secretText);
        _secretRecords.add(r);
        
        // Accumulate the secrets written.
        if (_numReads % 500 == 0) 
            debug("->Listings = " + _numListings
                + ",\tReads = "  + _numReads);
    }
    
    /* ---------------------------------------------------------------------- */
    /* readSecret:                                                            */
    /* ---------------------------------------------------------------------- */
    private String readSecret(String secretPath)
    {
        // Increment listing counter.
        _numReads++;
        
        // Make the request.
        HttpRequest request;
        HttpResponse<String> resp;
        try {
            request = HttpRequest.newBuilder()
                .uri(new URI(_parms.vurl + VAULT_BASE_URL_DATA + secretPath))
                .headers("X-Vault-Token", _parms.vtok, "Accept", "application/json", 
                         "Content-Type", "application/json")
                .build();
            resp = _httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            // Record read failure and display error message.
            recordFailedRead(_parms.vurl + VAULT_BASE_URL_DATA + secretPath);
            debug(e.getClass().getSimpleName() + ": " + e.getMessage());
            return null;
        }
        
        // Check return code.
        int rc = resp.statusCode();
        if (rc >= 300) {
            // Looks like an error.
            recordFailedRead(_parms.vurl + VAULT_BASE_URL_DATA + secretPath);
            debug("Received http status code " + rc + " on READ request to " +
                "source vault: " + request.uri().toString() + ".");
            return null;
        } 
        
        // Parse the response body and return the value of the data object.
        // The secrets look like:  "data": {"data": {"foo": "bar"}, "metadata": {..}}
        JsonObject jsonObj =  TapisGsonUtils.getGson().fromJson(resp.body(), JsonObject.class);
        var dataObj = jsonObj.get("data").getAsJsonObject();
        if (dataObj == null) return null;
          else return dataObj.get("data").toString();
    }
    
    /* ---------------------------------------------------------------------- */
    /* skipStore:                                                             */
    /* ---------------------------------------------------------------------- */
    /** Based on the output settings determine whether we ignore this record. 
     * 
     * @param secretPath the path of the secret.
     * @param resultType output variable that captures the secret type.
     * @return true if secret should be skipped, false to store and process.
     */
    private boolean skipStore(String secretPath, SecretTypeWrapper resultType)
    {
        // Always parse the path.
        var secretType = SecretTypeDetector.detectType(secretPath);
        if (secretType == null) {
            _numUnknownPaths++;
            return true; // skip
        }
        
        // Pass back the result secret type.
        resultType._secretType = secretType;
        
        // Is this a full dump of all secrets?
//TODO remove        if (_parms.noSkipUserSecrets) return false;
        
        // Determine if this is a user-initiated secret.
        if (secretType == SecretType.System || secretType == SecretType.User) 
            return true; // skip
        
        // Don't skip writing this secret.
        return false;
    }

    /* ---------------------------------------------------------------------- */
    /* calculateOutputRecs:                                                   */
    /* ---------------------------------------------------------------------- */
    private List<SecretOutput> calculateOutputRecs()
    {
        // Estimate the output list size based on the number of raw secrets.
        var olist = new ArrayList<SecretOutput>(2* _secretRecords.size());
        
        // Each raw record can create one or more output records.
        for (var srec : _secretRecords) { olist.add(getRawDumpOutputRec(srec)); }
        // Return the list.
        return olist;
    }
    
    /* ---------------------------------------------------------------------- */
    /* getServicePwdOutputRec:                                                */
    /* ---------------------------------------------------------------------- */
    private void getServicePwdOutputRec(SecretInfo srec, List<SecretOutput> olist)
    {
        // Construct the key string based on the user-selected output format.
        // Split the path into segments.  We know the split is valid since it 
        // already passed muster in SecretTypeDetector. The service name is 
        // at index 4.
        var parts = SPLIT_SLASH_PATTERN.split(srec.path(), 0);
        String keyPrefix = SecretType.ServicePwd.name().toUpperCase() + "_" +
                           parts[4].toUpperCase(); 
        addDynamicSecrets(keyPrefix, srec.secret(), olist);
    }
    
    /* ---------------------------------------------------------------------- */
    /* getDBCredentialOutputRec:                                              */
    /* ---------------------------------------------------------------------- */
    private void getDBCredentialOutputRec(SecretInfo srec, List<SecretOutput> olist)
    {
        // Construct the key string based on the user-selected output format.
        // Split the path into segments.  We know the split is valid since it 
        // already passed muster in SecretTypeDetector. The service name is 
        // at index 2, dbhost at 4, dbname at 6, dbuser at 8. 
        var parts = SPLIT_SLASH_PATTERN.split(srec.path(), 0);
        String keyPrefix = SecretType.DBCredential.name().toUpperCase() + "_" +
                           parts[2].toUpperCase() + "_" + 
                           parts[4].toUpperCase() + "_" +
                           parts[6].toUpperCase() + "_" +
                           parts[8].toUpperCase(); 
        addDynamicSecrets(keyPrefix, srec.secret(), olist);
    }
    
    /* ---------------------------------------------------------------------- */
    /* getJWTSigningOutputRec:                                                */
    /* ---------------------------------------------------------------------- */
    private void getJWTSigningOutputRec(SecretInfo srec, List<SecretOutput> olist)
    {
        // Construct the key string based on the user-selected output format.
        // Split the path into segments.  We know the split is valid since it 
        // already passed muster in SecretTypeDetector. The tenant name is 
        // at index 2. 
        var parts = SPLIT_SLASH_PATTERN.split(srec.path(), 0);
        
        // Process both public and private keys.
        String keyPrefix = SecretType.JWTSigning.name().toUpperCase() + "_" +
                           parts[2].toUpperCase(); 
        addKeyPair(keyPrefix, srec.secret(), olist);
    }
    
    /* ---------------------------------------------------------------------- */
    /* getSystemOutputRec:                                                    */
    /* ---------------------------------------------------------------------- */
    private void getSystemOutputRec(SecretInfo srec, List<SecretOutput> olist)
    {
        // Construct the key string based on the user-selected output format.
        // Split the path into segments.  We know the split is valid since it 
        // already passed muster in SecretTypeDetector. The tenant name is 
        // at index 2, the system id at 4.  
        var parts = SPLIT_SLASH_PATTERN.split(srec.path(), 0);
        
        // Set the key prefix.
        String keyPrefix = SecretType.System.name().toUpperCase() + "_" +
                           parts[2].toUpperCase() + "_" + 
                           parts[4].toUpperCase() + "_";
        
        // We need to know if we are using a dynamic or static user to complete the key.
        String keyType, key;
        if ("dynamicUserId".equals(parts[5])) {
            // Capture the authn type and the static dynamic user string.
            keyType = parts[6];
            key = keyPrefix + "DYNAMICUSERID";
        } else {
            // Capture the authn type and user.
            keyType = parts[7];
            key = keyPrefix + parts[6].toUpperCase();
        }
        
        // Lock down the key type.
        SecretPathMapper.KeyType keyTypeEnum = null;
        try {keyTypeEnum = SecretPathMapper.KeyType.valueOf(keyType);}
            catch (Exception e) {
                debug(srec.path() + " has invalid keyType: " + keyType + ".\n" + e.toString());
                return;
            }
        
        // Assign the value based on the key type.
        switch (keyTypeEnum) {
            case sshkey:
            case cert:
                addKeyPair(key, srec.secret(), olist);
            break;
            
            case password:
            case accesskey:
                addDynamicSecrets(key, srec.secret(), olist);
            break;
        }
    }

    /* ---------------------------------------------------------------------- */
    /* getUserOutputRec:                                                      */
    /* ---------------------------------------------------------------------- */
    private void getUserOutputRec(SecretInfo srec, List<SecretOutput> olist)
    {
        // Construct the key string based on the user-selected output format.
        // Split the path into segments.  We know the split is valid since it 
        // already passed muster in SecretTypeDetector. The tenant name is 
        // at index 2, user at 4, secretName at 6.
        var parts = SPLIT_SLASH_PATTERN.split(srec.path(), 0);
        String keyPrefix = SecretType.User.name().toUpperCase() + "_" +
                           parts[2].toUpperCase() + "_" +
                           parts[4].toUpperCase() + "_" +
                           parts[6].toUpperCase();
        addDynamicSecrets(keyPrefix, srec.secret(), olist);
    }
    
    /* ---------------------------------------------------------------------- */
    /* addDynamicSecrets:                                                     */
    /* ---------------------------------------------------------------------- */
    /** Create an output entry for each key/value pair listed in the Vault
     * secret text.
     * 
     * @param keyPrefix the prefix of the attribute we'll create
     * @param rawSecret the Vault secret value as json text
     * @param olist the result accumulator
     */
    private void addDynamicSecrets(String keyPrefix, String rawSecret, List<SecretOutput> olist)
    {
        // Dynamically discover the individual values associated with this
        // user secret.  Since the keys are user chosen, we may have to transform
        // them to avoid illegal characters in target context (e.g., env variables).
        // First let's see if there's any secret.
        if (rawSecret == null) {
            olist.add(new SecretOutput(keyPrefix, ""));
            return;
        }
        
        // The keys are at the top level in the json object.
        // We process the private key first.
        JsonObject jsonObj = TapisGsonUtils.getGson().fromJson(rawSecret, JsonObject.class);
        for (var entry : jsonObj.entrySet()) {
            var key = entry.getKey();
            var val = entry.getValue().getAsString();
            if (val == null) val = "";
            olist.add(new SecretOutput(keyPrefix + "_" + key.toUpperCase(), val));
        }
    }
    
    /* ---------------------------------------------------------------------- */
    /* addKeyPair:                                                            */
    /* ---------------------------------------------------------------------- */
    /** This specialized version of addDynamicSecrets ignores the "key" attribute
     * that Vault return in add to privateKey and publicKey.  Basically, we
     * hardcode the two attributes we're interested in and remove extraneous 
     * quotes from the value string.
     * 
     * @param keyPrefix the prefix of the attribute we'll create
     * @param rawSecret the Vault secret value as json text
     * @param olist the result accumulator
     */
    private void addKeyPair(String keyPrefix, String rawSecret, List<SecretOutput> olist)
    {
        // The keys are at the top level in the json object.
        // We process the private key first.
        String value = null;
        JsonObject jsonObj = null;
        if (rawSecret != null) {
            jsonObj = TapisGsonUtils.getGson().fromJson(rawSecret, JsonObject.class);
            if (jsonObj != null)
            {
                var v = jsonObj.get("privateKey");
                if (v != null) value = v.toString();
            }
        }
        
        // Massage the value.
        if (value == null) value = "";
         else {
             // For some reason there are double quotes around the secret string.
             if (value.startsWith("\"")) value = value.substring(1);
             if (value.endsWith("\"")) value = value.substring(0, value.length()-1);
         }
        
        // Construct the record.
        olist.add(new SecretOutput(keyPrefix + "_PRIVATEKEY", value));
        
        // Next process the public key.
        if (jsonObj != null) value = jsonObj.get("publicKey").toString();
        if (value == null) value = "";
        else {
            // For some reason there are double quotes around the secret string.
            if (value.startsWith("\"")) value = value.substring(1);
            if (value.endsWith("\"")) value = value.substring(0, value.length()-1);
        }
        
        // Construct the record.
        olist.add(new SecretOutput(keyPrefix + "_PUBLICKEY", value));
    }
    
    /* ---------------------------------------------------------------------- */
    /* sanitize:                                                              */
    /* ---------------------------------------------------------------------- */
    /** Replace all characters not in the sanitizer character class with underscore.
     * 
     * @param s string to be sanitized
     * @return sanitized string
     */
    private String sanitize(String s)
    {
        if (s == null) return s;
        return SANITIZER.matcher(s).replaceAll("_");
    }
    
    /* ---------------------------------------------------------------------- */
    /* getRawDumpOutputRec:                                                   */
    /* ---------------------------------------------------------------------- */
    private SecretOutput getRawDumpOutputRec(SecretInfo srec)
    {
        return new SecretOutput(srec.path(), srec.secret());
    }
    
    /* ---------------------------------------------------------------------- */
    /* recordFailedRead:                                                      */
    /* ---------------------------------------------------------------------- */
    /** Add a source read failure record.
     * 
     * @param path the complete path on which the read was attempted
     */
    private void recordFailedRead(String path)
    {
        try {
            URI uri = new URI(path);
            _failedReads.add(uri.toString());
        } catch (Exception e1) {_failedReads.add(path);}
    }
    
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
            .uri(new URI(baseUrl + "v1/sys/health"))
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
        debug("Vault at " + baseUrl + "is at version " + version +
            " and is " + (sealed ? "" : "not ") + "sealed.");
        if (sealed) {
            String msg = "Unable to continue because vault at " + baseUrl + " is sealed.";
            throw new RuntimeException(msg);
        }
    }

    /* ---------------------------------------------------------------------- */
    /* writeResults:                                                          */
    /* ---------------------------------------------------------------------- */
    private void writeResults(List<SecretOutput> olist)
    {
        // Populate a json object will all the secrets
        // in the user-specified format.
        String secrets = writeJsonOutput(olist);
        
        // Did we encounter unknown paths?
        var unknownPathMsg = _numUnknownPaths == 0 ? "" : " <-- INVESTIGATE";
        
        // Print summary information.
        var numWrites = _secretRecords.size();
        debug("\n-------------------------------------------------");
        debug("Attempted listings = " + _numListings + ", attempted reads = " + _numReads);
        debug("Unknown paths encountered = " + _numUnknownPaths + unknownPathMsg);
        debug("Secrets written = " + numWrites + ", secrets skipped = " + (_numReads - numWrites));
        if (!_failedReads.isEmpty()) {
            debug("\n-------------------------------------------------");
            debug("Failed secret reads: " + _failedReads.size() + "\n");
            var it = _failedReads.iterator();
            while (it.hasNext()) debug("  " + it.next());
        }
        
        // Print secrets.
        debug("\n-------------------------------------------------");
        debug("****** SECRETS ******");
        System.out.println(secrets); // Always write the secrets.
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
