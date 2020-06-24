package edu.utexas.tacc.tapis.systems.service;

import com.google.gson.JsonObject;
import edu.utexas.tacc.tapis.client.shared.exceptions.TapisClientException;
import edu.utexas.tacc.tapis.security.client.SKClient;
import edu.utexas.tacc.tapis.shared.exceptions.TapisException;
import edu.utexas.tacc.tapis.shared.threadlocal.TapisThreadContext;
import edu.utexas.tacc.tapis.shared.utils.TapisGsonUtils;
import edu.utexas.tacc.tapis.sharedapi.security.AuthenticatedUser;
import edu.utexas.tacc.tapis.sharedapi.security.ServiceJWT;
import edu.utexas.tacc.tapis.sharedapi.security.TenantManager;
import edu.utexas.tacc.tapis.systems.Protocol;
import edu.utexas.tacc.tapis.systems.config.RuntimeParameters;
import edu.utexas.tacc.tapis.systems.dao.SystemsDao;
import edu.utexas.tacc.tapis.systems.dao.SystemsDaoImpl;
import edu.utexas.tacc.tapis.systems.model.Capability;
import edu.utexas.tacc.tapis.systems.model.Capability.Category;
import edu.utexas.tacc.tapis.systems.model.Credential;
import edu.utexas.tacc.tapis.systems.model.PatchSystem;
import org.glassfish.hk2.api.ServiceLocator;
import org.glassfish.hk2.utilities.ServiceLocatorUtilities;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.jooq.tools.StringUtils;
import org.testng.Assert;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;

import edu.utexas.tacc.tapis.systems.model.TSystem;
import edu.utexas.tacc.tapis.systems.model.TSystem.AccessMethod;
import edu.utexas.tacc.tapis.systems.model.TSystem.TransferMethod;
import edu.utexas.tacc.tapis.systems.model.TSystem.SystemType;
import edu.utexas.tacc.tapis.systems.model.TSystem.Permission;

import javax.ws.rs.NotAuthorizedException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Test the SystemsService implementation class against a DB running locally
 * Note that this test has the following dependencies running locally or in dev
 *    Database - typically local
 *    Tenants service - typically dev
 *    Tokens service - typically dev and obtained from tenants service
 *    Security Kernel service - typically dev and obtained from tenants service
 */
@Test(groups={"integration"})
public class SystemsServiceTest
{
  private SystemsService svc;
  private SystemsServiceImpl svcImpl;
  private AuthenticatedUser authenticatedOwnerUsr, authenticatedTestUsr0, authenticatedTestUsr1, authenticatedTestUsr2,
          authenticatedTestUsr3, authenticatedAdminUsr, authenticatedFilesSvc;
  // Test data
  private static final String tenantName = "dev";
  private static final String ownerUser = "owner1";
  private static final String adminUser = "testSystemsAdminUsr";
  private static final String masterTenantName = "master";
  private static final String filesSvcName = "files";
  private static final String testUser0 = "testuser0";
  private static final String testUser1 = "testuser1";
  private static final String testUser2 = "testuser2";
  private static final String testUser3 = "testuser3";
  private static final List<TransferMethod> txfrMethodsList = new ArrayList<>(List.of(TransferMethod.SFTP, TransferMethod.S3));
  private static final List<TransferMethod> txfrMethodsEmpty = new ArrayList<>();
  private static final Protocol prot1 = new Protocol(AccessMethod.PKI_KEYS, txfrMethodsList, -1, false, "",-1);
  private static final Protocol prot2 = new Protocol(AccessMethod.PKI_KEYS, txfrMethodsList, 22, false, "",0);
  private static final Protocol prot3 = new Protocol(AccessMethod.ACCESS_KEY, txfrMethodsList, 23, true, "localhost",22);
  private static final Protocol prot4 = new Protocol(AccessMethod.PASSWORD, txfrMethodsEmpty, -1, false, "",-1);
  private static final Protocol prot5 = new Protocol(AccessMethod.PASSWORD, txfrMethodsEmpty, -1, false, null,-1);
  private static final Protocol prot6 = new Protocol(AccessMethod.PASSWORD, txfrMethodsEmpty, -1, false, "",-1);
  private static final Protocol prot7 = new Protocol(AccessMethod.PASSWORD, txfrMethodsEmpty, -1, false, "",-1);
  private static final Protocol prot8 = new Protocol(AccessMethod.PKI_KEYS, txfrMethodsList, -1, false, "",-1);
  private static final Protocol prot9 = new Protocol(AccessMethod.CERT, txfrMethodsList, -1, false, "",-1);
  private static final Protocol protA = new Protocol(AccessMethod.PKI_KEYS, txfrMethodsList, -1, false, "",-1);
  private static final Protocol protB = new Protocol(AccessMethod.PKI_KEYS, txfrMethodsList, -1, false, "",-1);
  private static final Protocol protC = new Protocol(AccessMethod.PKI_KEYS, null, -1, false, null,-1);
  private static final Set<Permission> testPermsALL = new HashSet<>(Set.of(Permission.READ, Permission.MODIFY, Permission.ALL));
  private static final Set<Permission> testPermsREADMODIFY = new HashSet<>(Set.of(Permission.READ, Permission.MODIFY));
  private static final Set<Permission> testPermsREAD = new HashSet<>(Set.of(Permission.READ));
  private static final Set<Permission> testPermsMODIFY = new HashSet<>(Set.of(Permission.MODIFY));
  private static final String[] tags1 = {"value1", "value2", "a",
      "a long tag with spaces and numbers (1 3 2) and special characters [_ $ - & * % @ + = ! ^ ? < > , . ( ) { } / \\ | ]. Backslashes must be escaped."};
  private static final String[] tags2 = {"value3", "value4"};
  private static final Object notes1 = TapisGsonUtils.getGson().fromJson("{\"project\": \"myproj1\", \"testdata\": \"abc1\"}", JsonObject.class);
  private static final Object notes2 = TapisGsonUtils.getGson().fromJson("{\"project\": \"myproj2\", \"testdata\": \"abc2\"}", JsonObject.class);
  private static final String scrubbedText = "{}";

  private static final Capability capA1 = new Capability(Category.SCHEDULER, "Type", "Slurm");
  private static final Capability capB1 = new Capability(Category.HARDWARE, "CoresPerNode", "4");
  private static final Capability capC1 = new Capability(Category.SOFTWARE, "OpenMP", "4.5");
  private static final Capability capD1 = new Capability(Category.CONTAINER, "Singularity", null);
  private static final List<Capability> cap1List = new ArrayList<>(List.of(capA1, capB1, capC1, capD1));
  private static final Capability capA2 = new Capability(Category.SCHEDULER, "Type", "Condor");
  private static final Capability capB2 = new Capability(Category.HARDWARE, "CoresPerNode", "128");
  private static final Capability capC2 = new Capability(Category.SOFTWARE, "OpenMP", "3.1");
  private static final List<Capability> cap2List = new ArrayList<>(List.of(capA2, capB2, capC2));

  // Constructor initializes all attributes except for JobCapabilitys and Credential
  TSystem sys1 = new TSystem(-1, tenantName, "Ssys1", "description 1", SystemType.LINUX, ownerUser, "host1", true,
          "effUser1", prot1.getAccessMethod(), "bucket1", "/root1", prot1.getTransferMethods(),
          prot1.getPort(), prot1.isUseProxy(), prot1.getProxyHost(), prot1.getProxyPort(),false,
          "jobLocalWorkDir1", "jobLocalArchDir1", "jobRemoteArchSystem1","jobRemoteArchDir1",
          tags1, notes1, false, null, null);
  TSystem sys2 = new TSystem(-1, tenantName, "Ssys2", "description 2", SystemType.LINUX, ownerUser, "host2", true,
          "effUser2", prot2.getAccessMethod(), "bucket2", "/root2", prot2.getTransferMethods(),
          prot2.getPort(), prot2.isUseProxy(), prot2.getProxyHost(), prot2.getProxyPort(),false,
          "jobLocalWorkDir2", "jobLocalArchDir2", "jobRemoteArchSystem2","jobRemoteArchDir2",
          tags1, notes1, false, null, null);
  TSystem sys3 = new TSystem(-1, tenantName, "Ssys3", "description 3", SystemType.OBJECT_STORE, ownerUser, "host3", true,
          "effUser3", prot3.getAccessMethod(), "bucket3", "/root3", prot3.getTransferMethods(),
          prot3.getPort(), prot3.isUseProxy(), prot3.getProxyHost(), prot3.getProxyPort(),false,
          "jobLocalWorkDir3", "jobLocalArchDir3", "jobRemoteArchSystem3","jobRemoteArchDir3",
          tags1, notes1, false, null, null);
  TSystem sys4 = new TSystem(-1, tenantName, "Ssys4", "description 4", SystemType.LINUX, ownerUser, "host4", true,
          "effUser4", prot4.getAccessMethod(), "bucket4", "/root4", prot4.getTransferMethods(),
          prot4.getPort(), prot4.isUseProxy(), prot4.getProxyHost(), prot4.getProxyPort(),false,
          "jobLocalWorkDir4", "jobLocalArchDir4", "jobRemoteArchSystem4","jobRemoteArchDir4",
          tags1, notes1, false, null, null);
  TSystem sys5 = new TSystem(-1, tenantName, "Ssys5", "description 5", SystemType.LINUX, ownerUser, "host5", true,
          "effUser5", prot5.getAccessMethod(), "bucket5", "/root5", prot5.getTransferMethods(),
          prot5.getPort(), prot5.isUseProxy(), prot5.getProxyHost(), prot5.getProxyPort(),false,
          "jobLocalWorkDir5", "jobLocalArchDir5", "jobRemoteArchSystem5","jobRemoteArchDir5",
          tags1, notes1, false, null, null);
  TSystem sys6 = new TSystem(-1, tenantName, "Ssys6", "description 6", SystemType.LINUX, ownerUser, "host6", true,
          "effUser6", prot6.getAccessMethod(), "bucket6", "/root6", prot6.getTransferMethods(),
          prot6.getPort(), prot6.isUseProxy(), prot6.getProxyHost(), prot6.getProxyPort(),false,
          "jobLocalWorkDir6", "jobLocalArchDir6", "jobRemoteArchSystem6","jobRemoteArchDir6",
          tags1, notes1, false, null, null);
  TSystem sys7 = new TSystem(-1, tenantName, "Ssys7", "description 7", SystemType.LINUX, ownerUser, "host7", true,
          "effUser7", prot7.getAccessMethod(), "bucket7", "/root7", prot7.getTransferMethods(),
          prot7.getPort(), prot7.isUseProxy(), prot7.getProxyHost(), prot7.getProxyPort(),false,
          "jobLocalWorkDir7", "jobLocalArchDir7", "jobRemoteArchSystem7","jobRemoteArchDir7",
          tags1, notes1, false, null, null);
  TSystem sys8 = new TSystem(-1, tenantName, "Ssys8", "description 8", SystemType.LINUX, "${apiUserId}", "host8", false,
          "${owner}", prot8.getAccessMethod(), "bucket8-${tenant}-${apiUserId}", "/root8/${tenant}",
          prot8.getTransferMethods(), prot8.getPort(), prot8.isUseProxy(), prot8.getProxyHost(), prot8.getProxyPort(),false,
          "jobLocalWorkDir8/${owner}/${tenant}/${apiUserId}", "jobLocalArchDir8/${apiUserId}",
          "jobRemoteArchSystem8","jobRemoteArchDir8${owner}${tenant}${apiUserId}",
          tags1, notes1, false, null, null);
  TSystem sys9 = new TSystem(-1, tenantName, "Ssys9", "description 9", SystemType.LINUX, ownerUser, "host9", true,
          ownerUser, prot9.getAccessMethod(), "bucket9", "/root9", prot9.getTransferMethods(),
          prot9.getPort(), prot9.isUseProxy(), prot9.getProxyHost(), prot9.getProxyPort(),false,
          "jobLocalWorkDir9", "jobLocalArchDir9", "jobRemoteArchSystem9","jobRemoteArchDir9",
          tags1, notes1, false, null, null);
  TSystem sysA = new TSystem(-1, tenantName, "SsysA", "description A", SystemType.LINUX, ownerUser, "hostA", true,
          "effUserA", protA.getAccessMethod(), "bucketA", "/rootA", protA.getTransferMethods(),
          protA.getPort(), protA.isUseProxy(), protA.getProxyHost(), protA.getProxyPort(),false,
          "jobLocalWorkDirA", "jobLocalArchDirA", "jobRemoteArchSystemA","jobRemoteArchDirA",
          tags1, notes1, false, null, null);
  TSystem sysB = new TSystem(-1, tenantName, "SsysB", "description B", SystemType.LINUX, ownerUser, "hostB", true,
          "effUserB", protB.getAccessMethod(), "bucketB", "/rootB", protB.getTransferMethods(),
          protB.getPort(), protB.isUseProxy(), protB.getProxyHost(), protB.getProxyPort(),false,
          "jobLocalWorkDirB", "jobLocalArchDirB", "jobRemoteArchSystemB","jobRemoteArchDirB",
          tags1, notes1, false, null, null);
  TSystem sysC = new TSystem(-1, tenantName, "SsysC", null, SystemType.LINUX, null, "hostC", true,
          null, protC.getAccessMethod(), null, null, protC.getTransferMethods(),
          protC.getPort(), protC.isUseProxy(), protC.getProxyHost(), protC.getProxyPort(),false,
          null, null, null, null,
          null, null, false, null, null);
  TSystem sysD = new TSystem(-1, tenantName, "SsysD", null, SystemType.LINUX, ownerUser, "hostD", true,
          "effUserD", protC.getAccessMethod(), null, null, protC.getTransferMethods(),
          protC.getPort(), protC.isUseProxy(), protC.getProxyHost(), protC.getProxyPort(),false,
          null, null, null, null,
          null, null, false, null, null);
  TSystem sysE = new TSystem(-1, tenantName, "SsysE", "description E", SystemType.LINUX, ownerUser, "hostE", true,
          "effUserE", prot1.getAccessMethod(), "bucketE", "/rootE", prot1.getTransferMethods(),
          prot1.getPort(), prot1.isUseProxy(), prot1.getProxyHost(), prot1.getProxyPort(),false,
          "jobLocalWorkDirE", "jobLocalArchDirE", "jobRemoteArchSystemE","jobRemoteArchDirE",
          tags1, notes1, false, null, null);
  TSystem sysE2 = new TSystem(-1, tenantName, "SsysE", "description PATCHED", SystemType.LINUX, ownerUser, "hostPATCHED", false,
          "effUserPATCHED", prot2.getAccessMethod(), "bucketE", "/rootE", prot2.getTransferMethods(),
          prot2.getPort(), prot2.isUseProxy(), prot2.getProxyHost(), prot2.getProxyPort(),false,
          "jobLocalWorkDirE", "jobLocalArchDirE", "jobRemoteArchSystemE","jobRemoteArchDirE",
          tags2, notes2, false, null, null);
  TSystem sysF = new TSystem(-1, tenantName, "SsysF", "description F", SystemType.LINUX, ownerUser, "hostF", true,
          "effUserF", prot1.getAccessMethod(), "bucketF", "/rootF", prot1.getTransferMethods(),
          prot1.getPort(), prot1.isUseProxy(), prot1.getProxyHost(), prot1.getProxyPort(),false,
          "jobLocalWorkDirF", "jobLocalArchDirF", "jobRemoteArchSystemF","jobRemoteArchDirF",
          tags1, notes1, false, null, null);
  TSystem sysG = new TSystem(-1, tenantName, "SsysG", "description G", SystemType.LINUX, ownerUser, "hostG", true,
          "effUserG", prot1.getAccessMethod(), "bucketG", "/rootG", prot1.getTransferMethods(),
          prot1.getPort(), prot1.isUseProxy(), prot1.getProxyHost(), prot1.getProxyPort(),false,
          "jobLocalWorkDirG", "jobLocalArchDirG", "jobRemoteArchSystemG","jobRemoteArchDirG",
          tags1, notes1, false, null, null);

  @BeforeSuite
  public void setUp() throws Exception
  {
    System.out.println("Executing BeforeSuite setup method: " + SystemsServiceTest.class.getSimpleName());
    // Setup for HK2 dependency injection
    ServiceLocator locator = ServiceLocatorUtilities.createAndPopulateServiceLocator();
    ServiceLocatorUtilities.bind(locator, new AbstractBinder() {
      @Override
      protected void configure() {
        bind(SystemsServiceImpl.class).to(SystemsService.class);
        bind(SystemsServiceImpl.class).to(SystemsServiceImpl.class);
        bind(SystemsDaoImpl.class).to(SystemsDao.class);
        bindFactory(SystemsServiceJWTFactory.class).to(ServiceJWT.class);
        bind(SKClient.class).to(SKClient.class);
      }
    });
    locator.inject(this);

    // Initialize TenantManager and services
    String url = RuntimeParameters.getInstance().getTenantsSvcURL();
    TenantManager.getInstance(url).getTenants();

    // Initialize services
    svc = locator.getService(SystemsService.class);
    svcImpl = locator.getService(SystemsServiceImpl.class);

    // Initialize authenticated user and service
    authenticatedOwnerUsr = new AuthenticatedUser(ownerUser, tenantName, TapisThreadContext.AccountType.user.name(), null, ownerUser, tenantName, null, null);
    authenticatedAdminUsr = new AuthenticatedUser(adminUser, tenantName, TapisThreadContext.AccountType.user.name(), null, adminUser, tenantName, null, null);
    authenticatedTestUsr0 = new AuthenticatedUser(testUser0, tenantName, TapisThreadContext.AccountType.user.name(), null, testUser0, tenantName, null, null);
    authenticatedTestUsr1 = new AuthenticatedUser(testUser1, tenantName, TapisThreadContext.AccountType.user.name(), null, testUser1, tenantName, null, null);
    authenticatedTestUsr2 = new AuthenticatedUser(testUser2, tenantName, TapisThreadContext.AccountType.user.name(), null, testUser2, tenantName, null, null);
    authenticatedTestUsr3 = new AuthenticatedUser(testUser3, tenantName, TapisThreadContext.AccountType.user.name(), null, testUser3, tenantName, null, null);
    authenticatedFilesSvc = new AuthenticatedUser(filesSvcName, masterTenantName, TapisThreadContext.AccountType.service.name(), null, ownerUser, tenantName, null, null);

    sys2.setJobCapabilities(cap1List);
    // Cleanup anything leftover from previous failed run
    tearDown();
  }

  @Test
  public void testCreateSystem() throws Exception
  {
    TSystem sys0 = sys1;
    int itemId = svc.createSystem(authenticatedOwnerUsr, sys0, scrubbedText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
  }

  // Create a system using minimal attributes:
  //   name, systemType, host, defaultAccessMethod, jobCanExec
  @Test
  public void testCreateSystemMinimal() throws Exception
  {
    TSystem sys0 = sysC;
    int itemId = svc.createSystem(authenticatedOwnerUsr, sys0, scrubbedText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
  }

  // Test retrieving a system including default access method
  //   and test retrieving for specified access method.
  @Test
  public void testGetSystemByName() throws Exception
  {
    TSystem sys0 = sys2;
    sys0.setJobCapabilities(cap1List);
    Credential cred0 = new Credential("fakePassword", "fakePrivateKey", "fakePublicKey",
            "fakeAccessKey", "fakeAccessSecret", "fakeCert");
    sys0.setAccessCredential(cred0);
    int itemId = svc.createSystem(authenticatedOwnerUsr, sys0, scrubbedText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    // Retrieve the system including the credential using the default access method defined for the system
    // Use files service AuthenticatedUser since only certain services can retrieve the cred.
    TSystem tmpSys = svc.getSystemByName(authenticatedFilesSvc, sys0.getName(), true, null);
    checkCommonSysAttrs(sys0, tmpSys);
    // Verify credentials. Only cred for default accessMethod is returned. In this case PKI_KEYS.
    Credential cred = tmpSys.getAccessCredential();
    Assert.assertNotNull(cred, "AccessCredential should not be null");
    Assert.assertEquals(cred.getPrivateKey(), cred0.getPrivateKey());
    Assert.assertEquals(cred.getPublicKey(), cred0.getPublicKey());
    Assert.assertNull(cred.getPassword(), "AccessCredential password should be null");
    Assert.assertNull(cred.getAccessKey(), "AccessCredential access key should be null");
    Assert.assertNull(cred.getAccessSecret(), "AccessCredential access secret should be null");
    Assert.assertNull(cred.getCertificate(), "AccessCredential certificate should be null");

    // Test retrieval using specified access method
    tmpSys = svc.getSystemByName(authenticatedFilesSvc, sys0.getName(), true, AccessMethod.PASSWORD);
    System.out.println("Found item: " + sys0.getName());
    // Verify credentials. Only cred for default accessMethod is returned. In this case PASSWORD.
    cred = tmpSys.getAccessCredential();
    Assert.assertNotNull(cred, "AccessCredential should not be null");
    Assert.assertEquals(cred.getPassword(), cred0.getPassword());
    Assert.assertNull(cred.getPrivateKey(), "AccessCredential private key should be null");
    Assert.assertNull(cred.getPublicKey(), "AccessCredential public key should be null");
    Assert.assertNull(cred.getAccessKey(), "AccessCredential access key should be null");
    Assert.assertNull(cred.getAccessSecret(), "AccessCredential access secret should be null");
    Assert.assertNull(cred.getCertificate(), "AccessCredential certificate should be null");
  }

  // Test updating a system
  @Test
  public void testUpdateSystem() throws Exception
  {
    TSystem sys0 = sysE;
    sys0.setJobCapabilities(cap1List);
    String createText = "{\"testUpdate\": \"0-create\"}";
    String patch1Text = "{\"testUpdate\": \"1-patch1\"}";
    PatchSystem patchSystem = new PatchSystem("description PATCHED", "hostPATCHED", false, "effUserPATCHED",
            prot2.getAccessMethod(), prot2.getTransferMethods(), prot2.getPort(), prot2.isUseProxy(), prot2.getProxyHost(),
            prot2.getProxyPort(), cap2List, tags2, notes2);
    patchSystem.setName(sys0.getName());
    patchSystem.setTenant(tenantName);
    int itemId = svc.createSystem(authenticatedOwnerUsr, sys0, createText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    // Update using patchSys
    svc.updateSystem(authenticatedOwnerUsr, patchSystem, patch1Text);
    TSystem tmpSys = svc.getSystemByName(authenticatedOwnerUsr, sys0.getName(), false, null);
    // Check common system attributes:
    sysE2.setJobCapabilities(cap2List);
    checkCommonSysAttrs(sysE2, tmpSys);
  }

  // Test changing system owner
  @Test
  public void testChangeSystemOwner() throws Exception
  {
    TSystem sys0 = sysG;
    sys0.setJobCapabilities(cap1List);
    String createText = "{\"testChangeOwner\": \"0-create\"}";
    String newOwnerName = testUser2;
    int itemId = svc.createSystem(authenticatedOwnerUsr, sys0, createText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    // Change owner using api
    svc.changeSystemOwner(authenticatedOwnerUsr, sys0.getName(), newOwnerName);
    TSystem tmpSys = svc.getSystemByName(authenticatedTestUsr2, sys0.getName(), false, null);
    Assert.assertEquals(tmpSys.getOwner(), newOwnerName);
    // Check expected auxillary updates have happened
    // New owner should be able to retrieve permissions and have the ALL permission
    Set<Permission> userPerms = svc.getUserPermissions(authenticatedTestUsr2, sys0.getName(), newOwnerName);
    Assert.assertNotNull(userPerms, "Null returned when retrieving perms.");
    Assert.assertTrue(userPerms.contains(Permission.ALL));
    // Original owner should no longer have the ALL permission
    userPerms = svc.getUserPermissions(authenticatedTestUsr2, sys0.getName(), ownerUser);
    Assert.assertFalse(userPerms.contains(Permission.ALL));
  }

  // Check that when a system is created variable substitution is correct for:
  //   owner, bucketName, rootDir, jobInputDir, jobOutputDir, workDir, scratchDir
  // And when system is retrieved effectiveUserId is resolved
  @Test
  public void testGetSystemByNameWithVariables() throws Exception
  {
    TSystem sys0 = sys8;
    int itemId = svc.createSystem(authenticatedOwnerUsr, sys0, scrubbedText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    TSystem tmpSys = svc.getSystemByName(authenticatedOwnerUsr, sys0.getName(), false, null);
    Assert.assertNotNull(tmpSys, "Failed to create item: " + sys0.getName());
    System.out.println("Found item: " + sys0.getName());

// sys8 = {tenantName, "Ssys8", "description 8", SystemType.LINUX.name(), "${apiUserId}", "host8",
//         "${owner}", prot1AccessMethName, "fakePassword8", "bucket8-${tenant}-${apiUserId}", "/root8/${tenant}", prot1TxfrMethods,
//         "jobLocalWorkDir8/${owner}/${tenant}/${apiUserId}", "jobLocalArchDir8/${apiUserId}", "jobRemoteArchSystem8",
//         "jobRemoteArchDir8${owner}${tenant}${apiUserId}", tags, notes, "{}"};
    String effectiveUserId = ownerUser;
    String bucketName = "bucket8-" + tenantName + "-" + effectiveUserId;
    String rootDir = "/root8/" + tenantName;
    String jobLocalWorkingDir = "jobLocalWorkDir8/" + ownerUser + "/" + tenantName + "/" + effectiveUserId;
    String jobLocalArchiveDir = "jobLocalArchDir8/" + effectiveUserId;
    String jobRemoteArchiveDir = "jobRemoteArchDir8" + ownerUser + tenantName + effectiveUserId;
    Assert.assertEquals(tmpSys.getName(), sys0.getName());
    Assert.assertEquals(tmpSys.getDescription(), sys0.getDescription());
    Assert.assertEquals(tmpSys.getSystemType().name(), sys0.getSystemType().name());
    Assert.assertEquals(tmpSys.getOwner(), ownerUser);
    Assert.assertEquals(tmpSys.getHost(), sys0.getHost());
    Assert.assertEquals(tmpSys.getEffectiveUserId(), effectiveUserId);
    Assert.assertEquals(tmpSys.getDefaultAccessMethod().name(), sys0.getDefaultAccessMethod().name());
    Assert.assertEquals(tmpSys.isEnabled(), sys0.isEnabled());
    Assert.assertEquals(tmpSys.getBucketName(), bucketName);
    Assert.assertEquals(tmpSys.getRootDir(), rootDir);
    Assert.assertEquals(tmpSys.getJobLocalWorkingDir(), jobLocalWorkingDir);
    Assert.assertEquals(tmpSys.getJobLocalArchiveDir(), jobLocalArchiveDir);
    Assert.assertEquals(tmpSys.getJobRemoteArchiveDir(), jobRemoteArchiveDir);
    Assert.assertEquals(tmpSys.getPort(), sys0.getPort());
    Assert.assertEquals(tmpSys.isUseProxy(), sys0.isUseProxy());
    Assert.assertEquals(tmpSys.getProxyHost(), sys0.getProxyHost());
    Assert.assertEquals(tmpSys.getProxyPort(), sys0.getProxyPort());
    List<TransferMethod> tMethodsList = tmpSys.getTransferMethods();
    Assert.assertNotNull(tMethodsList);
    Assert.assertNotNull(sys0.getTransferMethods());
    for (TransferMethod txfrMethod : sys0.getTransferMethods())
    {
      Assert.assertTrue(tMethodsList.contains(txfrMethod), "List of transfer methods did not contain: " + txfrMethod.name());
    }
  }

  @Test
  public void testGetSystemNames() throws Exception
  {
    TSystem sys0 = sys3;
    int itemId = svc.createSystem(authenticatedOwnerUsr, sys0, scrubbedText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    sys0 = sys4;
    itemId = svc.createSystem(authenticatedOwnerUsr, sys0, scrubbedText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    List<String> systemNames = svc.getSystemNames(authenticatedOwnerUsr);
    for (String name : systemNames) {
      System.out.println("Found item: " + name);
    }
    Assert.assertTrue(systemNames.contains(sys3.getName()), "List of systems did not contain system name: " + sys3.getName());
    Assert.assertTrue(systemNames.contains(sys4.getName()), "List of systems did not contain system name: " + sys4.getName());
  }

  @Test
  public void testGetSystems() throws Exception
  {
    TSystem sys0 = sys5;
    int itemId = svc.createSystem(authenticatedOwnerUsr, sys0, scrubbedText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    List<TSystem> systems = svc.getSystems(authenticatedOwnerUsr, null);
    for (TSystem system : systems) {
      System.out.println("Found item with id: " + system.getId() + " and name: " + system.getName());
    }
  }

  // Check that user only sees systems they are authorized to see.
  @Test
  public void testGetSystemsAuth() throws Exception
  {
    // Create 3 systems, 2 of which are owned by testUser3.
    String sys1Name = sys5.getName() + "a";
    String sys2Name = sys5.getName() + "b";
    String sys3Name = sys5.getName() + "c";
    int itemId = createSystemWithOwnerAndName(sys5, authenticatedTestUsr3, sys1Name);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    itemId = createSystemWithOwnerAndName(sys5, authenticatedTestUsr3, sys2Name);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    itemId = createSystemWithOwnerAndName(sys5, authenticatedOwnerUsr, sys3Name);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    // When retrieving systems as testUser3 only 2 should be returned
    List<TSystem> systems = svc.getSystems(authenticatedTestUsr3, null);
    System.out.println("Total number of systems retrieved: " + systems.size());
    for (TSystem system : systems)
    {
      System.out.println("Found item with id: " + system.getId() + " and name: " + system.getName());
      Assert.assertTrue(system.getName().equals(sys1Name) || system.getName().equalsIgnoreCase(sys2Name));
    }
    Assert.assertEquals(2, systems.size());
  }

  @Test
  public void testSoftDelete() throws Exception
  {
    // Create the system
    TSystem sys0 = sys6;
    int itemId = svc.createSystem(authenticatedOwnerUsr, sys0, scrubbedText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);

    // Soft delete the system
    int changeCount = svc.softDeleteSystemByName(authenticatedOwnerUsr, sys0.getName());
    Assert.assertEquals(changeCount, 1, "Change count incorrect when deleting a system.");
    TSystem tmpSys2 = svc.getSystemByName(authenticatedOwnerUsr, sys0.getName(), false, null);
    Assert.assertNull(tmpSys2, "System not deleted. System name: " + sys0.getName());
  }

  @Test
  public void testSystemExists() throws Exception
  {
    // If system not there we should get false
    Assert.assertFalse(svc.checkForSystemByName(authenticatedOwnerUsr, sys7.getName()));
    // After creating system we should get true
    TSystem sys0 = sys7;
    int itemId = svc.createSystem(authenticatedOwnerUsr, sys0, scrubbedText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    Assert.assertTrue(svc.checkForSystemByName(authenticatedOwnerUsr, sys7.getName()));
  }

  // Check that if systems already exists we get an IllegalStateException when attempting to create
  @Test(expectedExceptions = {IllegalStateException.class},  expectedExceptionsMessageRegExp = "^SYSLIB_SYS_EXISTS.*")
  public void testCreateSystemAlreadyExists() throws Exception
  {
    // Create the system
    TSystem sys0 = sys9;
    int itemId = svc.createSystem(authenticatedOwnerUsr, sys0, scrubbedText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    Assert.assertTrue(svc.checkForSystemByName(authenticatedOwnerUsr, sys0.getName()));
    // Now attempt to create again, should get IllegalStateException with msg SYSLIB_SYS_EXISTS
    svc.createSystem(authenticatedOwnerUsr, sys0, scrubbedText);
  }

  // Test creating, reading and deleting user permissions for a system
  @Test
  public void testUserPerms() throws Exception
  {
    // Create a system
    TSystem sys0 = sysA;
    int itemId = svc.createSystem(authenticatedOwnerUsr, sys0, scrubbedText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    // Create user perms for the system
    svc.grantUserPermissions(authenticatedOwnerUsr, sys0.getName(), testUser1, testPermsREADMODIFY, scrubbedText);
    // Get the system perms for the user and make sure permissions are there
    Set<Permission> userPerms = svc.getUserPermissions(authenticatedOwnerUsr, sys0.getName(), testUser1);
    Assert.assertNotNull(userPerms, "Null returned when retrieving perms.");
    Assert.assertEquals(userPerms.size(), testPermsREADMODIFY.size(), "Incorrect number of perms returned.");
    for (Permission perm: testPermsREADMODIFY) { if (!userPerms.contains(perm)) Assert.fail("User perms should contain permission: " + perm.name()); }
    // Remove perms for the user. Should return a change count of 2
    int changeCount = svc.revokeUserPermissions(authenticatedOwnerUsr, sys0.getName(), testUser1, testPermsREADMODIFY, scrubbedText);
    Assert.assertEquals(changeCount, 2, "Change count incorrect when revoking permissions.");
    // Get the system perms for the user and make sure permissions are gone.
    userPerms = svc.getUserPermissions(authenticatedOwnerUsr, sys0.getName(), testUser1);
    for (Permission perm: testPermsREADMODIFY) { if (userPerms.contains(perm)) Assert.fail("User perms should not contain permission: " + perm.name()); }
  }

  // Test creating, reading and deleting user credentials for a system
  @Test
  public void testUserCredentials() throws Exception
  {
    // Create a system
    TSystem sys0 = sysB;
    int itemId = svc.createSystem(authenticatedOwnerUsr, sys0, scrubbedText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    Credential cred0 = new Credential("fakePassword", "fakePrivateKey", "fakePublicKey",
            "fakeAccessKey", "fakeAccessSecret", "fakeCert");
    // Store and retrieve multiple secret types: password, ssh keys, access key and secret
    svc.createUserCredential(authenticatedOwnerUsr, sys0.getName(), testUser1, cred0, scrubbedText);
    // Use files service AuthenticatedUser since only certain services can retrieve the cred.
    Credential cred1 = svc.getUserCredential(authenticatedFilesSvc, sys0.getName(), testUser1, AccessMethod.PASSWORD);
    // Verify credentials
    Assert.assertEquals(cred1.getPassword(), cred0.getPassword());
    cred1 = svc.getUserCredential(authenticatedFilesSvc, sys0.getName(), testUser1, AccessMethod.PKI_KEYS);
    Assert.assertEquals(cred1.getPublicKey(), cred0.getPublicKey());
    Assert.assertEquals(cred1.getPrivateKey(), cred0.getPrivateKey());
    cred1 = svc.getUserCredential(authenticatedFilesSvc, sys0.getName(), testUser1, AccessMethod.ACCESS_KEY);
    Assert.assertEquals(cred1.getAccessKey(), cred0.getAccessKey());
    Assert.assertEquals(cred1.getAccessSecret(), cred0.getAccessSecret());
    // Delete credentials and verify they were destroyed
    int changeCount = svc.deleteUserCredential(authenticatedOwnerUsr, sys0.getName(), testUser1);
    Assert.assertEquals(changeCount, 1, "Change count incorrect when removing a credential.");
    cred1 = svc.getUserCredential(authenticatedFilesSvc, sys0.getName(), testUser1, AccessMethod.PASSWORD);
    Assert.assertNull(cred1, "Credential not deleted. System name: " + sys0.getName() + " User name: " + testUser1);

    // Attempt to delete again, should return 0 for change count
    changeCount = svc.deleteUserCredential(authenticatedOwnerUsr, sys0.getName(), testUser1);
    // TODO: Currently the attempt to return 0 if it does not exist is throwing an exception.
//    Assert.assertEquals(changeCount, 0, "Change count incorrect when removing a credential already removed.");

    // Set just ACCESS_KEY only and test
    cred0 = new Credential(null, null, null, "fakeAccessKey2", "fakeAccessSecret2", null);
    svc.createUserCredential(authenticatedOwnerUsr, sys0.getName(), testUser1, cred0, scrubbedText);
    cred1 = svc.getUserCredential(authenticatedFilesSvc, sys0.getName(), testUser1, AccessMethod.ACCESS_KEY);
    Assert.assertEquals(cred1.getAccessKey(), cred0.getAccessKey());
    Assert.assertEquals(cred1.getAccessSecret(), cred0.getAccessSecret());
    // Attempt to retrieve secret that has not been set
    cred1 = svc.getUserCredential(authenticatedFilesSvc, sys0.getName(), testUser1, AccessMethod.PKI_KEYS);
    Assert.assertNull(cred1, "Credential was non-null for missing secret. System name: " + sys0.getName() + " User name: " + testUser1);
    // Delete credentials and verify they were destroyed
    changeCount = svc.deleteUserCredential(authenticatedOwnerUsr, sys0.getName(), testUser1);
    Assert.assertEquals(changeCount, 1, "Change count incorrect when removing a credential.");
    try {
      cred1 = svc.getUserCredential(authenticatedFilesSvc, sys0.getName(), testUser1, AccessMethod.ACCESS_KEY);
    } catch (TapisException te) {
      Assert.assertTrue(te.getMessage().startsWith("SYSLIB_NOT_FOUND"));
      cred1 = null;
    }
    Assert.assertNull(cred1, "Credential not deleted. System name: " + sys0.getName() + " User name: " + testUser1);
  }

  // Test various cases when system is missing
  //  - get owner with no system
  //  - get perm with no system
  //  - grant perm with no system
  //  - revoke perm with no system
  //  - get credential with no system
  //  - create credential with no system
  //  - delete credential with no system
  @Test
  public void testMissingSystem() throws Exception
  {
    String fakeSystemName = "AMissingSystemName";
    String fakeUserName = "AMissingUserName";
    // Make sure system does not exist
    Assert.assertFalse(svc.checkForSystemByName(authenticatedOwnerUsr, fakeSystemName));

    // Get TSystem with no system should return null
    TSystem tmpSys = svc.getSystemByName(authenticatedOwnerUsr, fakeSystemName, false, null);
    Assert.assertNull(tmpSys, "TSystem not null for non-existent system");

    // Delete system with no system should return 0 changes
    int changeCount = svc.softDeleteSystemByName(authenticatedOwnerUsr, fakeSystemName);
    Assert.assertEquals(changeCount, 0, "Change count incorrect when deleting non-existent system.");

    // Get owner with no system should return null
    String owner = svc.getSystemOwner(authenticatedOwnerUsr, fakeSystemName);
    Assert.assertNull(owner, "Owner not null for non-existent system.");

    // Get perms with no system should return null
    Set<Permission> perms = svc.getUserPermissions(authenticatedOwnerUsr, fakeSystemName, fakeUserName);
    Assert.assertNull(perms, "Perms list was not null for non-existent system");

    // Revoke perm with no system should return 0 changes
    changeCount = svc.revokeUserPermissions(authenticatedOwnerUsr, fakeSystemName, fakeUserName, testPermsREADMODIFY, scrubbedText);
    Assert.assertEquals(changeCount, 0, "Change count incorrect when revoking perms for non-existent system.");

    // Grant perm with no system should throw an exception
    boolean pass = false;
    try { svc.grantUserPermissions(authenticatedOwnerUsr, fakeSystemName, fakeUserName, testPermsREADMODIFY, scrubbedText); }
    catch (TapisException tce)
    {
      Assert.assertTrue(tce.getMessage().startsWith("SYSLIB_NOT_FOUND"));
      pass = true;
    }
    Assert.assertTrue(pass);

    //Get credential with no system should return null
    Credential cred = svc.getUserCredential(authenticatedOwnerUsr, fakeSystemName, fakeUserName, AccessMethod.PKI_KEYS);
    Assert.assertNull(cred, "Credential was not null for non-existent system");
//    // Get credential with no system should throw an exception
//    // TODO/TBD: this is inconsistent other GETs return null. Make them consistent once decided?
//    pass = false;
//    try { svc.getUserCredential(authenticatedUser, fakeSystemName, fakeUserName, AccessMethod.PKI_KEYS); }
//    catch (TapisException te)
//    {
//      Assert.assertTrue(te.getMessage().startsWith("SYSLIB_NOT_FOUND"));
//      pass = true;
//    }
//    Assert.assertTrue(pass);

    // Create credential with no system should throw an exception
    pass = false;
    cred = new Credential(null, null, null, null,"fakeAccessKey2", "fakeAccessSecret2");
    try { svc.createUserCredential(authenticatedOwnerUsr, fakeSystemName, fakeUserName, cred, scrubbedText); }
    catch (TapisException te)
    {
      Assert.assertTrue(te.getMessage().startsWith("SYSLIB_NOT_FOUND"));
      pass = true;
    }
    Assert.assertTrue(pass);

    // Delete credential with no system should 0 changes
    changeCount = svc.deleteUserCredential(authenticatedOwnerUsr, fakeSystemName, fakeUserName);
    Assert.assertEquals(changeCount, 0, "Change count incorrect when deleting a user credential for non-existent system.");
  }

  // Test Auth denials
  // testUsr0 - no perms
  // testUsr1 - READ perm
  // testUsr2 - MODIFY perm
  @Test
  public void testAuthDeny() throws Exception
  {
    TSystem sys0 = sysD;
    PatchSystem patchSys = new PatchSystem("description PATCHED", "hostPATCHED", false, "effUserPATCHED",
            prot2.getAccessMethod(), prot2.getTransferMethods(), prot2.getPort(), prot2.isUseProxy(), prot2.getProxyHost(),
            prot2.getProxyPort(), cap2List, tags2, notes2);
    patchSys.setName(sys0.getName());
    patchSys.setTenant(tenantName);
    // CREATE - Deny user not owner/admin, deny service
    boolean pass = false;
    try { svc.createSystem(authenticatedTestUsr0, sys0, scrubbedText); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);
    pass = false;
    try { svc.createSystem(authenticatedFilesSvc, sys0, scrubbedText); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);

    // Create system for remaining auth access tests
    Credential cred0 = new Credential("fakePassword", "fakePrivateKey", "fakePublicKey",
            "fakeAccessKey", "fakeAccessSecret", "fakeCert");
    sys0.setAccessCredential(cred0);
    int itemId = svc.createSystem(authenticatedOwnerUsr, sys0, scrubbedText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    // Grant Usr1 - READ and Usr2 - MODIFY
    svc.grantUserPermissions(authenticatedOwnerUsr, sys0.getName(), testUser1, testPermsREAD, scrubbedText);
    svc.grantUserPermissions(authenticatedOwnerUsr, sys0.getName(), testUser2, testPermsMODIFY, scrubbedText);

    // READ - deny user not owner/admin and no READ or MODIFY access
    pass = false;
    try { svc.getSystemByName(authenticatedTestUsr0, sys0.getName(), false, null); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);

    // MODIFY Deny user with no READ or MODIFY, deny user with only READ, deny service
    pass = false;
    try { svc.updateSystem(authenticatedTestUsr0, patchSys, scrubbedText); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);
    pass = false;
    try { svc.updateSystem(authenticatedTestUsr1, patchSys, scrubbedText); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);
    pass = false;
    try { svc.updateSystem(authenticatedFilesSvc, patchSys, scrubbedText); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);

    // DELETE - deny user not owner/admin, deny service
    pass = false;
    try { svc.softDeleteSystemByName(authenticatedTestUsr1, sys0.getName()); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);
    pass = false;
    try { svc.softDeleteSystemByName(authenticatedFilesSvc, sys0.getName()); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);

    // CHANGE_OWNER - deny user not owner/admin, deny service
    pass = false;
    try { svc.changeSystemOwner(authenticatedTestUsr1, sys0.getName(), testUser2); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);
    pass = false;
    try { svc.changeSystemOwner(authenticatedFilesSvc, sys0.getName(), testUser2); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);

    // GET_PERMS - deny user not owner/admin and no READ or MODIFY access
    pass = false;
    try { svc.getUserPermissions(authenticatedTestUsr0, sys0.getName(), ownerUser); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);

    // GRANT_PERMS - deny user not owner/admin, deny service
    pass = false;
    try { svc.grantUserPermissions(authenticatedTestUsr1, sys0.getName(), testUser1, testPermsREADMODIFY, scrubbedText); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);
    pass = false;
    try { svc.grantUserPermissions(authenticatedFilesSvc, sys0.getName(), testUser1, testPermsREADMODIFY, scrubbedText); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);

    // REVOKE_PERMS - deny user not owner/admin, deny service
    pass = false;
    try { svc.revokeUserPermissions(authenticatedTestUsr1, sys0.getName(), ownerUser, testPermsREADMODIFY, scrubbedText); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);
    pass = false;
    try { svc.grantUserPermissions(authenticatedFilesSvc, sys0.getName(), ownerUser, testPermsREADMODIFY, scrubbedText); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);

    // SET_CRED - deny user not owner/admin and not target user, deny service
    pass = false;
    try { svc.createUserCredential(authenticatedTestUsr1, sys0.getName(), ownerUser, cred0, scrubbedText); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);
    pass = false;
    try { svc.createUserCredential(authenticatedFilesSvc, sys0.getName(), ownerUser, cred0, scrubbedText); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);

    // REMOVE_CRED - deny user not owner/admin and not target user, deny service
    pass = false;
    try { svc.deleteUserCredential(authenticatedTestUsr1, sys0.getName(), ownerUser); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);
    pass = false;
    try { svc.deleteUserCredential(authenticatedFilesSvc, sys0.getName(), ownerUser); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);

    // GET_CRED - deny user not owner/admin, deny owner
    pass = false;
    try { svc.getUserCredential(authenticatedTestUsr1, sys0.getName(), ownerUser, null); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);
    pass = false;
    try { svc.getUserCredential(authenticatedOwnerUsr, sys0.getName(), ownerUser, null); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = true;
    }
    Assert.assertTrue(pass);
  }

  // Test Auth allow
  // Many cases covered during other tests
  // Test special cases here:
  //    MODIFY implies READ
  // testUsr0 - no perms
  // testUsr1 - READ perm
  // testUsr2 - MODIFY perm
  @Test
  public void testAuthAllow() throws Exception
  {
    TSystem sys0 = sysF;
    // Create system for remaining auth access tests
    Credential cred0 = new Credential("fakePassword", "fakePrivateKey", "fakePublicKey",
            "fakeAccessKey", "fakeAccessSecret", "fakeCert");
    sys0.setAccessCredential(cred0);
    int itemId = svc.createSystem(authenticatedOwnerUsr, sys0, scrubbedText);
    Assert.assertTrue(itemId > 0, "Invalid system id: " + itemId);
    // Grant Usr1 - READ and Usr2 - MODIFY
    svc.grantUserPermissions(authenticatedOwnerUsr, sys0.getName(), testUser1, testPermsREAD, scrubbedText);
    svc.grantUserPermissions(authenticatedOwnerUsr, sys0.getName(), testUser2, testPermsMODIFY, scrubbedText);

    // READ - allow owner, service, with READ only, with MODIFY only
    boolean pass = true;
    try { svc.getSystemByName(authenticatedOwnerUsr, sys0.getName(), false, null); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = false;
    }
    Assert.assertTrue(pass);
    pass = true;
    try { svc.getSystemByName(authenticatedFilesSvc, sys0.getName(), false, null); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = false;
    }
    Assert.assertTrue(pass);
    pass = true;
    try { svc.getSystemByName(authenticatedTestUsr1, sys0.getName(), false, null); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = false;
    }
    Assert.assertTrue(pass);
    pass = true;
    try { svc.getSystemByName(authenticatedTestUsr2, sys0.getName(), false, null); }
    catch (NotAuthorizedException e)
    {
      Assert.assertTrue(e.getMessage().startsWith("HTTP 401 Unauthorized"));
      pass = false;
    }
    Assert.assertTrue(pass);
  }

  @AfterSuite
  public void tearDown() throws Exception
  {
    System.out.println("Executing AfterSuite teardown method" + SystemsServiceTest.class.getSimpleName());
    // Remove non-owner permissions granted during the tests
    svc.revokeUserPermissions(authenticatedOwnerUsr, sysA.getName(), testUser1, testPermsREADMODIFY, scrubbedText);
    svc.revokeUserPermissions(authenticatedOwnerUsr, sysA.getName(), testUser2, testPermsREADMODIFY, scrubbedText);
    svc.revokeUserPermissions(authenticatedOwnerUsr, sysD.getName(), testUser1, testPermsREADMODIFY, scrubbedText);
    svc.revokeUserPermissions(authenticatedOwnerUsr, sysD.getName(), testUser2, testPermsREADMODIFY, scrubbedText);
// TODO why is following revoke causing an exception?
    //    svc.revokeUserPermissions(authenticatedOwnerUsr, sysF.getName(), testUser1, testPermsREADMODIFY, scrubbedText);
    svc.revokeUserPermissions(authenticatedOwnerUsr, sysF.getName(), testUser2, testPermsREADMODIFY, scrubbedText);
    //Remove all objects created by tests
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sys1.getName());
    TSystem tmpSys = svc.getSystemByName(authenticatedAdminUsr, sys1.getName(), false, null);
    Assert.assertNull(tmpSys, "System not deleted. System name: " + sys1.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sys2.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sys3.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sys4.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sys5.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sys6.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sys7.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sys8.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sys9.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sysA.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sysB.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sysC.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sysD.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sysE.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sysF.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sysG.getName());
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sys5.getName() + "a");
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sys5.getName() + "b");
    svcImpl.hardDeleteSystemByName(authenticatedAdminUsr, sys5.getName() + "c");
  }

  /**
   * Check common attributes after creating and retrieving a system
   * @param sys0 - Test system
   * @param tmpSys - Retrieved system
   */
  private static void checkCommonSysAttrs(TSystem sys0, TSystem tmpSys)
  {
    Assert.assertNotNull(tmpSys, "Failed to create item: " + sys0.getName());
    System.out.println("Found item: " + sys0.getName());
    Assert.assertEquals(tmpSys.getName(), sys0.getName());
    Assert.assertEquals(tmpSys.getDescription(), sys0.getDescription());
    Assert.assertEquals(tmpSys.getSystemType().name(), sys0.getSystemType().name());
    Assert.assertEquals(tmpSys.getOwner(), sys0.getOwner());
    Assert.assertEquals(tmpSys.getHost(), sys0.getHost());
    Assert.assertEquals(tmpSys.getEffectiveUserId(), sys0.getEffectiveUserId());
    Assert.assertEquals(tmpSys.getDefaultAccessMethod().name(), sys0.getDefaultAccessMethod().name());
    Assert.assertEquals(tmpSys.isEnabled(), sys0.isEnabled());
    Assert.assertEquals(tmpSys.getBucketName(), sys0.getBucketName());
    Assert.assertEquals(tmpSys.getRootDir(), sys0.getRootDir());
    Assert.assertEquals(tmpSys.getJobLocalWorkingDir(), sys0.getJobLocalWorkingDir());
    Assert.assertEquals(tmpSys.getJobLocalArchiveDir(), sys0.getJobLocalArchiveDir());
    Assert.assertEquals(tmpSys.getJobRemoteArchiveSystem(), sys0.getJobRemoteArchiveSystem());
    Assert.assertEquals(tmpSys.getJobRemoteArchiveDir(), sys0.getJobRemoteArchiveDir());
    Assert.assertEquals(tmpSys.getPort(), sys0.getPort());
    Assert.assertEquals(tmpSys.isUseProxy(), sys0.isUseProxy());
    Assert.assertEquals(tmpSys.getProxyHost(), sys0.getProxyHost());
    Assert.assertEquals(tmpSys.getProxyPort(), sys0.getProxyPort());
    // Verify transfer methods
    List<TransferMethod> tMethodsList = tmpSys.getTransferMethods();
    Assert.assertNotNull(tMethodsList);
    Assert.assertNotNull(sys0.getTransferMethods());
    for (TransferMethod txfrMethod : sys0.getTransferMethods())
    {
      Assert.assertTrue(tMethodsList.contains(txfrMethod), "List of transfer methods did not contain: " + txfrMethod.name());
    }
    // Verify tags
    String[] origTags = sys0.getTags();
    String[] tmpTags = tmpSys.getTags();
    Assert.assertNotNull(tmpTags, "Tags value was null");
    Assert.assertNotNull(origTags);
    var tagsList = Arrays.asList(tmpTags);
    Assert.assertEquals(tmpTags.length, origTags.length, "Wrong number of tags.");
    for (String tagStr : origTags)
    {
      Assert.assertTrue(tagsList.contains(tagStr));
      System.out.println("Found tag: " + tagStr);
    }
    // Verify notes
    Assert.assertNotNull(sys0.getNotes(), "Orig Notes should not be null");
    Assert.assertNotNull(tmpSys.getNotes(), "Fetched Notes should not be null");
    System.out.println("Found notes: " + sys0.getNotes().toString());
    JsonObject tmpObj = (JsonObject) tmpSys.getNotes();
    JsonObject origNotes = (JsonObject) sys0.getNotes();
    Assert.assertTrue(tmpObj.has("project"));
    String projStr = origNotes.get("project").getAsString();
    Assert.assertEquals(tmpObj.get("project").getAsString(), projStr);
    Assert.assertTrue(tmpObj.has("testdata"));
    String testdataStr = origNotes.get("testdata").getAsString();
    Assert.assertEquals(tmpObj.get("testdata").getAsString(), testdataStr);
    // Verify capabilities
    List<Capability> origCaps = sys0.getJobCapabilities();
    List<Capability> jobCaps = tmpSys.getJobCapabilities();
    Assert.assertNotNull(origCaps, "Orig Caps was null");
    Assert.assertNotNull(jobCaps, "Fetched Caps was null");
    Assert.assertEquals(jobCaps.size(), origCaps.size());
    var capNamesFound = new ArrayList<String>();
    for (Capability capFound : jobCaps) {capNamesFound.add(capFound.getName());}
    for (Capability capSeedItem : origCaps)
    {
      Assert.assertTrue(capNamesFound.contains(capSeedItem.getName()),
              "List of capabilities did not contain a capability named: " + capSeedItem.getName());
    }
  }
  /**
   * Create a system using alternate system name if provided
   * System owner name is set using name from AuthenticateUser passed in which may be
   *   different from owner name set in the TSystem passed in.
   */
  private int createSystemWithOwnerAndName(TSystem sys, AuthenticatedUser owner, String altName)
          throws TapisException, TapisClientException
  {
    TSystem sys0 = new TSystem(sys);
    if (!StringUtils.isBlank(altName))
    {
      sys0.setName(altName);
    }
    sys0.setOwner(owner.getName());
    int itemId = svc.createSystem(owner, sys0, scrubbedText);
    return itemId;
  }
}
