package edu.utexas.tacc.tapis.security.commands.aux.utility;

import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import org.kohsuke.args4j.spi.StringArrayOptionHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import edu.utexas.tacc.tapis.shared.exceptions.TapisException;

/**
 * Support various actions for maintaining SK secrets.
 * Actions to take are determined by the option specified.
 * Only one action may be specified
 * If no actions are specified then only the check of the vault status is performed.
 * Actions:
 *  -sys_cleanup : Removes orphaned Systems secrets.
 *  -sys_export_meta : Exports metadata for systems secrets
 *      By default processes all tenants, systems and authentication methods.
 *      List of tenants to process may be provided using -tenant_list
 *      A single tenant may be specified using -tenant.
 *        When a single tenant is specified:
 *          - a list of systems to process may be provided using -system_list
 *          - Output may be restricted based on the presence of a given authn method using -authn_method
 *
 */
public class SkUtilityParameters
{
  /* ********************************************************************** */
  /*                               Constants                                */
  /* ********************************************************************** */
  // Tracing.
  private static final Logger log = LoggerFactory.getLogger(SkUtilityParameters.class);

  /* ********************************************************************** */
  /*                                 Fields                                 */
  /* ********************************************************************** */

  // ------------------------------------
  // General parameters
  // ------------------------------------
  @Option(name = "-o", required = false, aliases = {"--output"},
        usage = "write output")
  public boolean output = false;

  @Option(name = "-csv", required = false,
        usage = "write output in csv format")
  public boolean csv_output = false;

  @Option(name = "-v", required = false, aliases = {"--verbose"},
        forbids = {"-q"},
        usage = "write trace and debug log messages")
  public boolean verbose = false;

  @Option(name = "-q", required = false, aliases = {"--quiet"},
        forbids = {"-v"},
        usage = "suppress trace aall log messages")
  public boolean quiet = false;

  @Option(name = "-help", aliases = {"--help"},
        usage = "display help information")
  public boolean help;

  // ------------------------------------
  // Required parameters
  // ------------------------------------
  @Option(name = "-vtok", required = true, aliases = {"--vaulttoken"},
        usage = "Vault token with proper authorization")
  public String vtok;

  @Option(name = "-vurl", required = true, aliases = {"--vaulturl"},
        usage = "Vault URL including port, ex: http(s)://host:32342")
  public String vurl;

  // ------------------------------------
  // Actions
  // ------------------------------------

  // Systems cleanup
  @Option(name = "-sys_cleanup", required = false,
          forbids = {"-sys_export_meta"},
          usage = "Remove orphaned legacy Systems secrets")
  public boolean sysCleanup = false;

  // Systems secret metadata export
  @Option(name = "-sys_export_meta", required = false,
          forbids = {"-sys_cleanup"},
          usage = "Export metadata for Systems secrets")
  public boolean sysExportMeta = false;

  @Option(name = "-tenant_list", handler = StringArrayOptionHandler.class, required = false,
          depends = {"-sys_export_meta"},
          usage = "Process provided list of tenants")
  public List<String> tenantList = null;

  @Option(name = "-tenant", required = false,
          depends = {"-sys_export_meta"},
          forbids = {"-tenant_list"},
          usage = "Process single tenant")
  public String tenant = null;

  @Option(name = "-system_list", handler = StringArrayOptionHandler.class, required = false,
          depends = {"-tenant"},
          usage = "Process provided list of systems")
  public List<String> systemList = null;

  @Option(name = "-authn_method", required = false,
          depends = {"-sys_export_meta"},
          usage = "Output metadata only if record contains values for specified authentication method: PKI_KEYS, PASSWORD, TMS_KEYS, etc")
  public String authnMethod = null;

  /* ********************************************************************** */
    /*                              Constructors                              */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* constructor:                                                           */
    /* ---------------------------------------------------------------------- */
    public SkUtilityParameters(String[] args)
     throws TapisException
    {
      initializeParms(args);
      validateParms();
    }
    
    /* **************************************************************************** */
    /*                               Private Methods                                */
    /* **************************************************************************** */
    /* ---------------------------------------------------------------------------- */
    /* initializeParms:                                                             */
    /* ---------------------------------------------------------------------------- */
    /** Parse the input arguments. */
    private void initializeParms(String[] args) throws TapisException
    {
      // Get a command line parser to verify input.
      CmdLineParser parser = new CmdLineParser(this);
      parser.getProperties().withUsageWidth(120);
      try {
         // Parse the arguments.
         parser.parseArgument(args);
      }
      catch (CmdLineException e)
      {
        if (!help)
        {
            // Create message buffer of sufficient size.
            final int initialCapacity = 1024;
            StringWriter writer = new StringWriter(initialCapacity);
            
            // Write parser error message.
            writer.write("\n******* Input Parameter Error *******\n");
            writer.write(e.getMessage());
            writer.write("\n\n");
            
            // Write usage information--unfortunately we need an output stream.
            writer.write("SkUtility [options...]\n");
            ByteArrayOutputStream ostream = new ByteArrayOutputStream(initialCapacity);
            parser.printUsage(ostream);
            try {writer.write(ostream.toString(StandardCharsets.UTF_8));}
            catch (Exception e1) { /* Ignore. About to throw exception anyway. */ }
            writer.write("\n");
            // Throw exception.
            throw new TapisException(writer.toString());
           }
        }
      
    // Display help and exit program.
    if (help)
    {
      String s = "\nSkExport for exporting Tapis secrets from Vault.";
      System.out.println(s);
      System.out.println("\nSkExport [options...]");
      parser.printUsage(System.out);
      // Add a usage blurb.
      s = "\n\nThis utility exports as JSON all Tapis secrets currently in Vault.";
      System.out.println(s);
      System.exit(0);
    }
  }

  /* Check the semantic integrity of the input parameters. Replace all
   * placeholder characters with spaces in the name and contactName inputs
   */
  private void validateParms()
  {
    // Make sure there is no trailing slash in the url.
    vurl = StringUtils.removeEnd(vurl, "/");
  }
}
