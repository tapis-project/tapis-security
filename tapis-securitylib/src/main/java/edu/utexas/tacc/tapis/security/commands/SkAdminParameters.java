package edu.utexas.tacc.tapis.security.commands;

import java.io.ByteArrayOutputStream;
import java.io.StringWriter;

import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.utexas.tacc.tapis.shared.exceptions.TapisException;

/** Parse, validate and massage SkAdmin parameters.  
 * 
 * @author rcardone
 */
public class SkAdminParameters 
{
    /* ********************************************************************** */
    /*                               Constants                                */
    /* ********************************************************************** */
    // Tracing.
    private static final Logger _log = LoggerFactory.getLogger(SkAdminParameters.class);
    
    // Database defaults.
    private static final String DFT_BASE_URL = "http:/localhost:8080";
    
    // Secret generation defaults.
    private static final int DFT_PASSWORD_BYTES = 32;
    private static final int MIN_PASSWORD_BYTES = 16;
    
    /* ********************************************************************** */
    /*                                 Fields                                 */
    /* ********************************************************************** */
    // --------- Parameters passed directly to the tenants code
    @Option(name = "-c", required = false, aliases = {"-create"}, 
            usage = "create secrets that don't already exist")
    public boolean create;
    
    @Option(name = "-u", required = false, aliases = {"-update"}, 
            usage = "create new secrets and update existing ones")
    public boolean update;
    
    @Option(name = "-d", required = false, aliases = {"-deploy"}, 
            usage = "deploy secrets to kubernetes")
    public boolean deploy;
    
    @Option(name = "-f", required = true, aliases = {"-file"}, 
            metaVar = "<file path>", usage = "the json input file")
    public String jsonFile;
    
    @Option(name = "-b", required = false, aliases = {"-baseurl"}, 
            metaVar = "<base sk url>", usage = "SK base url (scheme://host)")
    public String baseUrl = DFT_BASE_URL;
    
    @Option(name = "-passwordlen", required = false,  
            usage = "number of random bytes in generated passwords")
    public int passwordLength = DFT_PASSWORD_BYTES;
    
    
    // --------- Parameters that control this programs execution
    @Option(name = "-help", aliases = {"--help"}, 
            usage = "display help information")
    public boolean help;
        
    /* ********************************************************************** */
    /*                              Constructors                              */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* constructor:                                                           */
    /* ---------------------------------------------------------------------- */
    public SkAdminParameters(String[] args) 
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
    private void initializeParms(String[] args)
        throws TapisException
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
            writer.write("CreateTenant [options...]\n");
            ByteArrayOutputStream ostream = new ByteArrayOutputStream(initialCapacity);
            parser.printUsage(ostream);
            try {writer.write(ostream.toString("UTF-8"));}
              catch (Exception e1) {}
            writer.write("\n");
            
            // Throw exception.
            throw new TapisException(writer.toString());
           }
        }
      
      // Display help and exit program.
      if (help)
        {
         String s = "\nCreateTenant for creating a new tenant and its default submission queue.";
         System.out.println(s);
         System.out.println("\nCreateTenant [options...]\n");
         parser.printUsage(System.out);
         System.exit(0);
        }
    }
    
    /* ---------------------------------------------------------------------- */
    /* validateParms:                                                         */
    /* ---------------------------------------------------------------------- */
    /** Check the semantic integrity of the input parameters. Replace all 
     * placeholder characters with spaces in the name and contactName inputs
     * only.
     * 
     * @throws JobException
     */
    private void validateParms()
     throws TapisException
    {
        // We need to perform some action.
        if (!(create || update || deploy)) {
            String msg = "At least one of the following action parameters must be "
                         + "specified: -create, -update, -deploy.";
            _log.error(msg);
            throw new TapisException(msg);
        }
        
        // Update trumps create.
        if (create && update) create = false;
        
        // Make sure password length exceeds minimum.
        if (passwordLength < MIN_PASSWORD_BYTES) {
            String msg = "The minumum password length is " + MIN_PASSWORD_BYTES + ".";
            _log.error(msg);
            throw new TapisException(msg);
        }
    }
}