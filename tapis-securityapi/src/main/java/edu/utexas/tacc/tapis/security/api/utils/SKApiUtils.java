package edu.utexas.tacc.tapis.security.api.utils;

import java.util.regex.Pattern;

import javax.ws.rs.core.Response.Status;

import org.apache.commons.lang3.StringUtils;

import edu.utexas.tacc.tapis.shared.exceptions.TapisImplException.Condition;
import edu.utexas.tacc.tapis.shared.security.TenantManager;
import edu.utexas.tacc.tapis.tenants.client.gen.model.Tenant;

public class SKApiUtils 
{
    /* **************************************************************************** */
    /*                                    Fields                                    */
    /* **************************************************************************** */
    // Role name validator.  Require names to start with alphabetic characters and 
    // be followed by zero or more alphanumeric characters and underscores.  Note that
    // in particular special characters are disallowed by this regex.  Most important,
    // a leading $ character is reserved for SK generated names and must be rejected.
    private static final Pattern _namePattern = Pattern.compile("^\\p{Alpha}(\\p{Alnum}|_)*");
    
    // Restricted service role name validator.  All such roles must begin with "$#service_" 
    // followed by at least one letter and zero or more alphanumerics and underscores.
    private static final Pattern _restrictedRolePattern = Pattern.compile("^\\$#service_\\p{Alpha}(\\p{Alnum}|_)*");
    
    // Restricted service permissions format validator. The minimum number of colon
    // separated segments is 4 and the maximum is 6. The first 3 segment values are 
    // each assigned from their own hardcoded set. The tenant variant expects only
    // 4 segments; the user and service variants expect 5; and the action variant  
    // expects 6 segments.  This regex doesn't enforce those cardinality constraints
    // so we use the next regex for validating the number of segments.
    //
    // See RestrictedResource.addServiceRolePermission() comments for more details.
    private static final Pattern _permPattern = 
        Pattern.compile("^service:(allow|deny):(tenant|user|action|service):(\\p{Alnum}|_)+(:(\\p{Alnum}|_)+)?(:(\\p{Alnum}|_)+)?$");

    // Split a string into colon separated segments to validate cardinality in 
    // restricted service permission strings.
    private static final Pattern _colonSeparated = Pattern.compile(":");
    
    /* **************************************************************************** */
    /*                                Public Methods                                */
    /* **************************************************************************** */
    /* ---------------------------------------------------------------------------- */
    /* toHttpStatus:                                                                */
    /* ---------------------------------------------------------------------------- */
    public static Status toHttpStatus(Condition condition)
    {
        // Conditions are expected to have the exact same names as statuses.
        try {return Status.valueOf(condition.name());}
        catch (Exception e) {return Status.INTERNAL_SERVER_ERROR;}     
    }
    
    /* ---------------------------------------------------------------------------- */
    /* isValidName:                                                                 */
    /* ---------------------------------------------------------------------------- */
    /** Check a candidate name against the name regex.
     * 
     * @param name the name to validate
     * @return true if matches regex, false otherwise
     */
    public static boolean isValidName(String name)
    {
        if (name == null) return false;
        return _namePattern.matcher(name).matches();
    }
    
    /* ---------------------------------------------------------------------------- */
    /* isValidRestrictedServiceRoleName:                                            */
    /* ---------------------------------------------------------------------------- */
    /** Check a candidate name against the restricted role name regex.
     * 
     * @param name the name to validate
     * @return true if matches regex, false otherwise
     */
    public static boolean isValidRestrictedServiceRoleName(String name)
    {
    	if (name == null) return false;
    	return _restrictedRolePattern.matcher(name).matches();
    }
    
    /* ---------------------------------------------------------------------------- */
    /* isValidRestrictedServicePermission:                                          */
    /* ---------------------------------------------------------------------------- */
    /** Check a candidate permission against the defined permission formats for 
     * restricted role names. The first regex rules out invalid characters and 
     * impossible number of colon separated segments.  The second regex guarantees
     * that the appropriate number of segments are supplied for each permission
     * format.
     * 
     * @param perm the permission to validate
     * @return true if perm has a valid format, false otherwise
     */
    public static boolean isValidRestrictedServicePermission(String perm)
    {
    	// Check the basic format of the permission string.
    	if (perm == null) return false;
    	if (!_permPattern.matcher(perm).matches()) return false;

    	// Further check the number of colon separated segments required
    	// by each permission category.  Note that we tradeoff a bit of 
    	// syntactic sugar by not interpreting missing components as '*'
    	// but instead require explicit '*' as placeholders.  The benefit
    	// is that we require the user to make explicit their intentions.
    	// During permission checking, however, the inputs to be checked 
    	// can have missing trailing components as usual.
    	var segments = _colonSeparated.split(perm);
    	if (segments[2].equals("tenant") && segments.length == 4) return true;
    	else if (segments[2].equals("user") && segments.length == 5) return true;
    	else if (segments[2].equals("service") && segments.length == 5) return true;
    	else if (segments[2].equals("action") && segments.length == 6) return true;
    	
    	// The perm format is ok but the number of required segments is wrong.
    	return false;
    }
    
    /* ---------------------------------------------------------------------------- */
    /* constructTenantURL:                                                          */
    /* ---------------------------------------------------------------------------- */
    /** Construct a path from the base url of the specified tenant and path.  We 
     * prevent double slashes from appearing between each of the components (url, path 
     * and pathSuffix) that comprise the final string.  We also guarentee that a 
     * single slash separates each of the components.
     * 
     * Exceptions are never thrown. 
     * 
     * The path with the optional suffix appended will be returned if the tenant's 
     * base url could not be found.  If the optional pathSuffix is provided, it will 
     * be appended to the constructed url with a preceding slash if necessary.
     * 
     * @param roleTenant the tenantId whose base url will be retrieved
     * @param path the path to append to the tenant's base url
     * @param pathSuffix optional suffix to append to the path
     * @return the tenant's base url with the path and suffix appended or just the 
     * 			path and suffix if the tenant is not found 
     */
     public static String constructTenantURL(String tenantId, String path, String pathSuffix)
    {
    	 // Append the optional suffix to the path to allow for early exit..
    	 if (!StringUtils.isBlank(pathSuffix)) {
    		 // Make sure there's exactly 1 slash between the path and suffix.
    		 if (path.endsWith("/") && pathSuffix.startsWith("/")) 
    			 pathSuffix = pathSuffix.substring(1);
    		 else if (!path.endsWith("/") && !pathSuffix.startsWith("/"))
    			 pathSuffix = "/" + pathSuffix;
    		 path += pathSuffix;
    	 }
    	 
    	 // Get the tenant object. TenantManager throws an exception if 
    	 // the tenant cannot be resolved.
    	 Tenant tenant;
    	 try {tenant = TenantManager.getInstance().getTenant(tenantId);}
    	 catch (Exception e) {return path;} // the error is already logged
    	 
    	 // Get the tenant record.
    	 String url = tenant.getBaseUrl();
    	 if (url == null) return path;
    	 
    	 // Construct the url with path separated by a slash.
		 if (url.endsWith("/") && path.startsWith("/")) 
			 path = path.substring(1);
		 else if (!url.endsWith("/") && !path.startsWith("/"))
			 path = "/" + path;
    	 return url + path;
    }
}
