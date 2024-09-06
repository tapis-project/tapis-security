package edu.utexas.tacc.tapis.security.api.requestBody;

import org.apache.commons.lang3.StringUtils;

import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;

public final class ReqServiceIsJwtPermitted 
 implements IReqBody
{
    public String oboTenant;  // from restricted service's JWT
    public String oboUser;    // from restricted service's JWT
    public String jwtUser;    // from restricted service's JWT (i.e, the restricted service name)
    public String receivingService; // the original request's recipient 
    
    /** Return a user-appropriate error message on failed validation
     *  and return null if validation succeeds.
     */ 
    @Override
    public String validate() 
    {
        if (StringUtils.isBlank(oboTenant)) 
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "serviceIsJwtPermitted", "oboTenant");
        if (StringUtils.isBlank(oboUser)) 
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "serviceIsJwtPermitted", "oboUser");
        if (StringUtils.isBlank(jwtUser)) 
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "serviceIsJwtPermitted", "sendingService");
        if (StringUtils.isBlank(receivingService)) 
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "serviceIsJwtPermitted", "receivingService");

        // Success.
    	return null;
    }
}
