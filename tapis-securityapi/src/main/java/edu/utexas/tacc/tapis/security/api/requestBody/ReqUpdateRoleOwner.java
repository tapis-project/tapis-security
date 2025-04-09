package edu.utexas.tacc.tapis.security.api.requestBody;

import edu.utexas.tacc.tapis.security.authz.model.SkRoleType;
import org.apache.commons.lang3.StringUtils;

import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;

public final class ReqUpdateRoleOwner 
 implements IReqBody
{
    public String roleTenant;
    public String roleType;
    public String newOwner;
    public String newTenant; // optional

    /** Return a user-appropriate error message on failed validation
     *  and return null if validation succeeds.
     */ 
    @Override
    public String validate() 
    {
        // Final checks.
        if (StringUtils.isBlank(roleTenant)) 
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "updateRoleDescription", "roleTenant");
        if (StringUtils.isBlank(roleType))
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "updateRoleDescription", "roleType");
        if (StringUtils.isBlank(newOwner))
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "updateRoleDescription", "newOwner");
        
        // Success.
        return null;
    }
}

