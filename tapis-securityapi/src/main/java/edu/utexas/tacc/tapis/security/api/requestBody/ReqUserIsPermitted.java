package edu.utexas.tacc.tapis.security.api.requestBody;

import edu.utexas.tacc.tapis.security.authz.model.SkRoleType;
import org.apache.commons.lang3.StringUtils;

import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;

import java.util.List;
import java.util.Set;

public final class ReqUserIsPermitted
 implements IReqBody
{
    public String  tenant;
    public String  user;
    public String  permSpec;
    public boolean orAdmin;
    public Set<String> roleTypes = Set.of(SkRoleType.USER.name(), SkRoleType.USER_DEFAULT.name());

    /** Return a user-appropriate error message on failed validation
     *  and return null if validation succeeds.
     */ 
    @Override
    public String validate() 
    {
        // Final checks.
        if (StringUtils.isBlank(tenant)) 
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "isPermitted", "tenant");
        if (StringUtils.isBlank(user)) 
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "isPermitted", "user");
        if (StringUtils.isBlank(permSpec)) 
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "isPermitted", "permSpec");
        
        // Success.
        return null;
    }
}
