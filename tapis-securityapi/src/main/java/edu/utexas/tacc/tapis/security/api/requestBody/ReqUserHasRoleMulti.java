package edu.utexas.tacc.tapis.security.api.requestBody;

import edu.utexas.tacc.tapis.security.authz.model.SkRoleDescriptor;
import edu.utexas.tacc.tapis.security.authz.model.SkRoleType;
import org.apache.commons.lang3.StringUtils;

import edu.utexas.tacc.tapis.security.api.utils.SKApiUtils;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;

public final class ReqUserHasRoleMulti
 implements IReqBody
{
    public String   tenant;
    public String   user;
    public SkRoleDescriptor[] roleDescriptors;
    public boolean  orAdmin;

    /** Return a user-appropriate error message on failed validation
     *  and return null if validation succeeds.
     */ 
    @Override
    public String validate() 
    {
        // Final checks.
        if (StringUtils.isBlank(tenant)) 
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "hasRoleMulti", "tenant");
        if (StringUtils.isBlank(user)) 
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "hasRoleMulti", "user");
        if (roleDescriptors == null || (roleDescriptors.length == 0))
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "hasRoleMulti", "roleDescriptors");

        // Check each role name.
        for (SkRoleDescriptor roleDescriptor : roleDescriptors) {
            if(!SkRoleDescriptor.descriptorIsValid(roleDescriptor))
                return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "hasRoleMulti", "roleDescriptor");
        }
        
        // Success.
        return null;
    }
/*
    @Deprecated
    public void setRoleNames(String[] roleNames) {
        roleDescriptors = new SkRoleDescriptor[roleNames.length];
        for(int i = 0;i < roleNames.length; i++) {
            // TODO:  Dan - Should this default to type user?  Is there a way to make this happen?
            SkRoleType roleType = SkRoleType.getRoleTypeFromRoleName(roleNames[i]);
            roleDescriptors[i] = SkRoleDescriptor.newSkRoleDescriptor(roleNames[i], roleType);
        }
    }

 */
}
