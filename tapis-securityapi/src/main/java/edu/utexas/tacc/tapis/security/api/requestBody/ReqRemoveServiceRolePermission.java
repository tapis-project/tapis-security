package edu.utexas.tacc.tapis.security.api.requestBody;

import org.apache.commons.lang3.StringUtils;

import edu.utexas.tacc.tapis.security.api.utils.SKApiUtils;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;

/** For use with restricted services only.
 * 
 * @author rcardone
 */
public class ReqRemoveServiceRolePermission 
extends ReqAddServiceRolePermission
{
   /** Return a user-appropriate error message on failed validation
    *  and return null if validation succeeds.
    */ 
   @Override
   public String validate() 
   {
       // Final checks.
       if (StringUtils.isBlank(roleTenant)) 
           return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "RemoveServiceRolePermission", "roleTenant");
       if (!SKApiUtils.isValidRestrictedServiceRoleName(roleName))
           return MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "RemoveServiceRolePermission", "roleName", roleName);
       if (!SKApiUtils.isValidRestrictedServicePermission(permSpec))
           return MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "RemoveServiceRolePermission", "permSpec");
       
       // Success.
       return null;
   }
}
