package edu.utexas.tacc.tapis.security.api.requestBody;

import org.apache.commons.lang3.StringUtils;

import edu.utexas.tacc.tapis.security.api.utils.SKApiUtils;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;

/** For use with restricted services only.
 * 
 * @author rcardone
 */
public class ReqAddServiceRolePermission 
implements IReqBody
{
   public String roleTenant;
   public String roleName;
   public String permSpec;

   /** Return a user-appropriate error message on failed validation
    *  and return null if validation succeeds.
    */ 
   @Override
   public String validate() 
   {
       // Final checks.
       if (StringUtils.isBlank(roleTenant)) 
           return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "AddServiceRolePermission", "roleTenant");
       if (!SKApiUtils.isValidRestrictedServiceRoleName(roleName))
           return MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "AddServiceRolePermission", "roleName", roleName);
       if (!SKApiUtils.isValidRestrictedServicePermission(permSpec))
           return MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "AddServiceRolePermission", "permSpec");
       
       // Success.
       return null;
   }
}
