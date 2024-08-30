package edu.utexas.tacc.tapis.security.api.requestBody;

import org.apache.commons.lang3.StringUtils;

import edu.utexas.tacc.tapis.security.api.utils.SKApiUtils;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;

/** For use with restricted services only.
 * 
 * @author rcardone
 */
public final class ReqCreateServiceRole 
implements IReqBody
{
   public String roleTenant;
   public String roleName;
   public String description;
   
   /** Return a user-appropriate error message on failed validation
    *  and return null if validation succeeds.
    */ 
   @Override
   public String validate() 
   {
       // Final checks.
       if (StringUtils.isBlank(roleTenant)) 
           return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "createServiceRole", "roleTenant");
       if (StringUtils.isBlank(description))
           return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "createServiceRole", "description");
       if (!SKApiUtils.isValidRestrictedServiceRoleName(roleName))
           return MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "createServiceRole", "roleName", roleName);
       
       // Success.
       return null;
   }
}
