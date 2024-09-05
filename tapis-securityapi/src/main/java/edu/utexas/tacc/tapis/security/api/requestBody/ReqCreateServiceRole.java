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
   public String adminTenant;
   public String serviceName;
   public String description;
   
   /** Return a user-appropriate error message on failed validation
    *  and return null if validation succeeds.
    */ 
   @Override
   public String validate() 
   {
       // Final checks.
       if (StringUtils.isBlank(adminTenant)) 
           return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "createServiceRole", "adminTenant");
       if (StringUtils.isBlank(description))
           return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "createServiceRole", "description");
       if (!SKApiUtils.isValidName(serviceName))
           return MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "createServiceRole", "roleName", serviceName);
       
       // Success.
       return null;
   }
}
