package edu.utexas.tacc.tapis.security.api.requestBody;

import edu.utexas.tacc.tapis.security.api.utils.SKApiUtils;
import edu.utexas.tacc.tapis.security.authz.model.SkRoleType;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import org.apache.commons.lang3.StringUtils;

public class ReqRolePermits implements IReqBody {
    public String roleTenant;
    public String permSpec;
    public boolean immediate;
    public String roleType= SkRoleType.USER.name();

    /** Return a user-appropriate error message on failed validation
     *  and return null if validation succeeds.
     */
    @Override
    public String validate()
    {
        // Final checks.
        if (StringUtils.isBlank(roleTenant)) {
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "rolePermits", "roleTenant");
        }
        if (StringUtils.isBlank(roleType)) {
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "rolePermits", "roleType");
        }
        if (StringUtils.isBlank(permSpec)) {
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "rolePermits", "permSpec");
        }

        // Success.
        return null;
    }

}
