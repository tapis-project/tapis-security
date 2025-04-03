package edu.utexas.tacc.tapis.security.api.responses;

import edu.utexas.tacc.tapis.security.authz.model.SkRole;
import edu.utexas.tacc.tapis.sharedapi.responses.RespAbstract;

public final class RespRole
 extends RespAbstract
{
    public RespRole(SkRole result) {
        this.result = result;
        this.result.setName(SkRole.Type.getRoleShortName(result.getName()));
    }
    
    public SkRole result;
}
