package edu.utexas.tacc.tapis.security.api.requestBody;

import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;

public class ReqAdminReinitialize implements IReqBody {

    public Boolean doReinitialize;


    /**
     * Return a user-appropriate error message on failed validation
     * and return null if validation succeeds.
     */
    @Override
    public String validate() {
        if (doReinitialize == null)
            return MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "reinitialize", "doReinitialize");

        // Success.
        return null;
    }
}
