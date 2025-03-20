package edu.utexas.tacc.tapis.security.api.utils;

import edu.utexas.tacc.tapis.security.authz.impl.UserImpl;
import edu.utexas.tacc.tapis.shared.exceptions.TapisNotFoundException;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import edu.utexas.tacc.tapis.shared.security.TenantManager;
import edu.utexas.tacc.tapis.shared.utils.SkConstants;
import edu.utexas.tacc.tapis.tenants.client.gen.model.Tenant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public final class PrimarySiteInit {
    private static final Logger _log = LoggerFactory.getLogger(PrimarySiteInit.class);
    public static void initializePrimarySite() throws Exception {
        // make sure we have a primary site admin role, and primary site admin
        String primarySiteAdminTenantId = TenantManager.getInstance().getPrimarySite().getSiteAdminTenantId();
        Tenant primarySiteAdminTenant = TenantManager.getInstance().getTenant(primarySiteAdminTenantId);
        String roleName = SkConstants.SK_PRIMARY_SITE_ADMIN_ROLE;

        // Get the list of all users with the primary site admin role.
        List<String> primarySiteAdmins = null;
        try {
            primarySiteAdmins = UserImpl.getInstance().getUsersWithRole(primarySiteAdminTenantId, roleName);
        } catch (TapisNotFoundException e) {
            String msg = MsgUtils.getMsg("SK_TENANT_INIT_WARN", primarySiteAdminTenantId,
                    roleName, e.getMessage());
            _log.warn(msg);
        } catch (Exception e) {
            // This should not happen even if the tenant and role don't exist.
            // We log the problem but proceed.
            String msg = MsgUtils.getMsg("SK_GET_USERS_WITH_ROLE_ERROR", primarySiteAdminTenantId,
                    roleName, e.getMessage());
            _log.error(msg, e);
        }

        if ((primarySiteAdmins == null) || (primarySiteAdmins.isEmpty())) {

            String siteAdminUserName = primarySiteAdminTenant.getAdminUser();
            // ensure that the siteAdmin role exists
            UserImpl.getInstance().grantRoleInternal(roleName, primarySiteAdminTenantId,
                    "Primary site admin role",
                    siteAdminUserName, primarySiteAdminTenantId,
                    SkConstants.SK_USER, primarySiteAdminTenantId);
        }
    }
}
