package edu.utexas.tacc.tapis.security.authz.model;

import edu.utexas.tacc.tapis.shared.utils.SkConstants;
import org.apache.commons.lang3.StringUtils;

public class SkRoleDescriptor {
    public static final SkRoleDescriptor TENANT_ADMIN_ROLE_DESCRIPTOR = SkRoleDescriptor.newSkRoleDescriptor(SkRoleType.getRoleShortName(SkConstants.ADMIN_ROLE_NAME), SkRoleType.TENANT_ADMIN);
    public static final SkRoleDescriptor SITE_ADMIN_ROLE_DESCRIPTOR = SkRoleDescriptor.newSkRoleDescriptor(SkRoleType.getRoleShortName(SkConstants.SK_PRIMARY_SITE_ADMIN_ROLE), SkRoleType.SITE_ADMIN);
    private final String roleName;
    private final SkRoleType roleType;

    private static SkRoleDescriptor newSkRoleDescriptor(String roleName, boolean allowTypeInferance) {
        return newSkRoleDescriptor(roleName, (SkRoleType)null, allowTypeInferance);
    }

    public static SkRoleDescriptor newSkRoleDescriptor(String roleName, SkRoleType roleType) {
        return newSkRoleDescriptor(roleName, roleType, false);
    }

    public static SkRoleDescriptor newSkRoleDescriptor(String roleName, String roleTypeName) {
        return newSkRoleDescriptor(roleName, roleTypeName, false);
    }

    private static SkRoleDescriptor newSkRoleDescriptor(String roleName, String roleTypeName, boolean allowTypeInferance) {
        SkRoleType roleType = null;
        if(!StringUtils.isBlank(roleTypeName)) {
            roleType = SkRoleType.getRoleTypeFromStringIgnoreCase(roleTypeName);
        }
        return new SkRoleDescriptor(roleName, roleType, allowTypeInferance);
    }

    private static SkRoleDescriptor newSkRoleDescriptor(String roleName, SkRoleType roleType, boolean allowTypeInferance) {
        return new SkRoleDescriptor(roleName, roleType, allowTypeInferance);
    }

    private SkRoleDescriptor(String roleName, SkRoleType roleType, boolean allowTypeInferance) {
        if((allowTypeInferance) && (roleType == null)) {
            this.roleName = SkRoleType.getRoleShortName(roleName);
            this.roleType = SkRoleType.getRoleTypeFromRoleName(roleName);
        } else {
            this.roleName = roleName;
            this.roleType = roleType;
        }
    }

    public boolean isValid() {
        if((StringUtils.isBlank(roleName)) || (roleType == null)) {
            return false;
        }

        return true;
    }

    public SkRoleType getRoleType() {
        return roleType;
    }

    public String getRoleTypeName() {
        return roleType.name();
    }

    public String getRoleName() {
        return roleName;
    }

    public String getRoleFullName() {
        String fullRoleName = roleName;
        switch (roleType) {
            case USER_DEFAULT -> {
                fullRoleName = SkRole.PREFIX_USER_DEFAULT + roleName;
            }
            case RESTRICTED_SVC -> {
                fullRoleName = SkRole.PREFIX_RESTRICTED_SVC + roleName;
            }
            case TENANT_ADMIN -> {
                fullRoleName = SkRole.PREFIX_TENANT_ADMIN + roleName;
            }
            case SITE_ADMIN -> {
                fullRoleName = SkRole.PREFIX_SITE_ADMIN + roleName;
            }
        }

        return fullRoleName;
    }

    public static boolean descriptorIsValid(SkRoleDescriptor roleDescriptor) {
        if(roleDescriptor == null) {
            return false;
        }

        return roleDescriptor.isValid();
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Name: ");
        builder.append(roleName);
        builder.append(", Type: ");
        builder.append(roleType);
        return builder.toString();
    }
}
