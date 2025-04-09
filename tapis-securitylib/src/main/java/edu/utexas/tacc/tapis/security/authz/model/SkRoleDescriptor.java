package edu.utexas.tacc.tapis.security.authz.model;

import org.apache.commons.lang3.StringUtils;

public class SkRoleDescriptor {
    private final String roleName;
    private final SkRoleType roleType;

    public static SkRoleDescriptor newSkRoleDescriptor(String roleName, boolean allowTypeInferance) {
        return newSkRoleDescriptor(roleName, (SkRoleType)null, allowTypeInferance);
    }

    public static SkRoleDescriptor newSkRoleDescriptor(String roleName, SkRoleType roleType) {
        return newSkRoleDescriptor(roleName, roleType, false);
    }

    public static SkRoleDescriptor newSkRoleDescriptor(String roleName, String roleTypeName) {
        return newSkRoleDescriptor(roleName, roleTypeName, false);
    }

    public static SkRoleDescriptor newSkRoleDescriptor(String roleName, String roleTypeName, boolean allowTypeInferance) {
        SkRoleType roleType = null;
        if(!StringUtils.isBlank(roleTypeName)) {
            roleType = SkRoleType.getRoleTypeFromStringIgnoreCase(roleTypeName);
        }
        return new SkRoleDescriptor(roleName, roleType, allowTypeInferance);
    }

    public static SkRoleDescriptor newSkRoleDescriptor(String roleName, SkRoleType roleType, boolean allowTypeInferance) {
        return new SkRoleDescriptor(roleName, roleType, allowTypeInferance);
    }

    public SkRoleDescriptor(String roleName, SkRoleType roleType, boolean allowTypeInferance) {
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
}
