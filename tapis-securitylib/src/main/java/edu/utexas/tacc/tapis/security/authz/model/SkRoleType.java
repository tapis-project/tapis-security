package edu.utexas.tacc.tapis.security.authz.model;

import java.util.EnumSet;

public enum SkRoleType {

    USER,
    USER_DEFAULT,   //  prefix: "$$"
    RESTRICTED_SVC, //  prefix: "$#"
    TENANT_ADMIN,   //  prefix: "$!"
    SITE_ADMIN;     //  prefix: "$~"

    public static final EnumSet<SkRoleType> ALL_TYPES = java.util.EnumSet.allOf(SkRoleType.class);

    public static SkRoleType getRoleTypeFromRoleName(String roleName) {
        if (roleName.startsWith(SkRole.PREFIX_USER_DEFAULT)) {
            return USER_DEFAULT;
        } else if (roleName.startsWith(SkRole.PREFIX_RESTRICTED_SVC)) {
            return RESTRICTED_SVC;
        } else if (roleName.startsWith(SkRole.PREFIX_TENANT_ADMIN)) {
            return TENANT_ADMIN;
        } else if (roleName.startsWith(SkRole.PREFIX_SITE_ADMIN)) {
            return SITE_ADMIN;
        }

        return USER;
    }
/*
    public static String getRoleFullName(String roleName, SkRoleType roleType) {
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
*/
    public static String getRoleShortName(String roleName) {
        if (roleName.startsWith(SkRole.PREFIX_USER_DEFAULT)) {
            return roleName.substring(SkRole.PREFIX_USER_DEFAULT.length());
        } else if (roleName.startsWith(SkRole.PREFIX_RESTRICTED_SVC)) {
            return roleName.substring(SkRole.PREFIX_RESTRICTED_SVC.length());
        } else if (roleName.startsWith(SkRole.PREFIX_TENANT_ADMIN)) {
            return roleName.substring(SkRole.PREFIX_TENANT_ADMIN.length());
        } else if (roleName.startsWith(SkRole.PREFIX_SITE_ADMIN)) {
            return roleName.substring(SkRole.PREFIX_SITE_ADMIN.length());
        }

        return roleName;
    }

    public static SkRoleType getRoleTypeFromStringIgnoreCase(String typeName) {
        return SkRoleType.valueOf(typeName.toUpperCase());
    }

}
