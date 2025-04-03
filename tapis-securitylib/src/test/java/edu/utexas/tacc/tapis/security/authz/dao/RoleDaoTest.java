package edu.utexas.tacc.tapis.security.authz.dao;

import edu.utexas.tacc.tapis.security.authz.model.SkRole;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

@Test(groups={"integration"})
public class RoleDaoTest {
    SkRoleDao dao;

    @BeforeClass
    public void beforeClass() throws Exception {
        dao = new SkRoleDao();
    }

    @AfterClass
    public void afterClass() throws Exception {
    }

    @Test
    public void createRoleTest() throws Exception {
        String roleName = "RoleOne";
        SkRole.Type roleType = SkRole.Type.TENANT_ADMIN;
        String roleTenant = "TestTenant";
        String roleDescription = "Test Role Description";
        String roleOwner = "TestRoleOwner";
        String roleOwnerTenant = "TestRoleOwnerTenant";

        int rolesCreated = dao.createRole(roleName, roleType, roleTenant, roleDescription, roleOwner, roleOwnerTenant);
        Assert.assertEquals(rolesCreated, 1);

        SkRole createdRole = new SkRole();
        createdRole.setName(roleName);
        createdRole.setType(roleType);
        createdRole.setTenant(roleTenant);
        createdRole.setDescription(roleDescription);
        createdRole.setOwner(roleOwner);
        createdRole.setOwnerTenant(roleOwnerTenant);

        SkRole retrievedRole = dao.getRole(roleTenant, roleName, roleType);
        compareRoles(retrievedRole, createdRole);
    }


    private void compareRoles(SkRole roleOne, SkRole roleTwo) {
        Assert.assertEquals(roleOne.getName(), roleTwo.getName());
        Assert.assertEquals(roleOne.getType(), roleTwo.getType());
        Assert.assertEquals(roleOne.getTenant(), roleTwo.getTenant());
        Assert.assertEquals(roleOne.getDescription(), roleTwo.getDescription());
        Assert.assertEquals(roleOne.getOwner(), roleTwo.getOwner());
        Assert.assertEquals(roleOne.getOwnerTenant(), roleTwo.getOwnerTenant());
    }
}
