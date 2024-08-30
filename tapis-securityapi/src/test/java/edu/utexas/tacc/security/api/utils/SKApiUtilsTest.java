package edu.utexas.tacc.security.api.utils;

import java.util.regex.Pattern;

import org.testng.Assert;
import org.testng.annotations.Test;

import edu.utexas.tacc.tapis.security.api.utils.SKApiUtils;

@Test()
public class SKApiUtilsTest 
{
	// Regexes
    private static final Pattern _permPattern = 
    	Pattern.compile("^service:(allow|deny):(tenant|user|action|service):(\\p{Alnum}|_)+(:(\\p{Alnum}|_)+)?(:(\\p{Alnum}|_)+)?$");
    private static final Pattern _colonSeparated = Pattern.compile(":");
    
	@Test(enabled=true)
	public void RestrictedServiceRoleNameTest()
	{
		// Valid names.
		String s = "$#banana";
		Assert.assertTrue(SKApiUtils.isValidRestrictedServiceRoleName(s));
		s = "$#another1";
		Assert.assertTrue(SKApiUtils.isValidRestrictedServiceRoleName(s));
		
		// Invalid names.
		s = "$##another2";
		Assert.assertFalse(SKApiUtils.isValidRestrictedServiceRoleName(s));
		s = "$$#another3";
		Assert.assertFalse(SKApiUtils.isValidRestrictedServiceRoleName(s));
		s = "$!another4";
		Assert.assertFalse(SKApiUtils.isValidRestrictedServiceRoleName(s));
		s = "another5";
		Assert.assertFalse(SKApiUtils.isValidRestrictedServiceRoleName(s));
		s = "$#_another6";
		Assert.assertFalse(SKApiUtils.isValidRestrictedServiceRoleName(s));
	}
	
	@Test(enabled=true)
	public void RestrictedServicePermissionsTest() 
	{
		// Valid perms.
		String s = "service:allow:tenant:t1";
		Assert.assertTrue(_permPattern.matcher(s).matches());
		s = "service:deny:tenant:t2";
		Assert.assertTrue(_permPattern.matcher(s).matches());
		s = "service:allow:user:t2:user66";
		Assert.assertTrue(_permPattern.matcher(s).matches());
		s = "service:deny:service:t2:myservice";
		Assert.assertTrue(_permPattern.matcher(s).matches());
		s = "service:deny:action:t2:t3:myaction";
		Assert.assertTrue(_permPattern.matcher(s).matches());
		
		// Invalid perms.
		s = "service:deny";
		Assert.assertFalse(_permPattern.matcher(s).matches());
		s = "service:allow:tenant";
		Assert.assertFalse(_permPattern.matcher(s).matches());
		s = "service:deny:tenant:";
		Assert.assertFalse(_permPattern.matcher(s).matches());
		s = "service:deny:user::";
		Assert.assertFalse(_permPattern.matcher(s).matches());
		s = "service:allow:user:t2:";
		Assert.assertFalse(_permPattern.matcher(s).matches());
		s = "service:deny:service:t2::myservice";
		Assert.assertFalse(_permPattern.matcher(s).matches());
		s = "service:deny:action:t2:t3:";
		Assert.assertFalse(_permPattern.matcher(s).matches());
		s = "service:allow:action:t2:t3:myaction:";
		Assert.assertFalse(_permPattern.matcher(s).matches());
		s = "service:allow:action:t2:t3:myaction:banana";
		Assert.assertFalse(_permPattern.matcher(s).matches());
		
		// Validate segment counting using the colon separator regex.
		Assert.assertEquals(_colonSeparated.split("service:allow:tenant:t1").length, 4);
		Assert.assertEquals(_colonSeparated.split("service:allow:user:t2:user66").length, 5);
		Assert.assertEquals(_colonSeparated.split("service:deny:service:t2:myservice").length, 5);
		Assert.assertEquals(_colonSeparated.split("service:deny:action:t2:t3:myaction").length, 6);
	}
}
