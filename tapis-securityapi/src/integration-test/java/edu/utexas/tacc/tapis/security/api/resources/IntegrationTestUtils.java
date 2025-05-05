package edu.utexas.tacc.tapis.security.api.resources;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import edu.utexas.tacc.tapis.shared.TapisConstants;
import edu.utexas.tacc.tapis.shared.exceptions.TapisException;
import edu.utexas.tacc.tapis.shared.parameters.TapisInput;
import edu.utexas.tacc.tapis.shared.utils.SkConstants;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

public class IntegrationTestUtils {
    private static final TapisInput tapisInput = new TapisInput(TapisConstants.SERVICE_NAME_SECURITY);
    public static final String TEST_ADMIN_TENANT = "admin";
    public static final String TEST_TENANT_1 = "dev";
    public static final String TEST_TENANT_2 = "dev2";
    public static final String TEST_SITE_ADMIN_USER = "site_admin";
    public static final String TEST_TENANT_ADMIN_USER = "admin";
    public static final String TEST_USER_1 = "testuser3";
    public static final String TEST_USER_2 = "testuser4";
    public static final String TEST_USER_SK = SkConstants.SK_USER;

    public static String getTokenForUser(String user, String tenant) {
        var jwt = JWT.create()
                .withClaim("tapis/tenant_id", tenant)
                .withClaim("tapis/token_type", "access")
                .withClaim("tapis/delegation", false)
                .withClaim("tapis/delegation_sub", (String)null)
                .withClaim("tapis/username", user)
                .withClaim("tapis/account_type", "user")
                .withClaim("tapis/client_id", (String)null)
                .withClaim("tapis/grant_type", "password")
                .withIssuer("https://dev.develop.tapis.io/v3/tokens")
                .withSubject(user + "@" + tenant)
                .withExpiresAt(Date.from(Instant.now().plus(Duration.ofDays(365))))
                .sign(Algorithm.none());
        return jwt.toString();
    }

    public static String getBaseUrl() throws TapisException {
        return tapisInput.getInputParameters().getProperty("tapis.test.base.url");
    }
}
