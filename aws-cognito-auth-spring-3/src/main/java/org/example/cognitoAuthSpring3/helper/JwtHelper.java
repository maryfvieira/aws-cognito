package org.example.cognitoAuthSpring3.helper;

import com.nimbusds.jwt.JWTClaimsSet;

public class JwtHelper {

    private static final String BEARER_PREFIX = "Bearer ";

    public String stripBearerToken(String token) {
        return token.startsWith(BEARER_PREFIX) ? token.substring(BEARER_PREFIX.length()) : token;
    }
    public void validateIssuer(String userPoolId, JWTClaimsSet claims) throws Exception {
        if (!claims.getIssuer().contains(userPoolId)) {
            throw new Exception("Issuer does not match to cognito idp");
        }
    }
    public void validateAccessToken(JWTClaimsSet claims) throws Exception {
        if (!claims.getClaim("token_use").equals("access")) {
            throw new Exception("Access Denied");
        }
    }
}
