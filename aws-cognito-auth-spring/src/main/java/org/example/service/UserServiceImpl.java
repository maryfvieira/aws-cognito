package org.example.service;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClient;
import com.amazonaws.services.cognitoidp.model.*;
//import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import lombok.SneakyThrows;
import org.example.config.CognitoConfig;
import org.example.model.*;
import org.example.service.contract.UserService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.net.URL;
import java.text.ParseException;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class UserServiceImpl implements UserService {
    private final AWSCognitoIdentityProvider identityProvider;
    private final ConfigurableJWTProcessor configurableJWTProcessor;
    private JwtIdTokenCredentialsHolder jwtIdTokenCredentialsHolder;
    private static final String BEARER_PREFIX = "Bearer ";
    private static String GROUPS_FIELD = "cognito:groups";
    private static final String ROLE_PREFIX = "ROLE_";
    private static final String EMPTY_PWD = "";

    public UserServiceImpl(AWSCognitoIdentityProvider identityProvider,
                           ConfigurableJWTProcessor configurableJWTProcessor,
                           JwtIdTokenCredentialsHolder jwtIdTokenCredentialsHolder){
        this.identityProvider = identityProvider;
        this.configurableJWTProcessor = configurableJWTProcessor;
        this.jwtIdTokenCredentialsHolder = jwtIdTokenCredentialsHolder;
    }

    public UserType signUp(String name, String userName, String email, String password) {

        AdminCreateUserRequest cognitoRequest = new AdminCreateUserRequest()
                .withUserPoolId("us-east-1_Qqtfujski")
                .withUsername(userName)
                .withUserAttributes(
                        new AttributeType()
                                .withName("email")
                                .withValue(email),
                        new AttributeType()
                                .withName("name")
                                .withValue(name),
                        new AttributeType()
                                .withName("password")
                                .withValue(password),
                        new AttributeType()
                                .withName("email_verified")
                                .withValue("true"))
                .withMessageAction("SUPPRESS")
                .withDesiredDeliveryMediums(DeliveryMediumType.EMAIL)
                .withForceAliasCreation(Boolean.FALSE);
        AdminCreateUserResult createUserResult =  identityProvider.adminCreateUser(cognitoRequest);
        return createUserResult.getUser();

    }
    public Map<String, String> signIn(String email, String password) {

        Map<String, String> authParams = new LinkedHashMap<>() {{
            put("USERNAME", email);
            put("PASSWORD", password);
        }};

        AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest()
                .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                .withUserPoolId(CognitoConfig.AWS_USER_POOL_ID)
                .withClientId(CognitoConfig.CLIENT_ID)
                .withAuthParameters(authParams);

        AdminInitiateAuthResult authResult = identityProvider.adminInitiateAuth(authRequest);

        AuthenticationResultType resultType = authResult.getAuthenticationResult();

        identityProvider.shutdown();

        return new LinkedHashMap<String, String>() {{
            put("idToken", resultType.getIdToken());
            put("accessToken", resultType.getAccessToken());
            put("refreshToken", resultType.getRefreshToken());
            put("message", "Successfully login");
        }};
    }
    public void confirmSignUp(String code, String userName) {

        ConfirmSignUpRequest signUpRequest = new ConfirmSignUpRequest()
                .withClientId(CognitoConfig.CLIENT_ID)
                .withConfirmationCode(code)
                .withUsername(userName);

        identityProvider.confirmSignUp(signUpRequest);
    }
    public void addUserToGroup(String username, String groupName) {

        AdminAddUserToGroupRequest addUserToGroupRequest = new AdminAddUserToGroupRequest()
                .withGroupName(groupName)
                .withUserPoolId(CognitoConfig.AWS_USER_POOL_ID)
                .withUsername(username);

        identityProvider.adminAddUserToGroup(addUserToGroupRequest);

        identityProvider.shutdown();
    }
    public UserResponse getUserInfo(String username) {

        AdminGetUserRequest userRequest = new AdminGetUserRequest()
                .withUsername(username)
                .withUserPoolId(CognitoConfig.AWS_USER_POOL_ID);

        AdminGetUserResult userResult = identityProvider.adminGetUser(userRequest);
        List<AttributeType> userAttributes = userResult.getUserAttributes();

        UserResponse userResponse = new UserResponse();
        userResponse.setUserName(userResult.getUsername());
        userResponse.setStatus(userResult.getUserStatus());

        for(AttributeType attribute: userAttributes) {
            if(attribute.getName().equals("email")) {
                userResponse.setEmail(attribute.getValue());
            }else if(attribute.getName().equals("name")){
                userResponse.setName(attribute.getValue());
            }
        }

        identityProvider.shutdown();
        return userResponse;

    }
    public void changePassword(String accessToken, String oldPassword, String newPassword) {

        ChangePasswordRequest changePasswordRequest= new ChangePasswordRequest()
                .withAccessToken(accessToken)
                .withPreviousPassword(oldPassword)
                .withProposedPassword(newPassword);

        identityProvider.changePassword(changePasswordRequest);
        identityProvider.shutdown();

    }
    public JwtAuthentication authenticate(String authorizationToken) throws Exception {

        String auth = "Deny";
        if (authorizationToken != null) {
            JWKSource jwkSource = new RemoteJWKSet(new URL(CognitoConfig.JWKS_URI));
            JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;
            JWSKeySelector keySelector = new JWSVerificationKeySelector(jwsAlgorithm, jwkSource);
            configurableJWTProcessor.setJWSKeySelector(keySelector);
            try {
                JWTClaimsSet claimsSet = this.configurableJWTProcessor.process(stripBearerToken(authorizationToken),null);

                validateIssuer(claimsSet);
                verifyIfAccessToken(claimsSet);

                String username = claimsSet.getClaims().get("username").toString();

                String sub = claimsSet.getStringClaim("sub");
                if(sub != null){
                    auth = "Allow";
                }
                Map<String, String> ctx = new HashMap<>();
                ctx.put("sub", sub);

                if (username != null) {

                    List<String> groups = (List<String>) claimsSet.getClaims().get(GROUPS_FIELD);
                    List<GrantedAuthority> grantedAuthorities = convertList(groups, group -> new SimpleGrantedAuthority(ROLE_PREFIX + group.toUpperCase()));
                    User user = new User(username, EMPTY_PWD, grantedAuthorities);

                    jwtIdTokenCredentialsHolder.setIdToken(stripBearerToken(authorizationToken));
                    return new JwtAuthentication(user, claimsSet, grantedAuthorities);
                }

//                APIGatewayProxyRequestEvent.RequestIdentity identity = proxyContext.getIdentity();
//
//                String arn = String.format("arn:aws:execute-api:%s:%s:%s/%s/%s/%s",CognitoConfig.AWS_REGION, proxyContext.getAccountId(),
//                        proxyContext.getApiId(), proxyContext.getStage(), proxyContext.getHttpMethod(), "*");
//                Statement statement = Statement.builder().effect(auth).resource(arn).build();
//                PolicyDocument policyDocument = PolicyDocument.builder().statements(Collections.singletonList(statement))
//                        .build();
//                return AuthResponse.builder().principalId(identity.getAccountId()).policyDocument(policyDocument)
//                        .context(ctx).build();

            }
            catch (BadJOSEException e) {
                //log
                throw e;
            } catch (JOSEException e) {
                e.printStackTrace();
                //log
                throw e;
            } catch (ParseException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                //log
                throw e;
            }

//            String username = claims.getClaims().get("username").toString();
//            if (username != null) {
//                List<GrantedAuthority> grantedAuthorities = of( new SimpleGrantedAuthority("ROLE_USER"));
//                User user = new User(username, "", of());
//                return new CognitoJwtAuthentication(username, claims, grantedAuthorities);
//            }
        }
        return null;
    }
    private String stripBearerToken(String token) {
        return token.startsWith(BEARER_PREFIX) ? token.substring(BEARER_PREFIX.length()) : token;
    }
    private void validateIssuer(JWTClaimsSet claims) throws Exception {
        if (!claims.getIssuer().contains(CognitoConfig.AWS_USER_POOL_ID)) {
            throw new Exception("Issuer does not match to cognito idp");
        }
    }
    private void verifyIfAccessToken(JWTClaimsSet claims) throws Exception {
        if (!claims.getClaim("token_use").equals("access")) {
            throw new Exception("Access Denied");
        }
    }

    private static <T, U> List<U> convertList(List<T> from, Function<T, U> func) {
        return from.stream().map(func).collect(Collectors.toList());
    }
}
