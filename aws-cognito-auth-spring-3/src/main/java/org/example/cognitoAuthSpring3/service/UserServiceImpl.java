package org.example.cognitoAuthSpring3.service;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import org.example.cognitoAuthSpring3.config.CognitoConfig;
import org.example.cognitoAuthSpring3.helper.JwtHelper;
import org.example.cognitoAuthSpring3.model.JwtAuthentication;
import org.example.cognitoAuthSpring3.model.JwtIdTokenCredentialsHolder;
import org.example.cognitoAuthSpring3.model.UserResponse;
import org.example.cognitoAuthSpring3.service.contract.UserService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.text.ParseException;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class UserServiceImpl implements UserService {
    private final AWSCognitoIdentityProvider identityProvider;
    private final ConfigurableJWTProcessor configurableJWTProcessor;
    private JwtIdTokenCredentialsHolder jwtIdTokenCredentialsHolder;
    private CognitoConfig cognitoConfig;
    private static String GROUPS_FIELD = "cognito:groups";
    private static final String ROLE_PREFIX = "ROLE_";
    private static final String EMPTY_PWD = "";
    private JWKSource jwkSource;
    private JwtHelper jwtHelper;

    public UserServiceImpl(AWSCognitoIdentityProvider identityProvider,
                           ConfigurableJWTProcessor configurableJWTProcessor,
                           JwtIdTokenCredentialsHolder jwtIdTokenCredentialsHolder,
                           CognitoConfig cognitoConfig,
                           JWKSource jwkSource,
                           JwtHelper jwtHelper) {

        this.identityProvider = identityProvider;
        this.configurableJWTProcessor = configurableJWTProcessor;
        this.jwtIdTokenCredentialsHolder = jwtIdTokenCredentialsHolder;
        this.cognitoConfig = cognitoConfig;
        this.jwkSource = jwkSource;
        this.jwtHelper = jwtHelper;
    }

    public Boolean createUser(String name, String userName, String email, String password) {
        SignUpResult result = null;

        try{
            SignUpRequest request = new SignUpRequest().withClientId(cognitoConfig.getCognito_clientId())
                    .withUsername(userName)
                    .withPassword(password)
                    .withUserAttributes(
                            new AttributeType()
                                    .withName("name")
                                    .withValue(name),
                            new AttributeType()
                                    .withName("email")
                                    .withValue(email));

            result = identityProvider.signUp(request);


        }catch (Exception ex){
            //create log
        }
        finally {
            identityProvider.shutdown();

            if (result != null)
                return true;
            else
                return false;
        }
    }
    public Map<String, String> signIn(String email, String password) {

        Date expirationTime = new Date(new Date().getTime() +  (1000 * 60 * 60 * 24));
        Map<String, String> result = new LinkedHashMap<>() {{
            put("idToken", "");
            put("accessToken", "");
            put("refreshToken", "");
            put("message", "Error to generate accessToken");
        }};

        try{
            Map<String, String> authParams = new LinkedHashMap<>() {{
                put("USERNAME", email);
                put("PASSWORD", password);
            }};

            AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest()
                    .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                    .withUserPoolId(cognitoConfig.getCognito_userPoolId())
                    .withClientId(cognitoConfig.getCognito_clientId())
                    .withAuthParameters(authParams);

            AdminInitiateAuthResult authResult = identityProvider.adminInitiateAuth(authRequest);

            if(authResult != null && authResult.getAuthenticationResult() != null){
                AuthenticationResultType authenticationResultType = authResult.getAuthenticationResult();

                result.replace("idToken", authenticationResultType.getIdToken());
                result.replace("accessToken", authenticationResultType.getAccessToken());
                result.replace("refreshToken", authenticationResultType.getRefreshToken());
                result.replace("message", "accessToken Successfully generated");
            }

        }catch (Exception ex){
            //log
        }
        finally {
            identityProvider.shutdown();
            return result;

        }
    }
    public void confirmUser(String code, String userName) {
        try{
            ConfirmSignUpRequest signUpRequest = new ConfirmSignUpRequest()
                    .withClientId(cognitoConfig.getCognito_clientId())
                    .withConfirmationCode(code)
                    .withUsername(userName);

            identityProvider.confirmSignUp(signUpRequest);

        }catch (Exception ex){
            //log
        }finally {
            identityProvider.shutdown();
        }
    }
    public UserResponse getUserInfo(String username) {
        UserResponse userResponse = new UserResponse();

        try{
            AdminGetUserRequest userRequest = new AdminGetUserRequest()
                    .withUsername(username)
                    .withUserPoolId(cognitoConfig.getCognito_userPoolId());

            AdminGetUserResult userResult = identityProvider.adminGetUser(userRequest);
            List<AttributeType> userAttributes = userResult.getUserAttributes();


            userResponse.setUserName(userResult.getUsername());
            userResponse.setStatus(userResult.getUserStatus());

            for(AttributeType attribute: userAttributes) {
                if(attribute.getName().equals("email")) {
                    userResponse.setEmail(attribute.getValue());
                }else if(attribute.getName().equals("name")){
                    userResponse.setName(attribute.getValue());
                }
            }

        }catch (Exception ex){
            //log
        }finally {
            identityProvider.shutdown();
            return userResponse;
        }
    }
    public void changePassword(String accessToken, String oldPassword, String newPassword) {

        try{
            ChangePasswordRequest changePasswordRequest= new ChangePasswordRequest()
                    .withAccessToken(accessToken)
                    .withPreviousPassword(oldPassword)
                    .withProposedPassword(newPassword);

            identityProvider.changePassword(changePasswordRequest);

        }catch (Exception ex){
            //log
        }finally {
            identityProvider.shutdown();
        }
    }
    public JwtAuthentication authenticate(String authorizationToken) throws Exception {

        String auth = "Deny";
        if (authorizationToken != null) {
            JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;
            JWSKeySelector keySelector = new JWSVerificationKeySelector(jwsAlgorithm, jwkSource);
            configurableJWTProcessor.setJWSKeySelector(keySelector);
            try {
                String token = jwtHelper.stripBearerToken(authorizationToken);

                JWTClaimsSet claimsSet = this.configurableJWTProcessor.process(token,null);

                jwtHelper.validateIssuer(cognitoConfig.getCognito_userPoolId(), claimsSet);
                jwtHelper.validateAccessToken(claimsSet);

                String username = claimsSet.getClaims().get("username").toString();

                String sub = claimsSet.getStringClaim("sub");
                if(sub != null){
                    auth = "Allow";
                }
                Map<String, String> ctx = new HashMap<>();
                ctx.put("sub", sub);

                if (username != null) {

                    List<String> groups = (List<String>) claimsSet.getClaims().get(GROUPS_FIELD);
                    List<GrantedAuthority> grantedAuthorities = null;
                    if(groups != null)
                        grantedAuthorities = convertList(groups, group -> new SimpleGrantedAuthority(ROLE_PREFIX + group.toUpperCase()));

                    User user = new User(username, EMPTY_PWD, grantedAuthorities);

                    //jwtIdTokenCredentialsHolder.setIdToken(token);
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
            catch (ParseException | BadJOSEException e) {
                //Token inválido
                System.err.println(e.getMessage());
                throw e;
            } catch (JOSEException e) {
                // Key sourcing failed or another internal exception
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
    private static <T, U> List<U> convertList(List<T> from, Function<T, U> func) {
        return from.stream().map(func).collect(Collectors.toList());
    }
}
