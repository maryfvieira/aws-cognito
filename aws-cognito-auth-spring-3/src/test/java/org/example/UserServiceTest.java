package org.example;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.SignUpRequest;
import com.amazonaws.services.cognitoidp.model.SignUpResult;
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
import org.example.cognitoAuthSpring3.service.UserServiceImpl;
import org.example.cognitoAuthSpring3.service.contract.UserService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserServiceTest {

    @Mock
    private AWSCognitoIdentityProvider identityProvider;

    @Mock
    private ConfigurableJWTProcessor configurableJWTProcessor;

    @Mock
    private JwtIdTokenCredentialsHolder jwtIdTokenCredentialsHolder;

    @Mock
    private JWKSource jwkSource;

    @Mock
    private JwtHelper jwtHelper;

    //@InjectMocks
    private UserService userService;

    private CognitoConfig cognitoConfig;

    private final String name = "integration test user 1";
    private final String password = "123456";
    private final String email = "test1@test.com";
    private final String userName = "test_user_1";
    private String authorizationToken = "authorizationToken";
    private static String GROUPS_FIELD = "cognito:groups";
    private static final String ROLE_PREFIX = "ROLE_";

    @BeforeEach
    void init() {
        MockitoAnnotations.initMocks(this);
        cognitoConfig = new CognitoConfig();
        userService = new UserServiceImpl(identityProvider, configurableJWTProcessor, jwtIdTokenCredentialsHolder, cognitoConfig, jwkSource, jwtHelper);
    }

    @Test
    void givenNewUser_whenSaveUser_thenSucceed(){

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

        SignUpResult result = new SignUpResult();
        result.setUserConfirmed(false);
        when(identityProvider.signUp(any(SignUpRequest.class))).thenReturn(result);
        doNothing().when(identityProvider).shutdown();

        Boolean hasCreatedUser = userService.createUser(name, userName, email, password);
        verify(identityProvider).signUp(any(SignUpRequest.class));
        verify(identityProvider).shutdown();
        Assertions.assertTrue(hasCreatedUser);
    }

    @Test
    void givenAuthorizationToken_whenAuthenticate_thenSucceed() throws Exception {

        Date issueTime = new Date();

        //expiration time in 30 minutes
        Date expirationTime = new Date(issueTime.getTime() + (1000 * 60 * 30));

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("5e185fdb-1bff-4ba8-9ce5-800273ea9476")
                .issuer("https://cognito-idp.sa-east-1.amazonaws.com/sa-east-1_88889997777")
                .expirationTime(expirationTime)
                .issueTime(issueTime)
                .claim("username", userName)
                .claim("cognito:groups", Arrays.asList("group1"))
                .audience("")
                .build();

        when(jwtHelper.stripBearerToken(authorizationToken)).thenReturn(authorizationToken);
        when(configurableJWTProcessor.process(authorizationToken, null)).thenReturn(claimsSet);
        doNothing().when(jwtHelper).validateIssuer(cognitoConfig.getCognito_userPoolId(), claimsSet);
        doNothing().when(jwtHelper).validateAccessToken(claimsSet);

        ArgumentCaptor<JWSKeySelector> argument = ArgumentCaptor.forClass(JWSKeySelector.class);
        JwtAuthentication jwtAuthentication = userService.authenticate(authorizationToken);
        verify(configurableJWTProcessor).setJWSKeySelector(argument.capture());

        JWSVerificationKeySelector jwsVerificationKeySelector = (JWSVerificationKeySelector)argument.getValue();

        Assert.notNull(jwtAuthentication, "jwtAuthentication cannot be null");
        Assert.isTrue(userName == jwtAuthentication.getName(), "userName must be " + userName);
        Assert.isTrue(jwtAuthentication.isAuthenticated(), "user must be authenticated");
        Assert.isTrue(jwsVerificationKeySelector.getJWKSource().equals(jwkSource), "jwkSource Needs to be equal to injected object");
        Assert.isTrue(jwsVerificationKeySelector.getExpectedJWSAlgorithm().equals(JWSAlgorithm.RS256), "The correct algorithm is RS256");

        List<String> groups = (List<String>) claimsSet.getClaims().get(GROUPS_FIELD);
        Collection<GrantedAuthority> grantedAuthorities = convertList(groups, group -> new SimpleGrantedAuthority(ROLE_PREFIX + group.toUpperCase()));
        Assert.isTrue(jwtAuthentication.getAuthorities().containsAll(grantedAuthorities), "grantedAuthorities must be equal content of cognito:groups");

    }

    @Test
    void givenAuthorizationToken_whenAuthenticate_thenThrowParseException() throws BadJOSEException, ParseException, JOSEException {

        when(jwtHelper.stripBearerToken(authorizationToken)).thenReturn(authorizationToken);
        when(configurableJWTProcessor.process(authorizationToken, null)).thenThrow(new ParseException("Invalid JWT serialization: Missing dot delimiter(s)", 0));

        Exception e = assertThrows(ParseException.class, () -> {
            JwtAuthentication jwtAuthentication = userService.authenticate(authorizationToken);
        });

        Assert.isTrue(e instanceof Exception, "e must be an instance of ParseException");
        Assert.isTrue(e.getMessage().contains("Invalid JWT serialization: Missing dot delimiter(s)"), "");

    }

    void givenRegisteredUser_whenConfirmUser_thenFail(){

    }

    void givenUserData_whenSigIn_thenFail(){

    }

    void givenUserData_whenSigIn_thenSucced(){

    }

    private static <T, U> List<U> convertList(List<T> from, Function<T, U> func) {
        return from.stream().map(func).collect(Collectors.toList());
    }

}
