package org.example;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.SignUpRequest;
import com.amazonaws.services.cognitoidp.model.SignUpResult;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import org.example.cognitoAuthSpring3.config.CognitoConfig;
import org.example.cognitoAuthSpring3.model.JwtIdTokenCredentialsHolder;
import org.example.cognitoAuthSpring3.service.UserServiceImpl;
import org.example.cognitoAuthSpring3.service.contract.UserService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserServiceTest {

    @Mock
    AWSCognitoIdentityProvider identityProvider;

    @Mock
    ConfigurableJWTProcessor configurableJWTProcessor;

    @Mock
    JwtIdTokenCredentialsHolder jwtIdTokenCredentialsHolder;

    UserService userService;

    CognitoConfig cognitoConfig;

    private final String name = "integration test user 1";
    private final String password = "123456";
    private final String email = "test1@test.com";
    private final String userName = "test_user_1";
    private final String client_Id = "Test";

    @BeforeEach
    void init() {
        MockitoAnnotations.initMocks(this);
        cognitoConfig = new CognitoConfig();
        userService = new UserServiceImpl(identityProvider, configurableJWTProcessor, jwtIdTokenCredentialsHolder, cognitoConfig);

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


//    @Test(expected = RuntimeException.class)
//    void givenNewUser_whenSaveUser_thenFail(){
//
//    }

    void givenRegisteredUser_whenConfirmUser_thenSucced(){

    }

    void givenRegisteredUser_whenConfirmUser_thenFail(){

    }

    void givenUserData_whenSigIn_thenFail(){

    }

    void givenUserData_whenSigIn_thenSucced(){

    }

}
