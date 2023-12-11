package org.example.service.contract;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClient;
import com.amazonaws.services.cognitoidp.model.SignUpResult;
//import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.cognitoidp.model.UserType;
import org.example.model.AuthResponse;
import org.example.model.JwtAuthentication;
import org.example.model.UserResponse;

import java.util.Map;

public interface UserService {
    UserType signUp(String name, String userName, String email, String password);
    Map<String, String> signIn(String email, String password);
    void confirmSignUp(String code, String userName);
    void changePassword(String accessToken, String oldPassword, String newPassword);
    JwtAuthentication authenticate(String authorizationToken) throws Exception;
    UserResponse getUserInfo(String username);
    void addUserToGroup(String username, String groupName);

}
