package org.example.cognitoAuthSpring3.service.contract;

import org.example.cognitoAuthSpring3.model.JwtAuthentication;
import org.example.cognitoAuthSpring3.model.UserResponse;

import java.util.Map;

public interface UserService {
    Boolean createUser(String name, String userName, String email, String password);
    Map<String, String> signIn(String email, String password);
    void confirmUser(String code, String userName);
    void changePassword(String accessToken, String oldPassword, String newPassword);
    JwtAuthentication authenticate(String authorizationToken) throws Exception;
    UserResponse getUserInfo(String username);

}
