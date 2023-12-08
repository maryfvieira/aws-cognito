package org.example.cognitoAuthSpring3.service;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import org.example.cognitoAuthSpring3.config.CognitoConfig;
import org.example.cognitoAuthSpring3.model.JwtIdTokenCredentialsHolder;
import org.example.cognitoAuthSpring3.service.contract.AdminService;

public class AdminServiceImpl implements AdminService {
    private final AWSCognitoIdentityProvider identityProvider;
    private final ConfigurableJWTProcessor configurableJWTProcessor;
    private final JwtIdTokenCredentialsHolder jwtIdTokenCredentialsHolder;
    private final CognitoConfig cognitoConfig;

    public AdminServiceImpl(AWSCognitoIdentityProvider identityProvider,
                            ConfigurableJWTProcessor configurableJWTProcessor,
                            JwtIdTokenCredentialsHolder jwtIdTokenCredentialsHolder,
                            CognitoConfig cognitoConfig){

        this.identityProvider = identityProvider;
        this.configurableJWTProcessor = configurableJWTProcessor;
        this.jwtIdTokenCredentialsHolder = jwtIdTokenCredentialsHolder;
        this.cognitoConfig = cognitoConfig;
    }

    public Boolean createUser(String name, String userName, String email) {
        AdminCreateUserResult createUserResult = null;

        try{
            AdminCreateUserRequest cognitoRequest = new AdminCreateUserRequest()
                    .withUserPoolId(cognitoConfig.getCognito_userPoolId())
                    .withUsername(userName)
                    .withTemporaryPassword("123456")
                    .withUserAttributes(
                            new AttributeType()
                                    .withName("email")
                                    .withValue(email),
                            new AttributeType()
                                    .withName("name")
                                    .withValue(name),
                            new AttributeType()
                                    .withName("email_verified")
                                    .withValue("true"))
                    .withMessageAction("SUPPRESS")
                    .withDesiredDeliveryMediums(DeliveryMediumType.EMAIL)
                    .withForceAliasCreation(Boolean.FALSE);
            createUserResult =  identityProvider.adminCreateUser(cognitoRequest);

        }catch (Exception ex){
            //log

        }finally {
            identityProvider.shutdown();
            if (createUserResult.getUser() != null)
                return true;
            else
                return false;
        }
    }

    public void deleteUser(String userName){

        try{
            AdminDeleteUserRequest user = new AdminDeleteUserRequest();
            user.setUserPoolId(cognitoConfig.getCognito_userPoolId());
            user.setUsername(userName);

            identityProvider.adminDeleteUser(user);

        }catch (Exception ex){
            //log

        }finally {
            identityProvider.shutdown();
        }
    }

    public void addUserToGroup(String username, String groupName) {

        try{
            AdminAddUserToGroupRequest addUserToGroupRequest = new AdminAddUserToGroupRequest()
                    .withGroupName(groupName)
                    .withUserPoolId(cognitoConfig.getCognito_userPoolId())
                    .withUsername(username);

            identityProvider.adminAddUserToGroup(addUserToGroupRequest);
        }catch (Exception ex){
            //log

        }finally {
            identityProvider.shutdown();
        }
    }

    public void confirmUser(String userName){

        try{
            AdminConfirmSignUpRequest adminConfirmSignUpRequest = new AdminConfirmSignUpRequest();
            adminConfirmSignUpRequest.setUserPoolId(cognitoConfig.getCognito_userPoolId());
            adminConfirmSignUpRequest.setUsername(userName);

            identityProvider.adminConfirmSignUp(adminConfirmSignUpRequest);

        }catch (Exception ex){
            //log

        }finally {
            identityProvider.shutdown();
        }
    }
}