package org.example;

import com.amazonaws.serverless.proxy.internal.LambdaContainerHandler;
import com.amazonaws.serverless.proxy.internal.testutils.AwsProxyRequestBuilder;
import com.amazonaws.serverless.proxy.internal.testutils.MockLambdaContext;
import com.amazonaws.serverless.proxy.model.AwsProxyResponse;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.core.MediaType;
import org.example.cognitoAuthSpring3.Application;
import org.example.cognitoAuthSpring3.handler.StreamLambdaHandler;
import org.example.cognitoAuthSpring3.model.UserGroupAddRequest;
import org.example.cognitoAuthSpring3.model.UserLoginRequestPayload;
import org.example.cognitoAuthSpring3.model.UserLoginResponsePayload;
import org.example.cognitoAuthSpring3.model.UserRegisterRequest;
import org.example.cognitoAuthSpring3.service.contract.AdminService;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.util.Assert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

@SpringBootTest(classes = {Application.class}, properties = "classpath:aws-integrated-tests.properties")
@TestPropertySource("classpath:aws-integrated-tests.properties")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(value = TestInstance.Lifecycle.PER_CLASS)
public class UserControllerIntegrationTest {

    @Autowired
    private AdminService adminService;

    private MockLambdaContext lambdaContext;
    private StreamLambdaHandler handler;
    private static Gson gson;

    private String userPath = "/api/v1/user";
    private String adminPath = "/api/v1/admin";
    private String userName = "test_cognito1";
    private String name = "integration test user 1";
    private String password = "123456";
    private String email = "test1@test.com";

    private String group = "api-test";
    private String token = "";

    private Map<String, String> headers = new HashMap<>();


    @BeforeAll
    public static void beforeAll(){
        gson = new GsonBuilder().create();
    }

    @BeforeEach
    public void setUp() {
        try {
            headers.put("Content-Type", MediaType.APPLICATION_JSON);
            headers.put("HttpHeaders.ACCEPT", MediaType.APPLICATION_JSON);

//            headers = Map.of(
//                    "Content-Type", MediaType.APPLICATION_JSON,
//                    HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);

            this.lambdaContext = new MockLambdaContext();
            this.handler = new StreamLambdaHandler();


        } catch (Exception ex) {

        }
    }

    @Test
    @Order(1)
    void whenIsToCreateUser(){

        UserRegisterRequest request = new UserRegisterRequest();
        request.setName(name);
        request.setEmail(email);
        request.setUserName(userName);
        request.setPassword(password);

        var response = execute(userPath, HttpMethod.POST, headers, request);

        Assert.isTrue(response.getBody().toString().equals("User successfully created"), "User must be created");
        Assert.isTrue(201 == response.getStatusCode(), "response status must be 201");
    }

    @Test
    @Order(2)
    void whenIsToConfirmEmail(){

        var response = execute(adminPath + "/user/"+ userName + "/confirm", HttpMethod.PUT, headers, null);

        Assert.notNull(response, "response cannot be null");
        Assert.isTrue(response.getBody().toString().equals("User successfully confirmed"), "User must be confirmed");
        Assert.isTrue(200 == response.getStatusCode(), "response status must be 200");
    }

    @Test
    @Order(3)
    void whenIsToAddUserToGroup(){

        UserGroupAddRequest userGroupAddRequest = new UserGroupAddRequest(userName, group);
        var response = execute(adminPath + "/user/group/add", HttpMethod.POST, headers, userGroupAddRequest);

        Assert.notNull(response, "response cannot be null");
        Assert.isTrue(200 == response.getStatusCode(), "response status must be 200");
    }

    @Test
    @Order(4)
    void whenIsToSignIn(){
        UserLoginRequestPayload userLoginRequestPayload = new UserLoginRequestPayload(userName, password);

        var response = execute(userPath + "/sigIn", HttpMethod.POST, headers, userLoginRequestPayload);
        var userLoginResponsePayload = gson.fromJson(response.getBody(), UserLoginResponsePayload.class);
        //UserLoginResponsePayload userLoginResponsePayload = (UserLoginResponsePayload)response.getBody();
        token = userLoginResponsePayload.getAccessToken();

        Assert.notNull(token, "token cannot be null");
    }

    @Test
    @Order(5)
    void whenIsToAuthUser(){

        headers.put("Authorization", token);

        var response = execute(userPath + "/auth", HttpMethod.POST, headers, null);
        Assert.notNull(response, "response cannot be null");
        Assert.isTrue(200 == response.getStatusCode(), "response status must be 200");
    }

    @AfterAll
    public void tearDown() {
        adminService.deleteUser(userName);
    }

    private <T> AwsProxyResponse execute(String path, String httpMethod, Map<String, String> headers, T request) {

        AwsProxyRequestBuilder req = new AwsProxyRequestBuilder(path, httpMethod);

        Iterator<Map.Entry<String, String>> iterator = headers.entrySet().iterator();
        while(iterator.hasNext()){
            Map.Entry<String, String> entry = iterator.next();
            req.header(entry.getKey(), entry.getValue());
        }

        if(request != null){
            req = req.body(gson.toJson(request));
        }

        InputStream inputStream = req.buildStream();

        ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
        handle(inputStream, responseStream);
        var response = gson.fromJson(responseStream.toString(), AwsProxyResponse.class);
        return response;
    }

    private void handle(InputStream is, ByteArrayOutputStream os) {
        try {
            handler.handleRequest(is, os, lambdaContext);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private AwsProxyResponse readResponse(ByteArrayOutputStream responseStream) {
        try {
            return LambdaContainerHandler.getObjectMapper().readValue(responseStream.toByteArray(), AwsProxyResponse.class);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
