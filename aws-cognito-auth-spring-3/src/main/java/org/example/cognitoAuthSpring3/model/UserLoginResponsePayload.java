package org.example.cognitoAuthSpring3.model;

import lombok.Data;

@Data
public class UserLoginResponsePayload {

    private String accessToken;
    private String refreshToken;

}

