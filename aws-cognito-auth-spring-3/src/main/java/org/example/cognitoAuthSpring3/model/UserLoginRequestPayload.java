package org.example.cognitoAuthSpring3.model;

import lombok.Data;

@Data
public class UserLoginRequestPayload {
    private final String userName;
    private final String password;
}