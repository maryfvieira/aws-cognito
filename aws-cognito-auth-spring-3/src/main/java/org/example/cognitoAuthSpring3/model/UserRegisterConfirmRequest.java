package org.example.cognitoAuthSpring3.model;

import lombok.Data;

@Data
public class UserRegisterConfirmRequest {
    private String userName;
    private String code;
}
