package org.example.cognitoAuthSpring3.model;

import lombok.Data;

@Data
public class UserRegisterRequest {
    private String name;
    private String userName;
    private String email;
    private String password;

}
