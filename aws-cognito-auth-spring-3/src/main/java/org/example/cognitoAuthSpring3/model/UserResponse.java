package org.example.cognitoAuthSpring3.model;

import lombok.Data;

@Data
public class UserResponse {
    String name;
    String userName;
    String status;
    String email;
}
