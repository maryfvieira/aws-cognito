package org.example.cognitoAuthSpring3.model;

import lombok.Data;

@Data
public class UserGroupAddRequest {
    private final String userName;
    private final String group;
}
