package org.example.model;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
public class UserRegisterRequest {
    private String name;
    private String email;
    private String password;

}
