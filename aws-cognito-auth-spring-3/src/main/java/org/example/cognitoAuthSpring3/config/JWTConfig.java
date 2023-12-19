package org.example.cognitoAuthSpring3.config;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource("classpath:jwt.properties")
@ConfigurationProperties(prefix = "jwt")
@Data
public class JWTConfig {

    @Value("${jwt.issue}")
    private String issue;
}
