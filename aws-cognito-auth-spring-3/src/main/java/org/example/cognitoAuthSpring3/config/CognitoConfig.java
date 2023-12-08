package org.example.cognitoAuthSpring3.config;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

@Component
@PropertySource("classpath:aws.properties")
@ConfigurationProperties(prefix = "aws")
@Data
public class CognitoConfig {

    @Value("${aws.accessKey:default}")
    private String accessKey;
    @Value("${aws.secretKey:default}")
    private String secretKey;
    @Value("${aws.cognito_userPoolId:default}")
    private String cognito_userPoolId;
    @Value("${aws.region:default}")
    private String region;
    @Value("${aws.cognito_clientId:default}")
    private String cognito_clientId;
    @Value("${aws.cognito_jwks_Uri:http://localhost}")
    private String cognito_jwks_Uri;
    @Value("${aws.timeout:1000}")
    private Integer timeout;

}