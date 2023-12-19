package org.example.cognitoAuthSpring3;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.example.cognitoAuthSpring3.config.CognitoConfig;
import org.example.cognitoAuthSpring3.config.JWTConfig;
import org.example.cognitoAuthSpring3.helper.JwtHelper;
import org.example.cognitoAuthSpring3.model.JwtIdTokenCredentialsHolder;
import org.example.cognitoAuthSpring3.service.AdminServiceImpl;
import org.example.cognitoAuthSpring3.service.UserServiceImpl;
import org.example.cognitoAuthSpring3.service.contract.AdminService;
import org.example.cognitoAuthSpring3.service.contract.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;

import static com.nimbusds.jose.JWSAlgorithm.RS256;

@Component
public class AppConfig {

    @Autowired
    private CognitoConfig cognitoConfig;

    @Autowired
    private JWTConfig jwtConfig;

    @Bean
    public JwtHelper jwtHelper(){
        return new JwtHelper();
    }

    @Bean
    public AWSCognitoIdentityProvider createAWSCognitoIdentityProvider() {
        BasicAWSCredentials creds = new BasicAWSCredentials(cognitoConfig.getAccessKey(), cognitoConfig.getSecretKey());
        AWSCognitoIdentityProviderClientBuilder builder
                = AWSCognitoIdentityProviderClientBuilder
                    .standard()
                    .withCredentials(new AWSStaticCredentialsProvider(creds));
        builder.setRegion(cognitoConfig.getRegion());
        return builder.build();
    }

    @Bean
    public ConfigurableJWTProcessor configurableJWTProcessor() throws MalformedURLException {
        ResourceRetriever resourceRetriever = new DefaultResourceRetriever(cognitoConfig.getTimeout(), cognitoConfig.getTimeout());
        URL jwkSetURL = new URL(cognitoConfig.getCognito_jwks_Uri());
        JWKSource keySource = new RemoteJWKSet(jwkSetURL, resourceRetriever);
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        JWSKeySelector keySelector = new JWSVerificationKeySelector(RS256, keySource);
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
                new JWTClaimsSet.Builder().issuer(jwtConfig.getIssue())
                        .build(),
                new HashSet<>(Arrays.asList(
                        JWTClaimNames.SUBJECT,
                        JWTClaimNames.ISSUED_AT,
                        JWTClaimNames.EXPIRATION_TIME,
                        "client_id",
                        "username",
                        "token_use",
                        JWTClaimNames.JWT_ID))));

        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor;
    }

    @Bean
    @Scope(value="request", proxyMode= ScopedProxyMode.TARGET_CLASS)
    public JwtIdTokenCredentialsHolder awsCognitoCredentialsHolder() {
        return new JwtIdTokenCredentialsHolder();
    }

    @Bean
    public UserService getUserService(AWSCognitoIdentityProvider awsCognitoIdentityProvider,
                                      ConfigurableJWTProcessor configurableJWTProcessor,
                                      JwtIdTokenCredentialsHolder jwtIdTokenCredentialsHolder,
                                      CognitoConfig cognitoConfig,
                                      JwtHelper jwtHelper
                                      ) throws MalformedURLException {

        JWKSource jwkSource = new RemoteJWKSet(new URL(cognitoConfig.getCognito_jwks_Uri()));
        return new UserServiceImpl(awsCognitoIdentityProvider, configurableJWTProcessor, jwtIdTokenCredentialsHolder, cognitoConfig, jwkSource, jwtHelper);
    }

    @Bean
    public AdminService getAdminService(AWSCognitoIdentityProvider awsCognitoIdentityProvider,
                                       ConfigurableJWTProcessor configurableJWTProcessor,
                                       JwtIdTokenCredentialsHolder jwtIdTokenCredentialsHolder,
                                        CognitoConfig cognitoConfig){
        return new AdminServiceImpl(awsCognitoIdentityProvider, configurableJWTProcessor, jwtIdTokenCredentialsHolder, cognitoConfig);
    }
}
