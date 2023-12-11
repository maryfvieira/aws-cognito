package org.example;

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
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.example.config.CognitoConfig;
import org.example.model.JwtIdTokenCredentialsHolder;
import org.example.service.UserServiceImpl;
import org.example.service.contract.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;
import java.net.MalformedURLException;
import java.net.URL;

import static com.nimbusds.jose.JWSAlgorithm.RS256;

@Component
public class AppConfig {

    @Bean
    public AWSCognitoIdentityProvider createAWSCognitoIdentityProvider() {
        BasicAWSCredentials creds = new BasicAWSCredentials(CognitoConfig.AWS_ACCESS_KEY, CognitoConfig.AWS_SECRET_KEY);
        AWSCognitoIdentityProviderClientBuilder builder
                = AWSCognitoIdentityProviderClientBuilder.standard().withCredentials(new AWSStaticCredentialsProvider(creds));
        builder.setRegion(CognitoConfig.AWS_REGION);
        return builder.build();
    }

    @Bean
    public ConfigurableJWTProcessor configurableJWTProcessor() throws MalformedURLException {
        ResourceRetriever resourceRetriever = new DefaultResourceRetriever(CognitoConfig.TIMEOUT, CognitoConfig.TIMEOUT);
        URL jwkSetURL = new URL(CognitoConfig.JWKS_URI);
        JWKSource keySource = new RemoteJWKSet(jwkSetURL, resourceRetriever);
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        JWSKeySelector keySelector = new JWSVerificationKeySelector(RS256, keySource);
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
                                      JwtIdTokenCredentialsHolder jwtIdTokenCredentialsHolder){
        return new UserServiceImpl(awsCognitoIdentityProvider, configurableJWTProcessor, jwtIdTokenCredentialsHolder);
    }
}
