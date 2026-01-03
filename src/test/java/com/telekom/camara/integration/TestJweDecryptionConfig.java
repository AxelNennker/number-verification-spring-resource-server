package com.telekom.camara.integration;

import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Test configuration that provides both the JWE decrypter and a properly configured JwtDecoder.
 * This ensures that JWTs with JWE-encrypted subject claims are properly decoded during tests.
 */
@TestConfiguration
public class TestJweDecryptionConfig {

    @Bean
    @Primary
    public RSADecrypter testJweDecrypter(MockAuthorizationServer mockAuthServer) {
        // Use the MockAuthorizationServer's JWE decrypter which has the private encryption key
        return mockAuthServer.getJweDecrypter();
    }

    @Bean
    @Primary
    public JwtDecoder testJwtDecoder(MockAuthorizationServer mockAuthServer) {
        // Create a JwtDecoder that uses the mock server's JWKS endpoint
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(mockAuthServer.getJwksUrl()).build();

        // The JWE decrypter will be autowired by Spring into your JwtAuthenticationConverter
        // or wherever you decrypt the subject claim

        return jwtDecoder;
    }
}