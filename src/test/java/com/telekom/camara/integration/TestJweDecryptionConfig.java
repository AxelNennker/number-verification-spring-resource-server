package com.telekom.camara.integration;

import com.nimbusds.jose.crypto.RSADecrypter;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * Test configuration for JWE decryption that uses the MockAuthorizationServer's encryption key.
 * This overrides the production JWE decryption configuration to use the mock server's keys.
 */
@TestConfiguration
public class TestJweDecryptionConfig {

    @Bean
    @Primary
    public RSADecrypter testJweDecrypter(MockAuthorizationServer mockAuthServer) {
        // Use the MockAuthorizationServer's JWE decrypter which has the private encryption key
        return mockAuthServer.getJweDecrypter();
    }
}