package com.telekom.camara.integration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Mock OAuth2 Authorization Server for testing purposes.
 * Provides JWKS endpoint and token generation capabilities.
 */
@SpringBootApplication
@RestController
@EnableWebSecurity
public class MockAuthorizationServer {

    private static RSAKey rsaKey;
    private static RSASSASigner signer;
    private static int serverPort;
    private ConfigurableApplicationContext context;

    static {
        try {
            // Generate RSA key pair
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair keyPair = gen.generateKeyPair();

            // Create RSA JWK
            rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyID(UUID.randomUUID().toString())
                    .build();

            signer = new RSASSASigner(rsaKey);

        } catch (NoSuchAlgorithmException | JOSEException e) {
            throw new RuntimeException("Failed to initialize RSA keys", e);
        }
    }

    /**
     * Security configuration to allow unauthenticated access to JWKS endpoint
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/.well-known/jwks.json").permitAll()
                        .anyRequest().denyAll()
                )
                .csrf(csrf -> csrf.disable());
        return http.build();
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public String jwks() {
        try {
            JWKSet jwkSet = new JWKSet(rsaKey.toPublicJWK());
            return jwkSet.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate JWKS JSON", e);
        }
    }

    public void start() {
        start(0); // Random port
    }

    public void start(int port) {
        SpringApplication app = new SpringApplication(MockAuthorizationServer.class);
        app.setDefaultProperties(java.util.Map.of(
                "server.port", port == 0 ? "0" : String.valueOf(port),
                "logging.level.root", "ERROR",
                "logging.level.com.telekom.camara.integration.MockAuthorizationServer", "INFO"
        ));
        context = app.run();
        serverPort = Integer.parseInt(context.getEnvironment().getProperty("local.server.port"));
    }

    public void shutdown() {
        if (context != null) {
            SpringApplication.exit(context);
        }
    }

    public int getPort() {
        return serverPort;
    }

    public String getJwksUrl() {
        return "http://localhost:" + serverPort + "/.well-known/jwks.json";
    }

    /**
     * Generate a valid JWT token with the given phone number claim.
     */
    public String generateValidToken(String phoneNumber) {
        return generateToken(phoneNumber, 3600); // Valid for 1 hour
    }

    /**
     * Generate an expired JWT token.
     */
    public String generateExpiredToken(String phoneNumber) {
        return generateToken(phoneNumber, -3600); // Expired 1 hour ago
    }

    /**
     * Generate a JWT token with custom expiration.
     */
    private String generateToken(String phoneNumber, long expiresInSeconds) {
        try {
            Instant now = Instant.now();

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject("user123")
                    .issuer("http://localhost:" + serverPort)
                    .audience("number-verification")
                    .expirationTime(Date.from(now.plusSeconds(expiresInSeconds)))
                    .notBeforeTime(Date.from(now))
                    .issueTime(Date.from(now))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("phone_number", phoneNumber)
                    .claim("scope", "openid phone")
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(rsaKey.getKeyID())
                            .build(),
                    claimsSet);

            signedJWT.sign(signer);

            return signedJWT.serialize();

        } catch (JOSEException e) {
            throw new RuntimeException("Failed to generate token", e);
        }
    }
}