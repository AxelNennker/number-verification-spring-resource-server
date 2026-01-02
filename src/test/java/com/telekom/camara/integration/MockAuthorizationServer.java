package com.telekom.camara.integration;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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
 * Provides JWKS endpoint, OpenID Configuration, and token generation capabilities.
 * Generates access tokens with JWE-encrypted phone numbers in the subject claim.
 */
@Configuration
@EnableAutoConfiguration
@RestController
public class MockAuthorizationServer {

    private static RSAKey signingKey;
    private static RSAKey encryptionKey;
    private static RSASSASigner signer;
    private static RSAEncrypter encrypter;
    private static int serverPort;
    private ConfigurableApplicationContext context;

    static {
        try {
            // Generate RSA key pair for signing
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair signingKeyPair = gen.generateKeyPair();

            signingKey = new RSAKey.Builder((RSAPublicKey) signingKeyPair.getPublic())
                    .privateKey((RSAPrivateKey) signingKeyPair.getPrivate())
                    .keyID(UUID.randomUUID().toString())
                    .build();

            signer = new RSASSASigner(signingKey);

            // Generate RSA key pair for encryption
            KeyPair encryptionKeyPair = gen.generateKeyPair();

            encryptionKey = new RSAKey.Builder((RSAPublicKey) encryptionKeyPair.getPublic())
                    .privateKey((RSAPrivateKey) encryptionKeyPair.getPrivate())
                    .keyID(UUID.randomUUID().toString())
                    .build();

            encrypter = new RSAEncrypter(encryptionKey);

        } catch (NoSuchAlgorithmException | JOSEException e) {
            throw new RuntimeException("Failed to initialize RSA keys", e);
        }
    }

    /**
     * Security configuration for mock server - permit all requests
     */
    @Bean
    public SecurityFilterChain mockServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/**")
                .authorizeHttpRequests(authz -> authz
                        .anyRequest().permitAll()
                )
                .csrf(csrf -> csrf.disable());
        return http.build();
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public String jwks() {
        try {
            // Only expose the public keys for signature verification
            JWKSet jwkSet = new JWKSet(signingKey.toPublicJWK());
            return jwkSet.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate JWKS JSON", e);
        }
    }

    @GetMapping(value = "/.well-known/openid-configuration", produces = MediaType.APPLICATION_JSON_VALUE)
    public String openidConfiguration() {
        String baseUrl = "http://localhost:" + serverPort;
        return String.format("""
            {
              "issuer": "%s",
              "authorization_endpoint": "%s/oauth/authorize",
              "token_endpoint": "%s/oauth/token",
              "jwks_uri": "%s/.well-known/jwks.json",
              "response_types_supported": ["code", "token"],
              "subject_types_supported": ["public"],
              "id_token_signing_alg_values_supported": ["RS256"],
              "scopes_supported": ["openid", "phone", "number-verification:verify", "number-verification:device-phone-number:read"]
            }
            """, baseUrl, baseUrl, baseUrl, baseUrl);
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
     * Generate a valid JWT token with the given phone number, scope, and audience.
     * The phone number is encrypted as a JWE and placed in the subject claim.
     */
    public String generateValidToken(String phoneNumber, String scope, String audience) {
        return generateToken(phoneNumber, scope, audience, 3600); // Valid for 1 hour
    }

    /**
     * Generate an expired JWT token.
     */
    public String generateExpiredToken(String phoneNumber, String scope, String audience) {
        return generateToken(phoneNumber, scope, audience, -3600); // Expired 1 hour ago
    }

    /**
     * Encrypt phone number as JWE to be used in the subject claim.
     */
    private String encryptPhoneNumber(String phoneNumber) {
        try {
            // Create JWT claims for the phone number
            JWTClaimsSet phoneNumberClaims = new JWTClaimsSet.Builder()
                    .claim("phone_number", phoneNumber)
                    .build();

            // Create JWE object with phone number
            JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                    .build();

            EncryptedJWT encryptedJWT = new EncryptedJWT(jweHeader, phoneNumberClaims);

            // Encrypt the JWT
            encryptedJWT.encrypt(encrypter);

            return encryptedJWT.serialize();

        } catch (JOSEException e) {
            throw new RuntimeException("Failed to encrypt phone number", e);
        }
    }

    /**
     * Generate a JWT token with custom expiration.
     * The subject contains a JWE-encrypted phone number.
     */
    private String generateToken(String phoneNumber, String scope, String audience, long expiresInSeconds) {
        try {
            Instant now = Instant.now();

            // Encrypt the phone number for the subject claim
            String encryptedPhoneNumber = encryptPhoneNumber(phoneNumber);

            // Build the access token claims
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(encryptedPhoneNumber)
                    .issuer("http://localhost:" + serverPort)
                    .audience("http://localhost:" + serverPort + audience)
                    .expirationTime(Date.from(now.plusSeconds(expiresInSeconds)))
                    .notBeforeTime(Date.from(now))
                    .issueTime(Date.from(now))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("scope", scope)
                    .build();

            // Sign the JWT
            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(signingKey.getKeyID())
                            .build(),
                    claimsSet);

            signedJWT.sign(signer);

            return signedJWT.serialize();

        } catch (JOSEException e) {
            throw new RuntimeException("Failed to generate token", e);
        }
    }

    /**
     * Get the public encryption key for use by the resource server to decrypt JWEs.
     */
    public RSAKey getPublicEncryptionKey() {
        try {
            return encryptionKey.toPublicJWK();
        } catch (Exception e) {
            throw new RuntimeException("Failed to get public encryption key", e);
        }
    }
}