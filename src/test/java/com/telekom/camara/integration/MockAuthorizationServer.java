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
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
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
 * Security is disabled for this mock server.
 */
@SpringBootApplication(exclude = {SecurityAutoConfiguration.class})
@Import(TestSecurityConfig.class)
@RestController
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
     * Generate a valid JWT token with the given phone number claim, scope and audience.
     */
    public String generateValidToken(String phoneNumber, String scope, String audience) {
        return generateToken(
                phoneNumber,
                300,
                scope,
                audience);
    }

    /**
     * Generate an expired JWT token.
     */
    public String generateExpiredToken(String phoneNumber, String scope, String audience) {
        return generateToken(phoneNumber,
                -300,
                scope,
                audience);
    }

    /**
     * Generate a JWT token with custom expiration.
     */
    private String generateToken(
            String phoneNumber,
            long expiresInSeconds,
            String scope,
            String audience) {
        try {
            Instant now = Instant.now();

            JWTClaimsSet subjectClaimSet = new JWTClaimsSet.Builder().claim("phone_number", phoneNumber).build();

            String subject = encryptSubject(subjectClaimSet);
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer("http://localhost:" + serverPort)
                    .audience(audience)
                    .expirationTime(Date.from(now.plusSeconds(expiresInSeconds)))
                    .issueTime(Date.from(now))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("scope", scope)
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

    private String encryptSubject(JWTClaimsSet jwtClaimsSet) throws JOSEException {
        RSAEncrypter encrypter = new RSAEncrypter(rsaKey.toRSAPublicKey());
        JWEHeader header = new JWEHeader(
                JWEAlgorithm.RSA_OAEP_256,
                EncryptionMethod.A128GCM
        );
        EncryptedJWT jwt = new EncryptedJWT(header, jwtClaimsSet);
        jwt.encrypt(encrypter);

        return jwt.serialize();
    }
}