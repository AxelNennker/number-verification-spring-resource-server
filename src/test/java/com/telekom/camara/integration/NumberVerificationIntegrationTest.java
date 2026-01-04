package com.telekom.camara.integration;

import com.nimbusds.jose.crypto.RSAEncrypter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.io.*;
import java.security.interfaces.RSAPublicKey;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import({NumberVerificationIntegrationTest.MockAuthServerConfig.class})
class NumberVerificationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    private static MockAuthorizationServer mockAuthServer;

    @TestConfiguration
    static class MockAuthServerConfig {
        @Bean
        public MockAuthorizationServer mockAuthorizationServer() {
            return mockAuthServer;
        }
    }

    @BeforeAll
    static void setupKeys() throws FileNotFoundException {
        // Start the mock authorization server before all tests
        mockAuthServer = new MockAuthorizationServer();

        RSAPublicKey rsaPublicKey = readPublicKey();
        mockAuthServer.start(0, new RSAEncrypter(rsaPublicKey));

        System.out.println("=".repeat(60));
        System.out.println("Mock Authorization Server started");
        System.out.println("Port: " + mockAuthServer.getPort());
        System.out.println("JWKS URL: " + mockAuthServer.getJwksUrl());
        System.out.println("=".repeat(60));
    }

    static RSAPublicKey readRsaPublicKeyFromFile(File file) throws IOException {
        try (FileReader keyReader = new FileReader(file)) {
            PEMParser pemParser = new PEMParser(keyReader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
            return (RSAPublicKey) converter.getPublicKey(publicKeyInfo);
        }
    }

    static RSAPublicKey readPublicKey() throws FileNotFoundException {
        String publicKeyPath = "/opt/CAMARA/resourceservers/numberverification/public-key.pem";

        File file = new File(publicKeyPath);
        if (!file.exists()) {
            throw new IllegalStateException("JWE public key file not found");
        }
        try (FileInputStream fis = new FileInputStream(file)) {
            System.out.println("Loading JWE encryption public key from: " + file.getAbsolutePath());

            RSAPublicKey publicKey = readRsaPublicKeyFromFile(file);

            System.out.println("JWE encrypter initialized successfully with algorithm: " + publicKey.getAlgorithm());
            return publicKey;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @AfterAll
    static void tearDown() {
        // Shutdown the mock authorization server after all tests
        if (mockAuthServer != null) {
            mockAuthServer.shutdown();
            System.out.println("Mock Authorization Server stopped");
        }
    }

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        // Configure the application to use the mock authorization server's JWKS endpoint
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> mockAuthServer.getJwksUrl());
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri",
                () -> "http://localhost:" + mockAuthServer.getPort() + "/");
    }

    @Test
    void testVerifyPhoneNumber_withValidToken() throws Exception {
        String phoneNumber = "+1234567890";
        String validToken = mockAuthServer.generateValidToken(phoneNumber, "number-verification:verify", "/verify");

        mockMvc.perform(post("/verify")
                        .with(csrf())
                        .header("Authorization", "Bearer " + validToken)
                        .contentType("application/json")
                        .content("{\"phoneNumber\":\"" + phoneNumber + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.devicePhoneNumberVerified").value(true));
    }

    @Test
    void testReadPhoneNumber_withValidToken() throws Exception {
        String phoneNumber = "+1234567890";
        String validToken = mockAuthServer.generateValidToken(phoneNumber, "number-verification:device-phone-number:read", "/device-phone-number");

        mockMvc.perform(get("/device-phone-number")
                        .header("Authorization", "Bearer " + validToken)
                        .contentType("application/json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.phoneNumber").value(phoneNumber));
    }

    @Test
    void testReadPhoneNumber_withScopePathMismatch() throws Exception {
        String phoneNumber = "+1234567890";
        // Token has device-phone-number:read scope but wrong audience path
        String validToken = mockAuthServer.generateValidToken(phoneNumber, "number-verification:device-phone-number:read", "/verify");

        mockMvc.perform(get("/device-phone-number")
                        .with(csrf())
                        .header("Authorization", "Bearer " + validToken)
                        .contentType("application/json")
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testReadPhoneNumber_withUnsupportedScope() throws Exception {
        String phoneNumber = "+1234567890";
        String validToken = mockAuthServer.generateValidToken(phoneNumber, "bogus-scope", "/device-phone-number");

        mockMvc.perform(get("/device-phone-number")
                        .header("Authorization", "Bearer " + validToken)
                        .contentType("application/json"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testVerifyPhoneNumber_withMismatchedNumber() throws Exception {
        String tokenPhoneNumber = "+1234567890";
        String requestPhoneNumber = "+9876543210";
        String validToken = mockAuthServer.generateValidToken(tokenPhoneNumber, "number-verification:verify", "/verify");

        mockMvc.perform(post("/verify")
                        .with(csrf())
                        .header("Authorization", "Bearer " + validToken)
                        .contentType("application/json")
                        .content("{\"phoneNumber\":\"" + requestPhoneNumber + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.devicePhoneNumberVerified").value(false));
    }

    @Test
    void testVerifyPhoneNumber_withInvalidToken() throws Exception {
        mockMvc.perform(post("/verify")
                        .with(csrf())
                        .header("Authorization", "Bearer invalid.token.here")
                        .contentType("application/json")
                        .content("{\"phoneNumber\":\"+1234567890\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testVerifyPhoneNumber_withoutToken() throws Exception {
        mockMvc.perform(post("/verify")
                        .with(csrf())
                        .contentType("application/json")
                        .content("{\"phoneNumber\":\"+1234567890\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testVerifyPhoneNumber_withExpiredToken() throws Exception {
        String phoneNumber = "+1234567890";
        String expiredToken = mockAuthServer.generateExpiredToken(phoneNumber, "number-verification:verify", "/verify");

        mockMvc.perform(post("/verify")
                        .with(csrf())
                        .header("Authorization", "Bearer " + expiredToken)
                        .contentType("application/json")
                        .content("{\"phoneNumber\":\"" + phoneNumber + "\"}"))
                .andExpect(status().isUnauthorized());
    }
}