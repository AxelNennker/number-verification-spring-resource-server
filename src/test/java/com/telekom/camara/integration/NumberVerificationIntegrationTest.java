package com.telekom.camara.integration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class NumberVerificationIntegrationTest {

    static final String SCOPE_VERIFY = "number-verification:verify";
    static final String SCOPE_READ = "number-verification:device-phone-number:read";
    static final String VERIFY_PATH = "/number-verification/v0/verify";
    static final String READ_PATH = "/number-verification/v0/device-phone-number";

    static private String baseAudience;

    @Autowired
    private MockMvc mockMvc;

    private static MockAuthorizationServer mockAuthServer;

    @BeforeAll
    static void setupKeys() {
        // Start the mock authorization server before all tests
        mockAuthServer = new MockAuthorizationServer();
        mockAuthServer.start();

        baseAudience = "http://localhost:" + mockAuthServer.getPort();

        System.out.println("=".repeat(60));
        System.out.println("Mock Authorization Server started");
        System.out.println("Port: " + mockAuthServer.getPort());
        System.out.println("JWKS URL: " + mockAuthServer.getJwksUrl());
        System.out.println("=".repeat(60));
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
    }

    @Test
    void testVerifyPhoneNumber_withValidToken() throws Exception {
        String phoneNumber = "+1234567890";
        String audience = baseAudience + VERIFY_PATH;
        String validToken = mockAuthServer.generateValidToken(phoneNumber, SCOPE_VERIFY, audience);

        mockMvc.perform(post(VERIFY_PATH)
                        .header("Authorization", "Bearer " + validToken)
                        .contentType("application/json")
                        .content("{\"phoneNumber\":\"" + phoneNumber + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.devicePhoneNumberVerified").value(true));
    }

    @Test
    void testReadPhoneNumber_withValidToken() throws Exception {
        String phoneNumber = "+1234567890";
        String audience = baseAudience + READ_PATH;
        String validToken = mockAuthServer.generateValidToken(phoneNumber, SCOPE_READ, audience);

        mockMvc.perform(post(VERIFY_PATH)
                        .header("Authorization", "Bearer " + validToken)
                        .contentType("application/json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.devicePhoneNumber").value(phoneNumber));
    }

    @Test
    void testReadPhoneNumber_withScopePathMismatch() throws Exception {
        String phoneNumber = "+1234567890";

        // scope does not match path
        String audience = baseAudience + READ_PATH;
        String validToken = mockAuthServer.generateValidToken(phoneNumber, SCOPE_VERIFY, audience);

        mockMvc.perform(post(VERIFY_PATH)
                        .header("Authorization", "Bearer " + validToken)
                        .contentType("application/json"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testReadPhoneNumber_withUnsupportedScope() throws Exception {
        String phoneNumber = "+1234567890";

        // scope does not match path
        String audience = baseAudience + READ_PATH;
        String validToken = mockAuthServer.generateValidToken(phoneNumber, "bogus-scope", audience);

        mockMvc.perform(post(VERIFY_PATH)
                        .header("Authorization", "Bearer " + validToken)
                        .contentType("application/json"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testVerifyPhoneNumber_withMismatchedNumber() throws Exception {
        String tokenPhoneNumber = "+1234567890";
        String requestPhoneNumber = "+9876543210";
        String audience = baseAudience + VERIFY_PATH;
        String validToken = mockAuthServer.generateValidToken(tokenPhoneNumber, SCOPE_VERIFY, audience);

        mockMvc.perform(post(VERIFY_PATH)
                        .header("Authorization", "Bearer " + validToken)
                        .contentType("application/json")
                        .content("{\"phoneNumber\":\"" + requestPhoneNumber + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.devicePhoneNumberVerified").value(false));
    }

    @Test
    void testVerifyPhoneNumber_withInvalidToken() throws Exception {
        mockMvc.perform(post(VERIFY_PATH)
                        .header("Authorization", "Bearer invalid.token.here")
                        .contentType("application/json")
                        .content("{\"phoneNumber\":\"+1234567890\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testVerifyPhoneNumber_withoutToken() throws Exception {
        mockMvc.perform(post(VERIFY_PATH)
                        .contentType("application/json")
                        .content("{\"phoneNumber\":\"+1234567890\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testVerifyPhoneNumber_withExpiredToken() throws Exception {
        String phoneNumber = "+1234567890";
        String audience = baseAudience + VERIFY_PATH;
        String expiredToken = mockAuthServer.generateExpiredToken(phoneNumber, SCOPE_VERIFY, audience);

        mockMvc.perform(post(VERIFY_PATH)
                        .header("Authorization", "Bearer " + expiredToken)
                        .contentType("application/json")
                        .content("{\"phoneNumber\":\"" + phoneNumber + "\"}"))
                .andExpect(status().isUnauthorized());
    }
}