package com.telekom.camara.service;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class SubClaimDecryptionService {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JWEDecrypter jweDecrypter;

    public String extractPhoneNumber(String encryptedSub) {
        try {
            String decryptedJson = decryptJwe(encryptedSub);
            
            JsonNode rootNode = objectMapper.readTree(decryptedJson);
            JsonNode phoneNumberNode = rootNode.get("phone_number");
            
            if (phoneNumberNode == null) {
                throw new IllegalStateException("phone_number field not found in sub claim");
            }
            
            String phoneNumber = phoneNumberNode.asText();
            log.debug("Successfully extracted phone number from sub claim");
            
            if (!phoneNumber.matches("^\\+[1-9][0-9]{4,14}$")) {
                throw new IllegalStateException("Invalid phone number format: " + phoneNumber);
            }
            
            return phoneNumber;
            
        } catch (Exception e) {
            log.error("Failed to extract phone number from encrypted sub claim", e);
            throw new IllegalStateException("Could not extract phone number from token", e);
        }
    }

    private String decryptJwe(String jweString) {
        try {
            JWEObject jweObject = JWEObject.parse(jweString);
            jweObject.decrypt(jweDecrypter);
            String payload = jweObject.getPayload().toString();
            log.debug("Successfully decrypted JWE sub claim");
            return payload;
        } catch (Exception e) {
            log.error("JWE decryption failed", e);
            throw new RuntimeException("Failed to decrypt JWE sub claim", e);
        }
    }
}
