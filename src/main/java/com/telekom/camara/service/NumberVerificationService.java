package com.telekom.camara.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Service
@Slf4j
public class NumberVerificationService {

    public boolean verifyPhoneNumber(String devicePhoneNumber, 
                                     String providedPhoneNumber,
                                     String providedHashedPhoneNumber) {
        
        log.debug("Verifying phone number. Device: {}", devicePhoneNumber);
        
        if (providedPhoneNumber != null) {
            boolean matches = devicePhoneNumber.equals(providedPhoneNumber);
            log.debug("Plain number comparison: {}", matches);
            return matches;
        }
        
        if (providedHashedPhoneNumber != null) {
            String deviceHash = sha256(devicePhoneNumber);
            boolean matches = deviceHash.equalsIgnoreCase(providedHashedPhoneNumber);
            log.debug("Hashed number comparison: {} (device hash: {})", matches, deviceHash);
            return matches;
        }
        
        return false;
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
