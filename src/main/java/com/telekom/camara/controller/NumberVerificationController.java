package com.telekom.camara.controller;

import com.telekom.camara.exception.UserNotAuthenticatedByMobileNetworkException;
import com.telekom.camara.model.*;
import com.telekom.camara.service.NumberVerificationService;
import com.telekom.camara.service.SubClaimDecryptionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Slf4j
public class NumberVerificationController {

    private final NumberVerificationService service;
    private final SubClaimDecryptionService subClaimDecryptionService;

    @PostMapping("/verify")
    public ResponseEntity<NumberVerificationMatchResponse> verify(
            @Valid @RequestBody NumberVerificationRequestBody request,
            @RequestHeader(value = "x-correlator", required = false) String correlator,
            Authentication authentication) {
        
        log.info("Verify request received. Correlator: {}", correlator);
        
        validateRequestBody(request);
        
        Jwt jwt = (Jwt) authentication.getPrincipal();
        verifyMobileNetworkAuthentication(jwt);
        
        String devicePhoneNumber = extractPhoneNumberFromToken(jwt);
        
        boolean verified = service.verifyPhoneNumber(
            devicePhoneNumber, 
            request.getPhoneNumber(),
            request.getHashedPhoneNumber()
        );
        
        return ResponseEntity.ok(new NumberVerificationMatchResponse(verified));
    }

    @GetMapping("/device-phone-number")
    public ResponseEntity<NumberVerificationShareResponse> getDevicePhoneNumber(
            @RequestHeader(value = "x-correlator", required = false) String correlator,
            Authentication authentication) {
        
        log.info("Device phone number request. Correlator: {}", correlator);
        
        Jwt jwt = (Jwt) authentication.getPrincipal();
        verifyMobileNetworkAuthentication(jwt);
        
        String devicePhoneNumber = extractPhoneNumberFromToken(jwt);
        
        return ResponseEntity.ok(new NumberVerificationShareResponse(devicePhoneNumber));
    }

    private void validateRequestBody(NumberVerificationRequestBody request) {
        boolean hasPhoneNumber = request.getPhoneNumber() != null;
        boolean hasHashedPhoneNumber = request.getHashedPhoneNumber() != null;
        
        if (!hasPhoneNumber && !hasHashedPhoneNumber) {
            throw new IllegalArgumentException(
                "Either phoneNumber or hashedPhoneNumber must be provided");
        }
        
        if (hasPhoneNumber && hasHashedPhoneNumber) {
            throw new IllegalArgumentException(
                "Only one of phoneNumber or hashedPhoneNumber must be provided");
        }
    }

    private void verifyMobileNetworkAuthentication(Jwt jwt) {
        Object amr = jwt.getClaim("amr");
        
        if (amr == null) {
            log.warn("AMR claim not present in token - cannot verify authentication method");
        }
    }

    private String extractPhoneNumberFromToken(Jwt jwt) {
        String sub = jwt.getSubject();
        log.debug("Extracting phone number from encrypted sub claim");
        
        try {
            return subClaimDecryptionService.extractPhoneNumber(sub);
        } catch (Exception e) {
            log.error("Failed to extract phone number from sub claim", e);
            throw new IllegalStateException("Could not extract phone number from token", e);
        }
    }
}
