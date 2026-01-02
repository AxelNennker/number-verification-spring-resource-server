package com.telekom.camara.config;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.List;

/**
 * Validates that all required claims per RFC 9068 are present
 */
public class RequiredClaimsValidator implements OAuth2TokenValidator<Jwt> {
    
    private static final String[] REQUIRED_CLAIMS = {
        "iss",       // Issuer
        "exp",       // Expiration Time
        "aud",       // Audience
        "sub",       // Subject
        "client_id", // Client ID
        "iat",       // Issued At
        "jti"        // JWT ID
    };
    
    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        List<String> missingClaims = new ArrayList<>();
        
        for (String claim : REQUIRED_CLAIMS) {
            if (jwt.getClaim(claim) == null) {
                missingClaims.add(claim);
            }
        }
        
        if (!missingClaims.isEmpty()) {
            return OAuth2TokenValidatorResult.failure(
                new OAuth2Error("invalid_token", 
                    "JWT missing required claims per RFC 9068: " + String.join(", ", missingClaims), 
                    null));
        }
        
        return OAuth2TokenValidatorResult.success();
    }
}
