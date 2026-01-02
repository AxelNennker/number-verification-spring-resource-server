package com.telekom.camara.config;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Validates that JWT has correct typ header as per RFC 9068
 */
public class JwtTypValidator implements OAuth2TokenValidator<Jwt> {
    
    private static final String TYP_HEADER = "typ";
    private static final String EXPECTED_TYP_SHORT = "at+jwt";
    private static final String EXPECTED_TYP_FULL = "application/at+jwt";
    
    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String typ = jwt.getHeaders().get(TYP_HEADER) != null 
            ? jwt.getHeaders().get(TYP_HEADER).toString() 
            : null;
        
        if (typ == null) {
            return OAuth2TokenValidatorResult.failure(
                new OAuth2Error("invalid_token", "JWT missing typ header", null));
        }
        
        if (!EXPECTED_TYP_SHORT.equals(typ) && !EXPECTED_TYP_FULL.equals(typ)) {
            return OAuth2TokenValidatorResult.failure(
                new OAuth2Error("invalid_token", 
                    String.format("JWT typ must be '%s' or '%s', but was '%s'", 
                        EXPECTED_TYP_SHORT, EXPECTED_TYP_FULL, typ), 
                    null));
        }
        
        return OAuth2TokenValidatorResult.success();
    }
}
