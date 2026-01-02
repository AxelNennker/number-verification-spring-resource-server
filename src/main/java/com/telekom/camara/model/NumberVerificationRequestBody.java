package com.telekom.camara.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class NumberVerificationRequestBody {
    @JsonProperty("phoneNumber")
    @Pattern(regexp = "^\\+[1-9][0-9]{4,14}$", 
        message = "phoneNumber must be in E.164 format")
    private String phoneNumber;
    
    @JsonProperty("hashedPhoneNumber")
    @Pattern(regexp = "^[a-fA-F0-9]{64}$",
        message = "hashedPhoneNumber must be SHA-256 hash")
    private String hashedPhoneNumber;
}
