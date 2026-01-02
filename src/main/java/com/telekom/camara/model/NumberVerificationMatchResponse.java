package com.telekom.camara.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class NumberVerificationMatchResponse {
    @JsonProperty("devicePhoneNumberVerified")
    private boolean devicePhoneNumberVerified;
}
