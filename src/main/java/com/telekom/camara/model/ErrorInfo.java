package com.telekom.camara.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ErrorInfo {
    @JsonProperty("status")
    private int status;
    @JsonProperty("code")
    private String code;
    @JsonProperty("message")
    private String message;
}
