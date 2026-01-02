package com.telekom.camara.exception;

public class UserNotAuthenticatedByMobileNetworkException extends RuntimeException {
    public UserNotAuthenticatedByMobileNetworkException() {
        super("Client must authenticate via the mobile network to use this service");
    }
}
