package com.telekom.camara.exception;

import com.telekom.camara.model.ErrorInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(InvalidBearerTokenException.class)
    public ResponseEntity<ErrorInfo> handleInvalidToken(InvalidBearerTokenException ex) {
        log.error("Invalid bearer token", ex);
        ErrorInfo error = new ErrorInfo(
            HttpStatus.UNAUTHORIZED.value(),
            "UNAUTHENTICATED",
            "Request not authenticated due to missing, invalid, or expired credentials."
        );
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorInfo> handleAccessDenied(AccessDeniedException ex) {
        log.error("Access denied", ex);
        ErrorInfo error = new ErrorInfo(
            HttpStatus.FORBIDDEN.value(),
            "PERMISSION_DENIED",
            "Client does not have sufficient permissions to perform this action."
        );
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    @ExceptionHandler(UserNotAuthenticatedByMobileNetworkException.class)
    public ResponseEntity<ErrorInfo> handleUserNotAuthenticatedByMobileNetwork(
            UserNotAuthenticatedByMobileNetworkException ex) {
        log.error("User not authenticated by mobile network", ex);
        ErrorInfo error = new ErrorInfo(
            HttpStatus.FORBIDDEN.value(),
            "NUMBER_VERIFICATION.USER_NOT_AUTHENTICATED_BY_MOBILE_NETWORK",
            ex.getMessage()
        );
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorInfo> handleValidationErrors(MethodArgumentNotValidException ex) {
        log.error("Validation error", ex);
        String message = ex.getBindingResult()
            .getFieldErrors()
            .stream()
            .map(error -> error.getField() + ": " + error.getDefaultMessage())
            .findFirst()
            .orElse("Client specified an invalid argument, request body or query param");
        ErrorInfo error = new ErrorInfo(
            HttpStatus.BAD_REQUEST.value(),
            "INVALID_ARGUMENT",
            message
        );
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorInfo> handleIllegalArgument(IllegalArgumentException ex) {
        log.error("Invalid argument", ex);
        ErrorInfo error = new ErrorInfo(
            HttpStatus.BAD_REQUEST.value(),
            "INVALID_ARGUMENT",
            ex.getMessage()
        );
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorInfo> handleException(Exception ex) {
        log.error("Unexpected error", ex);
        ErrorInfo error = new ErrorInfo(
            HttpStatus.INTERNAL_SERVER_ERROR.value(),
            "INTERNAL",
            "An internal server error occurred"
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}
