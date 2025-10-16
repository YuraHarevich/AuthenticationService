package ru.kharevich.authenticationservice.exceptions;

public class TokenValidationException extends RuntimeException {
    public TokenValidationException(String message) {
        super(message);
    }
}
