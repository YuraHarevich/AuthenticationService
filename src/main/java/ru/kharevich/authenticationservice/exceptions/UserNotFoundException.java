package ru.kharevich.authenticationservice.exceptions;

import org.springframework.http.HttpStatus;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(String message, HttpStatus status) {
        super(message);
    }
}
