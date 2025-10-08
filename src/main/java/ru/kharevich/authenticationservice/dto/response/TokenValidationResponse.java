package ru.kharevich.authenticationservice.dto.response;

public record TokenValidationResponse(
        boolean valid,
        String username
) {

}
