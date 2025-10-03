package ru.kharevich.authenticationservice.dto.response;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SignUpResponse (

        String username,

        String email,

        String firstName,

        String lastName
) {
}
