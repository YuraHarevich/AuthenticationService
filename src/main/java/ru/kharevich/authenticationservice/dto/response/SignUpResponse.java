package ru.kharevich.authenticationservice.dto.response;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.LocalDateTime;

public record SignUpResponse (

        String username,

        String email,

        String firstname,

        String lastname,

        LocalDateTime birthDate
) {
}
