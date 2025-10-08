package ru.kharevich.authenticationservice.dto.response;

import java.time.LocalDateTime;

public record SignUpResponse(

        String username,

        String email,

        String firstname,

        String lastname,

        LocalDateTime birthDate

) {
}
