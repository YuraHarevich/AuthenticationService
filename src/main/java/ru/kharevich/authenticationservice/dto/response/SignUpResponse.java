package ru.kharevich.authenticationservice.dto.response;

import java.time.LocalDateTime;
import java.util.UUID;

public record SignUpResponse(

        UUID id,

        String username,

        String email,

        String firstname,

        String lastname,

        LocalDateTime birthDate

) {
}
