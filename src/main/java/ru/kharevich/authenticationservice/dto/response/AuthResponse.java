package ru.kharevich.authenticationservice.dto.response;

import java.util.UUID;

public record AuthResponse (
    String accessToken,
    String refreshToken,
    String tokenType,
    UUID userId,
    String username
) {

}
