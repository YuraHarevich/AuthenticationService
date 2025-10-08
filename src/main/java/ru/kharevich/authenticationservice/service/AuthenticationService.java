package ru.kharevich.authenticationservice.service;

import ru.kharevich.authenticationservice.dto.request.RefreshTokenRequest;
import ru.kharevich.authenticationservice.dto.request.SignInRequest;
import ru.kharevich.authenticationservice.dto.request.SignUpRequest;
import ru.kharevich.authenticationservice.dto.response.AuthResponse;
import ru.kharevich.authenticationservice.dto.response.SignUpResponse;
import ru.kharevich.authenticationservice.dto.response.TokenValidationResponse;
import ru.kharevich.authenticationservice.model.RefreshToken;

import java.util.Optional;

public interface AuthenticationService {
    SignUpResponse signUp(SignUpRequest request);

    AuthResponse signIn(SignInRequest request);

    TokenValidationResponse validateToken(String token);

    AuthResponse getRefreshToken(RefreshTokenRequest request);

    RefreshToken createRefreshToken(String email);

    RefreshToken verifyExpiration(RefreshToken token);

    Optional<RefreshToken> findByToken(String token);
}
