package ru.kharevich.authenticationservice.controller.contract;

import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import ru.kharevich.authenticationservice.dto.request.RefreshTokenRequest;
import ru.kharevich.authenticationservice.dto.request.SignInRequest;
import ru.kharevich.authenticationservice.dto.request.SignUpRequest;
import ru.kharevich.authenticationservice.dto.response.AuthResponse;
import ru.kharevich.authenticationservice.dto.response.SignUpResponse;
import ru.kharevich.authenticationservice.dto.response.TokenValidationResponse;

public interface AuthApi {

    SignUpResponse signUp(@Valid @RequestBody SignUpRequest request);

    AuthResponse signIn(@Valid @RequestBody SignInRequest request);

    TokenValidationResponse validateToken(@RequestHeader("Authorization") String authHeader);

    AuthResponse refreshToken(@Valid @RequestBody RefreshTokenRequest request);

}
