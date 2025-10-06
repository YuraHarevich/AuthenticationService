package ru.kharevich.authenticationservice.controller.impl;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import ru.kharevich.authenticationservice.controller.contract.AuthApi;
import ru.kharevich.authenticationservice.dto.request.RefreshTokenRequest;
import ru.kharevich.authenticationservice.dto.request.SignInRequest;
import ru.kharevich.authenticationservice.dto.request.SignUpRequest;
import ru.kharevich.authenticationservice.dto.response.AuthResponse;
import ru.kharevich.authenticationservice.dto.response.SignUpResponse;
import ru.kharevich.authenticationservice.dto.response.TokenValidationResponse;
import ru.kharevich.authenticationservice.service.AuthenticationService;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController implements AuthApi {

    private final AuthenticationService authenticationService;

    @PostMapping("/sign-up")
    @ResponseStatus(HttpStatus.CREATED)
    public SignUpResponse signUp(@Valid @RequestBody SignUpRequest request){
        return authenticationService.signUp(request);
    }

    @PostMapping("/sign-in")
    @ResponseStatus(HttpStatus.OK)
    public AuthResponse signIn(@Valid @RequestBody SignInRequest request){
        return authenticationService.signIn(request);
    }

    @PostMapping("/validate")
    @ResponseStatus(HttpStatus.OK)
    public TokenValidationResponse validateToken(@RequestParam("token") String token){
        return authenticationService.validateToken(token);
    }

    @PostMapping("/refresh")
    @ResponseStatus(HttpStatus.OK)
    public AuthResponse refreshToken(@Valid @RequestBody RefreshTokenRequest request){
        return authenticationService.getRefreshToken(request);
    }

}
