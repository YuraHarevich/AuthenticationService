package ru.kharevich.authenticationservice.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import ru.kharevich.authenticationservice.dto.request.RefreshTokenRequest;
import ru.kharevich.authenticationservice.dto.request.SignInRequest;
import ru.kharevich.authenticationservice.dto.request.SignUpRequest;
import ru.kharevich.authenticationservice.dto.response.AuthResponse;
import ru.kharevich.authenticationservice.dto.response.SignUpResponse;
import ru.kharevich.authenticationservice.dto.response.TokenValidationResponse;
import ru.kharevich.authenticationservice.exceptions.RefreshTokenException;
import ru.kharevich.authenticationservice.model.RefreshToken;
import ru.kharevich.authenticationservice.model.User;
import ru.kharevich.authenticationservice.repository.RefreshTokenRepository;
import ru.kharevich.authenticationservice.repository.UserRepository;
import ru.kharevich.authenticationservice.security.JwtTokenProvider;
import ru.kharevich.authenticationservice.security.UserDetails;
import ru.kharevich.authenticationservice.service.AuthenticationService;
import ru.kharevich.authenticationservice.util.mapper.UserMapper;
import ru.kharevich.authenticationservice.util.properties.AuthServiceProperties;
import ru.kharevich.authenticationservice.util.validation.AuthenticationValidationService;

import java.time.Instant;
import java.util.Optional;

import static ru.kharevich.authenticationservice.util.constants.AuthenticationServiceConstantResponseMessages.*;
import static ru.kharevich.authenticationservice.util.constants.AuthenticationServiceConstantValues.DEFAULT_TOKEN_TYPE;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final AuthServiceProperties authServiceProperties;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserMapper userMapper;
    private final AuthenticationValidationService authenticationValidationService;

    public SignUpResponse signUp(SignUpRequest request) {
        authenticationValidationService.findByUsernameThrowsExceptionIfExists(
                request.username(),
                new IllegalStateException(USER_ALREADY_EXISTS_MESSAGE));
        User user = userMapper.toUser(request, encoder.encode(request.password()));
        User savedUser = userRepository.save(user);
        return userMapper.toResponse(savedUser);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public AuthResponse signIn(SignInRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username(), request.password())
            );
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException(INVALID_CREDENTIALS_MESSAGE);
        }
        User user = authenticationValidationService.findByUsernameThrowsExceptionIfDoesntExist(
                request.username(),
                new IllegalStateException(SIGN_IN_PROCESS_FAILED.formatted(request.username())
        ));
        UserDetails userDetails = new UserDetails(user);
        String accessToken = jwtTokenProvider.generateAccessToken(userDetails);
        RefreshToken refreshToken = createRefreshToken(request.username());

        return new AuthResponse(accessToken, refreshToken.getToken(), DEFAULT_TOKEN_TYPE, userDetails.getId(), userDetails.getUsername());
    }


    public TokenValidationResponse validateToken(String token) {
        if (!jwtTokenProvider.validateToken(token)){
            return new TokenValidationResponse(false, null);
        }

        String email = jwtTokenProvider.getUsernameFromToken(token);

        return new TokenValidationResponse(true, email);
    }

    public AuthResponse getRefreshToken(RefreshTokenRequest request) {
        return findByToken(request.refreshToken())
                .map(this::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    UserDetails appUserDetails = new UserDetails(user);
                    String newAccessToken = jwtTokenProvider.generateAccessToken(appUserDetails);

                    return new AuthResponse(newAccessToken, request.refreshToken(), DEFAULT_TOKEN_TYPE, user.getId(), user.getUsername());
                })
                .orElseThrow(
                        () -> new RefreshTokenException(REFRESH_TOKEN_INVALID_MESSAGE)
                );
    }

    @Transactional
    public RefreshToken createRefreshToken(String username) {

        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException(USER_NOT_FOUND_BY_USERNAME.formatted(username))
        );

        refreshTokenRepository.deleteByUser(user);

        UserDetails appUserDetails = new UserDetails(user);

        String token = jwtTokenProvider.generateRefreshToken(appUserDetails);

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .expiryDate(Instant.now().plusMillis(authServiceProperties.getRefreshTokenExpiration()))
                .token(token)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            throw new RefreshTokenException(REFRESH_TOKEN_INVALID_MESSAGE);
        }
        return token;
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

}
