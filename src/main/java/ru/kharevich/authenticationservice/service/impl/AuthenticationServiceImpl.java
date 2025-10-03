package ru.kharevich.authenticationservice.service.impl;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
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

import java.time.Instant;
import java.util.Optional;

import static ru.kharevich.authenticationservice.util.constants.AuthenticationServiceConstantResponseMessages.USER_NOT_FOUND_BY_USERNAME;

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

    public SignUpResponse signUp(SignUpRequest request) {

        if (userRepository.findByUsername(request.username()).isPresent()) {
            throw new IllegalStateException("Login is already taken");
        }
        User user = userMapper.toUser(request, encoder.encode(request.password()));
        User savedUser = userRepository.save(user);
        return userMapper.toResponse(savedUser);
    }

    public AuthResponse signIn(SignInRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username(), request.password())
            );
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("Invalid email or password");
        }

        User user = userRepository.findByUsername(request.username())
                .orElseThrow(
                        () -> new UsernameNotFoundException(USER_NOT_FOUND_BY_USERNAME.formatted(request.username()))
                );

        UserDetails userDetails = new UserDetails(user);
        String accessToken = jwtTokenProvider.generateAccessToken(userDetails);
        RefreshToken refreshToken = createRefreshToken(request.username());

        return new AuthResponse(accessToken, refreshToken.getToken(), "Bearer", userDetails.getId(), userDetails.getUsername());
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

                    return new AuthResponse(newAccessToken, request.refreshToken(), "Bearer", user.getId(), user.getUsername());
                })
                .orElseThrow(
                        () -> new RefreshTokenException("Refresh token is not in database or expired")
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
            throw new RefreshTokenException("Refresh token expired " + token.getToken());
        }
        return token;
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

}
