package ru.kharevich.authenticationservice.service.impl;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import ru.kharevich.authenticationservice.config.CustomSaltPasswordEncoder;
import ru.kharevich.authenticationservice.dto.request.SignInRequest;
import ru.kharevich.authenticationservice.dto.request.SignUpRequest;
import ru.kharevich.authenticationservice.dto.request.RefreshTokenRequest;
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
import ru.kharevich.authenticationservice.util.generator.SaltGenerator;
import ru.kharevich.authenticationservice.util.mapper.UserMapper;
import ru.kharevich.authenticationservice.util.properties.AuthServiceProperties;
import ru.kharevich.authenticationservice.util.validation.AuthenticationValidationService;


import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static ru.kharevich.authenticationservice.util.constants.AuthenticationServiceConstantResponseMessages.REFRESH_TOKEN_INVALID_MESSAGE;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceImplTest {

    @Mock
    private AuthServiceProperties authServiceProperties;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserRepository userRepository;

    @Mock
    private CustomSaltPasswordEncoder encoder;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private UserMapper userMapper;

    @Mock
    private AuthenticationValidationService authenticationValidationService;

    @Mock
    private SaltGenerator saltGenerator;

    @InjectMocks
    private AuthenticationServiceImpl authenticationService;

    private final UUID TEST_USER_ID = UUID.randomUUID();
    private final String TEST_USERNAME = "testuser";
    private final String TEST_EMAIL = "test@example.com";
    private final String TEST_PASSWORD = "password123";
    private final String TEST_SALT = "test-salt";
    private final String TEST_ACCESS_TOKEN = "test-access-token";
    private final String TEST_REFRESH_TOKEN = "test-refresh-token";
    private final String ENCODED_PASSWORD = "encoded-password";

    // Test Data
    private SignUpRequest createSignUpRequest() {
        return new SignUpRequest(
                TEST_USERNAME,
                TEST_EMAIL,
                TEST_PASSWORD,
                "John",
                "Doe",
                LocalDateTime.now().minusYears(20)
        );
    }

    private SignInRequest createSignInRequest() {
        return new SignInRequest(TEST_USERNAME, TEST_PASSWORD);
    }

    private User createUser() {
        User user = new User();
        user.setId(TEST_USER_ID);
        user.setUsername(TEST_USERNAME);
        user.setEmail(TEST_EMAIL);
        user.setPassword(ENCODED_PASSWORD);
        user.setSalt(TEST_SALT);
        return user;
    }

    private RefreshToken createRefreshToken(User user, boolean expired) {
        Instant expiryDate = expired ?
                Instant.now().minusSeconds(3600) :
                Instant.now().plusSeconds(3600);

        return RefreshToken.builder()
                .id(1L)
                .token(TEST_REFRESH_TOKEN)
                .expiryDate(expiryDate)
                .user(user)
                .build();
    }

    // Tests for signUp method
    @Test
    void signUp_ShouldSuccessfullyCreateUser() {
        // Given
        SignUpRequest request = createSignUpRequest();
        User user = createUser();
        SignUpResponse expectedResponse = new SignUpResponse(
                TEST_USERNAME, TEST_EMAIL, "John", "Doe", request.birthDate()
        );

        when(saltGenerator.generateSalt()).thenReturn(TEST_SALT);
        when(encoder.encodeWithSalt(eq(TEST_PASSWORD), eq(TEST_SALT))).thenReturn(ENCODED_PASSWORD);
        when(userMapper.toUser(eq(request), eq(ENCODED_PASSWORD), eq(TEST_SALT))).thenReturn(user);
        when(userRepository.save(eq(user))).thenReturn(user);
        when(userMapper.toResponse(eq(user))).thenReturn(expectedResponse);

        doNothing().when(authenticationValidationService)
                .findByUsernameThrowsExceptionIfExists(eq(TEST_USERNAME), any(IllegalStateException.class));

        // When
        SignUpResponse result = authenticationService.signUp(request);

        // Then
        assertNotNull(result);
        assertEquals(TEST_USERNAME, result.username());
        assertEquals(TEST_EMAIL, result.email());

        verify(authenticationValidationService).findByUsernameThrowsExceptionIfExists(
                eq(TEST_USERNAME), any(IllegalStateException.class));
        verify(saltGenerator).generateSalt();
        verify(encoder).encodeWithSalt(eq(TEST_PASSWORD), eq(TEST_SALT));
        verify(userMapper).toUser(eq(request), eq(ENCODED_PASSWORD), eq(TEST_SALT));
        verify(userRepository).save(eq(user));
        verify(userMapper).toResponse(eq(user));
    }

    @Test
    void signUp_ShouldThrowExceptionWhenUserAlreadyExists() {
        // Given
        SignUpRequest request = createSignUpRequest();

        doThrow(new IllegalStateException("User already exists"))
                .when(authenticationValidationService)
                .findByUsernameThrowsExceptionIfExists(eq(TEST_USERNAME), any(IllegalStateException.class));

        // When & Then
        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> authenticationService.signUp(request)
        );

        assertEquals("User already exists", exception.getMessage());
        verify(authenticationValidationService).findByUsernameThrowsExceptionIfExists(
                eq(TEST_USERNAME), any(IllegalStateException.class));
        verifyNoInteractions(saltGenerator, encoder, userMapper, userRepository);
    }

    // Tests for signIn method
    @Test
    void signIn_ShouldSuccessfullyAuthenticateUser() {
        // Given
        SignInRequest request = createSignInRequest();
        User user = createUser();
        UserDetails userDetails = new UserDetails(user);
        RefreshToken refreshToken = createRefreshToken(user, false);

        Authentication authentication = mock(Authentication.class);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authenticationValidationService.findByUsernameThrowsExceptionIfDoesntExist(
                eq(TEST_USERNAME), any(IllegalStateException.class)))
                .thenReturn(user);
        when(jwtTokenProvider.generateAccessToken(any(UserDetails.class))).thenReturn(TEST_ACCESS_TOKEN);

        // Mock the internal createRefreshToken call
        AuthenticationServiceImpl spyService = spy(authenticationService);
        doReturn(refreshToken).when(spyService).createRefreshToken(eq(TEST_USERNAME));

        // When
        AuthResponse result = spyService.signIn(request);

        // Then
        assertNotNull(result);
        assertEquals(TEST_ACCESS_TOKEN, result.accessToken());
        assertEquals(TEST_REFRESH_TOKEN, result.refreshToken());
        assertEquals(TEST_USER_ID, result.userId());
        assertEquals(TEST_USERNAME, result.username());

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(authenticationValidationService).findByUsernameThrowsExceptionIfDoesntExist(
                eq(TEST_USERNAME), any(IllegalStateException.class));
        verify(jwtTokenProvider).generateAccessToken(any(UserDetails.class));
        verify(spyService).createRefreshToken(eq(TEST_USERNAME));
    }

    @Test
    void signIn_ShouldThrowExceptionWhenAuthenticationFails() {
        // Given
        SignInRequest request = createSignInRequest();

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        // When & Then
        BadCredentialsException exception = assertThrows(
                BadCredentialsException.class,
                () -> authenticationService.signIn(request)
        );

        assertEquals("Invalid credentials", exception.getMessage());
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verifyNoInteractions(authenticationValidationService, jwtTokenProvider);
    }

    @Test
    void signIn_ShouldThrowExceptionWhenUserNotFound() {
        // Given
        SignInRequest request = createSignInRequest();
        Authentication authentication = mock(Authentication.class);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authenticationValidationService.findByUsernameThrowsExceptionIfDoesntExist(
                eq(TEST_USERNAME), any(IllegalStateException.class)))
                .thenThrow(new IllegalStateException("User not found"));

        // When & Then
        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> authenticationService.signIn(request)
        );

        assertEquals("User not found", exception.getMessage());
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(authenticationValidationService).findByUsernameThrowsExceptionIfDoesntExist(
                eq(TEST_USERNAME), any(IllegalStateException.class));
        verifyNoInteractions(jwtTokenProvider);
    }

    // Tests for validateToken method
    @Test
    void validateToken_ShouldReturnValidResponseWhenTokenIsValid() {
        // Given
        when(jwtTokenProvider.validateToken(eq(TEST_ACCESS_TOKEN))).thenReturn(true);
        when(jwtTokenProvider.getUsernameFromToken(eq(TEST_ACCESS_TOKEN))).thenReturn(TEST_EMAIL);

        // When
        TokenValidationResponse result = authenticationService.validateToken(TEST_ACCESS_TOKEN);

        // Then
        assertNotNull(result);
        assertTrue(result.valid());
        assertEquals(TEST_EMAIL, result.username());

        verify(jwtTokenProvider).validateToken(eq(TEST_ACCESS_TOKEN));
        verify(jwtTokenProvider).getUsernameFromToken(eq(TEST_ACCESS_TOKEN));
    }

    @Test
    void validateToken_ShouldReturnInvalidResponseWhenTokenIsInvalid() {
        // Given
        when(jwtTokenProvider.validateToken(eq(TEST_ACCESS_TOKEN))).thenReturn(false);

        // When
        TokenValidationResponse result = authenticationService.validateToken(TEST_ACCESS_TOKEN);

        // Then
        assertNotNull(result);
        assertFalse(result.valid());
        assertNull(result.username());

        verify(jwtTokenProvider).validateToken(eq(TEST_ACCESS_TOKEN));
        verify(jwtTokenProvider, never()).getUsernameFromToken(anyString());
    }

    // Tests for getRefreshToken method
    @Test
    void getRefreshToken_ShouldSuccessfullyRefreshToken() {
        // Given
        RefreshTokenRequest request = new RefreshTokenRequest(TEST_REFRESH_TOKEN);
        User user = createUser();
        RefreshToken refreshToken = createRefreshToken(user, false);
        UserDetails userDetails = new UserDetails(user);

        when(refreshTokenRepository.findByToken(eq(TEST_REFRESH_TOKEN)))
                .thenReturn(Optional.of(refreshToken));

        // Mock internal verifyExpiration call
        AuthenticationServiceImpl spyService = spy(authenticationService);
        doReturn(refreshToken).when(spyService).verifyExpiration(eq(refreshToken));

        when(jwtTokenProvider.generateAccessToken(any(UserDetails.class))).thenReturn(TEST_ACCESS_TOKEN);

        // When
        AuthResponse result = spyService.getRefreshToken(request);

        // Then
        assertNotNull(result);
        assertEquals(TEST_ACCESS_TOKEN, result.accessToken());
        assertEquals(TEST_REFRESH_TOKEN, result.refreshToken());
        assertEquals(TEST_USER_ID, result.userId());
        assertEquals(TEST_USERNAME, result.username());

        verify(refreshTokenRepository).findByToken(eq(TEST_REFRESH_TOKEN));
        verify(spyService).verifyExpiration(eq(refreshToken));
        verify(jwtTokenProvider).generateAccessToken(any(UserDetails.class));
    }

    @Test
    void getRefreshToken_ShouldThrowExceptionWhenTokenNotFound() {
        // Given
        RefreshTokenRequest request = new RefreshTokenRequest(TEST_REFRESH_TOKEN);

        when(refreshTokenRepository.findByToken(eq(TEST_REFRESH_TOKEN)))
                .thenReturn(Optional.empty());

        // When & Then
        RefreshTokenException exception = assertThrows(
                RefreshTokenException.class,
                () -> authenticationService.getRefreshToken(request)
        );

        assertEquals(REFRESH_TOKEN_INVALID_MESSAGE, exception.getMessage());
        verify(refreshTokenRepository).findByToken(eq(TEST_REFRESH_TOKEN));
        // Не проверяем verifyExpiration, так как он не вызывается при отсутствии токена
        verifyNoInteractions(jwtTokenProvider);
    }

    @Test
    void getRefreshToken_ShouldThrowExceptionWhenTokenExpired() {
        // Given
        RefreshTokenRequest request = new RefreshTokenRequest(TEST_REFRESH_TOKEN);
        User user = createUser();
        RefreshToken refreshToken = createRefreshToken(user, true);

        when(refreshTokenRepository.findByToken(eq(TEST_REFRESH_TOKEN)))
                .thenReturn(Optional.of(refreshToken));

        // Mock internal verifyExpiration to throw exception
        AuthenticationServiceImpl spyService = spy(authenticationService);
        doThrow(new RefreshTokenException("Refresh token is invalid"))
                .when(spyService).verifyExpiration(eq(refreshToken));

        // When & Then
        RefreshTokenException exception = assertThrows(
                RefreshTokenException.class,
                () -> spyService.getRefreshToken(request)
        );

        assertEquals("Refresh token is invalid", exception.getMessage());
        verify(refreshTokenRepository).findByToken(eq(TEST_REFRESH_TOKEN));
        verify(spyService).verifyExpiration(eq(refreshToken));
        verifyNoInteractions(jwtTokenProvider);
    }

    // Tests for createRefreshToken method
    @Test
    void createRefreshToken_ShouldSuccessfullyCreateRefreshToken() {
        // Given
        User user = createUser();
        long refreshTokenExpiration = 86400000L; // 24 hours

        when(userRepository.findByUsername(eq(TEST_USERNAME))).thenReturn(Optional.of(user));
        when(authServiceProperties.getRefreshTokenExpiration()).thenReturn(refreshTokenExpiration);
        when(jwtTokenProvider.generateRefreshToken(any(UserDetails.class))).thenReturn(TEST_REFRESH_TOKEN);
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> {
            RefreshToken token = invocation.getArgument(0);
            token.setId(1L);
            return token;
        });

        // When
        RefreshToken result = authenticationService.createRefreshToken(TEST_USERNAME);

        // Then
        assertNotNull(result);
        assertEquals(TEST_REFRESH_TOKEN, result.getToken());
        assertEquals(user, result.getUser());
        assertTrue(result.getExpiryDate().isAfter(Instant.now()));

        verify(userRepository).findByUsername(eq(TEST_USERNAME));
        verify(refreshTokenRepository).deleteByUser(eq(user));
        verify(authServiceProperties).getRefreshTokenExpiration();
        verify(jwtTokenProvider).generateRefreshToken(any(UserDetails.class));
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    void createRefreshToken_ShouldThrowExceptionWhenUserNotFound() {
        // Given
        when(userRepository.findByUsername(eq(TEST_USERNAME))).thenReturn(Optional.empty());

        // When & Then
        assertThrows(
                org.springframework.security.core.userdetails.UsernameNotFoundException.class,
                () -> authenticationService.createRefreshToken(TEST_USERNAME)
        );

        verify(userRepository).findByUsername(eq(TEST_USERNAME));
        verifyNoInteractions(refreshTokenRepository, jwtTokenProvider);
    }

    // Tests for verifyExpiration method
    @Test
    void verifyExpiration_ShouldReturnTokenWhenNotExpired() {
        // Given
        User user = createUser();
        RefreshToken refreshToken = createRefreshToken(user, false);

        // When
        RefreshToken result = authenticationService.verifyExpiration(refreshToken);

        // Then
        assertNotNull(result);
        assertEquals(refreshToken, result);
        verify(refreshTokenRepository, never()).delete(any(RefreshToken.class));
    }

    @Test
    void verifyExpiration_ShouldThrowExceptionAndDeleteWhenTokenExpired() {
        // Given
        User user = createUser();
        RefreshToken refreshToken = createRefreshToken(user, true);

        // When & Then
        RefreshTokenException exception = assertThrows(
                RefreshTokenException.class,
                () -> authenticationService.verifyExpiration(refreshToken)
        );

        assertEquals(REFRESH_TOKEN_INVALID_MESSAGE, exception.getMessage());
        verify(refreshTokenRepository).delete(eq(refreshToken));
    }

    // Tests for findByToken method
    @Test
    void findByToken_ShouldReturnTokenWhenExists() {
        // Given
        User user = createUser();
        RefreshToken expectedToken = createRefreshToken(user, false);

        when(refreshTokenRepository.findByToken(eq(TEST_REFRESH_TOKEN)))
                .thenReturn(Optional.of(expectedToken));

        // When
        Optional<RefreshToken> result = authenticationService.findByToken(TEST_REFRESH_TOKEN);

        // Then
        assertTrue(result.isPresent());
        assertEquals(expectedToken, result.get());
        verify(refreshTokenRepository).findByToken(eq(TEST_REFRESH_TOKEN));
    }

    @Test
    void findByToken_ShouldReturnEmptyWhenTokenNotFound() {
        // Given
        when(refreshTokenRepository.findByToken(eq(TEST_REFRESH_TOKEN)))
                .thenReturn(Optional.empty());

        // When
        Optional<RefreshToken> result = authenticationService.findByToken(TEST_REFRESH_TOKEN);

        // Then
        assertTrue(result.isEmpty());
        verify(refreshTokenRepository).findByToken(eq(TEST_REFRESH_TOKEN));
    }
}