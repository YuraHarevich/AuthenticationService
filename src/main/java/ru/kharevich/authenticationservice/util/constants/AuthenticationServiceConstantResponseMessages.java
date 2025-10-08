package ru.kharevich.authenticationservice.util.constants;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class AuthenticationServiceConstantResponseMessages {

    public static final String USER_NOT_FOUND_BY_USERNAME = "User with username %s not found";

    public static final String USER_ALREADY_EXISTS_MESSAGE = "User with username %s already exists";

    public static final String INVALID_CREDENTIALS_MESSAGE = "Invalid username or password";

    public static final String REFRESH_TOKEN_INVALID_MESSAGE = "Refresh token is not in database or expired";

    public static final String SIGN_IN_PROCESS_FAILED = "Unable to create new user with username %s";

    public static final String NOT_ENOUGH_RIGHTS_MESSAGE = "You dont have enough rights to access this source";

    public static final String UNAUTHORIZED_MESSAGE = "Unauthorized";


}
