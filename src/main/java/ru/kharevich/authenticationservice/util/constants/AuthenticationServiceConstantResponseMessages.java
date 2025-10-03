package ru.kharevich.authenticationservice.util.constants;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class AuthenticationServiceConstantResponseMessages {

    public static final String USER_NOT_FOUND_BY_USERNAME = "User with username %s not found";

    public static final String USER_ALREADY_EXISTS_MESSAGE = "User with username %s already exists";

}
