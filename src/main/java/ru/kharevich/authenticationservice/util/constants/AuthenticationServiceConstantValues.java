package ru.kharevich.authenticationservice.util.constants;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.List;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class AuthenticationServiceConstantValues {

    public static final List<String> DEFAULT_USER_ROLE = List.of("ROLE_USER");

}
