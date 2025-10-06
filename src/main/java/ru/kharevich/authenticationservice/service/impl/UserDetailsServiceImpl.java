package ru.kharevich.authenticationservice.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ru.kharevich.authenticationservice.model.User;
import ru.kharevich.authenticationservice.repository.UserRepository;
import ru.kharevich.authenticationservice.util.validation.AuthenticationValidationService;

import static ru.kharevich.authenticationservice.util.constants.AuthenticationServiceConstantResponseMessages.USER_NOT_FOUND_BY_USERNAME;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    private final AuthenticationValidationService authenticationValidationService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = authenticationValidationService.findByUsernameThrowsExceptionIfDoesntExist(
                username,
                new UsernameNotFoundException(USER_NOT_FOUND_BY_USERNAME.formatted(username)));
        return new ru.kharevich.authenticationservice.security.UserDetails(user);
    }

}
