package ru.kharevich.authenticationservice.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import ru.kharevich.authenticationservice.config.CustomSaltPasswordEncoder;
import ru.kharevich.authenticationservice.service.impl.UserDetailsServiceImpl;

import static ru.kharevich.authenticationservice.util.constants.AuthenticationServiceConstantResponseMessages.INVALID_CREDENTIALS_MESSAGE;

@Component
@RequiredArgsConstructor
public class CustomSaltAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsServiceImpl userDetailsService;

    private final CustomSaltPasswordEncoder customSaltPasswordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {

        String username = authentication.getName();
        String rawPassword = authentication.getCredentials().toString();

        UserDetails user = (UserDetails) userDetailsService.loadUserByUsername(username);
        String encodedPasswordFromDb = user.getPassword();

        if (customSaltPasswordEncoder.matchesWithExtractedSalt(rawPassword, encodedPasswordFromDb)) {
            return new UsernamePasswordAuthenticationToken(
                    user, rawPassword, user.getAuthorities());
        }

        throw new BadCredentialsException(INVALID_CREDENTIALS_MESSAGE);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
