package ru.kharevich.authenticationservice.util.validation;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ru.kharevich.authenticationservice.model.User;
import ru.kharevich.authenticationservice.repository.UserRepository;

import java.util.Optional;

import static ru.kharevich.authenticationservice.util.constants.AuthenticationServiceConstantResponseMessages.USER_ALREADY_EXISTS_MESSAGE;
import static ru.kharevich.authenticationservice.util.constants.AuthenticationServiceConstantResponseMessages.USER_NOT_FOUND_BY_USERNAME;

@Service
@RequiredArgsConstructor
public class AuthenticationValidationServiceImpl implements AuthenticationValidationService {

    private final UserRepository userRepository;

    @Override
    public User findByUsernameThrowsExceptionIfDoesntExist(String username, RuntimeException exception) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> exception);
        return user;
    }

    @Override
    public void findByUsernameThrowsExceptionIfExists(String username, RuntimeException exception) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isPresent()) {
            throw new IllegalStateException(USER_ALREADY_EXISTS_MESSAGE);
        }
    }
}
