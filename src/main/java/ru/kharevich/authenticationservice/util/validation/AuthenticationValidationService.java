package ru.kharevich.authenticationservice.util.validation;

import ru.kharevich.authenticationservice.model.User;

public interface AuthenticationValidationService {

    User findByUsernameThrowsExceptionIfDoesntExist(String username, RuntimeException exception);

    void findByUsernameThrowsExceptionIfExists(String username, RuntimeException exception);

}
