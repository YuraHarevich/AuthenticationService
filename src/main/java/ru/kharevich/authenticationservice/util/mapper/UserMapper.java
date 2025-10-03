package ru.kharevich.authenticationservice.util.mapper;

import org.mapstruct.InjectionStrategy;
import org.mapstruct.Mapper;
import org.mapstruct.MappingConstants;
import ru.kharevich.authenticationservice.dto.request.SignUpRequest;
import ru.kharevich.authenticationservice.dto.response.AuthResponse;
import ru.kharevich.authenticationservice.dto.response.SignUpResponse;
import ru.kharevich.authenticationservice.model.User;

@Mapper(
        componentModel = MappingConstants.ComponentModel.SPRING,
        injectionStrategy = InjectionStrategy.CONSTRUCTOR
)
public interface UserMapper {

    User toUser(SignUpRequest userRequest, String password);

    SignUpResponse toResponse(User user);

}
