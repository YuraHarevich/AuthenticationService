package ru.kharevich.authenticationservice.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import ru.kharevich.authenticationservice.dto.ErrorMessage;

import java.io.IOException;
import java.time.LocalDateTime;

import static ru.kharevich.authenticationservice.util.constants.AuthenticationServiceConstantResponseMessages.NOT_ENOUGH_RIGHTS_MESSAGE;

@Component
@RequiredArgsConstructor
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    private final HttpMessageConverter<Object> jsonMessageConverter;

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException exception) throws IOException {

        ErrorMessage errorMessage = ErrorMessage.builder()
                .message(NOT_ENOUGH_RIGHTS_MESSAGE)
                .timestamp(LocalDateTime.now())
                .build();

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        HttpOutputMessage outputMessage = new ServletServerHttpResponse(response);
        jsonMessageConverter.write(errorMessage, MediaType.APPLICATION_JSON, outputMessage);
    }

}
