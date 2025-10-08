package ru.kharevich.authenticationservice.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import ru.kharevich.authenticationservice.dto.ErrorMessage;

import java.io.IOException;
import java.time.LocalDateTime;

import static ru.kharevich.authenticationservice.util.constants.AuthenticationServiceConstantResponseMessages.UNAUTHORIZED_MESSAGE;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final HttpMessageConverter<Object> jsonMessageConverter;

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        ErrorMessage errorMessage = ErrorMessage.builder()
                .message(UNAUTHORIZED_MESSAGE)
                .timestamp(LocalDateTime.now())
                .build();
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        HttpOutputMessage outputMessage = new ServletServerHttpResponse(response);
        jsonMessageConverter.write(errorMessage, MediaType.APPLICATION_JSON, outputMessage);
    }
}
