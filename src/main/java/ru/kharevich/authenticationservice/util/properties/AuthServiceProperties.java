package ru.kharevich.authenticationservice.util.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "auth.jwt")
@Getter
@Setter
public class AuthServiceProperties {

    private long refreshTokenExpiration;

    private String secret;

    private long tokenExpiration;

}
