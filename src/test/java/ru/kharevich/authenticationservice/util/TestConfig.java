package ru.kharevich.authenticationservice.util;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import ru.kharevich.authenticationservice.util.generator.SaltGenerator;

@TestConfiguration
class TestConfig {

    @Bean
    public SaltGenerator saltGenerator() {
        return new SaltGenerator() {
            @Override
            public String generateSalt() {
                return "test-salt";
            }

            @Override
            public String generateSalt(int bytes) {
                return "test-salt-" + bytes;
            }
        };
    }
}