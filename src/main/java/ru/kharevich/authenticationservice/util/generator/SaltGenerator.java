package ru.kharevich.authenticationservice.util.generator;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;

@Component
public class SaltGenerator {

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Генерация случайной соли заданной длины
     * @param lengthInBytes длина соли в байтах (рекомендуется 16-32 байта)
     * @return соль в Base64 кодировке
     */
    public String generateSalt(int lengthInBytes) {
        byte[] salt = new byte[lengthInBytes];
        secureRandom.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Генерация соли стандартной длины (16 байт = 128 бит)
     */
    public String generateSalt() {
        return generateSalt(16); // 128 бит
    }

    /**
     * Генерация соли для паролей (рекомендуется 32 байта = 256 бит)
     */
    public String generatePasswordSalt() {
        return generateSalt(32); // 256 бит
    }
}