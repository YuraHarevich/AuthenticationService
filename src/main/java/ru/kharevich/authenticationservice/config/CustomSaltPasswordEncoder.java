package ru.kharevich.authenticationservice.config;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class CustomSaltPasswordEncoder implements PasswordEncoder {

    private final BCryptPasswordEncoder defaultEncoder = new BCryptPasswordEncoder();
    private static final String SALT_SEPARATOR = "::";

    /**
     * Этот метод будет использоваться Spring Security по умолчанию
     * Но в нашем случае мы его НЕ используем для аутентификации
     * Оставлен для совместимости с интерфейсом PasswordEncoder
     */
    @Override
    public String encode(CharSequence rawPassword) {
        String salt = generateSalt();
        return encodeWithSalt(rawPassword, salt);
    }

    /**
     * Этот метод будет использоваться Spring Security по умолчанию
     * Но мы его НЕ используем - вместо этого используем matchesWithCustomSalt
     */
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        // Если пароль закодирован в нашем формате (с разделителем ::)
        if (isEncodedByThisEncoder(encodedPassword)) {
            String salt = extractSalt(encodedPassword);
            String bcryptHash = extractBcryptHash(encodedPassword);
            String saltedPassword = createSaltedPassword(rawPassword, salt);
            return defaultEncoder.matches(saltedPassword, bcryptHash);
        }

        // Fallback: стандартная проверка BCrypt (для обратной совместимости)
        return defaultEncoder.matches(rawPassword, encodedPassword);
    }

    /**
     * Основной метод для регистрации пользователей с указанной солью
     */
    public String encodeWithSalt(CharSequence rawPassword, String salt) {
        String saltedPassword = createSaltedPassword(rawPassword, salt);
        String bcryptHash = defaultEncoder.encode(saltedPassword);

        // Сохраняем в формате: "bcryptHash::salt"
        return bcryptHash + SALT_SEPARATOR + salt;
    }

    /**
     * Основной метод для аутентификации с кастомной солью
     * Используется в кастомном AuthenticationManager
     */
    public boolean matchesWithCustomSalt(CharSequence rawPassword, String encodedPassword, String salt) {
        // Создаем salted пароль и проверяем через BCrypt
        String saltedPassword = createSaltedPassword(rawPassword, salt);
        return defaultEncoder.matches(saltedPassword, encodedPassword);
    }

    /**
     * Альтернативный метод для аутентификации, который сам извлекает соль из encodedPassword
     */
    public boolean matchesWithExtractedSalt(CharSequence rawPassword, String encodedPassword) {
        if (!isEncodedByThisEncoder(encodedPassword)) {
            return false;
        }

        String salt = extractSalt(encodedPassword);
        String bcryptHash = extractBcryptHash(encodedPassword);

        String saltedPassword = createSaltedPassword(rawPassword, salt);
        return defaultEncoder.matches(saltedPassword, bcryptHash);
    }

    /**
     * Безопасное создание salted пароля
     */
    private String createSaltedPassword(CharSequence rawPassword, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String combined = rawPassword + "|" + salt + "|" + rawPassword.length();
            byte[] hash = digest.digest(combined.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            return rawPassword + "{" + salt + "}";
        }
    }

    /**
     * Генерация криптографически безопасной соли
     */
    public String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[32]; // 256 бит
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Генерация соли указанного размера
     */
    public String generateSalt(int bytes) {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[bytes];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Извлечение соли из закодированного пароля
     */
    public String extractSalt(String encodedPassword) {
        if (!isEncodedByThisEncoder(encodedPassword)) {
            return null;
        }
        String[] parts = encodedPassword.split(SALT_SEPARATOR);
        return parts.length >= 2 ? parts[1] : null;
    }

    /**
     * Извлечение BCrypt хеша из закодированного пароля
     */
    public String extractBcryptHash(String encodedPassword) {
        if (!isEncodedByThisEncoder(encodedPassword)) {
            return encodedPassword; // Возвращаем как есть, если это чистый BCrypt
        }
        String[] parts = encodedPassword.split(SALT_SEPARATOR);
        return parts.length >= 1 ? parts[0] : encodedPassword;
    }

    /**
     * Проверка, закодирован ли пароль нашим энкодером
     */
    public boolean isEncodedByThisEncoder(String encodedPassword) {
        return encodedPassword != null && encodedPassword.contains(SALT_SEPARATOR);
    }

    /**
     * Конвертация старого BCrypt пароля в наш формат
     */
    public String migrateToSaltedFormat(String oldEncodedPassword, String salt) {
        if (isEncodedByThisEncoder(oldEncodedPassword)) {
            return oldEncodedPassword;
        }
        return oldEncodedPassword + SALT_SEPARATOR + salt;
    }

    /**
     * Получение только BCrypt части (для обратной совместимости)
     */
    public String getBcryptPart(String encodedPassword) {
        return extractBcryptHash(encodedPassword);
    }
}