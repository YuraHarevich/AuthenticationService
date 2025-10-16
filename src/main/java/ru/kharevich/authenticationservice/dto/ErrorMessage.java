package ru.kharevich.authenticationservice.dto;

import lombok.Builder;

import java.time.LocalDateTime;

@Builder
public class ErrorMessage {

    private String message;

    private LocalDateTime timestamp;

}
