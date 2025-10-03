package ru.kharevich.authenticationservice.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class ErrorMessage {

    private String message;

    private LocalDateTime timestamp;

}
