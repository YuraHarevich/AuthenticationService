package ru.kharevich.authenticationservice.controller.handler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import ru.kharevich.authenticationservice.dto.ErrorMessage;
import ru.kharevich.authenticationservice.exceptions.UserNotFoundException;

import java.time.LocalDateTime;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler({
        UserNotFoundException.class
    })
    public ResponseEntity<ErrorMessage> handle(Exception exception) {
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(ErrorMessage.builder()
                        .message(exception.getMessage())
                        .timestamp(LocalDateTime.now())
                        .build());
    }

    @ExceptionHandler({
            MethodArgumentNotValidException.class
    })
    public ResponseEntity<ErrorMessage> handleValidationExceptions(MethodArgumentNotValidException ex) {
        var error = ex.getBindingResult().getAllErrors().getFirst();
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ErrorMessage.builder()
                        .message(error.getDefaultMessage())
                        .timestamp(LocalDateTime.now())
                        .build());
    }

    @ExceptionHandler({
            Exception.class
    })
    public ResponseEntity<ErrorMessage> handleEverything(Exception exception) {
        return ResponseEntity
                .status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(ErrorMessage.builder()
                        .message(exception.getMessage())
                        .timestamp(LocalDateTime.now())
                        .build());
    }

}
