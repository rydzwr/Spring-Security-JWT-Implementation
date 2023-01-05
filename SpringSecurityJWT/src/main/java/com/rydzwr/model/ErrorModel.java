package com.rydzwr.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@AllArgsConstructor
public class ErrorModel {

    private HttpStatus httpStatus;

    private LocalDateTime timestamp;

    private String message;

    private Map<String, String> errors;
}
