package com.rydzwr.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@Component
public class FilterErrorHandler {

    public void sendError(HttpServletResponse response, HttpStatus status, String message) throws IOException {
        response.setHeader("error", message);
        response.setStatus(status.value());

        Map<String, String> error = new HashMap<>();
        error.put("error_message", message);

        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), error);
    }
}
