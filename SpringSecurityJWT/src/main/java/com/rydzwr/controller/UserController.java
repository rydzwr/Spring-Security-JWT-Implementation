package com.rydzwr.controller;

import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rydzwr.model.AppUser;
import com.rydzwr.model.UserDataResponse;
import com.rydzwr.repository.AppUserRepository;
import com.rydzwr.service.JWTService;
import com.rydzwr.service.TokenBlackList;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final TokenBlackList tokenBlackList;

    private final AppUserRepository repository;

    private final JWTService jwtService;

    @PreAuthorize("hasAuthority('USER')")
    @GetMapping("/data/user")
    public UserDataResponse user() {
        return new UserDataResponse("user public data");
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/data/admin")
    public UserDataResponse admin() {
        return new UserDataResponse("admin only data");
    }

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie[] cookies = request.getCookies();
        Map<String, Cookie> cookieMap = new HashMap<>();
        for (Cookie cookie : cookies) {
            cookieMap.put(cookie.getName(), cookie);
        }

        if (!cookieMap.containsKey("jwt")) {
            sendError(response, "Token Is Missing");
        }

        try {
            String refreshToken = cookieMap.get("jwt").getValue();
            Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
            AppUser user = repository.findByRefreshToken(refreshToken);

            if (user == null) {
                sendError(response, "Cannot find user");
                return;
            }

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String accessToken = jwtService.generateAccessToken(request, authentication);

            Map<String, String> tokens = new HashMap<>();
            tokens.put("access_token", accessToken);

            response.setContentType(APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(response.getOutputStream(), tokens);

        } catch (Exception e) {
            response.setHeader("error", e.getMessage());
            response.setStatus(FORBIDDEN.value());

            Map<String, String> error = new HashMap<>();
            error.put("error_message", e.getMessage());

            response.setContentType(APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(response.getOutputStream(), error);
        }
    }

    private void sendError(HttpServletResponse response, String message) throws IOException {
        response.setHeader("error", message);
        response.setStatus(UNAUTHORIZED.value());

        Map<String, String> error = new HashMap<>();
        error.put("error_message", message);

        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), error);
    }
}
