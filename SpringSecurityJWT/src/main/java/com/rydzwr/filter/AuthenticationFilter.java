package com.rydzwr.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rydzwr.model.AppUser;
import com.rydzwr.repository.AppUserRepository;
import com.rydzwr.service.CookieManager;
import com.rydzwr.service.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@Slf4j
@RequiredArgsConstructor
public class AuthenticationFilter extends OncePerRequestFilter {
    private final JWTService jwtService;
    private final AppUserRepository repository;
    private final CookieManager cookieManager;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // CREATING TOKENS
        String accessToken = jwtService.generateAccessToken(request, authentication);
        String refreshToken = jwtService.generateRefreshToken(request, authentication);

        // SAVING REFRESH TOKEN INTO DATABASE
        AppUser user = repository.findByName(authentication.getName());
        user.setRefreshToken(refreshToken);
        repository.save(user);

        // CREATING JSON MAP
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("role", jwtService.getUserRole(authentication));

        // CREATING HTTP COOKIE WITH REFRESH TOKEN
        cookieManager.addRefreshToken(response, refreshToken);

        // SENDING RESPONSE
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
        response.setStatus(200);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        final String pathLogin = "/api/login";
        return !request.getServletPath().equals(pathLogin);
    }
}
