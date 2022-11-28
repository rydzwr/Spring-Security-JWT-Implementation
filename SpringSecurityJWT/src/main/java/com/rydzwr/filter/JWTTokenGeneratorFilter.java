package com.rydzwr.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rydzwr.constants.SecurityConstants;
import com.rydzwr.model.AppUser;
import com.rydzwr.repository.AppUserRepository;
import com.rydzwr.service.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@Slf4j
@RequiredArgsConstructor
public class JWTTokenGeneratorFilter extends OncePerRequestFilter {

    private final JWTService jwtService;
    private final AppUserRepository repository;
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
        tokens.put("role", authentication.getAuthorities().toArray()[0].toString());

        // CREATING HTTP COOKIE WITH REFRESH TOKEN
        Cookie cookie = new Cookie("jwt", refreshToken);
        cookie.setMaxAge(1000 * 60 * 60 * 24);
        cookie.setHttpOnly(true);

        // SENDING RESPONSE
        response.addCookie(cookie);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
        response.setStatus(200);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getServletPath().equals("/api/login");
    }
}
