package com.rydzwr.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rydzwr.model.AppUser;
import com.rydzwr.repository.AppUserRepository;
import com.rydzwr.service.CookieManager;
import com.rydzwr.service.JWTService;
import com.rydzwr.service.TokenBlackList;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpStatus.*;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

@RequiredArgsConstructor
public class JWTTokenRefreshFilter extends OncePerRequestFilter {
    private final AppUserRepository repository;
    private final JWTService jwtService;

    private final CookieManager cookieManager;

    private final TokenBlackList tokenBlackList;

    private final FilterErrorHandler errorHandler;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException {

        final String tokenIsMissing = "Token Is Missing";
        final String invalidRefreshToken = "Invalid Refresh Token";
        final String couldNotGenerateRefreshToken = "Couldn't Generate Refresh Token";
        final String jwt = "jwt";

        // CREATING MAP OF COOKIES
        Map<String, Cookie> cookieMap = cookieManager.createCookieMap(request);

        // IF MAP DOESN'T CONTAIN JWT, SENDING UNAUTHORIZED
        if (!cookieMap.containsKey(jwt)) {
            errorHandler.sendError(response, UNAUTHORIZED, tokenIsMissing);
            return;
        }

        // ADDING OLD ACCESS TOKEN TO BLACK LIST
        String token = jwtService.getTokenFromAuthHeader(request);
        tokenBlackList.add(token);

        try {
            // FINDING USER BY REFRESH TOKEN IN DATABASE
            String refreshToken = cookieMap.get(jwt).getValue();
            AppUser user = repository.findByRefreshToken(refreshToken);

            // IF USER WITH GIVEN TOKEN DOESN'T EXIST, MEANS TOKEN IS INVALID
            if (user == null) {
                errorHandler.sendError(response, FORBIDDEN, invalidRefreshToken);
                return;
            }

            // GENERATING NEW ACCESS TOKEN
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String accessToken = jwtService.generateAccessToken(request, authentication);

            // CREATING AN OUTPUT JSON MAP
            Map<String, String> tokens = new HashMap<>();
            tokens.put("access_token", accessToken);

            // SENDING SUCCESSFUL RESPONSE
            response.setContentType(APPLICATION_JSON_VALUE);
            response.setStatus(CREATED.value());
            new ObjectMapper().writeValue(response.getOutputStream(), tokens);

        } catch (Exception e) {
            // IF SOMETHING WENT WRONG DURING GENERATING NEW TOKEN SENDING SERVER ERROR
            errorHandler.sendError(response, INTERNAL_SERVER_ERROR, couldNotGenerateRefreshToken);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        final String path = "/api/token/refresh";
        return !request.getServletPath().equals(path);
    }
}
