package com.rydzwr.filter;

import com.rydzwr.service.JWTService;
import com.rydzwr.service.TokenBlackList;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class AuthorizationFilter extends OncePerRequestFilter {
    private final JWTService jwtService;

    private final TokenBlackList tokenBlackList;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        boolean validAuth = jwtService.validateAuthHeader(request);

        String token = "";
        if (validAuth) {
            token = jwtService.getTokenFromAuthHeader(request);
        }

        if (!validAuth || tokenBlackList.contains(token)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        SecurityContextHolder.getContext().setAuthentication(jwtService.getAuthFromToken(request));
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        final String pathLogin = "/api/login";
        return request.getServletPath().equals(pathLogin);
    }
}
