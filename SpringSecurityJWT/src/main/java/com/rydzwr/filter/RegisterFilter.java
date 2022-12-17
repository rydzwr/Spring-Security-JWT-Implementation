package com.rydzwr.filter;

import com.rydzwr.model.AppUser;
import com.rydzwr.repository.AppUserRepository;
import com.rydzwr.service.AuthHeaderDataExtractor;
import com.rydzwr.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static jakarta.servlet.http.HttpServletResponse.SC_CREATED;
import static org.springframework.http.HttpStatus.CONFLICT;

@Slf4j
@RequiredArgsConstructor
public class RegisterFilter extends OncePerRequestFilter {
    private final AuthHeaderDataExtractor extractor;
    private final UserService service;
    private final FilterErrorHandler errorHandler;
    private final PasswordEncoder passwordEncoder;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException {
        final String userNameAlreadyInUse = "Given User Name Is Already In Use";
        String userData = extractor.extract(request);

        String[] parts = userData.split(":");
        String userName = parts[0];
        String password = parts[1];

        AppUser newUser = new AppUser(userName, passwordEncoder.encode(password), "USER", null);
        try {
            service.saveUser(newUser);
        } catch (Exception e) {
            errorHandler.sendError(response, CONFLICT, userNameAlreadyInUse);
            return;
        }

        response.setStatus(SC_CREATED);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        final String path = "/api/register";
        return !request.getServletPath().equals(path);
    }
}
