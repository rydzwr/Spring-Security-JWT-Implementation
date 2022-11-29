package com.rydzwr.filter;

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
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class LogoutFilter extends OncePerRequestFilter {

    private final JWTService jwtService;
    private final TokenBlackList tokenBlackList;
    private final AppUserRepository repository;
    private final CookieManager cookieManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        final String jwt = "jwt";

        // CREATING MAP OF COOKIES
        Map<String, Cookie> cookieMap = cookieManager.createCookieMap(request);

        // IF MAP !CONTAINS REFRESH TOKEN JUST SENDING 204 SUCCESSFUL WITHOUT ANY OPERATIONS
        if (!cookieMap.containsKey(jwt)) {
            response.setStatus(204);
            return;
        }

        // REPLACING REFRESH TOKEN WITH EMPTY COOKIE
        cookieManager.deleteRefreshToken(response);

        // ADDING ACCESS TOKEN TO BLACKLIST TO AVOID OPERATIONS AFTER LOGOUT
        String token = jwtService.getTokenFromAuthHeader(request);
        tokenBlackList.add(token);

        // FINDING USER IN DB BY REFRESH TOKEN
        // IF USER DOESN'T EXIST JUST SENDING 204 SUCCESSFUL
        AppUser user = repository.findByRefreshToken(cookieMap.get(jwt).getValue());
        if (user == null) {
            response.setStatus(204);
            return;
        }

        // SETTING USER'S REFRESH TOKEN TO NULL IN DATABASE
        user.setRefreshToken(null);
        repository.save(user);

        // SENDING SUCCESSFUL RESPONSE
        response.setStatus(204);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        final String path = "/api/logout";
        return !request.getServletPath().equals(path);
    }
}