package com.rydzwr.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class CookieManager {
    private final String jwt = "jwt";

    public Map<String, Cookie> createCookieMap(HttpServletRequest request) {
        return Arrays.stream(request.getCookies())
                .collect(Collectors.toMap(Cookie::getName, c -> c));
    }

    public void deleteRefreshToken(HttpServletResponse response) {
        Cookie deleteJWT = new Cookie(jwt, null);
        deleteJWT.setMaxAge(0);
        deleteJWT.setHttpOnly(true);
        response.addCookie(deleteJWT);
    }

    public void addRefreshToken(HttpServletResponse response, String refreshToken) {
        Cookie cookie = new Cookie(jwt, refreshToken);
        int ONE_DAY = 1000 * 60 * 60 * 24;
        cookie.setMaxAge(ONE_DAY);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }
}
