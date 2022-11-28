package com.rydzwr.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class CookieManager {
    public Map<String, Cookie> createCookieMap(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        Map<String, Cookie> cookieMap = new HashMap<>();
        for (Cookie cookie : cookies) {
            cookieMap.put(cookie.getName(), cookie);
        }
        return cookieMap;
    }

    public void deleteRefreshToken(HttpServletResponse response) {
        Cookie deleteJWT = new Cookie("jwt", null);
        deleteJWT.setMaxAge(0);
        deleteJWT.setHttpOnly(true);
        response.addCookie(deleteJWT);
    }

    public void addRefreshToken(HttpServletResponse response, String refreshToken) {
        Cookie cookie = new Cookie("jwt", refreshToken);
        cookie.setMaxAge(1000 * 60 * 60 * 24);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }
}
