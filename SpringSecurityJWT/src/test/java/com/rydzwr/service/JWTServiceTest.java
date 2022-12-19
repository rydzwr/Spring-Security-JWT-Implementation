package com.rydzwr.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.rydzwr.constants.SecurityConstants;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.*;

import static java.util.Arrays.asList;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Slf4j
public class JWTServiceTest {
    private final JWTService jwtService = new JWTService();
    private final HttpServletRequest request = mock(HttpServletRequest.class);

    @Test
    @DisplayName("Should Return Valid Access Token")
    public void shouldReturnValidAccessToken() {
        // GIVEN
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("TEST");
        Authentication authentication = new UsernamePasswordAuthenticationToken("TEST", Collections.singleton(authority));
        Algorithm algorithm = Algorithm.HMAC256(SecurityConstants.JWT_KEY.getBytes());

        // WHEN
        String token = jwtService.generateAccessToken(request, authentication);
        assertNotNull(token);

        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(token);

        // THEN
        assertEquals("TEST", decodedJWT.getSubject());
        assertTrue(decodedJWT.getExpiresAt().after(new Date()));
    }

    @Test
    @DisplayName("Should Return Valid Refresh Token")
    public void shouldReturnValidRefreshToken() {
        // GIVEN
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("TEST");
        Authentication authentication = new UsernamePasswordAuthenticationToken("TEST", Collections.singleton(authority));
        Algorithm algorithm = Algorithm.HMAC256(SecurityConstants.JWT_KEY.getBytes());

        // WHEN
        String token = jwtService.generateRefreshToken(request, authentication);
        assertNotNull(token);

        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(token);

        // THEN
        assertEquals("TEST", decodedJWT.getSubject());
        assertTrue(decodedJWT.getExpiresAt().after(new Date()));
    }

    @Test
    @DisplayName("Validate Auth Header With Auth Header ( RETURNS TRUE )")
    public void testValidateAuthHeader_withAuthHeader() {
        when(request.getHeader(SecurityConstants.JWT_HEADER)).thenReturn("some value");
        boolean result = jwtService.validateAuthHeader(request);
        assertTrue(result);
    }

    @Test
    @DisplayName("Validate Auth Header Without Auth Header ( RETURNS FALSE )")
    public void testValidateAuthHeader_withoutAuthHeader() {
        when(request.getHeader(SecurityConstants.JWT_HEADER)).thenReturn(null);
        boolean result = jwtService.validateAuthHeader(request);
        assertFalse(result);
    }

    @Test
    @DisplayName("Should Extract Bearer Value From Header")
    public void testGetTokenFromAuthHeader() {
        when(request.getHeader(SecurityConstants.JWT_HEADER)).thenReturn("Bearer test");
        String token = jwtService.getTokenFromAuthHeader(request);
        assertEquals("test", token);
    }
}
