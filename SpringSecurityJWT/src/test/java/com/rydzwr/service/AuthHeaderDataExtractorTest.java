package com.rydzwr.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;


public class AuthHeaderDataExtractorTest {

    private final AuthHeaderDataExtractor extractor = new AuthHeaderDataExtractor();
    private final HttpServletRequest request = mock(HttpServletRequest.class);

    @Test
    @DisplayName("Should Return Valid Decoded User Data")
    public void shouldReturnValidUserData() {
        // GIVEN
        final String encodedToken = "Basic dXNlcjpwYXNz";
        final String expected = "user:pass";

        // WHEN
        when(request.getHeader(AUTHORIZATION)).thenReturn(encodedToken);
        String token = extractor.extract(request);

        // THEN
        assertEquals(expected, token);
    }

    @Test
    @DisplayName("Should Throw Bad Credentials Exception")
    public void shouldThrowBadCredentialsException() {
        // GIVEN
        final String encodedToken = "Basic dXNlcjpwYXNzd29yZA==";
        final String expected = "Expected BadCredentialsException";

        // WHEN
        when(request.getHeader(AUTHORIZATION)).thenReturn(encodedToken);

        // THEN
        try {
            extractor.extract(request);
        } catch (BadCredentialsException e) {
            assertEquals(expected, e.getMessage());
        }
    }

    @Test
    @DisplayName("Should Throw Failed To Decode Auth Token")
    public void shouldThrowFailedToDecodeAuthToken() {
        final String encodedToken = "Basic !@#$%^&*()";
        when(request.getHeader(AUTHORIZATION)).thenReturn(encodedToken);
        try {
            extractor.extract(request);
        } catch (BadCredentialsException e) {
            assertEquals("Failed to decode basic authentication token", e.getMessage());
        }
    }

    @Test
    @DisplayName("Should Return Null")
    public void shouldReturnNull() {
        when(request.getHeader(AUTHORIZATION)).thenReturn(null);
        String token2 = extractor.extract(request);
        assertNull(token2);
    }
}
