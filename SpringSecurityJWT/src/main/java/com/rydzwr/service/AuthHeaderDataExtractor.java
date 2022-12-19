package com.rydzwr.service;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
@Component
public class AuthHeaderDataExtractor {
    public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";
    private final Charset credentialsCharset = StandardCharsets.UTF_8;
    public String extract(ServletRequest request) {
        HttpServletRequest req = (HttpServletRequest) request;

        String token = null;

        final String invalidBasicAuth = "Invalid basic authentication token";
        final String failedToDecode = "Failed to decode basic authentication token";

        String header = req.getHeader(AUTHORIZATION);
        if (header != null) {
            header = header.trim();

            if (StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BASIC)) {
                byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
                byte[] decoded;

                log.info("HEADER: -->> {}", header);

                try {
                    decoded = Base64.getDecoder().decode(base64Token);
                    token = new String(decoded, credentialsCharset);
                    log.info("TOKEN: -->> {}", token);
                    int delim = token.indexOf(":");

                    if (delim == -1) {
                        throw new BadCredentialsException(invalidBasicAuth);
                    }
                } catch (IllegalArgumentException e) {
                    throw new BadCredentialsException(failedToDecode);
                }
            }
        }
        return token;
    }
}
