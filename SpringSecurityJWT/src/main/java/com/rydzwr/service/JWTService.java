package com.rydzwr.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.rydzwr.constants.SecurityConstants;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;


import java.util.*;

@Service
public class JWTService {
    private final Algorithm algorithm = Algorithm.HMAC256(SecurityConstants.JWT_KEY.getBytes());
    public String generateAccessToken(HttpServletRequest request, Authentication authentication) {
        return JWT.create()
                .withSubject(authentication.getName())
                .withExpiresAt(new Date(System.currentTimeMillis() + 50000))
                .withIssuer(request.getRequestURI())
                .withClaim("authorities", populateAuthorities(authentication.getAuthorities()))
                .sign(algorithm);
    }

    public String generateRefreshToken(HttpServletRequest request, Authentication authentication) {
        return JWT.create()
                .withSubject(authentication.getName())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
                .withIssuer(request.getRequestURI())
                .sign(algorithm);
    }

    public boolean validateAuthHeader(HttpServletRequest request) {
        String authHeader = request.getHeader(SecurityConstants.JWT_HEADER);
        return authHeader != null;
    }

    public String getTokenFromAuthHeader(HttpServletRequest request) {
        String authHeader = request.getHeader(SecurityConstants.JWT_HEADER);
        return authHeader.substring("Bearer ".length());
    }

    public String getUserRole(Authentication authentication) {
        return authentication.getAuthorities().toArray()[0].toString();
    }

    public UsernamePasswordAuthenticationToken getAuthFromToken(HttpServletRequest request) {
        try {
            String token = getTokenFromAuthHeader(request);
            Algorithm algorithm = Algorithm.HMAC256(SecurityConstants.JWT_KEY.getBytes());
            JWTVerifier verifier = JWT.require(algorithm).build();

            DecodedJWT decodedJWT = verifier.verify(token);
            String username = decodedJWT.getSubject();
            String authoritiesString = decodedJWT.getClaim("authorities").asString();

            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(authoritiesString));

            return new UsernamePasswordAuthenticationToken(username, null, authorities);

        } catch (Exception e) {
            throw new BadCredentialsException("Invalid Token received!");
        }
    }
    private String populateAuthorities(Collection<? extends GrantedAuthority> collection) {
        Set<String> authoritiesSet = new HashSet<>();
        for (GrantedAuthority authority : collection) {
            authoritiesSet.add(authority.getAuthority());
        }
        return String.join(",", authoritiesSet);
    }
}
