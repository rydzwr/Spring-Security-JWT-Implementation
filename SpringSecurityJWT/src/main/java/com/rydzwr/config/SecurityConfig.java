package com.rydzwr.config;

import com.rydzwr.DBService.UserService;
import com.rydzwr.constants.SecurityConstants;
import com.rydzwr.filter.*;
import com.rydzwr.repository.AppUserRepository;
import com.rydzwr.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


import static com.rydzwr.constants.SecurityConstants.*;
import static java.util.Arrays.asList;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JWTService jwtService;

    @Autowired
    private UserService service;

    @Autowired
    private AppUserRepository repository;

    @Autowired
    private TokenBlackList tokenBlackList;

    @Autowired
    private CookieManager cookieManager;

    @Autowired
    private AuthHeaderDataExtractor extractor;

    @Autowired
    private FilterErrorHandler errorHandler;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors()
                .configurationSource(corsConfigurationSource())
                .and()
                .csrf()
                .disable().headers().frameOptions().sameOrigin();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.authorizeHttpRequests().requestMatchers(
                LOGIN_ENDPOINT,
                TOKEN_REFRESH_ENDPOINT,
                REGISTER_ENDPOINT
        ).permitAll();

        http.authorizeHttpRequests().anyRequest().authenticated();

        http.addFilterBefore(
                new RequestValidationBeforeFilter(extractor),
                BasicAuthenticationFilter.class
        );

        http.addFilterBefore(
                new AuthorizationFilter(jwtService, tokenBlackList, errorHandler),
                BasicAuthenticationFilter.class
        );

        http.addFilterAfter(
                new AuthenticationFilter(jwtService, service, repository, cookieManager),
                BasicAuthenticationFilter.class
        );

        http.addFilterBefore(
                new LogoutFilter(jwtService, tokenBlackList, repository, cookieManager),
                BasicAuthenticationFilter.class
        );
        http.addFilterBefore(
                new JWTTokenRefreshFilter(repository, jwtService, cookieManager, tokenBlackList, errorHandler),
                BasicAuthenticationFilter.class
        );

        http.httpBasic();

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(asList(SecurityConstants.ANGULAR_LOCALHOST_PATH, SecurityConstants.ANGULAR_IP_PATH));
        configuration.setAllowCredentials(true);
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
