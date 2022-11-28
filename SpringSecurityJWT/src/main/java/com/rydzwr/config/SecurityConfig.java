package com.rydzwr.config;

import com.rydzwr.filter.*;
import com.rydzwr.repository.AppUserRepository;
import com.rydzwr.service.CookieManager;
import com.rydzwr.service.JWTService;
import com.rydzwr.service.TokenBlackList;
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

import static java.util.Arrays.asList;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JWTService jwtService;

    @Autowired
    private AppUserRepository repository;

    @Autowired
    public TokenBlackList tokenBlackList;

    @Autowired
    public CookieManager cookieManager;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors()
                .configurationSource(corsConfigurationSource())
                .and()
                .csrf()
                .disable().headers().frameOptions().sameOrigin();


        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeHttpRequests().requestMatchers("api/login/**", "/api/token/refresh/**").permitAll();
        http.authorizeHttpRequests().anyRequest().authenticated();
        http.addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class);
        http.addFilterAfter(new AuthenticationFilter(jwtService, repository, cookieManager), BasicAuthenticationFilter.class);
        http.addFilterBefore(new AuthorizationFilter(jwtService, tokenBlackList), BasicAuthenticationFilter.class);
        http.addFilterBefore(new LogoutFilter(jwtService, tokenBlackList, repository, cookieManager), BasicAuthenticationFilter.class);
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
        configuration.setAllowedOrigins(asList("http://localhost:4200", "http://127.0.0.1:4200"));
        configuration.setAllowCredentials(true);
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
