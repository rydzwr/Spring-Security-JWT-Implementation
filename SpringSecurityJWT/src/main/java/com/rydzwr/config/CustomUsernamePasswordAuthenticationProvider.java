package com.rydzwr.config;

import com.rydzwr.model.AppUser;
import com.rydzwr.repository.AppUserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
public class CustomUsernamePasswordAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private AppUserRepository repository;

    @Autowired
    private PasswordEncoder encoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        final String invalidPassword = "Invalid password!";
        final String userNotFound = "No user registered with this details!";

        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        AppUser appUser = repository.findByName(username);
        if (appUser != null) {
            if (encoder.matches(password, appUser.getPassword())) {
                return new UsernamePasswordAuthenticationToken(username, password, getGrantedAuthorities(appUser.getRole()));
            } else {
                throw new BadCredentialsException(invalidPassword);
            }
        } else {
            throw new BadCredentialsException(userNotFound);
        }
    }

    private List<GrantedAuthority> getGrantedAuthorities(String role) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(new SimpleGrantedAuthority(role));
        return grantedAuthorities;
    }



    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
