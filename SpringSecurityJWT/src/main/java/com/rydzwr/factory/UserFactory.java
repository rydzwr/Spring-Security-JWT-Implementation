package com.rydzwr.factory;

import com.rydzwr.model.AppUser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserFactory {
    private final PasswordEncoder passwordEncoder;

    public AppUser createUser(String name, String pass) {
        pass = passwordEncoder.encode(pass);
        return new AppUser(name, pass, "USER", null);
    }

    public AppUser createAdmin(String name, String pass) {
        pass = passwordEncoder.encode(pass);
        return new AppUser(name, pass, "ADMIN", null);
    }
}
