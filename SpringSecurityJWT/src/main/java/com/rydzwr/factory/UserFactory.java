package com.rydzwr.factory;

import com.rydzwr.model.AppUser;
import com.rydzwr.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserFactory {
    private final PasswordEncoder passwordEncoder;
    private final UserRoleRepository roleRepository;

    public AppUser createUser(String name, String pass) {
        pass = passwordEncoder.encode(pass);

        AppUser appUser = new AppUser(name, pass);
        appUser.setRole(roleRepository.findByName("USER"));

        return appUser;
    }

    public AppUser createAdmin(String name, String pass) {
        pass = passwordEncoder.encode(pass);

        AppUser appUser = new AppUser(name, pass);
        appUser.setRole(roleRepository.findByName("ADMIN"));

        return appUser;
    }
}
