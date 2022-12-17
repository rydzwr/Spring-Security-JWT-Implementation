package com.rydzwr.service;

import com.rydzwr.model.AppUser;
import com.rydzwr.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataLoader implements ApplicationRunner {
    private final UserService service;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Profile("dev")
    public void run(ApplicationArguments args) {
        service.deleteAll();
        service.saveUser(new AppUser("user",passwordEncoder.encode("user123"),"USER", null));
        service.saveUser(new AppUser("admin",passwordEncoder.encode("admin123"),"ADMIN", null));
    }
}
