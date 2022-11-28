package com.rydzwr.service;

import com.rydzwr.model.AppUser;
import com.rydzwr.repository.AppUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataLoader implements ApplicationRunner {
    private final AppUserRepository userRepository;

    public DataLoader(AppUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Profile("dev")
    public void run(ApplicationArguments args) {
        userRepository.deleteAll();
        userRepository.save(new AppUser("user",passwordEncoder.encode("user123"),"USER", null));
        userRepository.save(new AppUser("admin",passwordEncoder.encode("admin123"),"ADMIN", null));
    }
}
