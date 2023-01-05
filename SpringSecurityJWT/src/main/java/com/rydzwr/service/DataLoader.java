package com.rydzwr.service;

import com.rydzwr.factory.UserFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataLoader implements ApplicationRunner {
    private final UserService service;
    private final UserFactory factory;

    @Profile("dev")
    public void run(ApplicationArguments args) {
        service.deleteAll();
        service.saveUser(factory.createUser("user", "user123"));
        service.saveUser(factory.createAdmin("admin", "admin123"));
    }
}
