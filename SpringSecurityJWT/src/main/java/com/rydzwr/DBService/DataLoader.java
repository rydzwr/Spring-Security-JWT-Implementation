package com.rydzwr.DBService;

import com.rydzwr.factory.UserFactory;
import com.rydzwr.factory.UserRoleFactory;
import com.rydzwr.model.AppUser;
import com.rydzwr.model.UserRole;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataLoader implements ApplicationRunner {
    private final UserService userService;
    private final RoleService roleService;
    private final UserFactory userFactory;
    private final UserRoleFactory roleFactory;

    @Profile("dev")
    public void run(ApplicationArguments args) {

        roleService.deleteAll();
        userService.deleteAll();

        UserRole userRole = roleFactory.createUserRole();
        UserRole adminRole = roleFactory.createAdminRole();
        roleService.saveRole(userRole);
        roleService.saveRole(adminRole);

        AppUser appUser = userFactory.createUser("user", "user123");
        AppUser appAdmin = userFactory.createAdmin("admin", "admin123");

        userService.saveUser(appUser);
        userService.saveUser(appAdmin);


    }
}
