package com.rydzwr.factory;

import com.rydzwr.model.UserRole;
import org.springframework.stereotype.Component;

@Component
public class UserRoleFactory {
    public UserRole createUserRole() {
        return new UserRole("USER");
    }

    public UserRole createAdminRole() {
        return new UserRole("ADMIN");
    }
}
