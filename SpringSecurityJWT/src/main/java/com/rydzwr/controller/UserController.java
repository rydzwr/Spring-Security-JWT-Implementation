package com.rydzwr.controller;

import com.rydzwr.model.UserDataResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/data/user")
    @PreAuthorize("hasAuthority('USER')")
    public UserDataResponse user() {
        final String userData = "user public data";
        return new UserDataResponse(userData);
    }

    @GetMapping("/data/admin")
    @PreAuthorize("hasAuthority('ADMIN')")
    public UserDataResponse admin() {
        final String adminData = "admin only data";
        return new UserDataResponse(adminData);
    }
}
