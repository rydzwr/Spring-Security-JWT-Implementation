package com.rydzwr.controller;

import com.rydzwr.model.AppUser;
import com.rydzwr.model.UserDataResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

@Slf4j
@RestController
@RequestMapping("/api")
public class UserController {

    @PostMapping("/test")
    @PreAuthorize("hasAuthority('USER')")
    public String test(@RequestBody @Valid AppUser appUser) {
        return appUser.toString();
    }

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
