package com.rydzwr.controller;

import com.rydzwr.model.UserDataResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/data")
public class DataController {
    @GetMapping("/user")
    @PreAuthorize("hasAuthority('USER')")
    public UserDataResponse user() {
        final String userData = "user public data";
        return new UserDataResponse(userData);
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ADMIN')")
    public UserDataResponse admin() {
        final String adminData = "admin only data";
        return new UserDataResponse(adminData);
    }
}
