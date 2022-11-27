package com.rydzwr.controller;

import com.rydzwr.model.UserDataResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    //@PreAuthorize("hasAuthority('USER')")
    @GetMapping("/data/user")
    public UserDataResponse user() {
        return new UserDataResponse("user public data");
    }

    //@PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/data/admin")
    public UserDataResponse admin() {
        return new UserDataResponse("admin only data");
    }

}
