package com.rydzwr.controller;

import com.rydzwr.dto.AppUserDto;
import com.rydzwr.factory.UserFactory;
import com.rydzwr.model.AppUser;
import com.rydzwr.service.AuthHeaderDataExtractor;
import com.rydzwr.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/user")
public class UserController {
    private final AuthHeaderDataExtractor extractor;
    private final UserService service;
    private final UserFactory factory;

    @PostMapping("/register")
    public ResponseEntity<String> register (@Valid @RequestBody AppUserDto appUserDto) {
        AppUser newUser = factory.createUser(appUserDto.getName(), appUserDto.getPassword());
        service.saveUser(newUser);
        return ResponseEntity.ok().build();
    }
}
