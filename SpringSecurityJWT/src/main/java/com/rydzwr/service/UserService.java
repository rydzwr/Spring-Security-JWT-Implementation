package com.rydzwr.service;

import com.rydzwr.model.AppUser;
import com.rydzwr.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.validation.Valid;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final AppUserRepository repository;

    @Transactional
    public void saveUser(AppUser appUser) {
        repository.save(appUser);
    }

    @Transactional
    public void deleteAll() {
        repository.deleteAll();
    }
}
