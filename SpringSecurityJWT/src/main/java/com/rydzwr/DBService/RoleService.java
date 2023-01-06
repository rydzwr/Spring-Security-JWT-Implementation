package com.rydzwr.DBService;

import com.rydzwr.model.UserRole;
import com.rydzwr.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class RoleService {
    private final UserRoleRepository repository;

    //@Transactional
    public void saveRole(UserRole role) {
        repository.save(role);
    }

    //@Transactional
    public void deleteAll() {
        repository.deleteAll();
    }
}
