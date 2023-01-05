package com.rydzwr.repository;

import com.rydzwr.model.UserRole;
import org.springframework.data.repository.CrudRepository;

public interface UserRoleRepository extends CrudRepository<UserRole, Integer> {
    UserRole findByName(String name);
}
