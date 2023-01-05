package com.rydzwr.repository;

import com.rydzwr.model.AppUser;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AppUserRepository extends CrudRepository<AppUser, Integer> {
    AppUser findByName(String name);
    boolean existsByName(String name);
    AppUser findByRefreshToken(String token);
}
