package com.aniks.springsecurity.auth;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AppUserDao {

    Optional<AppUser> findByUsername(String username);
}
