package com.aniks.springsecurity.auth;

import java.util.Optional;

public interface AppUserDao {

    Optional<AppUser> findByUsername(String username);
}
