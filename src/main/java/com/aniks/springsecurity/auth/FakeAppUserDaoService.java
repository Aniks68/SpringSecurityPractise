package com.aniks.springsecurity.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.aniks.springsecurity.security.AppUserRole.*;

@Repository("fake")
public class FakeAppUserDaoService implements AppUserDao {
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeAppUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<AppUser> findByUsername(String username) {
        return getAppUsers().stream().filter(user -> user.getUsername().equals(username)).findFirst();
    }

    private List<AppUser> getAppUsers() {
        List<AppUser> appUserList = Lists.newArrayList(
                new AppUser("goodness", passwordEncoder.encode("12345"), ADMIN.getGrantedAuthorities(), true, true, true, true),
                new AppUser("izu", passwordEncoder.encode("12345"), ADMINTRAINEE.getGrantedAuthorities(), true, true, true, true),
                new AppUser("achi", passwordEncoder.encode("12345"), STUDENT.getGrantedAuthorities(), true, true, true, true)
        );
        return appUserList;
    }
}
