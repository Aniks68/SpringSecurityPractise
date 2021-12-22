package com.aniks.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.aniks.springsecurity.security.AppUserPermission.*;
import static com.aniks.springsecurity.security.AppUserRole.*;

@Configuration
@EnableWebSecurity
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AppSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests() // authorise requests
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() //    whitelists url paths that don't need authorisation // permitting the non-authorisation of antMatchers
                .antMatchers("/api/**").hasRole(STUDENT.name()) //  using role-based authentication to protect api
                .antMatchers(HttpMethod.DELETE, "/management/**").hasAnyAuthority(COURSE_WRITE.getPermission(), STUDENT_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT, "/management/**").hasAnyAuthority(COURSE_WRITE.getPermission(), STUDENT_WRITE.getPermission())
                .antMatchers(HttpMethod.POST, "/management/**").hasAnyAuthority(COURSE_WRITE.getPermission(), STUDENT_WRITE.getPermission())
                .antMatchers(HttpMethod.GET, "/management/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                .anyRequest() // applies to any request
                .authenticated() // client must authenticate by supplying username and password
                .and() //
                .httpBasic(); //    the form of enforcing the authencity is by basic auth.
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails fabioUser = User.builder()
                .username("fabio")
                .password(passwordEncoder.encode("12345"))
                .roles(STUDENT.name()) //    spring identifies this as ROLE_STUDENT
                .build();

        UserDetails goodnessUser = User.builder()
                .username("goodness")
                .password(passwordEncoder.encode("12345"))
                .roles(ADMIN.name())
                .build();

        UserDetails izuUser = User.builder()
                .username("izuchukwu")
                .password(passwordEncoder.encode("12345"))
                .roles(ADMINTRAINEE.name())
                .build();

        return new InMemoryUserDetailsManager(fabioUser, goodnessUser, izuUser);
    }
}
