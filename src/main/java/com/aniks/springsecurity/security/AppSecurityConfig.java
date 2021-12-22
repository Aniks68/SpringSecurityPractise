package com.aniks.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

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
                .authorizeRequests() // authorise requests
                .antMatchers("/", "index", "/css/*", "/js/*") //    whitelists url paths that don't need authorisation
                .permitAll() // permitting the non-authorisation of antMatchers
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
                .roles("STUDENT") //    spring identifies this as ROLE_STUDENT
                .build();

        return new InMemoryUserDetailsManager(fabioUser);
    }
}
