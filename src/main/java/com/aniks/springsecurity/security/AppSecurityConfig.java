package com.aniks.springsecurity.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {
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
}
