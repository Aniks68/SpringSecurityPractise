package com.aniks.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.aniks.springsecurity.security.AppUserPermission.*;
import static com.aniks.springsecurity.security.AppUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AppSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .csrf().disable()
                .authorizeRequests() // authorise requests
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll() //    whitelists url paths that don't need authorisation // permitting the non-authorisation of antMatchers
                .antMatchers("/api/**").hasRole(STUDENT.name()) //  using role-based authentication to protect api
                .anyRequest() // applies to any request
                .authenticated() // client must authenticate by supplying username and password
                .and()
//                .httpBasic(); //    the form of enforcing the authenticity is by basic auth.
                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .defaultSuccessUrl("/courses", true)
                    .passwordParameter("password")
                    .usernameParameter("username")
                .and()
                .rememberMe()
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                    .key("shinigami")
                    .rememberMeParameter("remember-me")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) //   by default, the logout url is to be activated by a POST request, unless CSRF is disabled where this line of code has to come into play.
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login");

    }

    @Override
    @Bean /*    A bean of UserDetailsService is necessary for a number of reasons in spring security, one of which is for sessionId/remember-me     */
    protected UserDetailsService userDetailsService() {
        UserDetails fabioUser = User.builder()
                .username("fabio")
                .password(passwordEncoder.encode("12345"))
//                .roles(STUDENT.name()) //    spring identifies this as ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails goodnessUser = User.builder()
                .username("goodness")
                .password(passwordEncoder.encode("12345"))
//                .roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails izuUser = User.builder()
                .username("izu")
                .password(passwordEncoder.encode("12345"))
//                .roles(ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(fabioUser, goodnessUser, izuUser);
    }
}
