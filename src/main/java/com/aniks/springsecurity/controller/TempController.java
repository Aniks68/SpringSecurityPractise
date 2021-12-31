package com.aniks.springsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class TempController {

    @GetMapping("login")
    public String getLoginView() {
        System.out.println("Log in request coming through!");
        return "login";
    }

    @GetMapping("courses")
    public String getCourses() {
        System.out.println("Logged in!");
        return "courses";
    }
}
