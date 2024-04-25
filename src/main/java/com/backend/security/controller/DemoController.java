package com.backend.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @GetMapping("/admin")
    public String admin(){
        return "ADMIN";
    }

    @GetMapping("/user")
    public String user(){
        return "USER";
    }
}
