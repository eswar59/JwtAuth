package com.vrv.assignment.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.stream.Collectors;

@RestController
public class Controller {

    @GetMapping("/admin")
    public String getAdminResource(){
        return "You are seeing admin resource";
    }

    @GetMapping("/moderator")
    public String getModeratorResource(){
        return "You are seeing moderator resource";
    }

}
