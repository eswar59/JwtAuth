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

    private JwtEncoder jwtEncoder;

    public Controller(JwtEncoder jwtEncoder){
        this.jwtEncoder=jwtEncoder;
    }

    @PostMapping("/login")
    public String login(){
        return "login";
    }

//    @PostMapping("createUser")
//    public String signup(){
//
//        return "userCreated";
//    }
    @GetMapping("/index")
    public String home(){
        return "index";
    }

//    @PostMapping("/createToken")
//    public String giveToken(Authentication auth){
//        return createNewToken(auth);
//    }
//
//    @GetMapping("/login")
//    public String loginPage(){
//        return "you are in login page";
//    }
//
//    @GetMapping("/user")
//    public String homePage(){
//        return "You are in home page";
//    }
//
//    @GetMapping("/moderator")
//    public String moderatorPage(){
//        return "You are in moderator page";
//    }
//
//    @GetMapping("/admin")
//    public String adminPage(){
//        return "You are in admin page";
//    }
//
//    private String createNewToken(Authentication auth){
//        var claims = JwtClaimsSet
//                .builder()
//                .issuer("self")
//                .issuedAt(Instant.now())
//                .expiresAt(Instant.now().plusSeconds(60*5))
//                .subject(auth.getName())
//                .claim("scope", createScope(auth))
//                .build();
//
//        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
//    }
//
//    private String createScope(Authentication auth){
//        return auth.getAuthorities().stream()
//                .map(a -> a.getAuthority())
//                .collect(Collectors.joining(" "));
//    }
}
