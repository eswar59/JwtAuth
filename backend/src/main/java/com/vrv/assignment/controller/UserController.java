package com.vrv.assignment.controller;


import com.vrv.assignment.model.JwtTokenRequest;
import com.vrv.assignment.model.User;
import com.vrv.assignment.repository.UserRepository;
import jakarta.validation.Valid;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.stream.Collectors;


@RestController
public class UserController {

    // for sql db
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    // for jwt
    private JwtEncoder jwtEncoder;
    private final AuthenticationManager authenticationManager;


    public UserController(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtEncoder jwtEncoder, AuthenticationManager authenticationManager){
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtEncoder=jwtEncoder;
        this.authenticationManager = authenticationManager;
    }

    //free path no authentication
    //create a customer
    @PostMapping("/createUser")
    public User createUser(@Valid @RequestBody User user) {
        user.setRoles("ADMIN");
        String plainPassword = user.getPassword();
        user.setPassword(passwordEncoder.encode(plainPassword));
//        user.setPassword(plainPassword);
        userRepository.save(user);
        return user;
    }

//    @Bean
//    public BCryptPasswordEncoder passwordEncoder(){
//        return new BCryptPasswordEncoder();
//    }

    //authenticate user and create token for him and return token
    @PostMapping("/createToken")
    public String generateToken(@RequestBody JwtTokenRequest jwtTokenRequest) {

        var authenticationToken =
                new UsernamePasswordAuthenticationToken(
                        jwtTokenRequest.username(),
                        jwtTokenRequest.password());

        var authentication =
                authenticationManager.authenticate(authenticationToken);

        var token = createNewToken(authentication);
        System.out.println(token);
        return token;
    }

    private String createNewToken(Authentication auth){
        var claims = JwtClaimsSet
                .builder()
                .issuer("self")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60*5))
                .subject(auth.getName())
                .claim("scope", createScope(auth))
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    private String createScope(Authentication auth){
        return auth.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .collect(Collectors.joining(" "));
    }
}