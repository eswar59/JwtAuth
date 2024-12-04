package com.vrv.assignment.controller;


import com.vrv.assignment.model.User;
import com.vrv.assignment.repository.UserRepository;
import jakarta.validation.Valid;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


@RestController
public class UserController {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;

    public UserController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    //create a customer
    @PostMapping("/createUser")
    public User createUser(@Valid @RequestBody User user) {
        user.setRoles("ROLE_USER");
        String plainPassword = user.getPassword();
        user.setPassword(passwordEncoder.encode(plainPassword));
        userRepository.save(user);
        return user;
    }
}