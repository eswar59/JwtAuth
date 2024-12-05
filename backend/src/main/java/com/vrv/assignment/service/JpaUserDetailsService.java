package com.vrv.assignment.service;

import com.vrv.assignment.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.vrv.assignment.model.UserSecurity;

@Service
public class JpaUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    public JpaUserDetailsService(UserRepository userRepository){
        this.userRepository=userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .map(UserSecurity::new)
                .orElseThrow(()-> new UsernameNotFoundException("The customer name not found is:" + username));
    }
}
