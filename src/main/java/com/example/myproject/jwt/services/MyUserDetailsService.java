package com.example.myproject.jwt.services;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if ("foo".equals(username)) {
            return User.builder()
                    .username("foo")
                    .password("foo")
                    .roles("USER")
                    .build();
        } else {
            throw new UsernameNotFoundException("Utente non trovato");
        }
    }
}