package com.example.myproject.jwt;

import com.example.myproject.jwt.models.AuthenticationRequest;
import com.example.myproject.jwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import com.example.myproject.jwt.models.AuthenticationResponse;

@RestController
public class HomeHelloResource {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Autowired
    public HomeHelloResource(AuthenticationManager authenticationManager, JwtUtil jwtUtil, UserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @GetMapping("/hello")
    public String hello() {return "Hello World";}

    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUserName(), authenticationRequest.getPassword())
            );

            UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUserName());

            String jwtToken = jwtUtil.generateToken(userDetails);

            return ResponseEntity.ok(new AuthenticationResponse(jwtToken));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
