package com.anas.authorization_server.controllers;

import com.anas.authorization_server.authentication.models.LoginRequest;
import com.anas.authorization_server.authentication.models.RegisterRequest;
import com.anas.authorization_server.authentication.services.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationService authService;

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody LoginRequest request) {
        var authResponse = authService.authenticate(request);
        if (authResponse != null)
            return new ResponseEntity<>(authResponse, HttpStatus.OK);
        else
            return new ResponseEntity<>("Bad Credentials!", HttpStatus.BAD_REQUEST);
    }

    @PostMapping("/register")
    public ResponseEntity<Object> register(@RequestBody RegisterRequest request) {
        var authResponse = authService.register(request);
        if (authResponse != null)
            return new ResponseEntity<>(authResponse, HttpStatus.CREATED);
        else
            return new ResponseEntity<>("Check your inputs!", HttpStatus.BAD_REQUEST);
    }
}
