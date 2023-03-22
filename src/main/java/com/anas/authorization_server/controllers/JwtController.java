package com.anas.authorization_server.controllers;

import com.anas.authorization_server.authentication.services.AuthenticationService;
import com.anas.authorization_server.authentication.services.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/token")
@RequiredArgsConstructor
public class JwtController {
    private final JwtService jwtService;
    private final AuthenticationService authService;

    @PostMapping("/exchange")
    public ResponseEntity<String> refreshToken(@RequestBody String refToken) {
        String accessToken = authService.exchangeRefToken(refToken);
        if (accessToken != null) {
            return new ResponseEntity<>(accessToken, HttpStatus.OK);
        }
        return new ResponseEntity<>("Invalid Refresh Token!", HttpStatus.BAD_REQUEST);
    }

    @PostMapping("refresh_valid")
    public Boolean validRefreshToken(@RequestBody String refToken) {
        return jwtService.isValidRefreshToken(refToken);
    }

    @PostMapping("access_valid")
    public Boolean validAccessToken(@RequestBody String accessToken) {
        return jwtService.isValidAccessToken(accessToken);
    }
}
