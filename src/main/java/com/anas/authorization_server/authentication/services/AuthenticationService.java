package com.anas.authorization_server.authentication.services;

import com.anas.authorization_server.authentication.basic.CustomAuthentication;
import com.anas.authorization_server.authentication.models.LoginRequest;
import com.anas.authorization_server.authentication.models.RegisterRequest;
import com.anas.authorization_server.authentication.models.SecurityUserDetails;
import com.anas.authorization_server.model.User;
import com.anas.authorization_server.services.JpaUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.HashMap;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final JwtService jwtService;
    private final ValidationService validationService;
    private final JpaUserDetailsService userService;
    private final AuthenticationManager authManager;

    public HashMap<String, String> authenticate(LoginRequest request) {
        if (validationService.validRequest(request)) {
            var user = userService.loadUserByUsername(request.email());
            if (user != null) {
                String cred = request.email() + ":" + request.password();
                String token = Base64.getEncoder().encodeToString(cred.getBytes());
                var auth = new CustomAuthentication(token);
                if (authManager.authenticate(auth).isAuthenticated())
                    return jwtService.createTokens(user);
            }
        }
        return null;
    }

    public HashMap<String, String> register(RegisterRequest request) {
        if (validationService.validRequest(request)) {
            boolean userExists = userService.loadUserByUsername(request.email()) != null;
            if (!userExists) {
                var user = new User(
                        request.firstName(),
                        request.lastName(),
                        request.email(),
                        request.password()
                );
                userService.save(user);
                return jwtService.createTokens(new SecurityUserDetails(user));
            }
        }
        return null;
    }

    public String exchangeRefToken(String refToken) {
        if (jwtService.isValidRefreshToken(refToken)) {
            String username = jwtService.extractSubject(refToken);
            var user = userService.loadUserByUsername(username);
            if (user != null) {
                return jwtService.createAccessToken(user);
            }
        }
        return null;
    }
}
