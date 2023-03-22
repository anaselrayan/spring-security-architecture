package com.anas.authorization_server.authentication.jwt;

import com.anas.authorization_server.authentication.services.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;

@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var auth = (JwtAuthentication) authentication;
        String token = auth.getJwToken();
        var decodedJwt = jwtService.verifyToken(token);
        if (decodedJwt != null) {
            String username = decodedJwt.getSubject();
            var user = userDetailsService.loadUserByUsername(username);
            var tokens = jwtService.createTokens(user);
            return new JwtAuthentication(tokens, user);
        }
        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(JwtAuthentication.class);
    }
}
