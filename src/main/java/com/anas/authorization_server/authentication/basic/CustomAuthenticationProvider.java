package com.anas.authorization_server.authentication.basic;

import com.anas.authorization_server.authentication.models.Credentials;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Base64;

@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var auth = (CustomAuthentication) authentication;
        String token = auth.getEncryptedToken();
        var credentials = decode(token);
        if (credentials != null) {
            String email = credentials.getEmail();
            String rowPassword = credentials.getPassword();
            var user = userDetailsService.loadUserByUsername(email);
            if (user != null && passwordEncoder.matches(rowPassword, user.getPassword())) {
                return new CustomAuthentication(credentials, user);
            }
        }
        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(CustomAuthentication.class);
    }

    private Credentials decode(String encryptedToken) {
        String decodedToken = new String(Base64.getDecoder().decode(encryptedToken));
        String[] s = decodedToken.split(":");
        if (s.length == 2) {
            return new Credentials(s[0], s[1]);
        }
        return null;
    }
}
