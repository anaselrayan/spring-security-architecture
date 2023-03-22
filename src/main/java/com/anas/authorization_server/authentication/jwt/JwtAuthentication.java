package com.anas.authorization_server.authentication.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashMap;

public class JwtAuthentication implements Authentication {
    private final String jwToken;
    private final HashMap<String, String> grantedTokens;
    private final UserDetails user;
    private boolean authenticated;

    public JwtAuthentication(String jwToken) {
        this.jwToken = jwToken;
        this.authenticated = false;
        this.user = null;
        this.grantedTokens = null;
    }

    public JwtAuthentication(HashMap<String, String> tokens, UserDetails user) {
        this.grantedTokens = tokens;
        this.user = user;
        this.authenticated = true;
        this.jwToken = null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user != null ? user.getAuthorities() : null;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return user;
    }

    @Override
    public boolean isAuthenticated() {
        return this.authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return user != null ? user.getUsername(): "";
    }

    public String getJwToken() {
        return jwToken;
    }
}
