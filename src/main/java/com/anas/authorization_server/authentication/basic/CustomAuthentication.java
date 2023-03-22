package com.anas.authorization_server.authentication.basic;

import com.anas.authorization_server.authentication.models.Credentials;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class CustomAuthentication implements Authentication {
    private Credentials credentials;
    private UserDetails user;
    private String encryptedToken;
    private boolean authenticated;

    public CustomAuthentication(Credentials credentials, UserDetails user) {
        this.credentials = credentials;
        this.user = user;
        this.authenticated = true;
    }

    public CustomAuthentication(String token) {
        this.encryptedToken = token;
        this.authenticated = false;
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
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getAuthorities();
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public String getName() {
        return user!= null ? user.getUsername(): "";
    }

    public String getEncryptedToken() {
        return encryptedToken;
    }

}
