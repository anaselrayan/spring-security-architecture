package com.anas.authorization_server.authentication;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.ArrayList;
import java.util.List;

public class AppAuthenticationManager implements AuthenticationManager {
    private List<AuthenticationProvider> providers;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        for (AuthenticationProvider provider : providers) {
            if (provider.supports(authentication.getClass()))
                return provider.authenticate(authentication);
        }
        throw new ProviderNotFoundException("Authentication type " + authentication.getName() + " is not supported!");
    }

    public AppAuthenticationManager() {
        this.providers = new ArrayList<>();
    }

    public List<AuthenticationProvider> getProviders() {
        return providers;
    }

    public void addProvider(AuthenticationProvider provider) {
        this.providers.add(provider);
    }
}
