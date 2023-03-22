package com.anas.authorization_server.services;

import com.anas.authorization_server.authentication.models.SecurityUserDetails;
import com.anas.authorization_server.model.User;
import com.anas.authorization_server.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

@RequiredArgsConstructor
@Service
public class JpaUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        var user = userRepository.findByEmail(email);
        return user.map(SecurityUserDetails::new).orElse(null);
    }

    public void save(User user) {
        Assert.notNull(user, "User can't be null");
        user.setPassword(encoder.encode(user.getPassword()));
        this.userRepository.save(user);
    }
}
