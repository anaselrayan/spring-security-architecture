package com.anas.authorization_server.config;

import com.anas.authorization_server.model.User;
import com.anas.authorization_server.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;

@RequiredArgsConstructor
public class StartUp implements CommandLineRunner {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    @Override
    public void run(String... args) {
        var user = new User(
                "anas",
                "elrayan",
                "anas@email.com",
                passwordEncoder.encode("123")
        );
        userRepository.save(user);
    }
}
