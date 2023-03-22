package com.anas.authorization_server.config;

import com.anas.authorization_server.authentication.AppAuthenticationManager;
import com.anas.authorization_server.authentication.basic.CustomAuthenticationProvider;
import com.anas.authorization_server.authentication.basic.CustomAuthorizationFilter;
import com.anas.authorization_server.authentication.services.JwtService;
import com.anas.authorization_server.authentication.jwt.JwtAuthenticationProvider;
import com.anas.authorization_server.authentication.jwt.JwtAuthorizationFilter;
import com.anas.authorization_server.repositories.UserRepository;
import com.anas.authorization_server.services.JpaUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final UserRepository userRepository;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests()
                .requestMatchers("/auth/**").permitAll()
                .requestMatchers("/token/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(new CustomAuthorizationFilter(authenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new JwtAuthorizationFilter(authenticationManager()),
                        CustomAuthorizationFilter.class);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        var manager = new AppAuthenticationManager();
        manager.addProvider(new CustomAuthenticationProvider(passwordEncoder(), userDetailsService()));
        manager.addProvider(new JwtAuthenticationProvider(jwtService(), userDetailsService()));
        return manager;
    }

    @Bean
    public JwtService jwtService() {
        return new JwtService();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new JpaUserDetailsService(userRepository, passwordEncoder());
    }
}
