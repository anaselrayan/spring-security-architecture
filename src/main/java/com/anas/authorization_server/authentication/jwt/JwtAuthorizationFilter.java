package com.anas.authorization_server.authentication.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    private final AuthenticationManager authManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null
            && authHeader.startsWith("Bearer ")
            && authHeader.split(" ").length == 2) {

            String jwt = authHeader.split(" ")[1];
            var auth = new JwtAuthentication(jwt);
            var result = authManager.authenticate(auth);
            if (result.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(result);
                System.out.println("Jwt Authenticated!");
            }
        }
        filterChain.doFilter(request, response);
    }
}
