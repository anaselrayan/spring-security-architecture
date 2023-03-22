package com.anas.authorization_server.authentication.basic;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    private final AuthenticationManager authManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null
            && authHeader.startsWith("Basic ")
            && authHeader.split(" ").length == 2) {

            String token = authHeader.split(" ")[1];
            var auth = new CustomAuthentication(token);
            var result = authManager.authenticate(auth);
            if (result.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(result);
                System.out.println("Authenticated " + result.getName());
            }
        }
        filterChain.doFilter(request, response);
    }
}
