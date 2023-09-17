package com.alibou.security.configuration.security;

import com.alibou.security.repositories.TokenRepository;
import com.alibou.security.services.CustomUserDetailsServiceImpl;
import com.alibou.security.services.security.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomUserDetailsServiceImpl userDetailsService;
    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().contains("/api/v1/auth")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Check if the authorization bearer token is existing and return Forbidden 403 response if it is missing
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract the bearer token from the authorization header.
        final String jwt = authHeader.replace("Bearer ", "");

        // Extract the [ Email or Username ] from the bearer token claims.
        final String userEmail = jwtService.extractUsername(jwt);

        // After extracting the Username or Email from the bearer token claims, we'll check if it's not null and the SecurityContextHolder doesn't have an authenticated user.
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // After extracting the user form the bearer token we'll retrieve the user from the DB if it's exist.
            UserDetails loadedUser = userDetailsService.loadUserByUsername(userEmail);

            // This is to get only the valid token from the DB.
            // We'll use this to ensure that the user has only one valid token which will be the same token that passed with the request.
            var isTokenValid = tokenRepository.findByToken(jwt)
                    .map(t -> !t.isExpired() && !t.isRevoked())
                    .orElse(false);

            // Here we are checking if the user really has only one valid token.
            if (jwtService.isTokenValid(jwt, loadedUser) && isTokenValid) {
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        loadedUser,
                        null,
                        loadedUser.getAuthorities());
                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }
        filterChain.doFilter(request, response);
    }
}
