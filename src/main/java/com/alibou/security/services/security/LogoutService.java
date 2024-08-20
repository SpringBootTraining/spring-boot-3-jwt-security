package com.alibou.security.services.security;

import com.alibou.security.model.entities.Token;
import com.alibou.security.repositories.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import static java.lang.Boolean.TRUE;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        final String jwt = authHeader.replace("Bearer ", "");
        Token storedToken = tokenRepository.findByToken(jwt).orElse(null);
        Assert.notNull(storedToken, "No valid tokens found.");
        storedToken = Token.builder()
                .expired(TRUE)
                .revoked(TRUE)
                .build();
        tokenRepository.save(storedToken);
        SecurityContextHolder.clearContext();
    }
}
