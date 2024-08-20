package com.alibou.security.services.security;

import com.alibou.security.model.entities.Token;
import com.alibou.security.model.entities.User;
import com.alibou.security.model.enums.TokenType;
import com.alibou.security.repositories.TokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@RequiredArgsConstructor
@Service
public class TokenServiceImpl implements TokenService {

    private final TokenRepository tokenRepository;
    @Override
    public void saveUserToken(User user, String jwtToken) {
        Token token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    @Override
    public void revokeAllUserTokens(User user) {

        List<Token> validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty()) {
            return;
        }
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }
}
