package com.alibou.security.services.security;

import com.alibou.security.model.entities.User;
import org.springframework.stereotype.Service;

@Service
public interface TokenService {

    void saveUserToken(User user, String jwtToken);

    void revokeAllUserTokens(User user);
}
