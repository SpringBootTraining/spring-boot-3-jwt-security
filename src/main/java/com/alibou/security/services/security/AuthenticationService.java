package com.alibou.security.services.security;

import com.alibou.security.entities.User;
import com.alibou.security.dto.AuthenticationRequest;
import com.alibou.security.dto.RegisterRequest;
import com.alibou.security.repositories.UserRepository;
import com.alibou.security.dto.AuthenticationResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
  private final UserRepository userRepository;
  private final TokenService tokenService;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;


  /**
   * Registers a new user based on the provided register request.
   *
   * @param request The register request containing user details.
   * @return The authentication response containing the generated access token and refresh token.
   */
  public AuthenticationResponse register(RegisterRequest request) {
    User user = User.builder()
        .firstname(request.getFirstname())
        .lastname(request.getLastname())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        .role(request.getRole())
        .build();
    User savedUser = userRepository.save(user);

    String jwtToken = jwtService.generateToken(user);
    String refreshToken = jwtService.generateRefreshToken(user);
    tokenService.saveUserToken(savedUser, jwtToken);

    return AuthenticationResponse.builder()
        .accessToken(jwtToken)
        .refreshToken(refreshToken)
        .build();
  }

  /**
     * Authenticates a user based on the provided email and password
   *
   * @param request The authentication request containing the user's email and password.
   * @return The authentication response containing the generated access token and refresh token.
   */
  public AuthenticationResponse authenticate(AuthenticationRequest request) {

    //This class is an implementation of Authentication interface that represents a username and password in an authentication request. It is most commonly used with form-based authentication, or, in other words, when users are required to input their username and password.
    //This class has several constructors, one of which takes a principal and credentials as parameters. The principal typically stands for the loaded UserDetails object, while the credentials stands for the password. This is frequently used when the user has been authenticated.
    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword());

    authenticationManager.authenticate(auth);

    User user = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new UsernameNotFoundException("User Not Found"));
    String jwtToken = jwtService.generateToken(user);
    String refreshToken = jwtService.generateRefreshToken(user);

    // Revoke all user tokens stored in the DB before creating a new one once the user login, this is to ensure that the user has only one valid token.
    tokenService.revokeAllUserTokens(user);
    tokenService.saveUserToken(user, jwtToken);
    return AuthenticationResponse.builder()
        .accessToken(jwtToken)
        .refreshToken(refreshToken)
        .build();
  }

  /**
   * Refreshes the access token for the authenticated user in order to extend the user
   * authentication in our system instead of logout the user and let him re-authenticate
   *
   * @param request  the HttpServletRequest object containing the request information
   * @param response the HttpServletResponse object used to send the response
   * @throws IOException if an I/O error occurs while writing the response
   */
  public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
    final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return;
    }
    final String refreshToken = authHeader.replace("Bearer ", "");
    final String userEmail = jwtService.extractUsername(refreshToken);
    if (userEmail != null) {
      var user = this.userRepository.findByEmail(userEmail).orElseThrow();

      if (jwtService.isTokenValid(refreshToken, user)) {
        var accessToken = jwtService.generateToken(user);
        tokenService.revokeAllUserTokens(user);
        tokenService.saveUserToken(user, accessToken);
        var authResponse = AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
        new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
      }
    }
  }
}
