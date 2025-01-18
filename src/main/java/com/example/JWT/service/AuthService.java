package com.example.JWT.service;

import com.example.JWT.dto.AuthResponse;
import com.example.JWT.dto.LoginRequest;
import com.example.JWT.entity.Role;
import com.example.JWT.entity.User;
import com.example.JWT.repository.UserRepository;
import com.example.JWT.util.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    public User registerUser(String username, String email, String password) {
        validateUserExistence(username, email);
        User user = createUser(username, email, password, Role.USER);
        return userRepository.save(user);
    }

    public User registerAdmin(String username, String email, String password) {
        validateUserExistence(username, email);
        User user = createUser(username, email, password, Role.ADMIN);
        return userRepository.save(user);
    }

    public AuthResponse login(LoginRequest loginRequest) {
        User user = userRepository.findByUsername(loginRequest.getUsernameOrEmail())
                .or(() -> userRepository.findByEmail(loginRequest.getUsernameOrEmail()))
                .orElseThrow(() -> new BadCredentialsException("Invalid username/email or password"));

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid username/email or password");
        }

        String accessToken = jwtUtil.generateAccessToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);

        return new AuthResponse(accessToken, refreshToken);
    }

    private void validateUserExistence(String username, String email) {
        if (userRepository.findByUsername(username).isPresent() || userRepository.findByEmail(email).isPresent()) {
            throw new IllegalArgumentException("Username or Email already exists");
        }
    }

    private User createUser(String username, String email, String password, Role role) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(role);
        return user;
    }

    public String refreshAccessToken(String refreshToken) {
        // Validate the refresh token
        Claims claims = jwtUtil.validateToken(refreshToken);

        // Extract the username and check its existence
        String username = claims.getSubject();
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Optional: Check token revocation (if using a refresh token repository)
        if (!jwtUtil.isRefreshTokenValid(refreshToken)) {
            throw new IllegalArgumentException("Invalid or expired refresh token");
        }

        // Generate a new access token
        return jwtUtil.generateAccessToken(user);
    }

}

