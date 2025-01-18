package com.example.JWT.controller;

import com.example.JWT.dto.AuthResponse;
import com.example.JWT.dto.LoginRequest;
import com.example.JWT.dto.RefreshTokenRequest;
import com.example.JWT.entity.User;
import com.example.JWT.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;


@RequestMapping("/api/auth")
@RestController
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/test")
    public String test(){
        System.out.println("test");
        return "Test";
    }

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestParam String username,
                                         @RequestParam String email,
                                         @RequestParam String password) {
        return ResponseEntity.ok(authService.registerUser(username, email, password));
    }

    @PostMapping("/admin-register")
    public ResponseEntity<User> registerAdmin(@RequestParam String username,
                                         @RequestParam String email,
                                         @RequestParam String password) {
        return ResponseEntity.ok(authService.registerAdmin(username, email, password));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest loginRequest) {
        try {
            // Delegate to AuthService
            AuthResponse response = authService.login(loginRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> adminEndpoint() {
        return ResponseEntity.ok("Hello Admin!");
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshAccessToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        try {
            String newAccessToken = authService.refreshAccessToken(refreshTokenRequest.getRefreshToken());
            return ResponseEntity.ok(new AuthResponse(newAccessToken, refreshTokenRequest.getRefreshToken()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }
    }

}
