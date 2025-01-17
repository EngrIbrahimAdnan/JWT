package com.example.JWT.controller;

import com.example.JWT.dto.LoginRequest;
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

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestParam String username,
                                         @RequestParam String email,
                                         @RequestParam String password) {
        return ResponseEntity.ok(authService.registerUser(username, email, password));
    }
    @GetMapping("/test")
    public String test(){
        System.out.println("test");
        return "Test";
    }

    @PostMapping("/admin-register")
    public ResponseEntity<User> registerAdmin(@RequestParam String username,
                                         @RequestParam String email,
                                         @RequestParam String password) {
        return ResponseEntity.ok(authService.registerAdmin(username, email, password));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            // Delegate to AuthService
            String tokens = authService.login(loginRequest);
            return ResponseEntity.ok(tokens);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> adminEndpoint() {
        return ResponseEntity.ok("Hello Admin!");
    }
}
