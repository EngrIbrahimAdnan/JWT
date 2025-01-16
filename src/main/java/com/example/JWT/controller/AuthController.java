package com.example.JWT.controller;

import com.example.JWT.entity.User;
import com.example.JWT.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
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

}
