package com.example.JWT.controller;

import com.example.JWT.entity.Role;
import com.example.JWT.util.JwtKeyGenerator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final JwtKeyGenerator jwtKeyGenerator;

    public UserController(JwtKeyGenerator jwtKeyGenerator) {
        this.jwtKeyGenerator = jwtKeyGenerator;
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile(@RequestHeader("Authorization") String token) {
        try {
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(jwtKeyGenerator.getSecretKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();


            String username = claims.getSubject();
            String role = claims.get("role", String.class);

            if (role.equals("ADMIN")){
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Only for users, not Admin");
            }
            return ResponseEntity.ok(Map.of("username", username, "role", role));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired token");
        }
    }}