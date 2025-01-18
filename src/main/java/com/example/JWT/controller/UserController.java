package com.example.JWT.controller;

import com.example.JWT.entity.Role;
import com.example.JWT.util.JwtKeyGenerator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/user/profile")
    public ResponseEntity<?> getUserProfile(Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();

        String id = jwt.getId();
        String username = jwt.getSubject();
        Object role = jwt.getClaims().get("roles");

        Instant issue = jwt.getIssuedAt();
        Instant expire = jwt.getExpiresAt();

        System.out.println(id);
        System.out.println(username);
        System.out.println(role);
        System.out.println(issue);
        System.out.println(expire);


        if (role.equals(Role.ADMIN.toString())){
            return ResponseEntity.ok("Welcome, Admin!");
        }
        return ResponseEntity.ok(Map.of("username", username, "roles", jwt.getClaims().get("roles")));
    }
}
