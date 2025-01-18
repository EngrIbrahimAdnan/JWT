package com.example.JWT.util;

import com.example.JWT.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtUtil {
    private final SecretKey secretKey;

    public JwtUtil(JwtKeyGenerator jwtKeyGenerator) {
        this.secretKey = jwtKeyGenerator.getSecretKey();
    }

    public String generateAccessToken(User user) {
        String tokenId = UUID.randomUUID().toString();
        return Jwts.builder()
                .setId(tokenId)
                .setSubject(user.getUsername())
                .claim("roles", user.getRole().name())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour
                .signWith(secretKey)
                .compact();
    }

    public String generateRefreshToken(User user) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 604800000)) // 7 days
                .signWith(secretKey)
                .compact();
    }

    public Claims validateToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException e) {
            throw new IllegalArgumentException("Invalid token", e);
        }
    }

    public boolean isRefreshTokenValid(String refreshToken) {
        Claims claims = validateToken(refreshToken);
        return claims.getExpiration().after(new Date()); // Ensure it's not expired
    }

}

