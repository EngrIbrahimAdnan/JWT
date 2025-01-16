package com.example.JWT.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable() // Disable CSRF for development (enable in production with proper configuration)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/auth/**", "/test").permitAll() // Allow public access to /api/auth and /test
                        .anyRequest().authenticated() // Require authentication for all other endpoints
                )
                .httpBasic(); // Use basic authentication (or customize it as needed)

        return http.build();
    }
}

