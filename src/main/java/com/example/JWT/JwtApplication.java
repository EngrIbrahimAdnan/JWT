package com.example.JWT;

import com.example.JWT.util.JwtKeyGenerator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JwtApplication {

	public static void main(String[] args) {
//		JwtKeyGenerator generator = new JwtKeyGenerator();
//		String newSecretKey = generator.generateNewSecretKey();
//		System.out.println("Generated Key: " + newSecretKey);

		SpringApplication.run(JwtApplication.class, args);
	}

}
