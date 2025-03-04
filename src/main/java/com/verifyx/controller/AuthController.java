package com.verifyx.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.verifyx.dto.LoginRequest;
import com.verifyx.dto.RegisterRequest;
import com.verifyx.service.UserService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
	private final UserService userService;

	public AuthController(UserService userService) {
		this.userService = userService;
	}

	@PostMapping("/register")
	public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
		userService.registerUser(request);
		return ResponseEntity.ok("User registered successfully");
	}

	@PostMapping("/login")
	public ResponseEntity<String> login(@RequestBody LoginRequest request) {
		String response = userService.loginUser(request);
		return ResponseEntity.ok(response);
	}

	@GetMapping("/profile")
	public ResponseEntity<String> getUserProfile(@AuthenticationPrincipal UserDetails userDetails) {
		return ResponseEntity.ok("Welcome, " + userDetails.getUsername() + "! This is your profile.");
	}

}
