package com.verifyx.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.verifyx.dto.LoginRequest;
import com.verifyx.dto.RegisterRequest;
import com.verifyx.entity.User;
import com.verifyx.repository.UserRepository;
import com.verifyx.security.JwtUtil;

@Service
public class UserService {

	private final UserRepository userRepository;
	private final BCryptPasswordEncoder passwordEncoder;
	private final JwtUtil jwtUtil;

	@Autowired
	public UserService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtUtil = jwtUtil;
	}

	private void validateField(String field, String errorMessage) {
		if (field == null || field.trim().isEmpty()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, errorMessage);
		}
	}

	private String validateEmail(String email) {
		if (email == null || email.trim().isEmpty()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Please Enter Email!");
		}

		// 🔹 Check if email contains spaces
		if (email.contains(" ")) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email cannot contain spaces!");
		}

		// 🔹 Check if email format is valid using Regex
		String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";
		if (!email.matches(emailRegex)) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid Email Format!");
		}
		return email.trim();
	}

	public User registerUser(RegisterRequest request) {
		String Email = validateEmail(request.getEmail());
		if (userRepository.findByEmail(Email).isPresent()) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already in use!");
		}
		validateField(request.getUsername(), "Please Enter Username!");
		validateField(request.getPassword(), "Please Enter Password!");
		validateField(request.getRole(), "Please Enter Role!");

		User user = new User();
		user.setUsername(request.getUsername());
		user.setEmail(Email);
		user.setPassword(passwordEncoder.encode(request.getPassword()));
		user.setRole(request.getRole());
		

		return userRepository.save(user);
	}

	public String loginUser(LoginRequest request) {
		String Email = validateEmail(request.getEmail());
		User user = userRepository.findByEmail(Email)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not Found!"));

		if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
		}

		// ✅ JWT Token Generate Karna
		String token = jwtUtil.generateToken(user.getEmail());

		return token;

	}
}
