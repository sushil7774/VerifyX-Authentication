package com.verifyx.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtil {

	private final String SECRET_KEY = "yoursecretkeyyoursecretkeyyoursecretkeyyoursecretkeyyoursecretkeyyoursecretkey"; // 🔐 Secret Key (At least 32 characters)
	private final long EXPIRATION_TIME = 1000 * 60 * 60 * 10; // ⏳ Token Validity (10 Hours)

	// 🔹 1️⃣ Secret Key Ko Generate Karna (Latest JJWT Syntax)
	private SecretKey getSigningKey() {
		byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
		return Keys.hmacShaKeyFor(keyBytes);
	}

	// 🔹 2️⃣ JWT Token Generate Karna (Latest JJWT Syntax)
	public String generateToken(String email) {
		return Jwts.builder().subject(email) // ✅ Subject me email set kar raha hai
				.issuedAt(new Date()) // ✅ Issued time
				.expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) // ✅ Expiration time
				.signWith(getSigningKey()) // ✅ Signing with Secret Key (Latest Method)
				.compact();
	}

	// 🔹 3️⃣ Token Se Email Extract Karna
	public String extractEmail(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	// 🔹 4️⃣ Token Se Expiration Date Extract Karna
	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	// 🔹 5️⃣ Generic Method To Extract Claims (Latest Syntax)
	private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		Claims claims = Jwts.parser() // ✅ parser() use kar raha hai
				.verifyWith(getSigningKey()) // ✅ Latest verifyWith() use kar raha hai
				.build().parseSignedClaims(token).getPayload();
		return claimsResolver.apply(claims);
	}

	// 🔹 6️⃣ Token Valid Hai Ya Nahi?
	public boolean validateToken(String token, String email) {
		String extractedEmail = extractEmail(token);
		return (email.equals(extractedEmail) && !isTokenExpired(token));
	}

	// 🔹 7️⃣ Token Expired Hai Ya Nahi?
	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}
}
