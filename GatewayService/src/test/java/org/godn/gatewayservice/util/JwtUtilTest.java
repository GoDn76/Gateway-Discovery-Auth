package org.godn.gatewayservice.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.Key;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest {

    private JwtUtil jwtUtil;

    private final String TEST_SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";

    @BeforeEach
    void setUp() {
        // ✅ CLEAN: Just pass the secret directly!
        // No ReflectionTestUtils needed.
        jwtUtil = new JwtUtil(TEST_SECRET);
    }

    // --- Helper to generate a real token for testing ---
    private String generateTestToken(String userId, String secret, long expirationMs) {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        Key key = Keys.hmacShaKeyFor(keyBytes);

        return Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    @Test
    void testExtractUserId_Success() {
        String token = generateTestToken("user-123", TEST_SECRET, 1000 * 60); // 1 min valid

        String extractedId = jwtUtil.extractUserId(token);

        assertEquals("user-123", extractedId);
    }

    @Test
    void testValidateToken_Success() {
        String token = generateTestToken("user-123", TEST_SECRET, 1000 * 60);

        // Should NOT throw any exception
        assertDoesNotThrow(() -> jwtUtil.validateToken(token));
    }

    @Test
    void testValidateToken_Expired() {
        // Generate token that expired 1 second ago
        String expiredToken = generateTestToken("user-123", TEST_SECRET, -1000);

        // Should throw an Exception (ExpiredJwtException)
        assertThrows(Exception.class, () -> jwtUtil.validateToken(expiredToken));
    }

    @Test
    void testValidateToken_InvalidSignature() {
        // Generate token with a DIFFERENT secret key (Simulating a hacker)
        String fakeSecret = "9999999999999999999999999999999999999999999999999999999999999999";
        String forgedToken = generateTestToken("admin-user", fakeSecret, 1000 * 60);

        // Should throw an Exception (SignatureException)
        assertThrows(Exception.class, () -> jwtUtil.validateToken(forgedToken));
    }
}