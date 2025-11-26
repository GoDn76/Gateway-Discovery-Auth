package org.godn.gatewayservice.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;

@Component
public class JwtUtil {


    private final String secret;

    public JwtUtil(@Value("${jwt.secret}") String secret) {
        this.secret = secret;
    }

    /**
     * Validates the token signature and expiration.
     * Throws an exception if the token is invalid.
     */
    public void validateToken(String token) {
        Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token);
    }

    /**
     * Extracts the User ID (Subject) from the token.
     */
    public String extractUserId(String token) {
        return parseClaims(token).getSubject();
    }

    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignKey() {
        // Decodes your BASE64 secret key into a cryptographic key
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}