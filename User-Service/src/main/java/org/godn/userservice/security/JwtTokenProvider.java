package org.godn.userservice.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.godn.userservice.model.User;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtTokenProvider {

    private final Key jwtSecretKey;
    private final long jwtExpirationMs;

    // We use constructor injection to read values from application.yml
    public JwtTokenProvider(@Value("${app.jwt.secret}") String jwtSecret,
                            @Value("${app.jwt.expiration-ms}") long jwtExpirationMs) {
        // Decode the Base64 secret string into a secure Key object
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        this.jwtSecretKey = Keys.hmacShaKeyFor(keyBytes);
        this.jwtExpirationMs = jwtExpirationMs;
    }

    /**
     * Generates a new JWT for a given user.
     * @param user The user who has successfully logged in.
     * @return A signed JWT string.
     */
    public String generateToken(User user) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationMs);

        // We can add extra information to the token (claims)
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", user.getEmail());
        claims.put("name", user.getName());
        // Add any other non-sensitive info you might need

        return Jwts.builder()
                .setSubject(user.getId().toString()) // The "subject" is the User's ID
                .setClaims(claims)                   // Add our custom claims
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(jwtSecretKey, SignatureAlgorithm.HS512) // Sign with our secret key
                .compact();
    }

    public String getEmailFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(jwtSecretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.get("email").toString();
    }


    public boolean validateToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(jwtSecretKey).build().parseClaimsJws(authToken);
            return true;
        } catch (SignatureException ex) {
            System.out.println("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            System.out.println("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            System.out.println("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            System.out.println("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            System.out.println("JWT claims string is empty");
        }
        return false;
    }
}