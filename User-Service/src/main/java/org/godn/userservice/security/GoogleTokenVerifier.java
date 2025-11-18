package org.godn.userservice.security;


import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Optional;


@Component
public class GoogleTokenVerifier {

    private final GoogleIdTokenVerifier verifier;
    private final String googleClientId;

    public GoogleTokenVerifier(
            @Value("${spring.security.oauth2.client.registration.google.client-id}") String googleClientId
    ) {
        this.googleClientId = googleClientId;
        this.verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new GsonFactory())
                .setAudience(Collections.singletonList(googleClientId))
                .build();
    }


    /**
     * Verifies the Google ID token and returns the payload if valid.
     * @param idTokenString The token from the GoogleLoginDto
     * @return An Optional containing the token payload, or empty if invalid.
     */
    public Optional<GoogleIdToken.Payload> verifyToken(String idTokenString) {
        try {
            GoogleIdToken idToken = verifier.verify(idTokenString);
            if (idToken != null) {
                // Check if the token's audience matches our client ID
                if (idToken.getPayload().getAudience().equals(googleClientId)) {
                    return Optional.of(idToken.getPayload());
                }
            }
        } catch (GeneralSecurityException | IOException e) {
            // Log the error (we'll add logging later)
            // e.g., log.error("Token verification failed: {}", e.getMessage());
        }
        return Optional.empty();
    }


}
