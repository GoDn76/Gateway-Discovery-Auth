package org.godn.userservice.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Data
@NoArgsConstructor
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(updatable = false, nullable = false)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String token; // The 6-digit OTP

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private Instant expiryDate;

    /**
     * Helper constructor to easily create a new token for a user.
     * @param user The user requesting the reset.
     * @param token The unique 6-digit OTP.
     * @param expiryDurationInMinutes How long the token should be valid.
     */
    public PasswordResetToken(User user, String token, long expiryDurationInMinutes) {
        this.user = user;
        this.token = token;
        this.expiryDate = Instant.now().plusSeconds(expiryDurationInMinutes * 60);
    }
}