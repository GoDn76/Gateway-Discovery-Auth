package org.godn.userservice.repository;

import org.godn.userservice.model.PasswordResetToken;
import org.godn.userservice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {

    // A method to find a token by its string value
    Optional<PasswordResetToken> findByToken(String token);

    // A method to find a token associated with a specific user
    Optional<PasswordResetToken> findByUser(User user);
}