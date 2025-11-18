package org.godn.userservice.repository;

import org.godn.userservice.model.User;
import org.godn.userservice.model.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, UUID> {

    // A method to find a token by its string value
    Optional<VerificationToken> findByToken(String token);

    // A method to find a token associated with a specific user
    Optional<VerificationToken> findByUser(User user);
}
