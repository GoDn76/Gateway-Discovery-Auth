package org.godn.userservice.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Entity
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(columnNames = "email") // Ensures no duplicate emails
})
@Data // Lombok: Generates getters, setters, toString, equals, hashCode
@NoArgsConstructor // Lombok: Generates a no-argument constructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(updatable = false, nullable = false)
    private UUID id;

    @Column(nullable = false)
    private String name;

    @Email // Validates that the string is a valid email format
    @Column(nullable = false, unique = true)
    private String email;

    // This will be null for users who register with Google
    private String password;

    @NotNull // This field cannot be null
    @Enumerated(EnumType.STRING) // Stores the enum as a string ("LOCAL", "GOOGLE")
    private AuthProvider provider;

    // Stores the unique ID from the OAuth provider (e.g., Google's 'sub' field)
    private String providerId;

    @Column(nullable = false)
    private Boolean emailVerified = false; // Default to false
}
