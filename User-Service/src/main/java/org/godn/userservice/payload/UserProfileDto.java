package org.godn.userservice.payload;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.godn.userservice.model.AuthProvider;

import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileDto {
    private String name;
    private String email;
    private boolean emailVerified;
    // You could add other fields here later,
    // like profilePictureUrl or bio
}
