package org.godn.userservice.controller;

import jakarta.validation.Valid;
import org.godn.userservice.payload.UpdateProfileDto;
import org.godn.userservice.payload.UserProfileDto;
import org.godn.userservice.service.ProfileService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
// NOTE: This must match the path the Gateway sends.
// If Gateway path is /api/user/** and NO StripPrefix filter, use "/api/user" here.
@RequestMapping("/api/user")
public class ProfileController {

    private final ProfileService profileService;

    public ProfileController(ProfileService profileService) {
        this.profileService = profileService;
    }

    /**
     * Get the current user's profile.
     * The 'X-User-Id' header is injected by the API Gateway after validating the JWT.
     * It contains the 'sub' (Subject) from the token (usually Email or DB ID).
     */
    @GetMapping("/me")
    public ResponseEntity<UserProfileDto> getUserProfile(@RequestHeader("X-User-Id") String userId) {
        // Assuming your service looks up by Email/Username (which is what userId likely holds)
        UserProfileDto profile = profileService.getUserProfile(userId);
        return ResponseEntity.ok(profile);
    }

    /**
     * Update the current user's profile.
     */
    @PutMapping("/me")
    public ResponseEntity<UserProfileDto> updateProfile(
            @RequestHeader("X-User-Id") String userId,
            @Valid @RequestBody UpdateProfileDto updateProfileDto
    ) {
        UserProfileDto updatedProfile = profileService.updateProfile(userId, updateProfileDto);
        return ResponseEntity.ok(updatedProfile);
    }
}