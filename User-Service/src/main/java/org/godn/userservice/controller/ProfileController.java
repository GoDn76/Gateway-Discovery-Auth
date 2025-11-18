package org.godn.userservice.controller;

import jakarta.validation.Valid;
import org.godn.userservice.payload.UpdateProfileDto;
import org.godn.userservice.payload.UserProfileDto;
import org.godn.userservice.service.ProfileService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
// We use /users here, and Gateway strips nothing for this path usually, OR Gateway strips /users.
// WAIT: In your Gateway config, you strip prefix.
// If Gateway sends "/users/me" -> strips "users" -> sends "/me".
// So this controller should map to "/" or "/me" depending on your gateway config.
// Let's assume Gateway sends "/users/me" -> "/me"
@RequestMapping({"/users", "/"})
public class ProfileController {
    private final ProfileService profileService;

    public ProfileController(ProfileService profileService) {
        this.profileService = profileService;
    }

    /**
     * Get the current user's profile.
     * Path: GET /me
     */
    @GetMapping("/me")
    public UserProfileDto getUserProfile(@AuthenticationPrincipal UserDetails userDetails) {
        String email = userDetails.getUsername();
        return profileService.getUserProfile(email);
    }

    /**
     * Update the current user's profile.
     * Path: PUT /me
     */
    @PutMapping("/me")
    public ResponseEntity<UserProfileDto> updateProfile(@AuthenticationPrincipal UserDetails userDetails,
                                                        @Valid @RequestBody UpdateProfileDto updateProfileDto) {
        String email = userDetails.getUsername();
        return ResponseEntity.ok(profileService.updateProfile(email, updateProfileDto));
    }
}
