package org.godn.userservice.service;

import org.godn.userservice.payload.UpdateProfileDto;
import org.godn.userservice.payload.UserProfileDto;

public interface ProfileService {
    UserProfileDto getUserProfile(String email);

    // Update the profile of the currently logged-in user
    UserProfileDto updateProfile(String email, UpdateProfileDto updateProfileDto);
}
