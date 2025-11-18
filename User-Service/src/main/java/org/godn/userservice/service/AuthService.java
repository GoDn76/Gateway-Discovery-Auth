package org.godn.userservice.service;

import org.godn.userservice.payload.*;
import org.springframework.http.ResponseEntity;

public interface AuthService {
        /**
         * Registers a new user with the LOCAL (email/password) provider.
         * Generates a verification OTP and sends it via email.
         *
         * @param registerDto DTO containing name, email, and password.
         * @return A standard ApiResponseDto.
         */
    ResponseEntity<?> registerUser(RegisterDto registerDto);

        /**
         * Verifies a user's email using the provided OTP.
         *
         * @param verificationDto DTO containing email and OTP.
         * @return A standard ApiResponseDto.
         */
    ResponseEntity<?> verifyEmail(OtpVerificationDto verificationDto);

        /**
         * Authenticates a user with their email and password.
         *
         * @param loginDto DTO containing email and password.
         * @return A ResponseEntity containing an AuthResponseDto (with JWT) on success.
         */
    ResponseEntity<?> loginUser(LoginDto loginDto);

        /**
         * Authenticates a user via their Google Token.
         *
         * @param googleLoginDto DTO containing the Google token.
         * @return A ResponseEntity containing an AuthResponseDto (with JWT) on success.
         */
    ResponseEntity<?> loginWithGoogle(GoogleLoginDto googleLoginDto);

        /**
         * Initiates the password reset process for a user.
         * Generates a 6-digit OTP and sends it via email.
         *
         * @param emailDto DTO containing the user's email.
         * @return A standard ApiResponseDto.
         */
    ResponseEntity<?> requestPasswordReset(EmailDto emailDto);

        /**
         * Resets a user's password after they have verified their OTP.
         *
         * @param resetPasswordDto DTO containing email, OTP, and new password.
         * @return A standard ApiResponseDto.
         */
    ResponseEntity<?> resetPassword(ResetPasswordDto resetPasswordDto);
}
