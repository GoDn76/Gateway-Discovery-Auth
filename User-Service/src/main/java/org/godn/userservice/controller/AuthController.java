package org.godn.userservice.controller;

import org.godn.userservice.payload.*;
import org.godn.userservice.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/")
public class AuthController {

    private final AuthService authService;

    // We use constructor injection for the service
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Endpoint for user registration.
     * Accessible via: POST http://localhost:9090/users/register
     */
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterDto registerDto) {
        // @Valid triggers validation on the DTO
        return authService.registerUser(registerDto);
    }

    /**
     * Endpoint for verifying a user's email with an OTP.
     * Accessible via: POST http://localhost:9090/users/verify-email
     */
    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@Valid @RequestBody OtpVerificationDto verificationDto) {
        return authService.verifyEmail(verificationDto);
    }

    /**
     * Endpoint for standard email/password login.
     * Accessible via: POST <a href="http://localhost:9090/users/login">...</a>
     */
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginDto loginDto) {
        return authService.loginUser(loginDto);
    }

    /**
     * Endpoint to request a password reset OTP.
     * Accessible via: POST http://localhost:9090/users/request-password-reset
     */
    @PostMapping("/request-password-reset")
    public ResponseEntity<?> requestPasswordReset(@Valid @RequestBody EmailDto emailDto) {
        return authService.requestPasswordReset(emailDto);
    }

    /**
     * Endpoint to set a new password using an OTP.
     * Accessible via: POST http://localhost:9090/users/reset-password
     */
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordDto resetPasswordDto) {
        return authService.resetPassword(resetPasswordDto);
    }

    /**
     * Endpoint for Google Sign-In.
     * Accessible via: POST http://localhost:9090/login/google
     */
    @PostMapping("/login/google")
    public ResponseEntity<?> loginWithGoogle(@Valid @RequestBody GoogleLoginDto googleLoginDto) {
        return authService.loginWithGoogle(googleLoginDto);
    }
}
