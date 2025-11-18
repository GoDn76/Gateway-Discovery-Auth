package org.godn.userservice.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import org.godn.userservice.model.AuthProvider;
import org.godn.userservice.model.PasswordResetToken;
import org.godn.userservice.model.User;
import org.godn.userservice.model.VerificationToken;
import org.godn.userservice.payload.*;
import org.godn.userservice.repository.PasswordResetTokenRepository;
import org.godn.userservice.repository.UserRepository;
import org.godn.userservice.repository.VerificationTokenRepository;
import org.godn.userservice.security.GoogleTokenVerifier;
import org.godn.userservice.security.JwtTokenProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Optional;

@Service
public class AuthServiceImpl implements AuthService {

    private final SecureRandom secureRandom = new SecureRandom();

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final VerificationTokenRepository verificationTokenRepository;
    private final EmailService emailService;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final GoogleTokenVerifier googleTokenVerifier;

    public AuthServiceImpl(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            VerificationTokenRepository verificationTokenRepository,
            EmailService emailService,
            PasswordResetTokenRepository passwordResetTokenRepository,
            AuthenticationManager authenticationManager,
            JwtTokenProvider jwtTokenProvider,
            GoogleTokenVerifier googleTokenVerifier
    ) {


        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.verificationTokenRepository = verificationTokenRepository;
        this.emailService = emailService;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.googleTokenVerifier = googleTokenVerifier;
    }

    /**
     * Helper method to generate a 6-digit OTP (100000 - 999999).
     */
    private String generateOtp() {
        int otp = 100000 + secureRandom.nextInt(900000);
        return String.valueOf(otp);
    }

    /**
     * Creates, saves, and sends a verification OTP for a user.
     * @param user The user to send the token to.
     */
    private void createAndSendVerificationOtp(User user) {
        String otp = generateOtp();
        VerificationToken verificationToken = new VerificationToken(user, otp, 15); // 15 min expiry
        verificationTokenRepository.save(verificationToken);
        emailService.sendVerificationEmail(user.getEmail(), otp);
    }

    /**
     * Creates, saves, and sends a password reset OTP for a user.
     * @param user The user to send the token to.
     */
    private void createAndSendPasswordResetOtp(User user) {
        String otp = generateOtp();
        PasswordResetToken resetToken = new PasswordResetToken(user, otp, 15); // 15 min expiry
        passwordResetTokenRepository.save(resetToken);
        emailService.sendPasswordResetEmail(user.getEmail(), otp);
    }

    @Override
    @Transactional
    public ResponseEntity<?> registerUser(RegisterDto registerDto) {
        Optional<User> existingUser = userRepository.findByEmail(registerDto.getEmail());
        if(existingUser.isPresent()){
            if(existingUser.get().getProvider() == AuthProvider.GOOGLE){
                return ResponseEntity.badRequest().body(new ApiResponseDto(false, "This email is registered with Google. Please use Google Login."));
            } else {
                return ResponseEntity.badRequest().body(new ApiResponseDto(false, "Email is already in use."));
            }
        }

        // Saving User
        User user = new User();
        user.setName(registerDto.getName());
        user.setEmail(registerDto.getEmail());
        user.setPassword(passwordEncoder.encode(registerDto.getPassword()));
        user.setProvider(AuthProvider.LOCAL);
        user.setEmailVerified(false);
        User savedUser = userRepository.save(user);

        // Verification for Email
        createAndSendVerificationOtp(savedUser);
        return ResponseEntity.ok(new ApiResponseDto(true, "User registered successfully. Please check your email for the verification code."));
    }


    // Email Verification
    @Override
    @Transactional
    public ResponseEntity<?> verifyEmail(OtpVerificationDto verificationDto) {
        Optional<User> userOptional = userRepository.findByEmail(verificationDto.getEmail());
        if(userOptional.isEmpty()){
            return ResponseEntity.badRequest().body(new ApiResponseDto(false, "User not found."));
        }

        User user = userOptional.get();
        Optional<VerificationToken> tokenOptional = verificationTokenRepository.findByUser(user);
        if (tokenOptional.isEmpty()) {
            return ResponseEntity.badRequest().body(new ApiResponseDto(false, "No verification token found for this user."));
        }
        VerificationToken token = tokenOptional.get();

        if (!token.getToken().equals(verificationDto.getOtp())) {
            return ResponseEntity.badRequest().body(new ApiResponseDto(false, "Invalid OTP."));
        }

        if (token.getExpiryDate().isBefore(Instant.now())) {
            verificationTokenRepository.delete(token);
            return ResponseEntity.badRequest().body(new ApiResponseDto(false, "OTP has expired. Please register again."));
        }

        user.setEmailVerified(true);
        userRepository.save(user);
        verificationTokenRepository.delete(token);

        return ResponseEntity.ok(new ApiResponseDto(true, "Email verified successfully."));
    }

    @Override
    public ResponseEntity<?> loginUser(LoginDto loginDto) {
        Optional<User> userOptional = userRepository.findByEmail(loginDto.getEmail());

        if(userOptional.isEmpty()){
            return ResponseEntity.status(401).body(new ApiResponseDto(false, "Invalid email or password."));
        }

        User user = userOptional.get();

        // Check if user registered with LOCAL provider
        if(user.getProvider() != AuthProvider.LOCAL){
            return ResponseEntity.badRequest().body(new ApiResponseDto(false, "This account is registered with Google. Please use Google Login."));
        }

        // Check if email is verified
        if(!user.getEmailVerified()){
            return ResponseEntity.status(401).body(new ApiResponseDto(false, "Please verify your email before logging in."));
        }

        // Verify Password using AuthenticationManager
        try{
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginDto.getEmail(),
                            loginDto.getPassword()
                    )
            );

            // If successful, set the authentication in the context
            SecurityContextHolder.getContext().setAuthentication(authentication);
            // Generate a JWT token
            String jwt = jwtTokenProvider.generateToken(user);
            // Return the token in our AuthResponseDto
            return ResponseEntity.ok(new AuthResponseDto(jwt));

        } catch (Exception e) {
            // This catches bad passwords
            return ResponseEntity.status(401).body(new ApiResponseDto(false, "Invalid email or password."));
        }

    }

    @Override
    @Transactional
    public ResponseEntity<?> loginWithGoogle(GoogleLoginDto googleLoginDto) {
        // 1. Verify the Google token
        Optional<GoogleIdToken.Payload> payloadOptional = googleTokenVerifier.verifyToken(googleLoginDto.getGoogleToken());

        if (payloadOptional.isEmpty()) {
            return ResponseEntity.badRequest().body(new ApiResponseDto(false, "Invalid Google Token."));
        }

        GoogleIdToken.Payload payload = payloadOptional.get();
        String email = payload.getEmail();
        String name = (String) payload.get("name");
        String googleId = payload.getSubject();

        // 2. Check our "Account Linking" logic
        Optional<User> userOptional = userRepository.findByEmail(email);

        User user;
        if (userOptional.isPresent()) {
            // User exists
            user = userOptional.get();
            if (user.getProvider() == AuthProvider.LOCAL) {
                return ResponseEntity.badRequest().body(new ApiResponseDto(false, "This email is registered with a password. Please use password login."));
            }
            // If they are already a GOOGLE user, we just log them in.
        } else {
            // User does not exist - this is a NEW REGISTRATION via Google
            user = new User();
            user.setName(name);
            user.setEmail(email);
            user.setProvider(AuthProvider.GOOGLE);
            user.setProviderId(googleId);
            user.setEmailVerified(true); // Google already verified this email
            user = userRepository.save(user);
        }

        // 3. Generate our own JWT for the user
        String jwt = jwtTokenProvider.generateToken(user);

        return ResponseEntity.ok(new AuthResponseDto(jwt));
    }



    // Password Reset feature
    @Override
    @Transactional
    public ResponseEntity<?> requestPasswordReset(EmailDto emailDto) {
        Optional<User> userOptional = userRepository.findByEmail(emailDto.getEmail());
        if (userOptional.isEmpty()) {
            return ResponseEntity.ok(new ApiResponseDto(true, "If an account with this email exists, a reset code has been sent."));
        }
        User user = userOptional.get();

        if(user.getProvider() != AuthProvider.LOCAL) {
            return ResponseEntity.badRequest().body(new ApiResponseDto(false, "Cannot reset password for an account registered with Google."));
        }
        createAndSendPasswordResetOtp(user);

        return ResponseEntity.ok(new ApiResponseDto(true, "If an account with this email exists, a reset code has been sent."));
    }


    // Reset Password
    @Override
    @Transactional
    public ResponseEntity<?> resetPassword(ResetPasswordDto resetDto) {
        Optional<User> userOptional = userRepository.findByEmail(resetDto.getEmail());
        if (userOptional.isEmpty()) {
            return ResponseEntity.badRequest().body(new ApiResponseDto(false, "Invalid user or token."));
        }
        User user = userOptional.get();

        Optional<PasswordResetToken> tokenOptional = passwordResetTokenRepository.findByUser(user);
        if (tokenOptional.isEmpty()) {
            return ResponseEntity.badRequest().body(new ApiResponseDto(false, "No password reset token found."));
        }
        PasswordResetToken token = tokenOptional.get();

        if (!token.getToken().equals(resetDto.getOtp())) {
            return ResponseEntity.badRequest().body(new ApiResponseDto(false, "Invalid OTP."));
        }
        if (token.getExpiryDate().isBefore(Instant.now())) {
            passwordResetTokenRepository.delete(token);
            return ResponseEntity.badRequest().body(new ApiResponseDto(false, "OTP has expired. Please request a new one."));
        }

        user.setPassword(passwordEncoder.encode(resetDto.getNewPassword()));
        userRepository.save(user);
        passwordResetTokenRepository.delete(token);

        return ResponseEntity.ok(new ApiResponseDto(true, "Password reset successfully."));
    }
}
