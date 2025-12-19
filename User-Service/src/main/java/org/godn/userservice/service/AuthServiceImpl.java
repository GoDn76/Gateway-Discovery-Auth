package org.godn.userservice.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import org.godn.userservice.exception.BadRequestException;
import org.godn.userservice.exception.ResourceNotFoundException;
import org.godn.userservice.exception.UnauthorizedException;
import org.godn.userservice.model.*;
import org.godn.userservice.payload.*;
import org.godn.userservice.repository.PasswordResetTokenRepository;
import org.godn.userservice.repository.UserRepository;
import org.godn.userservice.repository.VerificationTokenRepository;
import org.godn.userservice.security.GoogleTokenVerifier;
import org.godn.userservice.security.JwtTokenProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

@Service
@Transactional
public class AuthServiceImpl implements AuthService {

    private final SecureRandom secureRandom = new SecureRandom();
    private static final int OTP_EXPIRY_MINUTES = 15;

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
     * Helper: Generates OTP and Updates/Creates the token in DB.
     */
    private void createAndSendVerificationOtp(User user) {
        String otp = generateOtp();

        // 1. Calculate Expiry: Current Time + 15 Minutes
        Instant expiryTime = Instant.now().plus(OTP_EXPIRY_MINUTES, ChronoUnit.MINUTES);

        // 2. Fetch or Create
        VerificationToken verificationToken = verificationTokenRepository.findByUser(user)
                .orElse(new VerificationToken(user, otp, OTP_EXPIRY_MINUTES));

        // 3. Update Token & Expiry
        verificationToken.setToken(otp);
        verificationToken.setExpiryDate(expiryTime); // ✅ Correct: Now + 15 mins

        verificationTokenRepository.save(verificationToken);

        // NOTE: Ensure sendVerificationEmail is annotated with @Async in EmailService
        emailService.sendVerificationEmail(user.getEmail(), otp);
    }

    /**
     * Helper: Password Reset OTP
     */
    private void createAndSendPasswordResetOtp(User user) {
        String otp = generateOtp();

        // 1. Calculate Expiry: Current Time + 15 Minutes
        Instant expiryTime = Instant.now().plus(OTP_EXPIRY_MINUTES, ChronoUnit.MINUTES);

        PasswordResetToken resetToken = passwordResetTokenRepository.findByUser(user)
                .orElse(new PasswordResetToken(user, otp, OTP_EXPIRY_MINUTES));

        resetToken.setToken(otp);
        resetToken.setExpiryDate(expiryTime); // ✅ Correct

        passwordResetTokenRepository.save(resetToken);

        emailService.sendPasswordResetEmail(user.getEmail(), otp);
    }

    private String generateOtp() {
        // Your OTP generation logic (e.g., Random 6 digits)
        return String.valueOf(new SecureRandom().nextInt(900000) + 100000);
    }

    @Override
    @Transactional
    public ApiResponseDto registerUser(RegisterDto registerDto) {
        Optional<User> existingUserOpt = userRepository.findByEmail(registerDto.getEmail());

        if (existingUserOpt.isPresent()) {
            User existingUser = existingUserOpt.get();

            if (existingUser.getProvider() == AuthProvider.GOOGLE) {
                throw new BadRequestException("This email is registered with Google. Please use Google Login.");
            }

            if (!existingUser.getEmailVerified()) {
                // Overwrite OLD details with NEW details
                existingUser.setName(registerDto.getName());
                existingUser.setPassword(passwordEncoder.encode(registerDto.getPassword()));
                existingUser.setProvider(AuthProvider.LOCAL); // Ensure provider is reset to LOCAL if needed
                userRepository.save(existingUser);
                createAndSendVerificationOtp(existingUser);

                return new ApiResponseDto(true, "A new verification code has been sent to your email.");
            }

            // 3. Handle Verified Account Conflict
            throw new BadRequestException("Email is already in use.");
        }

        // 4. Handle New User Registration
        User user = new User();
        user.setName(registerDto.getName());
        user.setEmail(registerDto.getEmail());
        user.setPassword(passwordEncoder.encode(registerDto.getPassword()));
        user.setProvider(AuthProvider.LOCAL);
        user.setEmailVerified(false);

        User savedUser = userRepository.save(user);

        createAndSendVerificationOtp(savedUser);

        return new ApiResponseDto(true, "User registered successfully. Please check your email for the verification code.");
    }


    @Override
    @Transactional
    public ApiResponseDto verifyEmail(OtpVerificationDto verificationDto) {
        User user = userRepository.findByEmail(verificationDto.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException("User", "email", verificationDto.getEmail()));

        VerificationToken token = verificationTokenRepository.findByUser(user)
                .orElseThrow(() -> new BadRequestException("No verification token found for this user."));

        if (!token.getToken().equals(verificationDto.getOtp())) {
            System.out.println(token.getToken() + " is Not Equal to " + verificationDto.getOtp());
            throw new BadRequestException("Invalid OTP.");
        }

        if (token.getExpiryDate().isBefore(Instant.now())) {
            verificationTokenRepository.delete(token);
            throw new BadRequestException("OTP has expired. Please register again.");
        }

        user.setEmailVerified(true);
        userRepository.save(user);
        verificationTokenRepository.delete(token);

        return new ApiResponseDto(true, "Email verified successfully.");
    }

    @Override
    public AuthResponseDto loginUser(LoginDto loginDto) {
        User user = userRepository.findByEmail(loginDto.getEmail())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password."));

        if (user.getProvider() != AuthProvider.LOCAL) {
            throw new BadRequestException("This account is registered with Google. Please use Google Login.");
        }

        if (!user.getEmailVerified()) {
            throw new UnauthorizedException("Please verify your email before logging in.");
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword())
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtTokenProvider.generateToken(user);
            return new AuthResponseDto(jwt);

        } catch (AuthenticationException e) {
            throw new BadCredentialsException("Invalid email or password.");
        }
    }

    @Override
    @Transactional
    public AuthResponseDto loginWithGoogle(GoogleLoginDto googleLoginDto) {
        Optional<GoogleIdToken.Payload> payloadOptional = googleTokenVerifier.verifyToken(googleLoginDto.getGoogleToken());

        if (payloadOptional.isEmpty()) {
            throw new BadRequestException("Invalid Google Token.");
        }

        GoogleIdToken.Payload payload = payloadOptional.get();
        String email = payload.getEmail();
        String name = (String) payload.get("name");
        String googleId = payload.getSubject();

        Optional<User> userOptional = userRepository.findByEmail(email);
        User user;

        if (userOptional.isPresent()) {
            user = userOptional.get();
            if (user.getProvider() == AuthProvider.LOCAL) {
                throw new BadRequestException("This email is registered with a password. Please use password login.");
            }
        } else {
            user = new User();
            user.setName(name);
            user.setEmail(email);
            user.setProvider(AuthProvider.GOOGLE);
            user.setProviderId(googleId);
            user.setEmailVerified(true);
            user = userRepository.save(user);
        }

        String jwt = jwtTokenProvider.generateToken(user);
        return new AuthResponseDto(jwt);
    }

    @Override
    @Transactional
    public ApiResponseDto requestPasswordReset(EmailDto emailDto) {
        Optional<User> userOptional = userRepository.findByEmail(emailDto.getEmail());

        if (userOptional.isEmpty()) {
            return new ApiResponseDto(true, "If an account with this email exists, a reset code has been sent.");
        }

        User user = userOptional.get();

        if (user.getProvider() != AuthProvider.LOCAL) {
            throw new BadRequestException("Cannot reset password for an account registered with Google.");
        }

        createAndSendPasswordResetOtp(user);
        return new ApiResponseDto(true, "If an account with this email exists, a reset code has been sent.");
    }

    @Override
    @Transactional
    public ApiResponseDto resetPassword(ResetPasswordDto resetDto) {
        User user = userRepository.findByEmail(resetDto.getEmail())
                .orElseThrow(() -> new BadRequestException("Invalid request."));

        PasswordResetToken token = passwordResetTokenRepository.findByUser(user)
                .orElseThrow(() -> new BadRequestException("No password reset token found."));

        if (!token.getToken().equals(resetDto.getOtp())) {
            throw new BadRequestException("Invalid OTP.");
        }

        if (token.getExpiryDate().isBefore(Instant.now())) {
            passwordResetTokenRepository.delete(token);
            throw new BadRequestException("OTP has expired. Please request a new one.");
        }

        user.setPassword(passwordEncoder.encode(resetDto.getNewPassword()));
        userRepository.save(user);
        passwordResetTokenRepository.delete(token);

        return new ApiResponseDto(true, "Password reset successfully.");
    }
}