package org.godn.userservice.service;

import org.godn.userservice.payload.LoginDto;
import org.godn.userservice.payload.RegisterDto;
import org.godn.userservice.model.AuthProvider;
import org.godn.userservice.model.User;
import org.godn.userservice.model.VerificationToken;
import org.godn.userservice.payload.ApiResponseDto;
import org.godn.userservice.payload.AuthResponseDto;
import org.godn.userservice.repository.PasswordResetTokenRepository;
import org.godn.userservice.repository.UserRepository;
import org.godn.userservice.repository.VerificationTokenRepository;
import org.godn.userservice.security.GoogleTokenVerifier;
import org.godn.userservice.security.JwtTokenProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private VerificationTokenRepository verificationTokenRepository;

    @Mock
    private EmailService emailService;

    @Mock
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private GoogleTokenVerifier googleTokenVerifier;

    @InjectMocks
    private AuthServiceImpl authService; // Use the Impl class for injection

    // --- TEST 1: SUCCESSFUL REGISTRATION ---
    @Test
    void testRegister_Success() {
        // 1. Prepare Data
        RegisterDto registerDto = new RegisterDto("Test User", "test@example.com", "password123");

        // 2. Define Mock Behavior
        // User does not exist yet
        when(userRepository.findByEmail(registerDto.getEmail())).thenReturn(Optional.empty());

        // Mock password encoding
        when(passwordEncoder.encode(registerDto.getPassword())).thenReturn("hashed_password");

        // Mock saving the user
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(UUID.randomUUID()); // Simulate DB generating ID
            return user;
        });

        // Mock verification token saving (Important!)
        when(verificationTokenRepository.save(any(VerificationToken.class))).thenReturn(new VerificationToken());

        // Mock sending email (Void method, so just do nothing)
        doNothing().when(emailService).sendVerificationEmail(anyString(), anyString());

        // 3. Execute
        ApiResponseDto response = authService.registerUser(registerDto);

        // 4. Verify
        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertEquals("User registered successfully. Please check your email for the verification code.", response.getMessage());

        // Ensure DB save was called
        verify(userRepository, times(1)).save(any(User.class));
        // Ensure Email was sent
        verify(emailService, times(1)).sendVerificationEmail(eq("test@example.com"), anyString());
    }

    // --- TEST 2: LOGIN SUCCESS ---
    @Test
    void testLogin_Success() {
        // 1. Prepare Data
        org.godn.userservice.payload.LoginDto loginDto = new LoginDto("test@example.com", "password123");

        // Create a mock User from DB
        User mockUser = new User();
        mockUser.setId(UUID.randomUUID());
        mockUser.setEmail("test@example.com");
        mockUser.setPassword("hashed_password");
        mockUser.setProvider(AuthProvider.LOCAL);
        mockUser.setEmailVerified(true); // Must be verified to login

        // 2. Define Mock Behavior
        when(userRepository.findByEmail(loginDto.getEmail())).thenReturn(Optional.of(mockUser));

        // Mock AuthenticationManager success
        Authentication mockAuth = mock(Authentication.class);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(mockAuth);

        // Mock JWT generation
        when(jwtTokenProvider.generateToken(mockUser)).thenReturn("mock-jwt-token");

        // 3. Execute
        AuthResponseDto response = authService.loginUser(loginDto);

        // 4. Verify
        assertNotNull(response);
        assertEquals("mock-jwt-token", response.getAccessToken());
    }
}