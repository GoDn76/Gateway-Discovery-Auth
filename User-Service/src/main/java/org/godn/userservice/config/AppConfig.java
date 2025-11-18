package org.godn.userservice.config;

import org.godn.userservice.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

@Configuration
public class AppConfig {

    private final UserRepository userRepository;

    public AppConfig(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // --- Moved from SecurityConfig ---
    @Bean
    public UserDetailsService userDetailsService() {
        return email -> {
            org.godn.userservice.model.User appUser = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

            return new org.springframework.security.core.userdetails.User(
                    appUser.getEmail(),
                    appUser.getPassword(),
                    appUser.getEmailVerified(),
                    true,
                    true,
                    true,
                    Collections.emptyList()
            );
        };
    }

    // --- Moved from SecurityConfig ---
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // --- Moved from SecurityConfig ---
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}