package org.godn.gatewayservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                // Disable CSRF (because we use JWTs, not sessions)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)

                // Allow ALL requests (The Gateway Routes + Custom Filters will handle specific security)
                .authorizeExchange(exchanges -> exchanges
                        .anyExchange().permitAll()
                )

                // Disable default HTTP Basic Auth (This is the culprit for the 401!)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable);

        return http.build();
    }
}