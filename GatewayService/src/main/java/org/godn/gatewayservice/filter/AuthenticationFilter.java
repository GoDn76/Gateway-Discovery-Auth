package org.godn.gatewayservice.filter;

import org.godn.gatewayservice.util.JwtUtil;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final JwtUtil jwtUtil;

    public AuthenticationFilter(JwtUtil jwtUtil) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // 0. Check Configuration: Is security enabled for this route?
            if (!config.isEnabled()) {
                return chain.filter(exchange); // Skip security check
            }

            // 1. Check if the request has the Authorization header
            if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "Missing Authorization Header", HttpStatus.UNAUTHORIZED);
            }

            // 2. Extract the Header
            // Note: using Objects.requireNonNull to avoid NullPointerException, though containsKey check usually prevents this.
            String authHeader = Objects.requireNonNull(exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION)).get(0);

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                // 3. Remove the "Bearer " prefix to get the raw token
                authHeader = authHeader.substring(7);
            } else {
                return onError(exchange, "Invalid Authorization Header Format", HttpStatus.UNAUTHORIZED);
            }

            try {
                // 4. Validate the Token (Signature & Expiration)
                jwtUtil.validateToken(authHeader);

                // 5. Extract the User ID from the token
                String userId = jwtUtil.extractUserId(authHeader);

                // 6. Mutate the request to add the 'X-User-Id' header
                // This allows downstream services to know WHO the user is without re-validating.
                ServerHttpRequest request = exchange.getRequest().mutate()
                        .header("X-User-Id", userId)
                        .build();

                // 7. Forward the modified request
                return chain.filter(exchange.mutate().request(request).build());

            } catch (Exception e) {
                // 8. Token validation failed
                // Log it for debugging (optional) but return a clean error to client
                // System.err.println("Invalid Token: " + e.getMessage());
                return onError(exchange, "Invalid Access Token", HttpStatus.UNAUTHORIZED);
            }
        };
    }

    /**
     * Custom Error Handler to return a nice JSON response instead of a blank error page.
     */
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String jsonResponse = String.format("{\"error\": \"%s\", \"status\": %d}", err, httpStatus.value());

        DataBuffer buffer = response.bufferFactory().wrap(jsonResponse.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Flux.just(buffer));
    }

    /**
     * Configuration class to pass settings from application.yml
     */
    public static class Config {
        private boolean enabled = true; // Default is secure

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }
}