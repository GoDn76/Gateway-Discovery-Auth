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
            // 1. Check if the request has the Authorization header
            if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "Missing Authorization Header");
            }

            String authHeader = Objects.requireNonNull(exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION)).getFirst();

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                // 2. Remove the "Bearer " prefix to get the raw token
                authHeader = authHeader.substring(7);
            } else {
                return onError(exchange, "Invalid Authorization Header Format");
            }

            try {
                // 3. Validate the Token (Signature & Expiration)
                // If invalid, this will throw an exception, caught below.
                jwtUtil.validateToken(authHeader);

                // 4. Extract the User ID from the token
                String userId = jwtUtil.extractUserId(authHeader);

                // 5. Mutate the request to add the 'X-User-Id' header
                // This effectively "logs in" the user for the downstream services (Upload/User Service)
                ServerHttpRequest request = exchange.getRequest().mutate()
                        .header("X-User-Id", userId)
                        .build();

                // 6. Continue the filter chain with the modified request
                return chain.filter(exchange.mutate().request(request).build());

            } catch (Exception e) {
                // 7. Token validation failed
                System.err.println("Invalid Token Access Attempt: " + e.getMessage());
                return onError(exchange, "Invalid Access Token");
            }
        };
    }

    /**
     * Custom Error Handler to return a nice JSON response instead of a blank 401 page.
     */
    private Mono<Void> onError(ServerWebExchange exchange, String err) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String jsonResponse = String.format("{\"error\": \"%s\", \"status\": %d}", err, HttpStatus.UNAUTHORIZED.value());

        DataBuffer buffer = response.bufferFactory().wrap(jsonResponse.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Flux.just(buffer));
    }

    public static class Config {
        // Put any configuration properties here if you need them later
    }
}