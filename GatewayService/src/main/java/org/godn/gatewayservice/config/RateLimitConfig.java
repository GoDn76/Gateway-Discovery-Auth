package org.godn.gatewayservice.config;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Configuration
public class RateLimitConfig {

    @Bean
    public KeyResolver userKeyResolver() {
        return exchange -> {
            // 1. Try to get User ID from headers (Added by your AuthFilter)
            String userId = exchange.getRequest().getHeaders().getFirst("X-User-ID");

            // 2. If not logged in, use IP Address
            if (userId == null) {
                userId = Objects.requireNonNull(exchange.getRequest().getRemoteAddress()).getAddress().getHostAddress();
            }

            return Mono.just(userId);
        };
    }
}