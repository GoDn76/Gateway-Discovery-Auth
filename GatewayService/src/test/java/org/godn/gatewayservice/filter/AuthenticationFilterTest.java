package org.godn.gatewayservice.filter;

import org.godn.gatewayservice.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationFilterTest {

    @Mock
    private JwtUtil jwtUtil; // Mock the utility

    @Mock
    private GatewayFilterChain chain; // Mock the filter chain

    private AuthenticationFilter authenticationFilter;

    @BeforeEach
    void setUp() {
        authenticationFilter = new AuthenticationFilter(jwtUtil);
    }

    @Test
    void testFilter_MissingHeader_ReturnsUnauthorized() {
        // 1. Create a Mock Request (No Auth Header)
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/protected").build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);

        // 2. Get the filter logic
        GatewayFilter filter = authenticationFilter.apply(new AuthenticationFilter.Config());

        // 3. Execute
        Mono<Void> result = filter.filter(exchange, chain);

        // 4. Verify Response is 401
        StepVerifier.create(result)
                .expectComplete()
                .verify();

        assert exchange.getResponse().getStatusCode() == HttpStatus.UNAUTHORIZED;
    }

    @Test
    void testFilter_ValidToken_ForwardsRequest() {
        // 1. Create Mock Request WITH Header
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/protected")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);

        // 2. Mock JwtUtil behavior
        doNothing().when(jwtUtil).validateToken("valid-token");
        when(jwtUtil.extractUserId("valid-token")).thenReturn("user-123");
        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

        // 3. Execute
        GatewayFilter filter = authenticationFilter.apply(new AuthenticationFilter.Config());
        filter.filter(exchange, chain).block(); // Block for testing

        // 4. Verify JwtUtil was called and Request was forwarded
        verify(jwtUtil).validateToken("valid-token");
        verify(chain).filter(any(ServerWebExchange.class));

        // Verify the X-User-Id header was added (advanced verification omitted for brevity)
    }
}