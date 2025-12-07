//package org.godn.gatewayservice.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.web.cors.CorsConfiguration;
//import org.springframework.web.cors.reactive.CorsWebFilter;
//import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
//@Configuration
//public class CorsConfig {
//
//    @Bean
//    public CorsWebFilter corsWebFilter() {
//        CorsConfiguration config = new CorsConfiguration();
//
//        // 1. Allow Cookies / Credentials
//        // This is important if your frontend sends JWTs or Cookies
//        config.setAllowCredentials(true);
//
//        // 2. Allow Origins (Who can call this API?)
//        // Use addAllowedOriginPattern("*") to allow ALL origins (React localhost, Cloudflare, etc.)
//        // This works even with setAllowCredentials(true).
//        config.addAllowedOriginPattern("*");
//
//        // For production security, you can replace the line above with specific domains:
//        // config.setAllowedOrigins(List.of("http://localhost:3000", "https://your-app.pages.dev"));
//
//        // 3. Allow Headers
//        // "Authorization", "Content-Type", "X-User-Id", etc.
//        config.addAllowedHeader("*");
//
//        // 4. Allow Methods
//        // GET, POST, PUT, DELETE, OPTIONS, etc.
//        config.addAllowedMethod("*");
//
//        // 5. Apply this config to ALL paths in the Gateway
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", config);
//
//        return new CorsWebFilter(source);
//    }
//}