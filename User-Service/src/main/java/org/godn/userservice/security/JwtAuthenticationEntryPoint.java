package org.godn.userservice.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.godn.userservice.payload.ApiResponseDto;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        // 1. Set the response status to 401 Unauthorized
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        // 2. Set the content type to JSON
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        // 3. Create our standard error response object
        ApiResponseDto apiResponse = new ApiResponseDto(false, "Unauthorized: " + authException.getMessage());

        // 4. Write the JSON manually to the response stream
        // (We can't use ResponseEntity here because we are inside a Filter, not a Controller)
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), apiResponse);
    }
}
