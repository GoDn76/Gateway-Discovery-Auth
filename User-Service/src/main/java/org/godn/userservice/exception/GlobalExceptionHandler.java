package org.godn.userservice.exception;

import org.godn.userservice.payload.ApiResponseDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
    /**
     * 1. HANDLE VALIDATION ERRORS
     * This triggers when @Valid fails (e.g., OTP is 7 digits instead of 6).
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponseDto> handleValidationExceptions(MethodArgumentNotValidException ex) {
        // Extract the specific error message from the annotation (e.g., "OTP must be 6 digits")
        String errorMessage = ex.getBindingResult().getAllErrors().getFirst().getDefaultMessage();

        // Return a clean JSON response
        return new ResponseEntity<>(new ApiResponseDto(false, errorMessage), HttpStatus.BAD_REQUEST);
    }

    /**
     * 2. HANDLE LOGIC ERRORS
     * This triggers when we throw new RuntimeException("User not found") in our service.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponseDto> handleRuntimeExceptions(RuntimeException ex) {
        return new ResponseEntity<>(new ApiResponseDto(false, ex.getMessage()), HttpStatus.BAD_REQUEST);
    }

    /**
     * 3. HANDLE UNEXPECTED ERRORS
     * This catches anything else we didn't plan for (like NullPointerException).
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponseDto> handleGlobalException(Exception ex) {
        return new ResponseEntity<>(new ApiResponseDto(false, "An unexpected error occurred: " + ex.getMessage()), HttpStatus.INTERNAL_SERVER_ERROR);
    }

}
