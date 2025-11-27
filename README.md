# Gateway Discovery Auth

A Spring Boot–based authentication and gateway/discovery service providing user management, authentication, verification, token handling, and profile APIs. This service is designed to act as a core identity and access layer in a microservices ecosystem, supporting JWT-based authentication and integration with service discovery.

---

## 📌 Overview

Auth Service is responsible for:
- User registration & login
- Email verification flow
- Password reset flow
- JWT token generation & validation
- Profile management
- Centralized authentication for microservices
- Integration with Spring Cloud components (Gateway, Eureka or Discovery services)

This README serves as a complete technical and developer guide for running, developing, and integrating the service.

---

## 🏗️ Architecture

```
                           +---------------------+
                           |  Client / Frontend  |
                           +----------+----------+
                                      |
                                      v
                         +------------+-------------+
                         |   API Gateway (Spring)   |
                         +------------+-------------+
                                      |
                                      v
                       +--------------+---------------+
                       |   Eureka Service Discovery   |
                       +--------------+---------------+
                                      |
                                      v
                    +-----------------+-----------------+
                    |            Auth Service           |
                    +-----------------+-----------------+
                    | Authentication Controller        |
                    | Profile Controller               |
                    | Global Exception Handler         |
                    | JWT Filter & Security Config     |
                    | Service Layer (AuthService, ...) |
                    | Repository Layer                 |
                    +-----------------+-----------------+
                                      |
                                      v
                         +------------+-------------+
                         |      Database (SQL)      |
                         +---------------------------+
```

---

## 🧰 Tech Stack

- **Java 21+**
- **Spring Boot 3+**
- **Spring Security**
- **Spring Web**
- **Spring Data JPA**
- **Validation (Jakarta Validation)**
- **JWT (JSON Web Tokens)**
- **MySQL/PostgreSQL or any SQL DB**
- **Lombok**
- **Maven**
- **Docker & Docker Compose** (optional)

---

## 📁 Folder Structure

```
Gateway-Discovery-Auth/
├── .env                                     <-- Secrets (DB Passwords, JWT Secret, Google Keys)
├── docker-compose.yml                       <-- Orchestrates all services
├── init-db.sh                               <-- Creates 'user_db' & 'health_db' in Postgres
├── pom.xml                                  <-- (Optional) Parent POM if you use Maven modules
│
├── ServiceDiscovery/                        <-- (Eureka Server)
│   ├── Dockerfile
│   ├── pom.xml
│   └── src/main/resources/application.yml   <-- Config: port 8761
│   └── src/main/java/org/godn/servicediscovery/ServiceDiscoveryApplication.java
│
├── GatewayService/                          <-- (API Gateway)
│   ├── Dockerfile
│   ├── pom.xml
│   └── src/
│       ├── main/
│       │   ├── resources/
│       │   │   └── application.yml          <-- Config: port 8080, Routes, Filters, Eureka
│       │   └── java/
│       │       └── org/
│       │           └── godn/
│       │               └── gatewayservice/
│       │                   ├── GatewayServiceApplication.java
│       │                   ├── config/
│       │                   │   └── CorsConfig.java            <-- Global CORS Bean
│       │                   ├── filter/
│       │                   │   └── AuthenticationFilter.java  <-- The "Bouncer" Logic
│       │                   └── util/
│       │                       └── JwtUtil.java               <-- JWT Validation Logic
│       └── test/
│           └── java/
│               └── org/
│                   └── godn/
│                       └── gatewayservice/
│                           └── util/
│                               └── JwtUtilTest.java           <-- Unit Tests
│
└── User-Service/
    ├── Dockerfile                       <-- For containerizing the service
    ├── .env                             <-- Local secrets (Gitignored)
    ├── pom.xml                          <-- Dependencies (Web, Data JPA, Postgres, Security, Eureka, Mail)
    └── src/
        ├── main/
        │   ├── resources/
        │   │   └── application.yml      <-- Config: Port 8081, DB URL, Eureka URL, JWT Secret
        │   │
        │   └── java/
        │       └── org/
        │           └── godn/
        │               └── userservice/
        │                   ├── UserServiceApplication.java  <-- @EnableDiscoveryClient
        │                   │
        │                   ├── config/
        │                   │   ├── AppConfig.java           <-- Beans: PasswordEncoder, AuthenticationManager
        │                   │   └── SecurityConfig.java      <-- Rules: permitAll() (Gateway handles security)
        │                   │
        │                   ├── controller/
        │                   │   ├── AuthController.java      <-- Login, Register, Verify Email
        │                   │   └── ProfileController.java   <-- Get/Update Profile (Reads X-User-Id header)
        │                   │
        │                   ├── exception/
        │                   │   ├── GlobalExceptionHandler.java <-- Returns JSON errors
        │                   │   ├── BadRequestException.java
        │                   │   ├── ResourceNotFoundException.java
        │                   │   └── UnauthorizedException.java
        │                   │
        │                   ├── model/                       <-- Database Entities
        │                   │   ├── User.java
        │                   │   ├── AuthProvider.java        <-- Enum (LOCAL, GOOGLE)
        │                   │   ├── VerificationToken.java
        │                   │   └── PasswordResetToken.java
        │                   │
        │                   ├── payload/                     <-- DTOs (Data Transfer Objects)
        │                   │   ├── ApiResponseDto.java
        │                   │   ├── AuthResponseDto.java
        │                   │   ├── LoginDto.java
        │                   │   ├── RegisterDto.java
        │                   │   ├── GoogleLoginDto.java
        │                   │   ├── OtpVerificationDto.java
        │                   │   ├── EmailDto.java
        │                   │   ├── ResetPasswordDto.java
        │                   │   ├── UserProfileDto.java
        │                   │   └── UpdateProfileDto.java
        │                   │
        │                   ├── repository/                  <-- Database Interfaces
        │                   │   ├── UserRepository.java
        │                   │   ├── VerificationTokenRepository.java
        │                   │   └── PasswordResetTokenRepository.java
        │                   │
        │                   ├── security/
        │                   │   ├── GoogleTokenVerifier.java      <-- Verifies Google ID Tokens
        │                   │   └── JwtTokenProvider.java         <-- Generates JWTs (Doesn't validate them anymore)
        │                   │
        │                   └── service/
        │                       ├── AuthService.java          <-- Interface
        │                       ├── AuthServiceImpl.java      <-- Logic: Register, Login, Reset Pass
        │                       ├── EmailService.java         <-- Logic: Sending SMTP emails
        │                       └── ProfileService.java       <-- Logic: Managing user details
        │
        └── test/
            └── java/
                └── org/
                    └── godn/
                        └── userservice/
                            └── service/
                                └── AuthServiceTest.java      <-- Unit Tests
```

---

## 🚀 Setup & Run Instructions

### **1. Clone the repository**
```bash
git clone https://github.com/GoDn76/Gateway-Discovery-Auth.git
cd Gateway-Discovery-Auth
```

### **2. Configure environment variables**
Create a `.env` file (example below).

### **3. Update database credentials**
Edit `src/main/resources/application.yml` or use env variables.

### **4. Build**
```bash
mvn clean package -DskipTests
```

### **5. Run**
```bash
java -jar target/*.jar
```

---

## 📄 Sample `.env`

```
SPRING_DATASOURCE_URL=jdbc:mysql://localhost:3306/authdb
SPRING_DATASOURCE_USERNAME=root
SPRING_DATASOURCE_PASSWORD=password

JWT_SECRET=my-super-secret-key
JWT_EXPIRATION=3600000

MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=example@gmail.com
MAIL_PASSWORD=yourpassword
```

---

# API Documentation for GatewayService

Generated by automated scan of repository files.

## Controllers & Endpoints

### Controller: `AuthController`

Source file: `User-Service/src/main/java/org/godn/userservice/controller/AuthController.java`

#### `GET` `/`

- Java method: `AuthController` (signature: `public AuthController`)



#### `POST` `/register`

- Java method: `registerUser` (signature: `ResponseEntity<ApiResponseDto> registerUser`)

- Request body type: `registerDto`



#### `POST` `/verify-email`

- Java method: `verifyEmail` (signature: `ResponseEntity<ApiResponseDto> verifyEmail`)

- Request body type: `verificationDto`



#### `POST` `/login`

- Java method: `loginUser` (signature: `ResponseEntity<AuthResponseDto> loginUser`)

- Request body type: `loginDto`



#### `POST` `/login/google`

- Java method: `loginWithGoogle` (signature: `ResponseEntity<AuthResponseDto> loginWithGoogle`)

- Request body type: `googleLoginDto`



#### `POST` `/request-password-reset`

- Java method: `requestPasswordReset` (signature: `ResponseEntity<ApiResponseDto> requestPasswordReset`)

- Request body type: `emailDto`



#### `POST` `/reset-password`

- Java method: `resetPassword` (signature: `ResponseEntity<ApiResponseDto> resetPassword`)

- Request body type: `resetPasswordDto`



### Controller: `ProfileController`

Source file: `User-Service/src/main/java/org/godn/userservice/controller/ProfileController.java`

Class-level base path: `/`

#### `GET` `/`

- Java method: `ProfileController` (signature: `public ProfileController`)



### Controller: `GlobalExceptionHandler`

Source file: `User-Service/src/main/java/org/godn/userservice/exception/GlobalExceptionHandler.java`


## DTOs / Models

### `PasswordResetToken` (file: `User-Service/src/main/java/org/godn/userservice/model/PasswordResetToken.java`)

Fields:

- `id`: `UUID`

- `token`: `String`

- `user`: `User`

- `expiryDate`: `Instant`



### `User` (file: `User-Service/src/main/java/org/godn/userservice/model/User.java`)

Fields:

- `id`: `UUID`

- `name`: `String`

- `email`: `String`

- `password`: `String`

- `provider`: `AuthProvider`

- `providerId`: `String`



### `VerificationToken` (file: `User-Service/src/main/java/org/godn/userservice/model/VerificationToken.java`)

Fields:

- `id`: `UUID`

- `token`: `String`

- `user`: `User`

- `expiryDate`: `Instant`



### `ApiResponseDto` (file: `User-Service/src/main/java/org/godn/userservice/payload/ApiResponseDto.java`)

Fields:

- `success`: `boolean`

- `message`: `String`



### `AuthResponseDto` (file: `User-Service/src/main/java/org/godn/userservice/payload/AuthResponseDto.java`)

Fields:

- `accessToken`: `String`



### `EmailDto` (file: `User-Service/src/main/java/org/godn/userservice/payload/EmailDto.java`)

Fields:

- `email`: `String`



### `GoogleLoginDto` (file: `User-Service/src/main/java/org/godn/userservice/payload/GoogleLoginDto.java`)

Fields:

- `googleToken`: `String`



### `LoginDto` (file: `User-Service/src/main/java/org/godn/userservice/payload/LoginDto.java`)

Fields:

- `email`: `String`

- `password`: `String`



### `OtpVerificationDto` (file: `User-Service/src/main/java/org/godn/userservice/payload/OtpVerificationDto.java`)

Fields:

- `email`: `String`

- `otp`: `String`



### `RegisterDto` (file: `User-Service/src/main/java/org/godn/userservice/payload/RegisterDto.java`)

Fields:

- `name`: `String`

- `email`: `String`

- `password`: `String`



### `ResetPasswordDto` (file: `User-Service/src/main/java/org/godn/userservice/payload/ResetPasswordDto.java`)

Fields:

- `email`: `String`

- `otp`: `String`

- `newPassword`: `String`



### `UpdateProfileDto` (file: `User-Service/src/main/java/org/godn/userservice/payload/UpdateProfileDto.java`)

Fields:

- `name`: `String`



### `UserProfileDto` (file: `User-Service/src/main/java/org/godn/userservice/payload/UserProfileDto.java`)

Fields:

- `name`: `String`

- `email`: `String`

- `emailVerified`: `boolean`




## Services

- `AuthServiceImpl` — `User-Service/src/main/java/org/godn/userservice/service/AuthServiceImpl.java`

- `EmailServiceImpl` — `User-Service/src/main/java/org/godn/userservice/service/EmailServiceImpl.java`

- `ProfileServiceImpl` — `User-Service/src/main/java/org/godn/userservice/service/ProfileServiceImpl.java`


## Configs

- `CorsConfig` — `GatewayService/src/main/java/org/godn/gatewayservice/config/CorsConfig.java`

- `AppConfig` — `User-Service/src/main/java/org/godn/userservice/config/AppConfig.java`

- `OpenApiConfig` — `User-Service/src/main/java/org/godn/userservice/config/OpenApiConfig.java`

- `SecurityConfig` — `User-Service/src/main/java/org/godn/userservice/config/SecurityConfig.java`


It includes:
- All endpoints
- Request/response schemas
- Authentication requirements
- Status codes
- Examples for Postman/Swagger

---

## 🔐 Authentication Flow

```
+------------+         +-------------------+         +------------------+
|   Client   | ---->   |  /auth/login      | ---->   | JWT Generation   |
+------------+         +-------------------+         +------------------+
        |                       |                             |
        | <---------------------+-----------------------------+
        |                 Returns Access Token (JWT)
        |
        | ----> Calls Protected APIs with Authorization: Bearer token
        |
        v
+------------------+
| Security Filter  |
| (JWT Validation) |
+------------------+
        |
        v
+------------------+
|   Controller     |
+------------------+
```

### Steps:
1. User logs in or registers.
2. Server generates **JWT Token**.
3. Client stores it (normally in cookies/localstorage).
4. Every request → `Authorization: Bearer <token>`
5. Token is validated via:
   - Signature check  
   - Expiry check  
   - Role validation (if applied)

---

## 🛠️ Build Instructions

### Maven
```bash
mvn clean package
```

Run tests:
```bash
mvn test
```

---

## 🐳 Docker Instructions (If Docker is present)

### 1. Build Docker image
```bash
docker build -t gateway-auth .
```

### 2. Run container
```bash
docker run -p 8080:8080 --env-file .env gateway-auth
```

### 3. Using Docker Compose
If `docker-compose.yml` exists:
```bash
docker-compose up --build
```

---

## 🤝 Contribution Guide

1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature/my-feature
   ```
3. Commit changes:
   ```bash
   git commit -m "Added new feature"
   ```
4. Push the branch:
   ```bash
   git push origin feature/my-feature
   ```
5. Open a Pull Request.

### Code style guidelines:
- Use meaningful commit messages.
- Follow standard Spring conventions.
- Write JUnit tests where applicable.
- Avoid pushing sensitive data (never commit `.env`).

---

## 📬 Support

For issues, open a GitHub issue or submit a PR.

---

## 👤 Author

Gaurav Uramliya

GoDn76

