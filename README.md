# Gateway-Discovery-Auth

> A microservices backend architecture using API Gateway, Service
> Discovery, and User Authentication.

## 🧭 Overview

Gateway-Discovery-Auth is a modular microservice backend built to
demonstrate distributed architecture patterns. It includes:

-   **Service Discovery** --- dynamic registration/discovery of
    microservices\
-   **API Gateway** --- unified entry point that routes traffic to
    microservices\
-   **User Service** --- handles authentication and user-related
    operations

## 📂 Project Structure

    /
    ├── GatewayService/         # Handles API gateway routing and authentication
    ├── ServiceDiscovery/       # Service registration and discovery server
    ├── User-Service/           # User management & authentication microservice
    ├── docker-compose.yml      # Spin up all services using Docker
    └── README.md

## 🚀 Getting Started

### Prerequisites

-   Java (JDK 17+ recommended)
-   Docker & Docker Compose
-   Git

### Clone the Repository

``` bash
git clone https://github.com/GoDn76/Gateway-Discovery-Auth.git
cd Gateway-Discovery-Auth
```

### Run All Services via Docker

``` bash
docker-compose up
```

## 📄 API Examples

### Register a User

``` bash
curl -X POST http://localhost:<gateway_port>/users/register   -H "Content-Type: application/json"   -d '{ "name": "Test User", "email": "testuser@gmail.com", "password": "password123" }'
```

### Fetch User Profile

``` bash
curl http://localhost:<gateway_port>/users/profile   -H "Authorization: Bearer <token>"
```

## 🛣️ Roadmap

-   Implement OpenAPI/Swagger documentation
-   Add DB persistence
-   Add RBAC support
-   Add monitoring/logging stack

## 👤 Author

GoDn76
