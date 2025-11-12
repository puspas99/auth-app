
# Auth App

A Spring Boot 3 application implementing JWT-based authentication and authorization with refresh tokens and role-based access control.

## Features

- JWT access tokens with configurable expiration
- Refresh token rotation for security
- Role-based access control (RBAC)
- User registration and login
- PostgreSQL database integration
- Flyway database migrations
- Docker support for development
- Comprehensive test coverage

## Tech Stack

- **Java 17**
- **Spring Boot 3.x**
- **Spring Security**
- **Spring Data JPA**
- **PostgreSQL**
- **JWT (JJWT library)**
- **Flyway**
- **Docker & Docker Compose**

## Quick Start

### Prerequisites

- Java 17+
- Docker & Docker Compose
- Maven 3.6+

### Running with Docker Compose (Recommended)

1. Clone the repository
2. Set environment variables (see Environment Variables section)
3. Run the application:

```bash
docker-compose up --build
```

The application will be available at `http://localhost:8080`

### Running Locally

1. Set up PostgreSQL database
2. Set environment variables
3. Run the application:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

### Running Tests

```bash
mvn test
```

## Environment Variables

Set the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SPRING_DATASOURCE_URL` | PostgreSQL database URL | `jdbc:postgresql://localhost:5432/authdb` |
| `SPRING_DATASOURCE_USERNAME` | Database username | `postgres` |
| `SPRING_DATASOURCE_PASSWORD` | Database password | `password` |
| `JWT_SECRET` | JWT signing secret (min 32 chars) | `change_me` |
| `ADMIN_PASSWORD` | Initial admin user password | `admin123` |

**⚠️ Important**: Change default values in production!

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout (revoke refresh token)

### User Management
- `GET /api/users/me` - Get current user profile (authenticated)
- `GET /api/admin/users` - Get all users (admin only)

### Documentation
- `GET /swagger-ui.html` - Swagger UI documentation
- `GET /v3/api-docs` - OpenAPI specification

## Default Users

The application seeds the following default data:

### Roles
- `ROLE_USER` - Standard user role
- `ROLE_ADMIN` - Administrator role

### Admin User
If `ADMIN_PASSWORD` environment variable is set, an admin user is created:
- Username: `admin`
- Email: `admin@evoke.com`
- Role: `ROLE_ADMIN`

## Token Configuration

- **Access Token**: 15 minutes (900,000 ms)
- **Refresh Token**: 30 days (2,592,000,000 ms)
- **Algorithm**: HS256

## Database Schema

The application uses Flyway for database migrations. The initial schema includes:

- `users` - User accounts
- `roles` - User roles
- `users_roles` - User-role associations
- `refresh_tokens` - Refresh token storage

## Development

### Database Setup

The docker-compose configuration includes a PostgreSQL database. For local development without Docker:

1. Install PostgreSQL
2. Create database: `createdb authdb`
3. Set environment variables to point to your local database

### Building Docker Image

```bash
docker build -t auth-app .
```

### CI/CD

GitHub Actions workflow is included for:
- Running tests
- Building Docker image
- Optional image publishing (configure secrets)

## Security Considerations

- Passwords are hashed using BCrypt
- JWT tokens are stateless
- Refresh tokens are stored in database and rotated on use
- CSRF protection disabled for API endpoints
- CORS can be configured as needed
- Input validation on all endpoints
- Proper exception handling with consistent error responses

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License.
