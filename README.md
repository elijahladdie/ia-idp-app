# Spring Boot Identity Provider System

A production-ready Identity Provider (IdP) built with Spring Boot that provides centralized authentication services for multiple internal applications.

## Features

### Authentication Methods
- **Email + Password Authentication** with mandatory email verification
- **LinkedIn OAuth 2.0 Integration** with full authorization code flow
- Secure password hashing using BCrypt with complexity requirements

### Token Management
- **JWT Access Tokens** (15 minutes expiry) signed with RSA private key (RS256)
- **Refresh Tokens** (30 days expiry) with automatic rotation and single-use policy
- **JWKS Endpoint** for public key distribution at `/.well-known/jwks.json`

### Security Features
- RSA 2048-bit key pair for JWT signing
- OAuth 2.0 client registration and validation
- Token revocation (single device and all devices)
- Email verification with time-limited tokens (24-hour expiry)
- Input validation and SQL injection prevention
- CORS configuration for cross-origin requests

## API Endpoints

### Authentication
- `POST /auth/register` - Register new user with email/password
- `POST /auth/login` - Authenticate with email/password
- `POST /auth/linkedin` - LinkedIn OAuth authentication
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Logout single device
- `POST /auth/logout-all` - Logout all devices

### Verification & Keys
- `GET /auth/verify-email?token=<token>` - Verify email address
- `GET /.well-known/jwks.json` - JSON Web Key Set for token verification
- `GET /health` - Health check endpoint

## Quick Start

### Prerequisites
- Java 17+
- PostgreSQL 12+
- Maven 3.6+

### Database Setup
1. Create PostgreSQL database:
```sql
CREATE DATABASE idp_db;
CREATE USER idp_user WITH PASSWORD 'idp_password';
GRANT ALL PRIVILEGES ON DATABASE idp_db TO idp_user;
```

### Configuration
1. Update `src/main/resources/application.properties`:
```properties
# Database
spring.datasource.url=jdbc:postgresql://localhost:5432/idp_db
spring.datasource.username=idp_user
spring.datasource.password=idp_password

# LinkedIn OAuth (optional)
linkedin.client-id=your-linkedin-client-id
linkedin.client-secret=your-linkedin-client-secret

# Email Configuration
spring.mail.host=smtp.gmail.com
spring.mail.username=your-email@gmail.com
spring.mail.password=your-app-password
```

### Run the Application
```bash
mvn spring-boot:run
```

The application will start on `http://localhost:8080`

## Usage Examples

### Register a New User
```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "firstName": "John",
    "lastName": "Doe",
    "clientId": "test-client-id"
  }'
```

### Login
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "clientId": "test-client-id"
  }'
```

### Refresh Token
```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "your-refresh-token",
    "clientId": "test-client-id"
  }'
```

### Get JWKS for Token Verification
```bash
curl http://localhost:8080/.well-known/jwks.json
```

## Client Integration

### Verifying JWT Tokens
Client applications can verify JWT tokens using the public key from the JWKS endpoint:

```java
// Example: Verify JWT token in a client application
String jwksUrl = "http://localhost:8080/.well-known/jwks.json";
JwkProvider provider = new UrlJwkProvider(new URL(jwksUrl));
Jwk jwk = provider.get("key-1"); // key ID from token header
Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
JWTVerifier verifier = JWT.require(algorithm).build();
DecodedJWT jwt = verifier.verify(token);
```

### OAuth Client Registration
Register your client application by inserting into the database:

```sql
INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, is_active) 
VALUES ('your-client-id', '$2a$12$...', 'Your App Name', true);

INSERT INTO oauth_client_redirect_uris (client_id, redirect_uri)
VALUES ('your-client-id', 'https://yourapp.com/auth/callback');

INSERT INTO oauth_client_grant_types (client_id, grant_type)
VALUES ('your-client-id', 'AUTHORIZATION_CODE'), ('your-client-id', 'REFRESH_TOKEN');
```

## LinkedIn OAuth Setup

1. Create a LinkedIn App at https://www.linkedin.com/developers/
2. Configure redirect URI: `http://localhost:8080/auth/linkedin/callback`
3. Update application.properties with your LinkedIn credentials
4. Use the authorization URL: `GET /auth/linkedin/authorize?state=<random-state>`

## Security Considerations

### Password Requirements
- Minimum 8 characters
- At least one lowercase letter
- At least one uppercase letter  
- At least one digit
- At least one special character

### Token Security
- Access tokens expire in 15 minutes
- Refresh tokens expire in 30 days and are single-use
- All tokens are cryptographically signed
- Refresh tokens are hashed before storage

### Email Verification
- Verification tokens expire in 24 hours
- Email verification is mandatory by default
- LinkedIn emails are pre-verified

## Development

### Running Tests
```bash
mvn test
```

### Building for Production
```bash
mvn clean package
java -jar target/identity-provider-1.0.0.jar
```

### Docker Deployment
```dockerfile
FROM openjdk:17-jdk-slim
COPY target/identity-provider-1.0.0.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

## Monitoring

### Health Check
```bash
curl http://localhost:8080/health
```

### Logging
Application logs include:
- Authentication attempts and failures
- Token generation and validation
- Email verification events
- OAuth flow details

## Architecture

### Database Schema
- **users** - User accounts and profile information
- **refresh_tokens** - Active refresh tokens with expiration
- **oauth_clients** - Registered client applications
- **oauth_client_redirect_uris** - Allowed redirect URIs per client
- **oauth_client_grant_types** - Allowed grant types per client

### Key Components
- **AuthenticationService** - Core authentication logic
- **JwtService** - JWT token operations and JWKS generation
- **LinkedInService** - OAuth 2.0 integration with LinkedIn
- **EmailService** - Email verification and notifications

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For issues and questions, please create an issue in the project repository.
