# CAMARA Number Verification Resource Server

Spring Boot 4.0.1 implementation of the CAMARA NumberVerification API as an OAuth2 Resource Server with RFC 9068 JWT and JWE support.

**Spring Boot Version:** 4.0.1 (Released December 18, 2024)

## Features

✅ RFC 9068 JWT Profile validation
✅ JWE-encrypted sub claim decryption  
✅ Production-level RSA key management
✅ Comprehensive integration tests
✅ CAMARA API compliance
✅ Spring Boot 4.0 modular architecture

## Key Dependencies

- Spring Boot 4.0.1
- Spring Framework 7.0.2
- Spring Security 7.0.2
- Nimbus JOSE+JWT 9.47
- Bouncy Castle 1.79
- Java 17+

## Quick Start

```bash
# Build
mvn clean package

# Run tests
mvn test

# Run application
mvn spring-boot:run
```

## API Endpoints

- POST `/number-verification/vwip/verify`
- GET `/number-verification/vwip/device-phone-number`

## Manually creating keypairs

mkdir src/test/resources/test-keys/
openssl genrsa -out src/test/resources/test-keys/jwe-private-key.pem 3072

mkdir src/main/resources/keys/
openssl genrsa -out src/main/resources/keys/jwe-private-key.pem 3072

## Testing

Tests automatically generate RSA key pairs and start a mock authorization server on port 18080.

```bash
mvn test
```

Tests include:
- JWT signing and validation
- JWE sub claim encryption/decryption
- Phone number verification (plain and hashed)
- OAuth2 scope validation
- Error handling

## Spring Boot 4.0 Migration Notes

This project uses Spring Boot 4.0's new modular starters:
- `spring-boot-starter-webmvc` (instead of `spring-boot-starter-web`)
- `spring-boot-starter-security-oauth2-resource-server` (renamed)
- `spring-boot-starter-webmvc-test` for testing

See [Spring Boot 4.0 Migration Guide](https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-4.0-Migration-Guide) for details.

## Configuration

See `src/main/resources/application.yml` for configuration options.

### JWE Key Configuration

```yaml
jwe:
  decryption:
    private-key-path: classpath:keys/jwe-private-key.pem
    key-algorithm: RSA-OAEP-256
    content-algorithm: A256GCM
```

## Security Updates

This version includes updated dependencies to address known vulnerabilities:
- Nimbus JOSE+JWT 9.47 (latest)
- Bouncy Castle 1.79 (latest)
- Spring Security 7.0.2
