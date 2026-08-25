# JWT Authentication API

A production-ready, stateless REST API built with **Java 17**, **Spring Boot 3.2**, **Spring Security 6**, and **PostgreSQL**. Demonstrates JWT-based authentication with full **Role-Based Access Control (RBAC)** across three tiers: `USER`, `MODERATOR`, and `ADMIN`. Containerized with Docker and horizontally scalable via Nginx.

---

## Table of Contents

1. [Tech Stack](#tech-stack)
2. [Project Structure](#project-structure)
3. [How JWT Works in This API](#how-jwt-works-in-this-api)
4. [Quick Start](#quick-start)
5. [Environment Variables](#environment-variables)
6. [API Reference](#api-reference)
   - [Auth Endpoints (Public)](#auth-endpoints-public)
   - [User Endpoints (Authenticated)](#user-endpoints-authenticated)
   - [Moderator Endpoints](#moderator-endpoints)
   - [Admin Endpoints](#admin-endpoints)
7. [Role-Based Access Control](#role-based-access-control)
8. [Token Expiry — How to Re-authenticate](#token-expiry--how-to-re-authenticate)
9. [Error Responses](#error-responses)
10. [Running Tests](#running-tests)
11. [Horizontal Scaling](#horizontal-scaling)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Java 17 |
| Framework | Spring Boot 3.2.5 |
| Security | Spring Security 6 + JJWT 0.12.5 |
| Database | PostgreSQL 16 |
| ORM | Spring Data JPA + Hibernate 6 |
| Containerization | Docker + Docker Compose + Nginx |
| Build | Maven 3.9 |
| Tests | JUnit 5 + Mockito + MockMvc + H2 |

---

## Project Structure

```
src/main/java/com/jatin/jwtauth/
├── config/
│   └── SecurityConfig.java          # Filter chain, RBAC URL rules, stateless session
├── controller/
│   ├── AuthController.java          # POST /api/auth/register, /api/auth/login
│   ├── UserController.java          # GET  /api/user/**      (USER+)
│   ├── ModeratorController.java     # GET  /api/moderator/** (MODERATOR+)
│   └── AdminController.java         # ALL  /api/admin/**     (ADMIN only)
├── dto/
│   ├── AuthRequest.java             # { username, password }
│   ├── AuthResponse.java            # { accessToken, tokenType, expiresIn, username, role }
│   ├── AdminRegisterRequest.java    # { username, password, role }
│   ├── ChangeRoleRequest.java       # { role }
│   └── UserSummary.java             # { id, username, role } — no password
├── entity/
│   └── User.java                    # JPA entity with Role enum (USER/MODERATOR/ADMIN)
├── exception/
│   └── GlobalExceptionHandler.java  # Consistent JSON error responses
├── filter/
│   └── JwtAuthFilter.java           # OncePerRequestFilter — reads + validates Bearer token
├── repository/
│   └── UserRepository.java
├── security/
│   └── UserDetailsServiceImpl.java  # Loads user from DB for Spring Security
├── service/
│   ├── AuthService.java             # register + login logic
│   └── AdminService.java            # user management (ADMIN operations)
└── util/
    └── JwtUtil.java                 # Token generation, validation, claim extraction
```

---

## How JWT Works in This API

### What is a JWT?

A JSON Web Token is a compact, URL-safe string split into three Base64-encoded parts separated by `.`:

```
eyJhbGciOiJIUzM4NCJ9   .   eyJyb2xlIjoiVVNFUiIsInN1YiI6ImphdGluIn0   .   <signature>
      HEADER                           PAYLOAD                                SIGNATURE
```

| Part | Content | Description |
|---|---|---|
| **Header** | `{ "alg": "HS384" }` | Signing algorithm used |
| **Payload** | `{ "sub": "jatin", "role": "USER", "iat": 1234567890, "exp": 1234654290 }` | Claims — who you are, when issued, when it expires |
| **Signature** | `HMAC(base64(header) + "." + base64(payload), SECRET_KEY)` | Tamper-proof seal — only the server can produce this |

### Claims this API embeds in every token

| Claim | Meaning |
|---|---|
| `sub` | Username (subject) |
| `role` | The user's role: `USER`, `MODERATOR`, or `ADMIN` |
| `iat` | Issued-at timestamp (Unix epoch seconds) |
| `exp` | Expiry timestamp (Unix epoch seconds) — default **24 hours** after `iat` |

### Auth Flow Diagram

```
┌──────────┐                          ┌───────────────┐              ┌────────┐
│  Client  │                          │  Spring Boot  │              │  DB    │
└──────────┘                          └───────────────┘              └────────┘
     │                                        │                           │
     │  POST /api/auth/register               │                           │
     │  { username, password }  ─────────────►│                           │
     │                                        │── BCrypt hash password    │
     │                                        │── Save user ─────────────►│
     │                                        │◄─ Saved ──────────────────│
     │◄──────── 201 { accessToken } ──────────│                           │
     │                                        │                           │
     │  POST /api/auth/login                  │                           │
     │  { username, password }  ─────────────►│                           │
     │                                        │── Load user ─────────────►│
     │                                        │◄─ User ───────────────────│
     │                                        │── Verify BCrypt hash      │
     │◄──────── 200 { accessToken } ──────────│── Sign JWT                │
     │                                        │                           │
     │  GET /api/user/me                      │                           │
     │  Authorization: Bearer <token> ───────►│                           │
     │                                        │── JwtAuthFilter validates │
     │                                        │   signature + expiry      │
     │                                        │── Sets SecurityContext    │
     │◄──────── 200 { id, username, role } ───│                           │
```

> **Stateless:** The server stores **no session**. Every request is independently verified using the JWT signature and the shared `JWT_SECRET`. This is why the API scales horizontally — any instance can validate any token.

---

## Quick Start

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- Java 17+ and Maven 3.9+ (only needed to run locally without Docker)

### 1 — Clone and configure

```bash
git clone https://github.com/Jatinghataliya/JWT-Authentication-API.git
cd JWT-Authentication-API

# Copy the example env file and fill in your values
copy .env.example .env
```

Open `.env` and set your values:

```env
POSTGRES_DB=jwtauthdb
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_strong_db_password

# Generate a secure 256-bit key:  openssl rand -base64 32
JWT_SECRET=your_base64_encoded_256bit_secret
JWT_EXPIRATION_MS=86400000
```

### 2 — Start with Docker Compose (single instance)

```bash
docker compose up --build
```

The API will be available at `http://localhost:8080`.

### 3 — Start horizontally scaled (3 instances + Nginx load balancer)

```bash
docker compose up --build --scale app=3
```

Nginx round-robins requests across all 3 instances. Still on `http://localhost:8080`.

### 4 — Run locally (no Docker)

Start PostgreSQL separately, then:

```bash
export DB_URL=jdbc:postgresql://localhost:5432/jwtauthdb
export DB_USERNAME=postgres
export DB_PASSWORD=your_password
export JWT_SECRET=your_base64_secret

mvn spring-boot:run
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DB_URL` | `jdbc:postgresql://localhost:5432/jwtauthdb` | JDBC connection URL |
| `DB_USERNAME` | `postgres` | Database username |
| `DB_PASSWORD` | `postgres` | Database password |
| `JWT_SECRET` | *(insecure default — change in prod)* | Base64-encoded 256-bit HMAC key |
| `JWT_EXPIRATION_MS` | `86400000` | Token lifetime in milliseconds (default: 24 hours) |

> **Security note:** Always override `JWT_SECRET` in production. Generate one with:
> ```bash
> openssl rand -base64 32
> ```

---

## API Reference

**Base URL:** `http://localhost:8080`

All protected requests require the header:
```
Authorization: Bearer <your_token>
```

---

### Auth Endpoints (Public)

No token required.

---

#### Register a new user

```
POST /api/auth/register
```

**Request headers:**
```
Content-Type: application/json
```

**Request body:**
```json
{
  "username": "jatin",
  "password": "secret123"
}
```

| Field | Type | Constraints |
|---|---|---|
| `username` | `string` | 3–50 characters, required |
| `password` | `string` | Minimum 6 characters, required |

**Response — `201 Created`:**
```json
{
  "accessToken": "eyJhbGciOiJIUzM4NCJ9.eyJyb2xlIjoiVVNFUiIsInN1YiI6ImphdGluIiwiaWF0IjoxNzA5MDAwMDAwLCJleHAiOjE3MDkwODY0MDB9.SIGNATURE",
  "tokenType": "Bearer",
  "expiresIn": 86400000,
  "username": "jatin",
  "role": "USER"
}
```

> New users always receive the `USER` role. To create a `MODERATOR` or `ADMIN`, use the [Admin create user](#create-user-with-role-admin-only) endpoint.

---

#### Login

```
POST /api/auth/login
```

**Request headers:**
```
Content-Type: application/json
```

**Request body:**
```json
{
  "username": "jatin",
  "password": "secret123"
}
```

**Response — `200 OK`:**
```json
{
  "accessToken": "eyJhbGciOiJIUzM4NCJ9.eyJyb2xlIjoiVVNFUiIsInN1YiI6ImphdGluIiwiaWF0IjoxNzA5MDAwMDAwLCJleHAiOjE3MDkwODY0MDB9.SIGNATURE",
  "tokenType": "Bearer",
  "expiresIn": 86400000,
  "username": "jatin",
  "role": "USER"
}
```

---

### User Endpoints (Authenticated)

Accessible by **all authenticated users** (USER, MODERATOR, ADMIN).

**Required header on every request:**
```
Authorization: Bearer <accessToken>
```

---

#### Get my profile

```
GET /api/user/me
```

**Response — `200 OK`:**
```json
{
  "id": 1,
  "username": "jatin",
  "role": "USER"
}
```

---

#### User dashboard

```
GET /api/user/dashboard
```

**Response — `200 OK`:**
```json
{
  "message": "Welcome, jatin!",
  "access": "USER level"
}
```

---

### Moderator Endpoints

Accessible by **MODERATOR** and **ADMIN** only.

---

#### Moderator dashboard

```
GET /api/moderator/dashboard
```

**Response — `200 OK`:**
```json
{
  "message": "Moderator Dashboard",
  "access": "MODERATOR level"
}
```

---

#### List all users

```
GET /api/moderator/users
```

**Response — `200 OK`:**
```json
[
  { "id": 1, "username": "jatin",     "role": "USER"      },
  { "id": 2, "username": "mod1",      "role": "MODERATOR" },
  { "id": 3, "username": "superuser", "role": "ADMIN"     }
]
```

---

#### Get user by ID

```
GET /api/moderator/users/{id}
```

**Response — `200 OK`:**
```json
{
  "id": 1,
  "username": "jatin",
  "role": "USER"
}
```

---

### Admin Endpoints

Accessible by **ADMIN** only.

---

#### Admin dashboard

```
GET /api/admin/dashboard
```

**Response — `200 OK`:**
```json
{
  "message": "Admin Dashboard",
  "access": "ADMIN level — full control"
}
```

---

#### Create user with role (Admin only)

```
POST /api/admin/users
```

**Request headers:**
```
Content-Type: application/json
Authorization: Bearer <admin_token>
```

**Request body:**
```json
{
  "username": "mod1",
  "password": "securepass",
  "role": "MODERATOR"
}
```

| `role` value | Description |
|---|---|
| `USER` | Standard user |
| `MODERATOR` | Can view all users |
| `ADMIN` | Full administrative access |

**Response — `201 Created`:**
```json
{
  "accessToken": "eyJhbGciOiJIUzM4NCJ9...",
  "tokenType": "Bearer",
  "expiresIn": 86400000,
  "username": "mod1",
  "role": "MODERATOR"
}
```

---

#### List all users (Admin)

```
GET /api/admin/users
```

**Response — `200 OK`:**
```json
[
  { "id": 1, "username": "jatin", "role": "USER" },
  { "id": 2, "username": "mod1",  "role": "MODERATOR" }
]
```

---

#### Get user by ID (Admin)

```
GET /api/admin/users/{id}
```

**Response — `200 OK`:**
```json
{
  "id": 1,
  "username": "jatin",
  "role": "USER"
}
```

---

#### Change a user's role

```
PATCH /api/admin/users/{id}/role
```

**Request headers:**
```
Content-Type: application/json
Authorization: Bearer <admin_token>
```

**Request body:**
```json
{
  "role": "MODERATOR"
}
```

**Response — `200 OK`:**
```json
{
  "id": 1,
  "username": "jatin",
  "role": "MODERATOR"
}
```

---

#### Delete a user

```
DELETE /api/admin/users/{id}
```

**Response — `204 No Content`** (empty body)

---

## Role-Based Access Control

### Permission Matrix

| Endpoint | USER | MODERATOR | ADMIN |
|---|:---:|:---:|:---:|
| `POST /api/auth/register` | ✅ | ✅ | ✅ |
| `POST /api/auth/login` | ✅ | ✅ | ✅ |
| `GET /api/user/me` | ✅ | ✅ | ✅ |
| `GET /api/user/dashboard` | ✅ | ✅ | ✅ |
| `GET /api/moderator/dashboard` | ❌ | ✅ | ✅ |
| `GET /api/moderator/users` | ❌ | ✅ | ✅ |
| `GET /api/moderator/users/{id}` | ❌ | ✅ | ✅ |
| `GET /api/admin/dashboard` | ❌ | ❌ | ✅ |
| `POST /api/admin/users` | ❌ | ❌ | ✅ |
| `GET /api/admin/users` | ❌ | ❌ | ✅ |
| `GET /api/admin/users/{id}` | ❌ | ❌ | ✅ |
| `PATCH /api/admin/users/{id}/role` | ❌ | ❌ | ✅ |
| `DELETE /api/admin/users/{id}` | ❌ | ❌ | ✅ |

### Two Layers of Defence

Every admin/moderator endpoint is protected at **two independent layers**:

```
HTTP Request
     │
     ▼
┌────────────────────────────────────────┐
│  Layer 1: SecurityConfig               │   URL pattern rules
│  .requestMatchers("/api/admin/**")     │   Returns 403 if role doesn't match
│   .hasRole("ADMIN")                    │
└────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────┐
│  Layer 2: @PreAuthorize on controller  │   Method-level annotation
│  @PreAuthorize("hasRole('ADMIN')")     │   Returns 403 if role doesn't match
└────────────────────────────────────────┘
     │
     ▼
  Controller method executes
```

---

## Token Expiry — How to Re-authenticate

### Understanding token expiry

Every token contains an `exp` (expiry) claim. The default is **24 hours** after login. Once expired, every API call returns:

```
HTTP/1.1 401 Unauthorized
```

```json
"Invalid or expired JWT token"
```

### How to decode and inspect your token

Paste any token into [jwt.io](https://jwt.io) to read its payload:

```json
{
  "role": "USER",
  "sub": "jatin",
  "iat": 1709000000,
  "exp": 1709086400
}
```

Convert `exp` to a human-readable date:
```bash
# Linux / macOS
date -d @1709086400

# PowerShell
[DateTimeOffset]::FromUnixTimeSeconds(1709086400).LocalDateTime
```

### How to get a new token (re-login)

This API is **stateless** — there is no refresh token endpoint. When your token expires, simply call login again with your credentials:

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "jatin", "password": "secret123"}'
```

You will receive a fresh token with a new `exp` 24 hours from now.

> **In a real production app** you would implement a Refresh Token — a long-lived, single-use token stored in the database that lets you obtain a new access token without re-entering your password. This is intentionally left as a learning exercise.

### Adjusting the expiry window

Change `JWT_EXPIRATION_MS` in your `.env` file:

| Value | Duration |
|---|---|
| `900000` | 15 minutes |
| `3600000` | 1 hour |
| `86400000` | 24 hours *(default)* |
| `604800000` | 7 days |

---

## Error Responses

All errors follow the same JSON shape:

```json
{
  "timestamp": "2024-02-27T10:30:00",
  "status": 400,
  "error": "Bad Request",
  "message": "Human-readable description"
}
```

| HTTP Status | When it happens |
|---|---|
| `400 Bad Request` | Validation failed, duplicate username, user not found |
| `401 Unauthorized` | No token provided, expired token, invalid signature |
| `403 Forbidden` | Valid token but insufficient role |
| `500 Internal Server Error` | Unexpected server error |

---

## Running Tests

```bash
# Run all 54 tests
mvn test

# Run only a specific test class
mvn test -Dtest="RoleBasedControllerIntegrationTest"

# Run with verbose output
mvn test -B
```

### Test coverage summary

| Test Class | Count | Type |
|---|---|---|
| `JwtUtilTest` | 9 | Unit |
| `AuthServiceTest` | 5 | Unit (Mockito) |
| `JwtAuthFilterTest` | 6 | Unit (Mockito) |
| `AuthControllerIntegrationTest` | 8 | Integration (MockMvc + H2) |
| `DemoControllerIntegrationTest` | 8 | Integration (MockMvc + H2) |
| `RoleBasedControllerIntegrationTest` | 18 | Integration (MockMvc + H2) |
| **Total** | **54** | |

> Integration tests use an **H2 in-memory database** — no PostgreSQL needed to run tests.

---

## Horizontal Scaling

The API is designed to scale without any changes to the code:

```bash
# Run 3 app instances behind the Nginx load balancer
docker compose up --build --scale app=3
```

```
Client → Nginx (port 8080) → Round-robin → [ App:1 | App:2 | App:3 ]
                                                        ↓
                                              Shared PostgreSQL DB
```

**Why it works:**
- **No server-side session** — `SessionCreationPolicy.STATELESS` in `SecurityConfig`
- **Shared `JWT_SECRET`** — all instances use the same env variable, so any instance can validate any token
- **Shared database** — all instances read/write the same PostgreSQL instance

---

## License

MIT — free to use for learning and production.

---

*Built with Spring Boot 3 · Spring Security 6 · JJWT 0.12 · PostgreSQL · Docker*
