# Full Stack FastAPI Template - Architecture Document

## Table of Contents
1. [System Overview](#system-overview)
2. [Architecture Patterns](#architecture-patterns)
3. [System Architecture](#system-architecture)
4. [Component Architecture](#component-architecture)
5. [Data Flow Diagrams](#data-flow-diagrams)
6. [Security Architecture](#security-architecture)
7. [Deployment Architecture](#deployment-architecture)
8. [Domain Knowledge](#domain-knowledge)
9. [Technology Stack](#technology-stack)
10. [API Design](#api-design)

## System Overview

The Full Stack FastAPI Template is a modern, production-ready web application template that provides a complete foundation for building scalable web applications. It follows a microservices-inspired architecture with clear separation of concerns between frontend and backend components.

### Key Characteristics
- **Full-Stack**: Complete frontend and backend solution
- **Modern Stack**: Latest technologies and best practices
- **Production-Ready**: Includes deployment, monitoring, and security features
- **Scalable**: Designed for horizontal scaling
- **Secure**: Built-in authentication, authorization, and security measures
- **Developer-Friendly**: Comprehensive testing, documentation, and development tools

## Architecture Patterns

### 1. Layered Architecture
The application follows a layered architecture pattern:

```
┌─────────────────────────────────────┐
│           Presentation Layer        │
│         (React Frontend)            │
└─────────────────────────────────────┘
┌─────────────────────────────────────┐
│           API Gateway Layer         │
│         (Traefik Proxy)             │
└─────────────────────────────────────┘
┌─────────────────────────────────────┐
│           Application Layer         │
│         (FastAPI Backend)           │
└─────────────────────────────────────┘
┌─────────────────────────────────────┐
│           Data Access Layer         │
│         (SQLModel ORM)              │
└─────────────────────────────────────┘
┌─────────────────────────────────────┐
│           Data Storage Layer        │
│         (PostgreSQL Database)       │
└─────────────────────────────────────┘
```

### 2. Repository Pattern
The backend implements the repository pattern through CRUD operations in `crud.py`, providing a clean abstraction layer between business logic and data access.

### 3. Dependency Injection
FastAPI's dependency injection system is used throughout the application for managing dependencies, authentication, and database sessions.

## System Architecture

### High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Internet                                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Traefik Proxy                                    │
│                    (Load Balancer & SSL Termination)                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    │                   │                   │
                    ▼                   ▼                   ▼
┌─────────────────────────┐ ┌─────────────────────────┐ ┌─────────────────────────┐
│    Frontend Container   │ │    Backend Container    │ │   Adminer Container     │
│   (React + Vite)        │ │   (FastAPI + Uvicorn)   │ │   (Database Admin)      │
│   Port: 80              │ │   Port: 8000            │ │   Port: 8080            │
└─────────────────────────┘ └─────────────────────────┘ └─────────────────────────┘
                    │                   │                   │
                    └───────────────────┼───────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PostgreSQL Database                                  │
│                           Port: 5432                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Container Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Docker Compose Stack                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │   Frontend      │    │    Backend      │    │   Adminer       │         │
│  │   Container     │    │   Container     │    │   Container     │         │
│  │                 │    │                 │    │                 │         │
│  │  React 18       │    │  FastAPI        │    │  Adminer        │         │
│  │  TypeScript     │    │  SQLModel       │    │  Database UI    │         │
│  │  Chakra UI      │    │  Pydantic       │    │                 │         │
│  │  TanStack Router│    │  JWT Auth       │    │                 │         │
│  │  Vite           │    │  Email Service  │    │                 │         │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘         │
│           │                       │                       │                 │
│           └───────────────────────┼───────────────────────┘                 │
│                                   │                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    PostgreSQL Database                              │   │
│  │                                                                     │   │
│  │  - Users Table                                                      │   │
│  │  - Items Table                                                      │   │
│  │  - Alembic Migrations                                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Architecture

### Backend Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FastAPI Application                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │   API Routes    │    │   Core Config   │    │   Security      │         │
│  │                 │    │                 │    │                 │         │
│  │  - /login       │    │  - Settings     │    │  - JWT Tokens   │         │
│  │  - /users       │    │  - Environment  │    │  - Password     │         │
│  │  - /items       │    │  - Database     │    │    Hashing      │         │
│  │  - /utils       │    │  - Email        │    │  - CORS         │         │
│  │  - /private     │    │  - Sentry       │    │                 │         │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘         │
│           │                       │                       │                 │
│           └───────────────────────┼───────────────────────┘                 │
│                                   │                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Business Logic                               │   │
│  │                                                                     │   │
│  │  - CRUD Operations                                                  │   │
│  │  - Authentication                                                   │   │
│  │  - Email Services                                                   │   │
│  │  - Data Validation                                                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Data Models                                  │   │
│  │                                                                     │   │
│  │  - User Models                                                      │   │
│  │  - Item Models                                                      │   │
│  │  - Token Models                                                     │   │
│  │  - SQLModel Integration                                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Database Layer                               │   │
│  │                                                                     │   │
│  │  - SQLModel ORM                                                     │   │
│  │  - PostgreSQL Connection                                            │   │
│  │  - Alembic Migrations                                               │   │
│  │  - Session Management                                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Frontend Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           React Application                               │
├─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │   UI Components │    │   State Mgmt    │    │   Routing       │         │
│  │                 │    │                 │    │                 │         │
│  │  - Chakra UI    │    │  - React Query  │    │  - TanStack     │         │
│  │  - Custom       │    │  - Local Storage│    │    Router       │         │
│  │    Components   │    │  - Context      │    │  - Route Guards │         │
│  │  - Dark Mode    │    │                 │    │  - Navigation   │         │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘         │
│           │                       │                       │                 │
│           └───────────────────────┼───────────────────────┘                 │
│                                   │                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        API Client                                   │   │
│  │                                                                     │   │
│  │  - Auto-generated from OpenAPI                                      │   │
│  │  - Axios HTTP Client                                                │   │
│  │  - JWT Token Management                                             │   │
│  │  - Error Handling                                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Pages & Features                             │   │
│  │                                                                     │   │
│  │  - Authentication (Login/Register)                                  │   │
│  │  - Dashboard                                                        │   │
│  │  - User Management                                                  │   │
│  │  - Item Management                                                  │   │
│  │  - Settings                                                         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow Diagrams

### Authentication Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Frontend  │    │   Backend   │    │  Database   │    │   Email     │
│             │    │             │    │             │    │  Service    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       │ 1. Login Request  │                   │                   │
       │ ──────────────────►                   │                   │
       │                   │                   │                   │
       │                   │ 2. Validate User  │                   │
       │                   │ ──────────────────►                   │
       │                   │                   │                   │
       │                   │ 3. User Found     │                   │
       │                   │ ◄──────────────────                   │
       │                   │                   │                   │
       │                   │ 4. Verify Password│                   │
       │                   │ ──────────────────►                   │
       │                   │                   │                   │
       │                   │ 5. Password Valid │                   │
       │                   │ ◄──────────────────                   │
       │                   │                   │                   │
       │ 6. JWT Token      │                   │                   │
       │ ◄──────────────────                   │                   │
       │                   │                   │                   │
       │ 7. Store Token    │                   │                   │
       │ (LocalStorage)    │                   │                   │
       │                   │                   │                   │
```

### User Registration Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Frontend  │    │   Backend   │    │  Database   │    │   Email     │
│             │    │             │    │             │    │  Service    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       │ 1. Register Form  │                   │                   │
       │ ──────────────────►                   │                   │
       │                   │                   │                   │
       │                   │ 2. Validate Data  │                   │
       │                   │                   │                   │
       │                   │ 3. Hash Password  │                   │
       │                   │                   │                   │
       │                   │ 4. Create User    │                   │
       │                   │ ──────────────────►                   │
       │                   │                   │                   │
       │                   │ 5. User Created   │                   │
       │                   │ ◄──────────────────                   │
       │                   │                   │                   │
       │ 6. Success        │                   │                   │
       │ ◄──────────────────                   │                   │
       │                   │                   │                   │
```

### Item Management Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Frontend  │    │   Backend   │    │  Database   │
│             │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       │ 1. CRUD Request   │                   │
       │ (with JWT)        │                   │
       │ ──────────────────►                   │
       │                   │                   │
       │                   │ 2. Verify Token   │
       │                   │                   │
       │                   │ 3. Authorize User │
       │                   │                   │
       │                   │ 4. Execute CRUD   │
       │                   │ ──────────────────►
       │                   │                   │
       │                   │ 5. Data Response  │
       │                   │ ◄──────────────────
       │                   │                   │
       │ 6. Update UI      │                   │
       │ ◄──────────────────                   │
       │                   │                   │
```

## Security Architecture

### Security Layers

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Security Architecture                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Transport Security                           │   │
│  │                                                                     │   │
│  │  - HTTPS/TLS (Traefik)                                             │   │
│  │  - CORS Configuration                                               │   │
│  │  - Secure Headers                                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Authentication                               │   │
│  │                                                                     │   │
│  │  - JWT Tokens                                                       │   │
│  │  - Password Hashing (bcrypt)                                        │   │
│  │  - Token Expiration                                                 │   │
│  │  - Refresh Token Logic                                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Authorization                                │   │
│  │                                                                     │   │
│  │  - Role-based Access Control                                        │   │
│  │  - Superuser Privileges                                             │   │
│  │  - Resource Ownership                                               │   │
│  │  - API Endpoint Protection                                          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Data Security                                │   │
│  │                                                                     │   │
│  │  - Input Validation (Pydantic)                                      │   │
│  │  - SQL Injection Prevention                                         │   │
│  │  - XSS Protection                                                    │   │
│  │  - CSRF Protection                                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### JWT Token Structure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           JWT Token Structure                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Header:                                                                   │
│  {                                                                         │
│    "alg": "HS256",                                                        │
│    "typ": "JWT"                                                           │
│  }                                                                         │
│                                                                             │
│  Payload:                                                                  │
│  {                                                                         │
│    "sub": "user-uuid",                                                    │
│    "exp": "expiration-timestamp",                                         │
│    "iat": "issued-at-timestamp"                                           │
│  }                                                                         │
│                                                                             │
│  Signature:                                                                │
│  HMACSHA256(base64UrlEncode(header) + "." +                               │
│             base64UrlEncode(payload), secret_key)                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Deployment Architecture

### Production Deployment

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Production Environment                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Traefik Proxy                                │   │
│  │                                                                     │   │
│  │  - SSL/TLS Termination                                              │   │
│  │  - Load Balancing                                                    │   │
│  │  - Automatic HTTPS (Let's Encrypt)                                   │   │
│  │  - Domain Routing                                                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Application Stack                            │   │
│  │                                                                     │   │
│  │  - Frontend: dashboard.domain.com                                   │   │
│  │  - Backend: api.domain.com                                          │   │
│  │  - Adminer: adminer.domain.com                                      │   │
│  │  - Traefik Dashboard: traefik.domain.com                            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Infrastructure                               │   │
│  │                                                                     │   │
│  │  - Docker Containers                                                │   │
│  │  - PostgreSQL Database                                              │   │
│  │  - Persistent Volumes                                               │   │
│  │  - Health Checks                                                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### CI/CD Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CI/CD Pipeline                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐   │
│  │   GitHub    │    │   GitHub    │    │   Self-     │    │   Production│   │
│  │   Push      │    │   Actions   │    │   Hosted    │    │   Server    │   │
│  │             │    │             │    │   Runner    │    │             │   │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘   │
│        │                    │                    │                    │     │
│        │ 1. Code Push       │                    │                    │     │
│        │ ──────────────────►                    │                    │     │
│        │                    │                    │                    │     │
│        │                    │ 2. Trigger Build   │                    │     │
│        │                    │ ──────────────────►                    │     │
│        │                    │                    │                    │     │
│        │                    │                    │ 3. Build & Test   │     │
│        │                    │                    │ ──────────────────►     │
│        │                    │                    │                    │     │
│        │                    │                    │ 4. Deploy         │     │
│        │                    │                    │ ◄──────────────────     │
│        │                    │                    │                    │     │
│        │                    │ 5. Success        │                    │     │
│        │                    │ ◄──────────────────                    │     │
│        │                    │                    │                    │     │
│        │ 6. Status Update   │                    │                    │     │
│        │ ◄──────────────────                    │                    │     │
│        │                    │                    │                    │     │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Domain Knowledge

### Business Domain

The application serves as a template for building user management and item management systems. The core business entities are:

#### User Management Domain
- **User Registration**: New users can register with email and password
- **User Authentication**: Secure login with JWT token-based authentication
- **User Authorization**: Role-based access control (regular users vs superusers)
- **Password Management**: Secure password reset via email
- **User Profile**: Users can update their profile information

#### Item Management Domain
- **Item Creation**: Users can create items with title and description
- **Item Ownership**: Items are associated with their creators
- **Item Management**: CRUD operations for items with proper authorization
- **Item Listing**: Users can view items they own

#### Administrative Domain
- **User Administration**: Superusers can manage all users
- **System Monitoring**: Health checks and system status
- **Email Management**: Password reset and notification emails

### Data Models

#### User Entity
```python
class User:
    id: UUID (Primary Key)
    email: EmailStr (Unique, Indexed)
    hashed_password: str
    full_name: str (Optional)
    is_active: bool
    is_superuser: bool
    items: List[Item] (Relationship)
```

#### Item Entity
```python
class Item:
    id: UUID (Primary Key)
    title: str
    description: str (Optional)
    owner_id: UUID (Foreign Key to User)
    owner: User (Relationship)
```

#### Token Entity
```python
class Token:
    access_token: str
    token_type: str = "bearer"
```

### Business Rules

1. **Authentication Rules**:
   - Users must provide valid email and password for login
   - Passwords must be at least 8 characters long
   - JWT tokens expire after 8 days
   - Inactive users cannot log in

2. **Authorization Rules**:
   - Users can only access their own items
   - Superusers can access all resources
   - Regular users cannot access administrative functions

3. **Data Validation Rules**:
   - Email addresses must be valid format
   - Item titles must be 1-255 characters
   - Item descriptions must be 0-255 characters
   - User names must be 0-255 characters

4. **Security Rules**:
   - Passwords are hashed using bcrypt
   - JWT tokens are signed with secret key
   - CORS is configured for security
   - Input validation prevents injection attacks

### Workflows

#### User Registration Workflow
1. User submits registration form
2. System validates input data
3. System checks if email is already registered
4. System hashes password
5. System creates user record
6. System returns success response

#### User Login Workflow
1. User submits login credentials
2. System validates email format
3. System retrieves user by email
4. System verifies password hash
5. System checks if user is active
6. System generates JWT token
7. System returns token to client

#### Password Reset Workflow
1. User requests password reset
2. System validates email exists
3. System generates reset token
4. System sends email with reset link
5. User clicks reset link
6. System validates reset token
7. System updates password
8. System confirms password change

#### Item Management Workflow
1. User authenticates with JWT token
2. System validates token and user
3. User performs CRUD operation
4. System validates authorization
5. System executes database operation
6. System returns result to user

## Technology Stack

### Backend Technologies

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Framework** | FastAPI | 0.114.2+ | Modern Python web framework |
| **ORM** | SQLModel | 0.0.21+ | SQL database toolkit and ORM |
| **Database** | PostgreSQL | 17 | Primary database |
| **Validation** | Pydantic | 2.0+ | Data validation and settings |
| **Authentication** | JWT + bcrypt | Latest | Token-based auth and password hashing |
| **Email** | emails + Jinja2 | Latest | Email templating and sending |
| **Migrations** | Alembic | 1.12.1+ | Database migration tool |
| **Testing** | pytest | 7.4.3+ | Testing framework |
| **Linting** | ruff | 0.2.2+ | Fast Python linter |
| **Type Checking** | mypy | 1.8.0+ | Static type checker |

### Frontend Technologies

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Framework** | React | 18.2.0+ | UI library |
| **Language** | TypeScript | 5.2.2+ | Type-safe JavaScript |
| **Build Tool** | Vite | 6.3.4+ | Fast build tool |
| **UI Library** | Chakra UI | 3.8.0+ | Component library |
| **Routing** | TanStack Router | 1.19.1+ | Type-safe routing |
| **State Management** | TanStack Query | 5.28.14+ | Server state management |
| **HTTP Client** | Axios | 1.9.0+ | HTTP client |
| **Forms** | React Hook Form | 7.49.3+ | Form handling |
| **Testing** | Playwright | 1.52.0+ | E2E testing |
| **Code Quality** | Biome | 1.9.4+ | Linter and formatter |

### Infrastructure Technologies

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Containerization** | Docker | Application packaging |
| **Orchestration** | Docker Compose | Multi-container deployment |
| **Reverse Proxy** | Traefik | Load balancing and SSL |
| **SSL Certificates** | Let's Encrypt | Automatic HTTPS |
| **CI/CD** | GitHub Actions | Automated deployment |
| **Monitoring** | Sentry | Error tracking |
| **Database Admin** | Adminer | Database management UI |

## API Design

### RESTful API Structure

The API follows RESTful principles with the following structure:

```
/api/v1/
├── /login/
│   ├── POST /access-token          # User login
│   ├── POST /test-token            # Validate token
│   ├── POST /password-recovery/{email}  # Request password reset
│   └── POST /reset-password/       # Reset password
├── /users/
│   ├── GET /                       # List users (admin only)
│   ├── POST /                      # Create user (admin only)
│   ├── GET /me                     # Get current user
│   ├── PUT /me                     # Update current user
│   ├── PUT /me/password            # Change password
│   ├── GET /{user_id}              # Get user by ID (admin only)
│   ├── PUT /{user_id}              # Update user (admin only)
│   └── DELETE /{user_id}           # Delete user (admin only)
├── /items/
│   ├── GET /                       # List items
│   ├── POST /                      # Create item
│   ├── GET /{item_id}              # Get item by ID
│   ├── PUT /{item_id}              # Update item
│   └── DELETE /{item_id}           # Delete item
├── /utils/
│   └── GET /health-check/          # Health check
└── /private/                       # Development endpoints
```

### API Response Format

All API responses follow a consistent format:

```json
{
  "data": {
    // Response data
  },
  "count": 10,  // For list responses
  "message": "Success message"  // For simple responses
}
```

### Error Handling

The API uses standard HTTP status codes and provides detailed error messages:

```json
{
  "detail": "Error description",
  "status_code": 400
}
```

### Authentication

All protected endpoints require a JWT token in the Authorization header:

```
Authorization: Bearer <jwt_token>
```

### Rate Limiting

The API implements rate limiting to prevent abuse and ensure fair usage.

### Documentation

The API includes automatic OpenAPI/Swagger documentation available at `/docs` and `/redoc` endpoints.

---

*This architecture document provides a comprehensive overview of the Full Stack FastAPI Template system, including its design patterns, components, data flows, security measures, and deployment strategies. It serves as a reference for developers, architects, and stakeholders involved in the project.*
