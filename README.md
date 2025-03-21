# Python-info-sec-TASK2
# API Documentation

## Authorization Functionality

### JWT-Based Authentication
The API uses **JSON Web Tokens (JWT)** to secure protected endpoints. Tokens are generated during login and must be sent in the `Authorization` header as `Bearer <JWT>` with subsequent requests.

---

## User Authentication Endpoints

### `/signup`
- **Purpose**: Allows new users to register by providing their name, username, and password.
- **Security**: Passwords are securely hashed before storage.

### `/login`
- **Purpose**: Authenticates a user based on their username and password.
- **Token Generation**: On successful authentication, a JWT token is generated (valid for 10 minutes) using the user's ID as the identity.

---

## Token Protection with Decorators
Endpoints that require user authorization use the `@jwt_required()` decorator. This decorator:

1. **Verifies Token Presence**: Checks if the request includes a valid JWT in the `Authorization` header.
2. **Validates Token Integrity and Expiration**: Automatically rejects requests with missing, invalid, or expired tokens, ensuring that only authenticated users can access the protected routes.

---

## User-Specific Authorization (Update User Endpoint)

### Endpoint: `/users/<int:id>`
#### How It Works:
1. **Identity Verification**:
   - Uses `get_jwt_identity()` to extract the user ID from the JWT and compares it to the ID in the URL.
2. **Access Control**:
   - If the IDs do not match, the API returns a `403` error ("Unauthorized"), ensuring that users can only update their own information.

---

## Protected Product CRUD Operations

### Endpoints:
All product endpoints (for create, retrieve, update, and delete) are protected with `@jwt_required()`.

### Functionality:
- Only requests with a valid JWT token can perform product operations, thereby preventing unauthorized access or modifications.

---

