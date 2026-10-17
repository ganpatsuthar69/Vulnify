# Vulnify API Contract

## Authentication & User Management Endpoints

All authenticated endpoints use cookie-based session management (`httpOnly` session cookie named `vulnify_session`). State-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) require the `X-Requested-With: vulnify` header and validate the `Origin` header to prevent CSRF attacks.

---

### 1. `POST /api/auth/register`

Registers a new user account with default `user` role and issues an `httpOnly` session cookie upon success.

#### Request
- **Method**: `POST`
- **Path**: `/api/auth/register`
- **Headers**:
  - `Content-Type: application/json`
  - `X-Requested-With: vulnify`
- **Body**:
  ```json
  {
    "name": "Jane Doe",
    "email": "jane@example.com",
    "password": "<min_8_chars_password>"
  }
  ```

#### Responses
- **`201 Created`**: User registered and authenticated.
  - **Headers**: `Set-Cookie: vulnify_session=<token>; HttpOnly; SameSite=Lax; Path=/`
  - **Body**:
    ```json
    {
      "id": "uuid-v4-string",
      "email": "jane@example.com",
      "name": "Jane Doe",
      "role": "user"
    }
    ```
- **`409 Conflict`**: An account with this email address already exists.
  - **Body**:
    ```json
    {
      "detail": "An account with this email already exists."
    }
    ```
- **`422 Unprocessable Entity`**: Validation failure (short password, invalid email format, empty name).

---

### 2. `POST /api/auth/login`

Authenticates a registered user with email and password and issues an `httpOnly` session cookie upon success.

#### Request
- **Method**: `POST`
- **Path**: `/api/auth/login`
- **Headers**:
  - `Content-Type: application/json`
  - `X-Requested-With: vulnify`
- **Body**:
  ```json
  {
    "email": "jane@example.com",
    "password": "<user_password>"
  }
  ```

#### Responses
- **`200 OK`**: Successfully authenticated.
  - **Headers**: `Set-Cookie: vulnify_session=<token>; HttpOnly; SameSite=Lax; Path=/`
  - **Body**:
    ```json
    {
      "id": "uuid-v4-string",
      "email": "jane@example.com",
      "name": "Jane Doe",
      "role": "user"
    }
    ```
- **`401 Unauthorized`**: Invalid email or password.
  - **Body**:
    ```json
    {
      "detail": "Invalid email or password."
    }
    ```
- **`429 Too Many Attempts`**: Rate limit exceeded (5 failed logins per 15 minutes).
  - **Headers**: `Retry-After: <seconds>` (integer)
  - **Body**:
    ```json
    {
      "detail": "Too many attempts. Try again in 900s."
    }
    ```

---

### 3. `GET /api/auth/me`

Retrieves the currently authenticated user's profile.

#### Request
- **Method**: `GET`
- **Path**: `/api/auth/me`
- **Credentials**: `include` (transmits `httpOnly` session cookie)

#### Responses
- **`200 OK`**: Valid session.
  - **Body**:
    ```json
    {
      "id": "uuid-v4-string",
      "email": "jane@example.com",
      "name": "Jane Doe",
      "role": "user"
    }
    ```
- **`401 Unauthorized`**: Missing, expired, or invalid session cookie.
  - **Body**:
    ```json
    {
      "detail": "Authentication required."
    }
    ```

---

### 4. `POST /api/auth/logout`

Terminates the active user session and clears the session cookie.

#### Request
- **Method**: `POST`
- **Path**: `/api/auth/logout`
- **Headers**:
  - `X-Requested-With: vulnify`
- **Credentials**: `include`

#### Responses
- **`204 No Content`**: Session revoked and cookie deleted.

---

### 5. `POST /api/admin/promote`

Admin-only route to update a registered user's role (e.g. promote to `admin`).

#### Request
- **Method**: `POST`
- **Path**: `/api/admin/promote`
- **Headers**:
  - `Content-Type: application/json`
  - `X-Requested-With: vulnify`
- **Credentials**: `include`
- **Body**:
  ```json
  {
    "email": "jane@example.com",
    "role": "admin"
  }
  ```

#### Responses
- **`200 OK`**: Role updated.
- **`403 Forbidden`**: Authenticated user is not an administrator.
- **`404 Not Found`**: Target user email does not exist.
