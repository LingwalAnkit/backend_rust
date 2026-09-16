# Axum Auth Backend — Ankit's Codebase Guide

This is my Rust authentication backend built with **Axum**, **MongoDB**, JWT access tokens, rotating refresh tokens, Argon2 password hashing, and a small in-memory login rate limiter.

This README is written for future me: if I return after a break and have forgotten how everything fits together, I should be able to start here.

## The mental model

A request travels through the project like this:

```text
client request
    -> routes.rs chooses a handler
    -> handlers.rs runs the use-case
    -> auth.rs handles tokens/auth extraction when needed
    -> models.rs describes MongoDB documents
    -> db.rs/state.rs provide shared infrastructure
    -> error.rs converts failures into HTTP responses
```

`main.rs` is the composition root. It loads configuration, connects to MongoDB, builds shared application state, creates the router, and starts the HTTP server.

## What each file is responsible for

| File | Remember it as | Responsibility |
| --- | --- | --- |
| `src/main.rs` | Startup | Loads `.env`, connects to MongoDB, creates `AppState`, and listens on port `3000`. |
| `src/routes.rs` | URL map | Connects HTTP methods and paths to handler functions. |
| `src/handlers.rs` | Use-cases | Registration, login, refresh, logout, health checks, and the protected `/me` endpoint. |
| `src/auth.rs` | Authentication toolbox | Creates and verifies JWTs, generates refresh tokens, hashes refresh tokens, and defines the `AuthUser` extractor. |
| `src/models.rs` | Database shapes | Defines the `User` and `RefreshToken` MongoDB documents. |
| `src/db.rs` | MongoDB setup | Opens the database and creates the TTL index for expired refresh tokens. |
| `src/state.rs` | Shared dependencies | Holds the MongoDB handle, JWT secret, and login-attempt tracker passed to handlers. |
| `src/rate_limit.rs` | Brute-force guard | Tracks recent failed login attempts per username in memory. |
| `src/error.rs` | Error boundary | Maps internal errors to consistent HTTP status codes and JSON responses. |

## Authentication flow

### 1. Register

`POST /register`:

1. Looks for an existing MongoDB user with the same username.
2. Hashes the password with Argon2.
3. Stores the username and password hash in `users`.
4. Never stores the plain-text password.

### 2. Log in

`POST /login`:

1. Checks whether the username has reached the failed-attempt limit.
2. Finds the user and verifies the supplied password against the Argon2 hash.
3. Records failures for missing users and incorrect passwords.
4. Clears previous failures after a successful login.
5. Returns a short-lived JWT access token and a refresh token.
6. Stores only the SHA-256 hash of the refresh token in MongoDB.

The access token lasts **15 minutes**. The refresh token record lasts **7 days**.

### 3. Access a protected route

`GET /me` takes `AuthUser` as a handler argument. That is important: Axum automatically runs the `FromRequestParts` implementation in `auth.rs` before calling the handler.

The extractor:

1. Reads `Authorization: Bearer <access-token>`.
2. Verifies the JWT signature and expiry using `JWT_SECRET`.
3. puts the JWT `sub` claim into `AuthUser.username`.

If extraction fails, the handler never runs.

### 4. Refresh tokens

`refresh` hashes the client-provided token, finds that hash in MongoDB, and deletes the old record before issuing a new token pair. This is **refresh-token rotation**: a successfully used refresh token cannot be reused.

MongoDB also has a TTL index on `refresh_tokens.expires_at`, allowing it to clean up expired records automatically. The handler still checks expiry because TTL deletion is asynchronous and may not happen at the exact expiration instant.

### 5. Log out

`POST /logout` requires a valid access token and a refresh token. It deletes the matching refresh-token record for the authenticated username. The access JWT remains valid until its short expiry because JWTs are stateless and no access-token denylist exists here.

## Database documents

The database name is hardcoded as `axum_auth_demo`.

```text
users
  _id: ObjectId
  username: String
  password_hash: String

refresh_tokens
  _id: ObjectId
  username: String
  token_hash: String
  expires_at: BSON DateTime
```

The code checks for duplicate usernames before insertion, but the database currently does not create a unique index on `users.username`. Under simultaneous registration requests, duplicates are therefore still possible. Adding a unique MongoDB index is the durable fix.

## Run it locally

### Requirements

- Rust with Cargo
- MongoDB running locally, or a MongoDB connection URI

Create a `.env` file in the project root:

```env
MONGODB_URI=mongodb://localhost:27017
JWT_SECRET=replace-this-with-a-long-random-secret
```

Do not commit the real `.env` or use a weak production secret.

Then run:

```powershell
cargo check
cargo run
```

The server listens at `http://localhost:3000`.

## Try the API from PowerShell

Health checks:

```powershell
Invoke-RestMethod http://localhost:3000/health
Invoke-RestMethod http://localhost:3000/health/db
```

Register:

```powershell
$registerBody = @{ username = "ankit"; password = "change-me" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://localhost:3000/register -ContentType "application/json" -Body $registerBody
```

Log in and keep the returned tokens:

```powershell
$loginBody = @{ username = "ankit"; password = "change-me" } | ConvertTo-Json
$tokens = Invoke-RestMethod -Method Post -Uri http://localhost:3000/login -ContentType "application/json" -Body $loginBody
$tokens
```

Call the protected endpoint:

```powershell
$headers = @{ Authorization = "Bearer $($tokens.access_token)" }
Invoke-RestMethod -Uri http://localhost:3000/me -Headers $headers
```

Log out:

```powershell
$logoutBody = @{ refresh_token = $tokens.refresh_token } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://localhost:3000/logout -Headers $headers -ContentType "application/json" -Body $logoutBody
```

## Endpoint reference

| Method | Path | Authentication | Purpose |
| --- | --- | --- | --- |
| `GET` | `/health` | None | Confirms that the HTTP server is alive. |
| `GET` | `/health/db` | None | Pings MongoDB. |
| `POST` | `/register` | None | Creates a user. |
| `POST` | `/login` | None | Verifies credentials and returns a token pair. |
| `GET` | `/me` | Bearer access token | Returns the authenticated username. |
| `GET` currently | `/refresh` | Refresh token in JSON | Rotates the refresh token and returns a new pair. |
| `POST` | `/logout` | Bearer access token plus refresh token in JSON | Revokes the supplied refresh token. |

All application errors use this shape:

```json
{
  "error": "error message"
}
```

## Current rough edges I should remember

These are not reasons to distrust the project; they are the clearest next improvements:

- `/refresh` is registered as `GET` but expects a JSON request body. Some clients and proxies do not reliably support GET bodies. Change it to `POST` in `routes.rs`.
- `AppState.rate_limt` is misspelled. Rename it to `rate_limit` everywhere for readability.
- `JWT_SECRET` defaults to an empty string when missing. Startup should fail loudly instead, for example with `expect("JWT_SECRET must be set")`.
- Login rate limiting lives only in this process. It resets on restart and is not shared across multiple server instances. Redis or database-backed limiting would be needed for distributed production use.
- Rate limiting is keyed only by the supplied username. It can protect an account from guessing, but an attacker could deliberately lock out a known username. Combining account and IP-based controls would be stronger.
- Add a unique index for usernames; the application-level existence check alone has a race condition.
- Request validation is not implemented yet. Add username/password length and format rules before treating this as production-ready.
- There are no automated tests yet. Handler/integration tests around login, refresh rotation, expiry, logout, and rate limiting would give the most value.
- The dependency list includes crates that may not currently be used (`dotenv`, `lettre`, `uuid`, and others). Run a dependency audit before cleanup rather than deleting them blindly if upcoming features need them.

## Details that are easy to forget

- `AppState` is cloned cheaply: MongoDB's `Database` is a handle, and `LoginAttempts` wraps its map in `Arc<Mutex<_>>`.
- The mutex is asynchronous (`tokio::sync::Mutex`) because handlers may run concurrently.
- `?` works for MongoDB, Argon2, and JWT failures because `error.rs` implements the required `From` conversions.
- Parsing a stored Argon2 string uses `phc::PasswordHash`; verifying it uses the `PasswordVerifier` trait.
- The server binds to `0.0.0.0:3000`, so it is reachable through any available network interface, not only localhost.
- Refresh tokens are random secrets sent to the client; only their hashes are stored. This limits damage if the token collection is leaked.
- A successful login clears that username's recorded failures.

## A sensible learning roadmap for future me

If I return wanting to improve this project, this order keeps the work understandable:

1. Add tests for the current behavior.
2. Change refresh to `POST` and validate all request bodies.
3. Require a non-empty JWT secret at startup.
4. Add a unique username index and handle duplicate-key errors.
5. Move rate limiting to a persistent/shared store if deploying multiple instances.
6. Add structured tracing instead of `println!` and `eprintln!`.
7. Add email verification or password reset only after the authentication foundation is tested.

The central idea to keep in mind is: **handlers coordinate the work, while focused modules own authentication, persistence, shared state, and error translation.** If a handler becomes large, move reusable mechanics into the module that owns that concern.
