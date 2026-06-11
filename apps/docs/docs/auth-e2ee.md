# Auth And E2EE Flow

This page describes the current authentication and local encryption flow used by
the mobile app, the shared `@repo/e2ee-auth` package, and the Rust backend.

## High-level model

The current design splits password handling into two responsibilities:

- the device derives keys locally from `password + salt`
- the backend only verifies a derived auth key and never receives the raw password
- note content is encrypted and decrypted locally on the device

That means the backend participates in login, account creation, and token
issuance, but it is not involved in local note encryption.

## Algorithms in use

| Purpose | Algorithm | Where used |
| --- | --- | --- |
| Password-based key derivation | Argon2id via libsodium | derive the per-user `cryptKey` |
| Subkey derivation | HKDF-SHA512 | derive the auth subkey and encryption subkey from `cryptKey` |
| Local symmetric encryption | XSalsa20-Poly1305 via TweetNaCl `secretbox` | encrypt and decrypt local notes |
| Backend auth-key storage | SHA-512 hash of `authKey` | store a verifier instead of the raw derived auth key |
| Session tokens | JWT signed with backend secret | issue access and refresh tokens |

## Registration flow

Registration happens in this order:

1. The user enters an email address and password in the mobile app.
2. The app normalizes the email by trimming whitespace and lowercasing it.
3. The app generates a random 16-byte salt locally and hex-encodes it.
4. The app derives a 64-byte `cryptKey` from the password and salt with Argon2id.
5. The app derives an `authKey` from the `cryptKey` with HKDF-SHA512 using the `auth:` context.
6. The app sends `email`, `authKey`, and `saltHex` to `POST /api/auth/register`.
7. The backend stores:
   - the normalized email
   - a SHA-512 hash of `authKey`
   - the user salt as `auth_salt`
8. The backend returns an access token, a refresh token, and the user record.

## Login flow

Login is a two-step handshake because the client needs the stored salt before it
can derive the same `authKey` again:

1. The user enters email and password.
2. The mobile app normalizes the email.
3. The app sends the email to `POST /api/auth/salt`.
4. The backend looks up the user and returns the stored `saltHex`.
5. The app derives the `cryptKey` from `password + saltHex` with Argon2id.
6. The app derives `authKey` from `cryptKey` with HKDF-SHA512 using the `auth:` context.
7. The app sends `email` and `authKey` to `POST /api/auth/login`.
8. The backend hashes the received `authKey` with SHA-512 and compares it in constant time with the stored hash.
9. If verification succeeds, the backend issues access and refresh JWTs.

## Local note encryption flow

After login or registration, the mobile app keeps the derived `cryptKey` in
memory for the authenticated session.

When a note is saved:

1. The app derives an encryption subkey from `cryptKey` with HKDF-SHA512 using the `enc:` context.
2. The app generates a fresh nonce.
3. The note text is encrypted locally with XSalsa20-Poly1305.
4. The encrypted payload is stored in SecureStore.

When a note is loaded:

1. The app reads the encrypted payload from SecureStore.
2. The app derives the same encryption subkey from the in-memory `cryptKey`.
3. The payload is decrypted locally on-device.

The backend never sees the plaintext note or the local encryption key.

## What the backend stores

The current backend user record stores:

- `email`
- `auth_key_hash`
- `auth_salt`
- timestamps and user metadata

The backend does not store:

- the raw password
- the derived `cryptKey`
- the raw `authKey`
- locally encrypted note contents

## Current routes

| Route | Purpose |
| --- | --- |
| `POST /api/auth/salt` | return the stored per-user salt for login |
| `POST /api/auth/register` | create a user from `email + authKey + saltHex` |
| `POST /api/auth/login` | verify the derived auth key and issue tokens |

## Important implications

- Existing accounts created under older derivation schemes are not compatible with the current flow.
- The email is an identifier now, not an input to the password KDF.
- Encryption remains local-only; the current backend auth flow is not end-to-end note synchronization.