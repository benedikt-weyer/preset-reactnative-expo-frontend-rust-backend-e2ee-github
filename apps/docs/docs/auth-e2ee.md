# Auth And E2EE Flow

This page describes the current authentication and end-to-end encrypted note
sync flow used by the mobile app, the shared `@repo/e2ee-auth` package, and the
Rust backend.

## High-level model

The current design splits password handling into two responsibilities:

- the device derives keys locally from `password + salt`
- the backend only verifies a derived auth key and never receives the raw password
- note content is encrypted and decrypted locally on the device with a per-resource DEK

That means the backend participates in login, account creation, and token
issuance, plus ciphertext sync, but it never receives plaintext notes, raw DEKs,
or the unwrapped KEK.

## Algorithms in use

| Purpose | Algorithm | Where used |
| --- | --- | --- |
| Password-based key derivation | Argon2id via libsodium | derive the per-user `cryptKey` |
| Subkey derivation | HKDF-SHA512 | derive the auth subkey and the KEK from `cryptKey` |
| Resource encryption | XSalsa20-Poly1305 via libsodium `crypto_secretbox` | encrypt and decrypt note documents with random DEKs |
| DEK wrapping | XSalsa20-Poly1305 via libsodium `crypto_secretbox` | encrypt and decrypt each resource DEK with the derived KEK |
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

## Synced note encryption flow

After login or registration, the mobile app keeps the derived `cryptKey` in
memory for the authenticated session.

When a note is saved:

1. The app derives a KEK from `cryptKey` with HKDF-SHA512 using the `enc:` context.
2. The app generates a fresh random DEK for that specific resource row.
3. The app encrypts the note document with XSalsa20-Poly1305 using the DEK and a fresh nonce.
4. The app encrypts the DEK with XSalsa20-Poly1305 using the KEK and a separate fresh nonce.
5. The app sends both encrypted objects to the backend:
   - `encryptedPayload`: the note ciphertext + nonce
   - `encryptedDek`: the wrapped DEK + nonce
6. The backend stores:
   - the encrypted note row in `notes`
   - the wrapped DEK row in `deks`, keyed by `resource_id`

When a note is loaded:

1. The app fetches the encrypted note row and its wrapped DEK from the backend.
2. The app derives the same KEK from the in-memory `cryptKey`.
3. The app decrypts the wrapped DEK locally on-device.
4. The app decrypts the note document locally on-device with the unwrapped DEK.

The backend never sees the plaintext note, the raw DEK, or the unwrapped KEK.

## What the backend stores

The current backend stores these user fields:

- `email`
- `auth_key_hash`
- `auth_salt`
- timestamps and user metadata

For each encrypted resource row, the backend also stores:

- the encrypted resource payload in its own table, for example `notes`
- one wrapped DEK in the `deks` table
- `resource_id` on the DEK row, which points at the encrypted row id
- `user_id` on the DEK row, which binds the wrapped DEK to the owning user
- separate nonces for the encrypted payload and the wrapped DEK

The backend does not store:

- the raw password
- the derived `cryptKey`
- the raw `authKey`
- the raw DEK for any encrypted resource
- plaintext note contents

## Current routes

| Route | Purpose |
| --- | --- |
| `POST /api/auth/salt` | return the stored per-user salt for login |
| `POST /api/auth/register` | create a user from `email + authKey + saltHex` |
| `POST /api/auth/login` | verify the derived auth key and issue tokens |
| `GET /api/notes` | return encrypted notes plus wrapped DEKs for the authenticated user |
| `POST /api/notes` | create an encrypted note row and its wrapped DEK row |
| `GET /api/notes/{note_id}` | return one encrypted note and wrapped DEK |
| `PUT /api/notes/{note_id}` | replace the encrypted note payload and wrapped DEK |
| `DELETE /api/notes/{note_id}` | delete the encrypted note and its wrapped DEK |

## Important implications

- Existing accounts and encrypted note rows created under older schemes are not compatible with the current flow.
- The email is an identifier now, not an input to the password KDF.
- Every encrypted resource row gets its own client-generated random DEK.
- The backend can store and serve encrypted notes, but it still cannot decrypt them.