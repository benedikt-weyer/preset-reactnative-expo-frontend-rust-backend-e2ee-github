# Auth And E2EE Flow

This page describes the current authentication and end-to-end encrypted note
sync flow used by the mobile app, the shared `@repo/e2ee-auth` package, and the
Rust backend.

## High-level model

The current design splits password handling into two responsibilities:

- the device derives keys locally from `password + salt`
- the backend only verifies a derived auth key and never receives the raw password
- note content is encrypted and decrypted locally on the device with a per-resource DEK
- each active KEK is tracked server-side with a `kek_id` and `kek_epoch_version` so clients can relink rotated passwords

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
   - one initial `kek_metadata` row with a server-generated `kek_id` and `kek_epoch_version = 1`
8. The backend returns an access token, a refresh token, the user record, and the active KEK metadata list.

## Login flow

Login is a two-step handshake because the client needs the stored salt before it
can derive the same `authKey` again:

1. The user enters email and password.
2. The mobile app normalizes the email.
3. The app sends the email to `POST /api/auth/salt`.
4. The backend looks up the user and returns the stored `saltHex` plus all active `kek_metadata` rows for that user.
5. The app derives the `cryptKey` from `password + saltHex` with Argon2id.
6. The app links that derived key to the newest `kek_epoch_version` locally and reuses any previously stored older KEKs by `kek_id`.
7. If older active KEKs exist but are not linked locally yet, the app asks for the matching older passwords during login and derives those older KEKs locally with the same salt.
8. The app derives `authKey` from `cryptKey` with HKDF-SHA512 using the `auth:` context.
9. The app sends `email` and `authKey` to `POST /api/auth/login`.
10. The backend hashes the received `authKey` with SHA-512 and compares it in constant time with the stored hash.
11. If verification succeeds, the backend issues access and refresh JWTs and returns the current KEK metadata list.

## Password rotation flow

Password rotation keeps the same stored salt, but changes the derived auth key and
starts a new KEK epoch:

1. The authenticated client asks the user for a new password.
2. The client derives a new `cryptKey` and `authKey` locally from `newPassword + existing saltHex`.
3. The client sends the new derived `authKey` to `POST /api/auth/rotate-password` with the current access token.
4. The backend updates `auth_key_hash` for that user.
5. The backend inserts a new `kek_metadata` row with a fresh server-generated `kek_id` and the next `kek_epoch_version`.
6. The backend returns the updated KEK metadata list.
7. The client links the new locally derived KEK to that newest `kek_id`.
8. The client starts a KEK migration pass that rewraps each stored DEK onto the newest KEK epoch.

The salt stays unchanged so the client can still derive older KEKs from older
passwords when an older epoch still has encrypted rows assigned to it.

## DEK rewrap migration flow

After a password rotation, the encrypted note payloads stay unchanged. Only the
wrapped DEKs are rotated:

1. The client fetches the current encrypted rows.
2. For each row whose `encryptedDek.kekId` is not the newest `kek_id`, the client:
   - decrypts the wrapped DEK locally with the old linked KEK
   - re-encrypts the same DEK locally with the newest linked KEK
   - sends `PUT /api/notes/{note_id}` with the unchanged encrypted payload and the updated wrapped DEK
3. The backend updates the stored `wrapped_dek_hex`, `nonce_hex`, and `kek_id` on the existing DEK row.
4. The client calls `GET /api/auth/kek-status` for a final verification pass.
5. Migration is considered complete only when every DEK row for that user points at the newest KEK epoch.

If the client does not have one of the older KEKs linked locally yet, it asks for
the matching older password before continuing the migration.

## Synced note encryption flow

After login or registration, the web and mobile clients keep a local keyring of
linked KEKs keyed by `kek_id`. The newest epoch is the active KEK for newly
encrypted resources, while older epochs remain available to decrypt older rows.

When a note is saved:

1. The app derives a KEK from `cryptKey` with HKDF-SHA512 using the `enc:` context.
2. The app generates a fresh random DEK for that specific resource row.
3. The app encrypts the note document with XSalsa20-Poly1305 using the DEK and a fresh nonce.
4. The app encrypts the DEK with XSalsa20-Poly1305 using the KEK and a separate fresh nonce.
5. The app includes the active `kekId` inside the wrapped DEK payload.
6. The app sends both encrypted objects to the backend:
   - `encryptedPayload`: the note ciphertext + nonce
   - `encryptedDek`: `kekId` + wrapped DEK + nonce
7. The backend stores:
   - the encrypted note row in `notes`
   - the wrapped DEK row in `deks`, keyed by `resource_id` and linked to the relevant `kek_id`

When a note is loaded:

1. The app fetches the encrypted note row and its wrapped DEK from the backend.
2. The app reads `encryptedDek.kekId` and resolves the matching KEK from local storage.
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
- `kek_id` on the DEK row, which links the wrapped DEK to one server-tracked KEK epoch
- `resource_id` on the DEK row, which points at the encrypted row id
- `user_id` on the DEK row, which binds the wrapped DEK to the owning user
- `wrapped_dek_hex` on the DEK row, which stores the wrapped DEK ciphertext
- separate nonces for the encrypted payload and the wrapped DEK

For each active KEK, the backend also stores one `kek_metadata` row with:

- `kek_id`, generated server-side
- `kek_epoch_version`, incremented per user for rotations
- `user_id`, which scopes that KEK metadata row to one account

For migration bookkeeping, the backend can also compute:

- the latest KEK epoch for that user
- how many DEK rows already use that latest epoch
- how many DEK rows are still pending migration

The backend does not store:

- the raw password
- the derived `cryptKey`
- the raw `authKey`
- the raw DEK for any encrypted resource
- plaintext note contents

The client stores locally:

- linked KEKs keyed by `kek_id`
- the latest known `kek_epoch_version` values returned by the backend
- any older active KEKs that were relinked with older passwords during login
- temporary client-side migration progress while rewrapping DEKs to a new epoch

## Current routes

| Route | Purpose |
| --- | --- |
| `POST /api/auth/salt` | return the stored per-user salt plus active KEK metadata for login |
| `POST /api/auth/register` | create a user from `email + authKey + saltHex` and return the initial KEK metadata |
| `POST /api/auth/login` | verify the derived auth key, issue tokens, and return active KEK metadata |
| `POST /api/auth/rotate-password` | update the stored auth-key hash and create the next KEK epoch |
| `GET /api/auth/kek-status` | report whether all DEKs for the user already use the newest KEK epoch |
| `GET /api/notes` | return encrypted notes plus wrapped DEKs for the authenticated user |
| `POST /api/notes` | create an encrypted note row and its wrapped DEK row |
| `GET /api/notes/{note_id}` | return one encrypted note and wrapped DEK |
| `PUT /api/notes/{note_id}` | replace the encrypted note payload and wrapped DEK |
| `DELETE /api/notes/{note_id}` | delete the encrypted note and its wrapped DEK |

## Important implications

- Existing accounts and encrypted note rows created under older schemes are not compatible with the current flow.
- The email is an identifier now, not an input to the password KDF.
- Every encrypted resource row gets its own client-generated random DEK.
- Every wrapped DEK is linked to a specific `kek_id`, which allows password rotations without reusing a single long-lived KEK identifier.
- Clients must keep older linked KEKs locally if older ciphertext rows are still active.
- Rotating the password is not finished until the client verifies that every DEK row was rewrapped onto the newest KEK epoch.
- The backend can store and serve encrypted notes, but it still cannot decrypt them.