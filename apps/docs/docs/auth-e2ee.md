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

```plantuml format="svg_inline" alt="High-level auth and E2EE flow" title="High-level auth and E2EE flow"
@startuml
left to right direction
skinparam shadowing false
skinparam packageStyle rectangle

actor User
rectangle "Mobile / Web Client" as Client {
   component "Normalize email" as Normalize
   component "Derive cryptKey\nArgon2id(password + salt)" as Kdf
   component "Derive authKey / KEK\nHKDF-SHA512" as Hkdf
   component "Encrypt notes with DEK\nand wrap DEK with KEK" as Encrypt
   database "Local keyring\nlinked KEKs by kek_id" as Keyring
}

rectangle "Rust Backend" as Backend {
   database "Users\nauth_key_hash + auth_salt" as Users
   database "KEK metadata\nkek_id + kek_epoch_version" as KekMeta
   database "Encrypted notes + wrapped DEKs" as Ciphertext
}

User --> Normalize
Normalize --> Kdf
Kdf --> Hkdf
Hkdf --> Keyring
Hkdf --> Backend : register/login with authKey
Encrypt --> Backend : sync ciphertext only
Keyring --> Encrypt
Backend --> Users
Backend --> KekMeta
Backend --> Ciphertext

note bottom of Backend
The backend can verify auth material and store ciphertext,
but it cannot derive the password or decrypt notes.
end note
@enduml
```

## Algorithms in use

| Purpose | Algorithm | Where used |
| --- | --- | --- |
| Password-based key derivation | Argon2id via libsodium | derive the per-user `cryptKey` |
| Subkey derivation | HKDF-SHA512 | derive the auth subkey and the KEK from `cryptKey` |
| Resource encryption | XSalsa20-Poly1305 via libsodium `crypto_secretbox` | encrypt and decrypt note documents with random DEKs |
| DEK wrapping | XSalsa20-Poly1305 via libsodium `crypto_secretbox` | encrypt and decrypt each resource DEK with the derived KEK |
| Backend auth-key storage | SHA-512 hash of `authKey` | store a verifier instead of the raw derived auth key |
| Session tokens | JWT signed with backend secret | issue access and refresh tokens |

## Documentation map

- [Registration And Login](auth-authentication.md) explains account creation, salt lookup, and login verification with sequence diagrams.
- [Password Rotation](auth-password-rotation.md) covers rotating the auth verifier, creating a new KEK epoch, and rewrapping DEKs.
- [Note Encryption](auth-note-encryption.md) shows how note payloads and wrapped DEKs move through save and load paths.
- [Storage And Routes](auth-storage-routes.md) summarizes persisted fields, API routes, and operational implications.

## Flow summary

1. Registration generates the user salt locally, derives `cryptKey`, derives `authKey`, and sends only `authKey` plus `saltHex` to the backend.
2. Login fetches the stored salt first, then re-derives `cryptKey` and `authKey` client-side before backend verification.
3. Password rotation updates the backend verifier and creates a new KEK epoch without changing the salt.
4. Note sync encrypts note payloads with per-note DEKs and wraps those DEKs with the currently active KEK.
5. KEK migration rewraps DEKs in place until all encrypted rows point at the newest `kek_id`.

```plantuml format="svg_inline" alt="Top-level auth and note lifecycle" title="Top-level auth and note lifecycle"
@startuml
start
:User enters credentials;
:Client normalizes email;

if (New account?) then (yes)
   :Generate random salt locally;
   :Derive cryptKey and authKey;
   :POST /api/auth/register;
else (no)
   :POST /api/auth/salt;
   :Derive cryptKey and authKey
   from password + returned salt;
   :POST /api/auth/login;
endif

:Client stores linked KEKs by kek_id;

if (Saving note?) then (yes)
   :Generate per-note DEK;
   :Encrypt note with DEK;
   :Wrap DEK with active KEK;
   :POST/PUT encrypted payload and wrapped DEK;
else (loading)
   :Fetch encrypted payload + wrapped DEK;
   :Resolve KEK by kek_id;
   :Unwrap DEK locally;
   :Decrypt note locally;
endif

if (Password rotated?) then (yes)
   :Derive new authKey and KEK locally;
   :POST /api/auth/rotate-password;
   :Rewrap old DEKs onto newest kek_id;
endif

stop
@enduml
```

## Core guarantees

- The backend receives a derived auth key, never the raw password.
- Every encrypted resource row gets its own random DEK.
- Wrapped DEKs stay tied to a server-tracked `kek_id`, which makes password rotation explicit and auditable.
- Clients must retain or relink older KEKs locally until all ciphertext has been migrated to the newest epoch.
