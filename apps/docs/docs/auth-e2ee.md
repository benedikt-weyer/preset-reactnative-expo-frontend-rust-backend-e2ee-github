# Auth And E2EE Flow

This page describes the current authentication and end-to-end encrypted note
sync flow used by the mobile app, the shared `@repo/e2ee-auth` package, and the
Rust backend.

## High-level model

The current design splits password handling into two responsibilities:

- the device derives keys locally from `password + salt`
- the backend only verifies a derived auth key and never receives the raw password
- note content is encrypted and decrypted locally on the device with a per-resource DEK
- each active KEK is tracked server-side with a client-derived public-key `kek_public_key` and a `kek_epoch_version` so clients can relink rotated passwords
- encrypted resources can have multiple linked recipients, including owner users and API users under the same owner account

That means the backend participates in login, account creation, and token
issuance, plus ciphertext sync, but it never receives plaintext notes, raw DEKs,
or the unwrapped KEK private key.

```plantuml format="svg_inline" alt="High-level auth and E2EE flow" title="High-level auth and E2EE flow"
@startuml
left to right direction
skinparam shadowing false
skinparam packageStyle rectangle

actor User
rectangle "Mobile / Web Client" as Client {
   component "Normalize email" as Normalize
   component "Derive cryptKey\nArgon2id(password + salt)" as Kdf
   component "Derive authKey / KEK keypair\nHKDF-SHA512 + seeded ML-KEM" as Hkdf
   component "Encrypt notes with DEK\nand wrap DEK for linked principals" as Encrypt
   database "Local keyring\nlinked KEKs by kek_public_key" as Keyring
}

rectangle "Rust Backend" as Backend {
   database "Users\nauth_key_hash + auth_salt" as Users
   database "KEK metadata\nkek_public_key + kek_epoch_version" as KekMeta
   database "Encrypted notes + wrapped DEKs" as Ciphertext
}

User --> Normalize
Normalize --> Kdf
Kdf --> Hkdf
Hkdf --> Keyring
Hkdf --> Backend : register/login with authKey + kekPublicKey
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
| Subkey derivation | HKDF-SHA512 | derive the auth subkey, KEK seed, and DEK wrap key material |
| KEK identity | Deterministic ML-KEM-768 keypair derivation | derive a stable KEK public/private keypair from the seeded local secret |
| Resource encryption | XSalsa20-Poly1305 via libsodium `crypto_secretbox` | encrypt and decrypt note documents with random DEKs |
| DEK wrapping | ML-KEM-768 encapsulation plus XSalsa20-Poly1305 | encapsulate to each recipient public key, derive a wrap key from the shared secret, and encrypt the DEK |
| Backend auth-key storage | SHA-512 hash of `authKey` | store a verifier instead of the raw derived auth key |
| Session tokens | JWT signed with backend secret | issue access and refresh tokens |

## Documentation map

- [E2EE Auth Package](auth-e2ee-package.md) inventories the public `@repo/e2ee-auth` API surface, platform differences, and the boundary between package and application responsibilities.
- [Registration And Login](auth-authentication.md) explains account creation, salt lookup, and login verification with sequence diagrams.
- [Password Rotation](auth-password-rotation.md) covers rotating the auth verifier, creating a new KEK epoch, and rewrapping DEKs.
- [Note Encryption](auth-note-encryption.md) shows how note payloads and wrapped DEKs move through save and load paths.
- [Realtime Updates](realtime-updates.md) documents the websocket event stream that pushes note changes to authenticated clients.
- [Realtime Package](realtime-package.md) inventories the public `@repo/realtime` client API, the subscription lifecycle, and the division of responsibilities between the package and the consuming app.
- [Storage And Routes](auth-storage-routes.md) summarizes persisted fields, API routes, and operational implications.

## Flow summary

1. Registration generates the user salt locally, derives `cryptKey`, derives `authKey`, derives a KEK keypair, and sends `authKey`, `saltHex`, and the KEK public key as `kekPublicKey` to the backend.
2. Login fetches the stored salt first, then re-derives `cryptKey`, `authKey`, and the current KEK keypair client-side before backend verification.
3. Auth sessions are principal-aware: the backend returns the owner account, the current principal, and the linked principals with their latest KEK public keys.
4. Note sync encrypts note payloads with per-note DEKs and wraps those DEKs separately for every linked principal using ML-KEM encapsulation.
5. Password rotation updates the owner verifier and creates a new KEK epoch from a newly derived public key without changing the salt.
6. KEK migration rebuilds recipient wraps in place until all encrypted rows point at the newest owner `kek_public_key` while preserving current linked-principal recipients.

```plantuml format="svg_inline" alt="Top-level auth and note lifecycle" title="Top-level auth and note lifecycle"
@startuml
start
:User enters credentials;
:Client normalizes email;

if (New account?) then (yes)
   :Generate random salt locally;
   :Derive cryptKey, authKey,
   and kekPublicKey;
   :POST /api/auth/register;
else (no)
   :POST /api/auth/salt;
   :Derive cryptKey, authKey,
   and kekPublicKey from password + returned salt;
   :POST /api/auth/login;
endif

:Client stores linked KEK keypairs by kek_public_key;

if (Saving note?) then (yes)
   :GET /api/auth/linked-principals;
   :Generate per-note DEK;
   :Encrypt note with DEK;
   :Wrap DEK for each linked principal;
   :POST/PUT encrypted payload and wrapped DEKs[];
else (loading)
   :Fetch encrypted payload + wrapped DEK;
   :Resolve KEK by kek_public_key;
   :Decapsulate shared secret locally;
   :Unwrap DEK locally;
   :Decrypt note locally;
endif

if (Password rotated?) then (yes)
   :Derive new authKey and KEK keypair locally;
   :POST /api/auth/rotate-password;
   :Rewrap old DEKs onto newest kek_public_key;
endif

stop
@enduml
```

## Core guarantees

- The backend receives a derived auth key, never the raw password.
- Every encrypted resource row gets its own random DEK.
- Wrapped DEKs stay tied to a client-derived public-key `kek_public_key`, which makes password rotation explicit and auditable.
- Each wrapped DEK also carries a per-recipient `kem_ciphertext_hex`, which is required to reconstruct the shared secret during decrypt.
- The backend stores one wrapped DEK row per `(resource_id, user_id)` recipient pair, not one row per resource.
- Clients must retain or relink older KEKs locally until all ciphertext has been migrated to the newest epoch.
