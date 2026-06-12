# Note Encryption

This page focuses on how note payloads are encrypted locally, how DEKs are
wrapped, and how the backend stores only ciphertext.

## Save flow

After login or registration, the web and mobile clients keep a local keyring of
linked KEK keypairs keyed by `kek_id`. The newest epoch is the active KEK for
newly encrypted resources, while older epochs remain available to decrypt older
rows.

When a note is saved:

1. The app deterministically derives an ML-KEM-768 KEK keypair from `cryptKey`.
2. The app generates a fresh random DEK for that specific resource row.
3. The app encrypts the note document with XSalsa20-Poly1305 using the DEK and a fresh nonce.
4. The app derives a stable symmetric wrap key from the KEK private key bytes with HKDF-SHA512 using the `kek-wrap:` context.
5. The app encrypts the DEK with XSalsa20-Poly1305 using that wrap key and a separate fresh nonce.
6. The app includes the active `kekId` inside the wrapped DEK payload.
7. The app sends both encrypted objects to the backend:
   - `encryptedPayload`: the note ciphertext + nonce
   - `encryptedDek`: `kekId` + wrapped DEK + nonce
8. The backend stores:
   - the encrypted note row in `notes`
   - the wrapped DEK row in `deks`, keyed by `resource_id` and linked to the relevant `kek_id`

```plantuml format="svg_inline" alt="Encrypted note save sequence" title="Encrypted note save sequence"
@startuml
skinparam shadowing false

actor User
participant "Client App" as Client
participant "@repo/e2ee-auth" as Shared
database "Local keyring" as Keyring
participant "Notes API" as Api
database "notes" as Notes
database "deks" as Deks

User -> Client: Save note
Client -> Keyring: Resolve active KEK by newest kek_id
Keyring --> Client: active KEK keypair
Client -> Shared: derive/use KEK keypair for current cryptKey
Shared --> Client: KEK public/private keypair
Client -> Client: Generate random DEK
Client -> Client: Encrypt note with DEK + payload nonce
Client -> Client: Derive wrap key from KEK private key
Client -> Client: Wrap DEK with private-key-derived wrap key + wrap nonce
Client -> Api: POST /api/notes\nencryptedPayload + encryptedDek
Api -> Notes: Store encrypted note payload
Api -> Deks: Store wrapped DEK + kek_id
Api --> Client: Stored encrypted note row
@enduml
```

## Load flow

When a note is loaded:

1. The app fetches the encrypted note row and its wrapped DEK from the backend.
2. The app reads `encryptedDek.kekId` and resolves the matching KEK keypair from local storage.
3. The app derives the same symmetric wrap key from the KEK private key locally on-device.
4. The app decrypts the wrapped DEK locally on-device.
5. The app decrypts the note document locally on-device with the unwrapped DEK.

The backend never sees the plaintext note, the raw DEK, or the unwrapped KEK.

```plantuml format="svg_inline" alt="Encrypted note load sequence" title="Encrypted note load sequence"
@startuml
skinparam shadowing false

actor User
participant "Client App" as Client
database "Local keyring" as Keyring
participant "Notes API" as Api
database "notes + deks" as Store

User -> Client: Open note
Client -> Api: GET /api/notes/{note_id}
Api -> Store: Load encrypted payload + wrapped DEK
Store --> Api: encryptedPayload + encryptedDek
Api --> Client: encryptedPayload + encryptedDek
Client -> Keyring: Resolve KEK keypair using encryptedDek.kekId
Keyring --> Client: matching KEK keypair
Client -> Client: Derive wrap key from KEK private key
Client -> Client: Unwrap DEK locally
Client -> Client: Decrypt note locally
Client --> User: Plaintext note on device
@enduml
```

## Key hierarchy

```plantuml format="svg_inline" alt="Key hierarchy for note encryption" title="Key hierarchy for note encryption"
@startuml
skinparam shadowing false

rectangle "password + salt" as Input
rectangle "cryptKey\nArgon2id" as CryptKey
rectangle "authKey\nHKDF auth:" as AuthKey
rectangle "KEK keypair\nML-KEM-768 seeded" as KekPair
rectangle "Wrap key\nHKDF kek-wrap: privateKey" as WrapKey
rectangle "Per-note DEK\nrandom" as Dek
rectangle "Encrypted note payload" as Payload
rectangle "Wrapped DEK + kek_id" as WrappedDek

Input --> CryptKey
CryptKey --> AuthKey
CryptKey --> KekPair
KekPair --> WrapKey
WrapKey --> WrappedDek
Dek --> Payload
Dek --> WrappedDek

note right of AuthKey
Sent to backend for verification only.
end note

note right of KekPair
Public key becomes kek_id. Private key never leaves the device.
end note
@enduml
```