# Note Encryption

This page focuses on how note payloads are encrypted locally, how DEKs are
wrapped, and how the backend stores only ciphertext.

## Save flow

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
Keyring --> Client: active KEK
Client -> Shared: derive/use KEK for enc: context
Shared --> Client: KEK
Client -> Client: Generate random DEK
Client -> Client: Encrypt note with DEK + payload nonce
Client -> Client: Wrap DEK with KEK + wrap nonce
Client -> Api: POST /api/notes\nencryptedPayload + encryptedDek
Api -> Notes: Store encrypted note payload
Api -> Deks: Store wrapped DEK + kek_id
Api --> Client: Stored encrypted note row
@enduml
```

## Load flow

When a note is loaded:

1. The app fetches the encrypted note row and its wrapped DEK from the backend.
2. The app reads `encryptedDek.kekId` and resolves the matching KEK from local storage.
3. The app decrypts the wrapped DEK locally on-device.
4. The app decrypts the note document locally on-device with the unwrapped DEK.

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
Client -> Keyring: Resolve KEK using encryptedDek.kekId
Keyring --> Client: matching KEK
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
rectangle "KEK\nHKDF enc:" as Kek
rectangle "Per-note DEK\nrandom" as Dek
rectangle "Encrypted note payload" as Payload
rectangle "Wrapped DEK + kek_id" as WrappedDek

Input --> CryptKey
CryptKey --> AuthKey
CryptKey --> Kek
Kek --> WrappedDek
Dek --> Payload
Dek --> WrappedDek

note right of AuthKey
Sent to backend for verification only.
end note

note right of Kek
Kept local and indexed by kek_id.
end note
@enduml
```