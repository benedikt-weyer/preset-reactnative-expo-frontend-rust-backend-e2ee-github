# Note Encryption

This page focuses on how note payloads are encrypted locally, how DEKs are
wrapped, and how the backend stores only ciphertext.

## API user dashboard

The web client exposes an API user dashboard for the owner user. That screen
lists the current API users, shows their provisioning progress across notes,
and lets the owner remove an API user when that principal should no longer be
able to decrypt account data.

Creating an API user uses the same local encryption model as notes, but for an
encrypted label instead of a note body:

1. The client creates a fresh API token locally.
2. The client derives an auth key plus a KEK keypair for that API user from the token.
3. The client encrypts the human-readable label locally.
4. The client wraps the label DEK once for the owner principal and once for the new API user principal.
5. The backend stores the API user row, its first `kek_metadata` row, and the wrapped label DEKs.
6. The client then provisions wrapped note DEKs for any existing notes that do not yet include that API user as a recipient.

Removing an API user is intentionally destructive for that principal's access:

1. The owner confirms the removal in the dashboard.
2. The backend deletes all note-recipient DEK rows whose `user_id` matches that API user.
3. The backend deletes the wrapped label DEK rows whose `resource_id` points at that API user's label resource.
4. The backend deletes the API user's `kek_metadata` rows.
5. The backend deletes the `api_users` row itself.

After that cleanup, the removed API user no longer has any KEK metadata or any
wrapped DEKs left in the database, so it cannot continue decrypting either note
data or its own encrypted label.

Owner account deletion is the wider version of that same cleanup. When the user
deletes the account, the backend removes the owner row, every linked API user,
all note rows, all wrapped DEKs for those notes, and every KEK metadata row that
belongs to either the owner or one of the linked API users.

## Save flow

After login or registration, the web and mobile clients keep a local keyring of
linked KEK keypairs keyed by `kek_public_key`. The owner user plus any API users
under that owner are treated as linked principals. Each principal has a latest
KEK public key published in `kek_metadata`.

When a note is saved:

1. The app fetches the latest linked principals so it has the newest published `kek_public_key` for every recipient.
2. The app generates a fresh random DEK for that specific note.
3. The app encrypts the note document with XSalsa20-Poly1305 using the DEK and a fresh nonce.
4. For each linked principal, the app encapsulates to that principal's ML-KEM-768 public key.
5. Each encapsulation yields a KEM ciphertext and a shared secret.
6. The app derives a wrap key from that shared secret and encrypts the DEK with XSalsa20-Poly1305 using a separate nonce.
7. The app sends both encrypted objects to the backend:
   - `encryptedPayload`: the note ciphertext + nonce
   - `encryptedDeks[]`: one wrapped DEK per recipient, each containing `kekPublicKey`, `kemCiphertextHex`, `wrappedDekHex`, `nonceHex`, `version`, and `userId`
8. The backend stores:
   - the encrypted note row in `notes`
   - one wrapped DEK row per recipient in `deks`, keyed by `(resource_id, user_id)` and linked to the relevant `kek_public_key`

```plantuml format="svg_inline" alt="Encrypted note save sequence" title="Encrypted note save sequence"
@startuml
skinparam shadowing false

actor User
participant "Client App" as Client
participant "@repo/e2ee-auth" as Shared
database "Local keyring" as Keyring
database "Linked principals" as Principals
participant "Notes API" as Api
database "notes" as Notes
database "deks" as Deks

User -> Client: Save note
Client -> Api: GET /api/auth/linked-principals
Api --> Client: principals + latest kek_public_key values
Client -> Principals: choose recipients
Client -> Client: Generate random DEK
Client -> Client: Encrypt note with DEK + payload nonce
loop once per linked principal
   Client -> Shared: encapsulate to recipient kek_public_key
   Shared --> Client: kem ciphertext + shared secret
   Client -> Client: Wrap DEK with shared-secret-derived key + wrap nonce
end
Client -> Api: POST /api/notes\nencryptedPayload + encryptedDeks[]
Api -> Notes: Store encrypted note payload
Api -> Deks: Store wrapped DEK rows for each recipient
Api --> Client: Stored encrypted note row
@enduml
```

## Load flow

When a note is loaded:

1. The app fetches the encrypted note row and the wrapped DEK that belongs to the current principal.
2. The app reads `encryptedDek.kekPublicKey` and resolves the matching KEK keypair from local storage.
3. The app uses `encryptedDek.kemCiphertextHex` plus its private key to decapsulate the shared secret locally on-device.
4. The app derives the wrap key from that shared secret.
5. The app decrypts `encryptedDek.wrappedDekHex` locally on-device to recover the DEK.
6. The app decrypts the note document locally on-device with the unwrapped DEK.

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
Api -> Store: Load encrypted payload + current principal wrapped DEK
Store --> Api: encryptedPayload + encryptedDek
Api --> Client: encryptedPayload + encryptedDek
Client -> Keyring: Resolve KEK keypair using encryptedDek.kekPublicKey
Keyring --> Client: matching KEK keypair
Client -> Client: Decapsulate shared secret with private key
Client -> Client: Derive wrap key from shared secret
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
rectangle "KEM ciphertext\nper recipient" as KemCiphertext
rectangle "Shared secret\nfrom encapsulation" as SharedSecret
rectangle "Wrap key\nHKDF kek-wrap: sharedSecret" as WrapKey
rectangle "Per-note DEK\nrandom" as Dek
rectangle "Encrypted note payload" as Payload
rectangle "Wrapped DEK row\nkek_public_key + kem_ciphertext_hex + wrapped_dek_hex" as WrappedDek

Input --> CryptKey
CryptKey --> AuthKey
CryptKey --> KekPair
KekPair --> KemCiphertext
KemCiphertext --> SharedSecret
SharedSecret --> WrapKey
WrapKey --> WrappedDek
Dek --> Payload
Dek --> WrappedDek

note right of AuthKey
Sent to backend for verification only.
end note

note right of KekPair
Public key becomes kek_public_key. Private key never leaves the device.
Each recipient also gets a distinct kem_ciphertext_hex so the shared secret can
be reconstructed during decrypt.
end note
@enduml
```