# Password Rotation

Password rotation updates authentication state and encryption state in two
separate but coordinated phases.

## Rotation flow

Password rotation keeps the same stored salt, but changes the derived auth key and
starts a new KEK epoch:

1. The authenticated client asks the user for a new password.
2. The client derives a new `cryptKey` and `authKey` locally from `newPassword + existing saltHex`.
3. The client deterministically derives a new ML-KEM-768 KEK keypair from that `cryptKey` and uses the public key as the next `kekPublicKey`.
4. The client sends the new derived `authKey` and `kekPublicKey` to `POST /api/auth/rotate-password` with the current access token.
5. The backend updates `auth_key_hash` for that user.
6. The backend inserts a new `kek_metadata` row with the client-derived public key as `kek_public_key` and the next `kek_epoch_version`.
7. The backend returns the updated KEK metadata list.
8. The client links the new locally derived KEK keypair to that newest `kek_public_key`.
9. The client starts a KEK migration pass that rebuilds each stored wrapped DEK set using the latest linked principals and the newest owner KEK epoch.

The salt stays unchanged so the client can still derive older KEKs from older
passwords when an older epoch still has encrypted rows assigned to it.

```plantuml format="svg_inline" alt="Password rotation sequence" title="Password rotation sequence"
@startuml
skinparam shadowing false

actor User
participant "Client App" as Client
participant "@repo/e2ee-auth" as Shared
participant "Auth API" as Api
database "Users" as Users
database "KEK metadata" as KekMeta

User -> Client: Enter new password
Client -> Shared: derive cryptKey(newPassword, existing saltHex)
Shared --> Client: new cryptKey
Client -> Shared: derive authKey and KEK keypair from new cryptKey
Shared --> Client: new authKey + kekPublicKey
Client -> Api: POST /api/auth/rotate-password\nauthKey, kekPublicKey
Api -> Users: Replace auth_key_hash
Api -> KekMeta: Insert next kek_public_key and kek_epoch_version
Api --> Client: Updated KEK metadata list
Client -> Client: Link new KEK keypair to newest kek_public_key
Client -> Client: Start DEK rewrap migration
@enduml
```

## DEK rewrap migration flow

After a password rotation, the encrypted note payloads stay unchanged. Only the
wrapped DEKs are rotated:

1. The client fetches the current encrypted rows.
2. The client fetches the latest linked principals so every recipient uses the newest published `kek_public_key` from the backend.
3. For each row whose owner `encryptedDek.kekPublicKey` is not the newest owner `kek_public_key`, the client:
  - uses the old linked KEK private key plus `encryptedDek.kemCiphertextHex` to decapsulate the old shared secret and unwrap the DEK
  - re-encapsulates the same DEK for each linked principal using that principal's latest `kek_public_key`
  - sends `PUT /api/notes/{note_id}` with the unchanged encrypted payload and the full updated `encryptedDeks[]` set
4. The backend replaces the stored wrapped DEK rows for that note.
5. The client calls `GET /api/auth/kek-status` for a final verification pass.
6. Migration is considered complete only when every owner-addressed DEK row for that user points at the newest KEK epoch.

If the client does not have one of the older KEKs linked locally yet, it asks for
the matching older password before continuing the migration.

```plantuml format="svg_inline" alt="DEK migration flow" title="DEK migration flow"
@startuml
start
:Fetch encrypted rows and wrapped DEKs;
:GET /api/auth/linked-principals;

while (Rows left to inspect?) is (yes)
  :Read encryptedDek.kekPublicKey;
  if (Already newest kek_public_key?) then (yes)
    :Leave row unchanged;
  else (no)
    if (Old KEK linked locally?) then (yes)
      :Decapsulate old shared secret with old KEK private key;
      :Unwrap DEK with old shared secret;
      :Re-encapsulate DEK for each linked principal;
      :PUT /api/notes/{note_id}
      with unchanged ciphertext
      and updated wrapped DEKs[];
    else (missing)
      :Prompt for matching older password;
      :Derive and link missing old KEK;
    endif
  endif
endwhile (no)

:GET /api/auth/kek-status;
if (Every row points at newest kek_public_key?) then (yes)
  :Migration complete;
else (no)
  :Keep migrating remaining rows;
endif
stop
@enduml
```

## Operational meaning

- Salt stability keeps older password epochs derivable when a user still has old ciphertext in storage.
- KEK epoch creation is immediate on rotation, but migration completion is deferred until all owner-addressed DEKs are rewrapped.
- The encrypted note payload itself does not change during migration; only the DEK wrapper set does.
- Because `PUT /api/notes/{note_id}` replaces the note's wrapped DEKs, the client must submit a complete current recipient set for every updated note.