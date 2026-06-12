# Password Rotation

Password rotation updates authentication state and encryption state in two
separate but coordinated phases.

## Rotation flow

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
Client -> Shared: derive authKey and KEK from new cryptKey
Shared --> Client: new authKey + new KEK
Client -> Api: POST /api/auth/rotate-password\nauthKey
Api -> Users: Replace auth_key_hash
Api -> KekMeta: Insert next kek_id and kek_epoch_version
Api --> Client: Updated KEK metadata list
Client -> Client: Link new KEK to newest kek_id
Client -> Client: Start DEK rewrap migration
@enduml
```

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

```plantuml format="svg_inline" alt="DEK migration flow" title="DEK migration flow"
@startuml
start
:Fetch encrypted rows and wrapped DEKs;

while (Rows left to inspect?) is (yes)
  :Read encryptedDek.kekId;
  if (Already newest kek_id?) then (yes)
    :Leave row unchanged;
  else (no)
    if (Old KEK linked locally?) then (yes)
      :Unwrap DEK with old KEK;
      :Rewrap same DEK with newest KEK;
      :PUT /api/notes/{note_id}
      with unchanged ciphertext
      and updated wrapped DEK;
    else (missing)
      :Prompt for matching older password;
      :Derive and link missing old KEK;
    endif
  endif
endwhile (no)

:GET /api/auth/kek-status;
if (Every row points at newest kek_id?) then (yes)
  :Migration complete;
else (no)
  :Keep migrating remaining rows;
endif
stop
@enduml
```

## Operational meaning

- Salt stability keeps older password epochs derivable when a user still has old ciphertext in storage.
- KEK epoch creation is immediate on rotation, but migration completion is deferred until all DEKs are rewrapped.
- The encrypted note payload itself does not change during migration; only the DEK wrapper does.