# Storage And Routes

This page summarizes the persisted data model, the public routes that support
the flow, and the practical constraints that fall out of the design.

## What the backend stores

The current backend stores these user fields:

- `email`
- `auth_key_hash`
- `auth_salt`
- timestamps and user metadata

For each encrypted resource row, the backend also stores:

- the encrypted resource payload in its own table, for example `notes`
- one wrapped DEK in the `deks` table
- `kek_id` on the DEK row, which links the wrapped DEK to one public-key-based KEK epoch
- `resource_id` on the DEK row, which points at the encrypted row id
- `user_id` on the DEK row, which binds the wrapped DEK to the owning user
- `wrapped_dek_hex` on the DEK row, which stores the wrapped DEK ciphertext
- separate nonces for the encrypted payload and the wrapped DEK

For each active KEK, the backend also stores one `kek_metadata` row with:

- `kek_id`, supplied by the client as the KEK public key
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

- linked KEK keypairs keyed by `kek_id`
- the latest known `kek_epoch_version` values returned by the backend
- any older active KEKs that were relinked with older passwords during login
- temporary client-side migration progress while rewrapping DEKs to a new epoch

```plantuml format="svg_inline" alt="Backend storage model" title="Backend storage model"
@startuml
skinparam shadowing false
skinparam linetype ortho

entity "users" as users {
  * id
  --
  email
  auth_key_hash
  auth_salt
}

entity "kek_metadata" as kek_metadata {
  * kek_id
  --
  user_id
  kek_epoch_version
}

entity "notes" as notes {
  * id
  --
  user_id
  encrypted_payload
  payload_nonce
}

entity "deks" as deks {
  * id
  --
  user_id
  resource_id
  kek_id
  wrapped_dek_hex
  nonce_hex
}

users ||--o{ kek_metadata
users ||--o{ notes
users ||--o{ deks
notes ||--|| deks : resource_id
kek_metadata ||--o{ deks : kek_id
@enduml
```

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

```plantuml format="svg_inline" alt="Route coverage by lifecycle step" title="Route coverage by lifecycle step"
@startuml
start
:POST /api/auth/register;
:POST /api/auth/salt;
:POST /api/auth/login;

if (Password change?) then (yes)
  :POST /api/auth/rotate-password;
  :GET /api/auth/kek-status;
endif

if (Sync encrypted note?) then (yes)
  :GET /api/notes or GET /api/notes/{note_id};
  :POST /api/notes or PUT /api/notes/{note_id};
  :DELETE /api/notes/{note_id} when removing data;
endif
stop
@enduml
```

## Important implications

- Existing accounts and encrypted note rows created under older schemes are not compatible with the current flow.
- The email is an identifier now, not an input to the password KDF.
- Every encrypted resource row gets its own client-generated random DEK.
- Every wrapped DEK is linked to a specific public-key `kek_id`, which allows password rotations without reusing a single long-lived KEK identifier.
- Clients must keep older linked KEKs locally if older ciphertext rows are still active.
- Rotating the password is not finished until the client verifies that every DEK row was rewrapped onto the newest KEK epoch.
- The backend can store and serve encrypted notes, but it still cannot decrypt them.