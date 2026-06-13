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
- one or more wrapped DEKs in the `deks` table
- `kek_public_key` on each DEK row, which links the wrapped DEK to one public-key-based KEK epoch
- `resource_id` on the DEK row, which points at the encrypted row id
- `user_id` on the DEK row, which binds the wrapped DEK to one linked principal recipient
- `kem_ciphertext_hex` on the DEK row, which stores the ML-KEM encapsulation ciphertext for that recipient
- `wrapped_dek_hex` on the DEK row, which stores the wrapped DEK ciphertext
- separate nonces for the encrypted payload and each wrapped DEK

For each active KEK, the backend also stores one `kek_metadata` row with:

- `kek_public_key`, supplied by the client as the KEK public key
- `kek_epoch_version`, incremented per principal for rotations
- `user_id`, which scopes that KEK metadata row to one principal

For linked-principal management, the backend also stores:

- owner users in `users`
- API users in `api_users`
- one encrypted API-user label plus its wrapped DEKs
- API-user provisioning progress, which is derived from missing note DEK rows for that API user

When an API user is deleted, the backend also removes all database rows that
would otherwise keep that principal decryptable:

- note-recipient DEK rows whose `user_id` matches the API user id
- label DEK rows whose `resource_id` matches the API user id
- KEK metadata rows in `kek_metadata` scoped to that API user id
- the API user row in `api_users`

When the owner account is deleted, the backend removes everything tied to that
account tree:

- the owner user's note rows in `notes`
- every DEK row whose `resource_id` points at one of those notes
- every DEK row whose `user_id` matches either the owner or one of the linked API users
- every linked API user row in `api_users`
- every KEK metadata row for the owner and each linked API user
- the owner row in `users`

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

- linked KEK keypairs keyed by `kek_public_key`
- the latest linked-principal metadata returned by the backend
- the latest known `kek_epoch_version` values returned by the backend
- any older active KEKs that were relinked with older passwords during login
- temporary client-side migration progress while rewrapping DEKs to a new epoch
- temporary API-user provisioning progress while creating missing recipient wraps

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
  * kek_public_key
  --
  user_id
  kek_epoch_version
}

entity "api_users" as api_users {
  * id
  --
  user_id
  username
  auth_key_hash
  label_ciphertext
}

entity "notes" as notes {
  * id
  --
  user_id
  encrypted_payload
  payload_nonce
}

entity "deks" as deks {
  * resource_id
  * user_id
  --
  kek_public_key
  kem_ciphertext_hex
  wrapped_dek_hex
  nonce_hex
}

users ||--o{ kek_metadata
users ||--o{ notes
users ||--o{ api_users
notes ||--|| deks : resource_id
kek_metadata ||--o{ deks : kek_public_key
api_users ||--o{ deks : user_id
@enduml
```

## Current routes

| Route | Purpose |
| --- | --- |
| `POST /api/auth/salt` | return the stored per-user salt plus active KEK metadata for login |
| `POST /api/auth/register` | create a user from `email + authKey + saltHex` and return the initial KEK metadata |
| `POST /api/auth/login` | verify the derived auth key, issue tokens, and return active KEK metadata |
| `POST /api/auth/refresh` | exchange a refresh token for a fresh access token pair plus the latest KEK metadata |
| `POST /api/auth/api-users/login` | verify an API user's derived auth key and issue principal-aware tokens |
| `POST /api/auth/rotate-password` | update the stored auth-key hash and create the next KEK epoch |
| `GET /api/auth/linked-principals` | return the owner plus linked principals with their latest KEK public keys |
| `GET /api/auth/kek-status` | report whether all DEKs for the user already use the newest KEK epoch |
| `DELETE /api/auth/account` | remove the owner account and all linked api users, notes, KEKs, DEKs, and encrypted rows tied to it |
| `GET /api/auth/api-users` | list API users for the owner account, including label ciphertext and provisioning state |
| `POST /api/auth/api-users` | create an API user and store the initial label ciphertext plus wrapped label DEKs |
| `GET /api/auth/api-users/{api_user_id}` | load one API user and its provisioning state |
| `DELETE /api/auth/api-users/{api_user_id}` | remove one API user and delete its linked KEK metadata plus all linked DEK rows |
| `POST /api/auth/api-users/{api_user_id}/provision` | append wrapped DEKs for notes that still need that API user recipient |
| `GET /api/notes` | return encrypted notes plus the wrapped DEK for the authenticated principal |
| `GET /api/notes/events?accessToken=...` | upgrade to a websocket stream and push note change events to the authenticated principal |
| `POST /api/notes` | create an encrypted note row and its wrapped DEK rows |
| `GET /api/notes/{note_id}` | return one encrypted note and the current principal wrapped DEK |
| `PUT /api/notes/{note_id}` | replace the encrypted note payload and the full wrapped DEK recipient set |
| `DELETE /api/notes/{note_id}` | delete the encrypted note and all of its wrapped DEK rows |

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
  :GET /api/notes/events for websocket updates;
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
- Every wrapped DEK is linked to a specific public-key `kek_public_key`, which allows password rotations without reusing a single long-lived KEK identifier.
- Every wrapped DEK also needs a `kem_ciphertext_hex`; `wrapped_dek_hex` alone is not enough to reconstruct the shared secret during decrypt.
- A note update replaces the entire wrapped-DEK recipient set, so clients must write all current recipients together.
- Clients must keep older linked KEKs locally if older ciphertext rows are still active.
- Rotating the password is not finished until the client verifies that every DEK row was rewrapped onto the newest KEK epoch.
- Deleting an API user must remove both note-recipient DEKs and label DEKs before deleting that principal's KEK metadata, because DEK rows reference `kek_public_key`.
- Deleting the owner account must remove note-resource DEKs as well as principal-linked DEKs, because note ciphertext rows and linked principals fan out across the same `deks` table.
- Realtime note updates are pushed over a websocket stream, but the encrypted payload still comes from the normal notes routes. The event stream is a signal to refetch, not a second ciphertext transport.
- The backend can store and serve encrypted notes, but it still cannot decrypt them.