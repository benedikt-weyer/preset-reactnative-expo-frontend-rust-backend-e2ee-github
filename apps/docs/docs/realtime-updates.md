# Realtime Updates

This page describes the websocket-based note update stream that lets the web
and mobile clients react to note changes without polling.

## What exists now

The backend now exposes one note-event websocket endpoint:

- `GET /api/notes/events?accessToken=...`

That route upgrades to a websocket and emits a small JSON event whenever a note
row changes in a way that matters to the authenticated principal.

The current implementation covers these note mutations:

- note creation
- note update
- note deletion

The event stream does not carry encrypted note payloads or wrapped DEKs. It
only signals that the client should reload note state from the existing note
routes.

## Why it works this way

The repository already had one authoritative load path for encrypted notes:

- `GET /api/notes`
- `GET /api/notes/{note_id}`

Keeping websocket messages as invalidation signals avoids duplicating that
payload contract across two transports. The apps can continue using the same
decrypt logic, selection logic, and KEK resolution they already use for normal
HTTP note loads.

That means the realtime flow is:

1. The client authenticates normally and gets an access token.
2. The client opens the websocket with that access token.
3. The backend broadcasts a small note-change event after a successful note transaction commit.
4. The client receives the event and refetches notes through the normal REST route.
5. The client decrypts the refreshed ciphertext locally with the existing KEK keyring.

```plantuml format="svg_inline" alt="Realtime websocket refresh flow" title="Realtime websocket refresh flow"
@startuml
skinparam shadowing false

actor User
participant "Web / Mobile Client" as Client
participant "Notes WebSocket" as Ws
participant "Notes REST API" as Api
database "notes + deks" as Store

User -> Client: Log in
Client -> Ws: GET /api/notes/events?accessToken=...
Ws --> Client: websocket connected

User -> Api: create / update / delete note
Api -> Store: commit note + DEK changes
Api -> Ws: broadcast note change event
Ws --> Client: { kind, noteId, occurredAt, ... }
Client -> Api: GET /api/notes
Api -> Store: load encrypted notes for principal
Store --> Api: encrypted payload + wrapped DEKs
Api --> Client: refreshed encrypted notes
Client -> Client: decrypt locally with KEKs
@enduml
```

## Event payload

The shared `@repo/realtime` package expects this payload shape:

| Field | Type | Meaning |
| --- | --- | --- |
| `audiencePrincipalIds` | `string[]` | principals that should receive the event |
| `kind` | `'created' | 'updated' | 'deleted'` | note mutation type |
| `noteId` | `string` | note identifier |
| `occurredAt` | `string` | RFC 3339 timestamp for the committed change |
| `ownerUserId` | `string` | owner account scope for the note |

Clients usually only need `kind` and `noteId` for UI behavior. The remaining
fields let the backend scope delivery and leave room for future client-side
routing or analytics.

## Delivery rules

The backend broadcasts only after the database transaction commits. That avoids
notifying clients about writes that later roll back.

For recipient-aware note updates, the backend includes all principals that need
to hear about the change:

- the owner user
- every current note recipient on create
- the union of old and new recipients on update
- every prior recipient on delete

That union matters for recipient removal. If an API user loses access during a
note update, it still receives one final event telling it to refetch and learn
that the note is no longer available to that principal.

## Authentication and transport notes

The websocket handshake uses the same access token that the REST routes use for
note reads and writes. The current route accepts that token via the
`accessToken` query string because browser websocket APIs do not let the client
set a custom `Authorization` header during the initial handshake.

The shared package converts backend URLs like this:

- `https://...` becomes `wss://...`
- `http://...` becomes `ws://...`

Use `wss` in deployed environments. If the Rust backend is served behind HTTPS
or behind a reverse proxy that terminates TLS, the shared client will upgrade to
`wss` automatically from the public base URL.

## Shared package

The monorepo now includes `@repo/realtime` as the shared websocket client
surface for both app targets.

That package is responsible for:

- building the websocket URL from the configured backend base URL
- upgrading `http` to `ws` and `https` to `wss`
- validating incoming note-change payloads
- reconnecting after disconnects

See [Realtime Package](realtime-package.md) for the package-level API,
exported interfaces, and the consumer/package responsibility split.

The web and mobile apps subscribe to that shared package and reuse their
existing note reload paths when an event arrives.

## Current limitations

- Only note events are streamed right now.
- The websocket stream is a refetch signal, not a partial-sync protocol.
- API-user dashboards still refresh by reusing existing REST fetches after note events rather than receiving dedicated API-user events.
- Browser clients place the access token in the websocket query string during the handshake, so production deployments should still rely on HTTPS and secure logging practices.

## Practical implication

Realtime updates improve freshness, but they do not change the core E2EE model:

- the backend still stores ciphertext only
- the backend still cannot decrypt notes
- clients still need their local KEK material to turn refreshed ciphertext into plaintext