# `@repo/realtime` Package Guide

This page documents the public `@repo/realtime` API that consumers use to
connect to the backend note-event websocket stream.

The package is intentionally small. It does not carry note payloads, auth
refresh logic, or decrypt logic. Its job is to turn a backend URL plus an
access token into a resilient websocket subscription that emits validated note
change events.

## Package surface

The public interface consists of:

- `buildNoteEventsUrl()`
- `subscribeToNoteEvents()`
- `NoteChangeEvent`
- `SubscribeToNoteEventsOptions`
- `NoteEventSubscription`

Everything else in the implementation is internal wiring.

## Boundary overview

```plantuml format="svg_inline" alt="Package boundary for realtime" title="Package boundary for realtime"
@startuml
left to right direction
skinparam shadowing false
skinparam packageStyle rectangle

rectangle "Consuming App" as App {
  component "Provide backend URL
and access token" as Inputs
  component "Handle reconnect errors
and note invalidation" as Logic
  component "Refetch notes and decrypt" as Reload
}

rectangle "@repo/realtime" as Package {
  component "Build websocket URL" as Url
  component "Open websocket" as Socket
  component "Validate note events" as Validate
  component "Reconnect on disconnect" as Reconnect
}

rectangle "Backend" as Backend {
  component "GET /api/notes/events" as Ws
}

Inputs --> Url
Url --> Socket
Socket --> Ws
Ws --> Validate
Validate --> Logic
Logic --> Reload
Reconnect --> Socket
App --> Package

note bottom of Package
The package does not refetch notes, refresh tokens,
or decide how the UI should react to an event.
end note
@enduml
```

## Responsibility split

### Package responsibilities

`@repo/realtime` is responsible for:

- validating that `baseUrl` and `accessToken` are present before opening a socket
- building the websocket endpoint URL from the configured backend base URL
- converting `http` to `ws` and `https` to `wss`
- appending `accessToken` as a query-string parameter
- opening the websocket with either the global runtime constructor or a caller-provided constructor
- parsing incoming string messages as JSON
- validating that an incoming payload matches `NoteChangeEvent`
- ignoring non-string websocket messages
- reporting connection and payload errors through `onError`
- reconnecting automatically after disconnects or failed open attempts
- stopping reconnect attempts when the consumer explicitly closes the subscription

### Consumer responsibilities

The package user is responsible for:

- passing the current backend base URL
- passing a valid access token for the authenticated principal
- providing the `onEvent` callback that decides what to do when an event arrives
- providing an `onError` callback if the UI needs to surface connection problems
- closing the returned subscription on logout, unmount, or scope change
- refetching notes or note details after an event arrives
- decrypting refreshed ciphertext with the existing E2EE flow
- refreshing expired auth sessions before reconnecting if the app requires it
- choosing a custom websocket path when the backend route differs from the default `/api/notes/events`
- deciding whether the UI should debounce, batch, or ignore certain event bursts

### What the package does not do

The package intentionally does not:

- fetch note data from REST endpoints
- merge or cache note state
- refresh access tokens
- store subscriptions globally for you
- know which screen or component should react to an event
- decrypt payloads or load KEKs
- guarantee event ordering across reconnect boundaries beyond whatever the backend provides

## Public interfaces

### `NoteChangeEvent`

This is the event payload shape the package emits to `onEvent`.

| Field | Type | Meaning |
| --- | --- | --- |
| `audiencePrincipalIds` | `string[]` | principals the backend considered eligible for the event |
| `kind` | `'created' | 'updated' | 'deleted'` | the note mutation type |
| `noteId` | `string` | the affected note id |
| `occurredAt` | `string` | RFC 3339 timestamp for the committed change |
| `ownerUserId` | `string` | owner account scope for the note |

Consumers usually use `kind` and `noteId` immediately, and may use the other
fields for filtering, telemetry, or principal-aware logic.

### `NoteEventSubscription`

The `subscribeToNoteEvents()` call returns this object:

| Field | Type | Meaning |
| --- | --- | --- |
| `close` | `() => void` | closes the current socket and cancels future reconnect attempts |

If the consumer does not call `close()`, the package will continue attempting to
reconnect after disconnects.

### `SubscribeToNoteEventsOptions`

These are the options required to create a subscription.

| Field | Required | Type | Meaning |
| --- | --- | --- | --- |
| `accessToken` | yes | `string` | bearer token sent as the `accessToken` query parameter |
| `baseUrl` | yes | `string` | backend base URL used to derive the websocket URL |
| `onEvent` | yes | `(event: NoteChangeEvent) => void` | called for every validated event |
| `onError` | no | `(error: Error) => void` | called when the socket or payload handling fails |
| `path` | no | `string` | overrides the default websocket path `/api/notes/events` |
| `reconnectDelayMs` | no | `number` | overrides the default reconnect delay of `1500` ms |
| `WebSocketCtor` | no | `new (url: string) => WebSocket-like` | injects a runtime-specific websocket constructor when `globalThis.WebSocket` is unavailable or when tests need a mock |

The only truly required behavioral hooks are `baseUrl`, `accessToken`, and
`onEvent`. Everything else customizes how the consumer wants the subscription to
behave in a given runtime.

## Public functions

### `buildNoteEventsUrl(baseUrl, accessToken, path?)`

`buildNoteEventsUrl()` creates the exact websocket URL that
`subscribeToNoteEvents()` will use.

| Parameter | Type | Meaning |
| --- | --- | --- |
| `baseUrl` | `string` | backend URL, such as `https://api.example.com` |
| `accessToken` | `string` | access token placed into the websocket query string |
| `path` | `string` | optional route override, defaulting to `/api/notes/events` |

Returns: `string`

Use this helper when the consumer needs to:

- inspect or log the final websocket endpoint
- verify URL generation in tests
- build a socket connection outside `subscribeToNoteEvents()` while still reusing the shared URL normalization rules

Validation behavior:

- throws if `baseUrl` is blank
- throws if `accessToken` is blank
- throws if the URL protocol is not `http`, `https`, `ws`, or `wss`
- upgrades `http` to `ws` and `https` to `wss`

Example:

```ts
import { buildNoteEventsUrl } from '@repo/realtime';

const websocketUrl = buildNoteEventsUrl(
  'https://api.example.com',
  'token-123',
);

// wss://api.example.com/api/notes/events?accessToken=token-123
```

### `subscribeToNoteEvents(options)`

`subscribeToNoteEvents()` is the primary integration function. It opens the
socket, validates incoming messages, and reconnects automatically when needed.

Returns: `NoteEventSubscription`

Behavior summary:

1. Resolves the websocket constructor from `options.WebSocketCtor` or `globalThis.WebSocket`.
2. Builds the websocket URL with `buildNoteEventsUrl()`.
3. Opens the socket.
4. Parses incoming string messages.
5. Validates each payload against `NoteChangeEvent`.
6. Calls `onEvent` for valid events.
7. Calls `onError` for invalid payloads or websocket-level failures.
8. Reconnects after disconnects unless the consumer called `close()`.

Example:

```ts
import { subscribeToNoteEvents } from '@repo/realtime';

const subscription = subscribeToNoteEvents({
  accessToken: session.token,
  baseUrl: backendUrl,
  onError: (error) => {
    console.error(error.message);
  },
  onEvent: () => {
    void reloadNotes();
  },
});

// later
subscription.close();
```

## Minimum integration flow

### 1. Login first

The package expects an already-authenticated app state. The consumer must first
obtain an access token through the normal auth flow.

### 2. Open the subscription

Call `subscribeToNoteEvents()` with the current backend URL, the current access
token, and an `onEvent` handler.

### 3. Treat events as invalidation signals

When `onEvent` fires, the consumer should usually reload notes through the
existing REST path rather than trying to rebuild note state only from the event.

### 4. Close on lifecycle changes

Close the subscription when:

- the screen unmounts
- the principal changes
- the backend URL changes
- the session is cleared or the user logs out

## Failure modes the consumer should plan for

- If `baseUrl` is blank, the package throws before connecting.
- If `accessToken` is blank, the package throws before connecting.
- If the runtime has no websocket implementation, the package throws before connecting.
- If the backend sends invalid JSON or the wrong payload shape, the package reports an error through `onError` and ignores that message.
- If the socket drops, the package retries after the configured reconnect delay.
- If the token expires, the package cannot refresh it on its own; the consumer must refresh the session and recreate the subscription with a new token.

## Consumer-owned policy decisions

Even with the shared package in place, these integration decisions stay outside
the package boundary:

- whether every event should trigger a full notes reload or a targeted note reload
- whether events should be ignored when the app is backgrounded
- how websocket errors should be shown to the user
- whether reconnect storms should back off more aggressively than the default fixed delay
- whether multiple screens should share one subscription or keep their own scoped subscriptions

## Example React lifecycle pattern

```ts
useEffect(() => {
  if (!session) {
    return;
  }

  const subscription = subscribeToNoteEvents({
    accessToken: session.token,
    baseUrl: backendUrl,
    onError: (error) => {
      setStatusMessage(error.message);
    },
    onEvent: () => {
      void loadNotes();
    },
  });

  return () => {
    subscription.close();
  };
}, [backendUrl, loadNotes, session]);
```

That pattern matches the actual app integration in this repository: the shared
package owns websocket mechanics, while the app owns session state, note
reloading, and decrypted UI state.