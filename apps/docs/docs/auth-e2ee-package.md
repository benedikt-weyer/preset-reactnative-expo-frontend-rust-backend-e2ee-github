# `@repo/e2ee-auth` Package Guide

This page documents the public `@repo/e2ee-auth` API that a consumer must use
to integrate local credential derivation, KEK derivation, and encrypted payload
handling into an app.

It focuses on the package boundary itself: what the package exports, what each
export is for, and which responsibilities stay with the package user.

## Import paths

The package exposes two consumer entry points:

| Import path | Use from | Notes |
| --- | --- | --- |
| `@repo/e2ee-auth/web` | browser-based apps such as Next.js | includes the full web feature set, including API-token helpers and multi-recipient encryption helpers |
| `@repo/e2ee-auth/native` | React Native / Expo apps | omits the web-only token helpers and the multi-recipient helper |

The root export `@repo/e2ee-auth` currently resolves to the web entry point.
For application code, prefer the explicit `/web` or `/native` subpath so the
platform contract stays obvious.

## Boundary overview

```plantuml format="svg_inline" alt="Package boundary for e2ee-auth" title="Package boundary for e2ee-auth"
@startuml
left to right direction
skinparam shadowing false
skinparam packageStyle rectangle

rectangle "Consuming App" as App {
  component "Collect email, password, token" as Inputs
  component "Call auth and note APIs" as Api
  database "Persist salt, session, linked KEKs" as Storage
  component "Select recipients and migration policy" as Policy
}

rectangle "@repo/e2ee-auth" as Package {
  component "Normalize email" as Normalize
  component "Derive cryptKey + authKey" as Derive
  component "Derive deterministic KEK keypair" as Kek
  component "Encrypt/decrypt payloads" as Encrypt
  component "Wrap/rewrap DEKs" as Wrap
}

Inputs --> Normalize
Inputs --> Derive
Derive --> Kek
Kek --> Api : send authKey / kekPublicKey
Encrypt --> Api : send ciphertext payloads
Wrap --> Api : send wrapped DEKs
Storage --> App
Policy --> App
App --> Package

note bottom of Package
The package never stores state, never calls the backend,
and never decides which recipient or KEK epoch to use.
end note
@enduml
```

## Responsibility split

### Package responsibilities

`@repo/e2ee-auth` is responsible for:

- normalizing an email consistently with `normalizeEmail()`
- deriving `cryptKey` and `authKey` locally from `email + password + saltHex`
- deriving a deterministic ML-KEM KEK keypair from a `cryptKey`
- generating random password salts and, on web, random API tokens
- encrypting plaintext strings into typed ciphertext payloads
- decrypting ciphertext payloads back into plaintext strings
- wrapping DEKs with either a password-derived KEK or an asymmetric recipient KEK
- rewrapping an existing DEK onto a new KEK without changing the encrypted note payload
- validating basic package input constraints such as empty passwords, malformed salts, malformed tokens, and missing KEK ids

### Consumer responsibilities

The package user is responsible for:

- collecting raw secrets such as email, password, and API token input
- choosing the correct import path: `@repo/e2ee-auth/web` or `@repo/e2ee-auth/native`
- fetching and persisting the per-account `saltHex`
- sending `authKey`, `email`, `saltHex`, and `kekPublicKey` to the backend on the correct routes
- persisting enough local state to decrypt later, typically the active `cryptKey`, linked historical KEKs, and the associated `kekPublicKey`
- deciding which recipients should receive wrapped DEKs for each encrypted resource
- storing and transporting the returned payload objects without mutating their fields
- determining when an older KEK epoch still exists and when a rewrap or migration pass is required
- associating wrapped DEKs with application-level resource ids, recipient ids, and backend records
- handling auth sessions, refresh tokens, access tokens, and retry logic
- surfacing package errors to the user in a way that matches the app UX

### What the package does not do

The package intentionally does not:

- fetch salts from the backend
- store `cryptKey`, salts, sessions, or ciphertext for you
- know your user ids, note ids, or backend route schema
- choose the owner KEK epoch or linked principals to target
- migrate stored ciphertext automatically
- provide React hooks, context, storage adapters, or API clients

## Minimum integration flow

Most consumers need four flows.

### 1. Registration

1. Normalize the email with `normalizeEmail(email)`.
2. Generate a salt with `createPasswordSalt()`.
3. Derive credentials with `deriveCredentials(email, password, saltHex)`.
4. Derive the current KEK keypair with `deriveKekKeyPair(cryptKey)`.
5. Send `email`, `authKey`, `saltHex`, and `kekPublicKey` to the backend.

### 2. Login

1. Normalize the email with `normalizeEmail(email)`.
2. Fetch the stored `saltHex` from the backend.
3. Derive credentials with `deriveCredentials(email, password, saltHex)`.
4. Optionally derive the KEK keypair with `deriveKekKeyPair(cryptKey)` when you need to compare or link the active `kekPublicKey`.
5. Persist the `cryptKey` and any linked historical KEKs your app needs for later decrypt or migration.

### 3. Encrypt and decrypt content

1. Keep the current `cryptKey` available locally after login or token derivation.
2. Encrypt plaintext with one of the `encrypt...` helpers.
3. Persist the returned payload object exactly as returned.
4. Load that payload later and pass it to the matching `decrypt...` helper with the correct `cryptKey`.

### 4. Password rotation or KEK migration

1. Derive the next `cryptKey` from the new password.
2. Derive the next KEK keypair and link the new `kekPublicKey` server-side.
3. For each stored wrapped DEK, call the matching `rewrap...` helper.
4. Replace only the wrapped DEK metadata on the backend; the encrypted note payload stays unchanged.

## Public functions

### Common exports on web and native

| Function | Returns | Use when | Consumer responsibilities |
| --- | --- | --- | --- |
| `normalizeEmail(email)` | `string` | before registration or login | still validate UI input and decide when to call it |
| `createPasswordSalt()` | `Promise<string>` | creating a new password-based identity | persist the returned lowercase hex salt and send it to the backend |
| `deriveCredentials(email, password, saltHex)` | `Promise<DerivedCredentials>` | deriving local auth and encryption material from a password | fetch the correct `saltHex`, hold `cryptKey` securely, send only `authKey` to the backend |
| `deriveKekKeyPair(cryptKey)` | `Promise<KekKeyPair>` | linking or comparing the current deterministic ML-KEM KEK | persist or compare `kekPublicKey` and keep the private material local only |
| `encryptString(value, cryptKey)` | `EncryptedPayload` | encrypting a string directly with a key derived from the current password | store the returned payload object exactly |
| `decryptString(payload, cryptKey)` | `string` | decrypting a payload created with `encryptString` | supply the same logical `cryptKey` that encrypted the data |
| `encryptStringWithDek(value, cryptKey, kekPublicKey)` | `KekDekEncryptedPayload` | encrypting content under a random DEK, then wrapping that DEK with a password-derived KEK | decide which `kekPublicKey` label to attach and store both payload parts |
| `decryptStringWithDek(payload, cryptKey)` | `string` | decrypting data produced by `encryptStringWithDek` | supply the matching `cryptKey` and preserve the payload fields unchanged |
| `encryptStringWithAsymmetricKek(value, recipientKekId)` | `Promise<KekAsymmetricDekEncryptedPayload>` | encrypting content for one recipient KEK public key | choose the correct recipient key and store the full payload |
| `decryptStringWithAsymmetricKek(payload, cryptKey)` | `Promise<string>` | decrypting a single-recipient asymmetric payload | keep the correct `cryptKey` locally so the package can re-derive the recipient KEK keypair |
| `rewrapEncryptedDek(payload, currentCryptKey, nextCryptKey, nextKekId)` | `KekWrappedPayload` | moving a password-wrapped DEK from one password-derived KEK to another | replace only the wrapped DEK metadata in storage |
| `rewrapAsymmetricEncryptedDek(payload, currentCryptKey, nextRecipientKekId)` | `Promise<KekAsymmetricWrappedPayload>` | moving an asymmetrically wrapped DEK from the current deterministic KEK to a new recipient KEK | update only the wrapped DEK record and keep the encrypted payload untouched |

### Web-only exports

| Function | Returns | Use when | Consumer responsibilities |
| --- | --- | --- | --- |
| `createApiToken()` | `Promise<string>` | provisioning a browser-side API principal or token-based identity | persist or display the token exactly once according to your security policy |
| `deriveApiTokenCredentials(tokenHex)` | `Promise<DerivedApiTokenCredentials>` | deriving auth and KEK material from a token instead of a password | store the token securely, send only `authKey`, and keep `cryptKey` local |
| `encryptStringWithAsymmetricKeks(value, recipientKekIds)` | `Promise<MultiRecipientKekAsymmetricDekEncryptedPayload>` | encrypting one payload for multiple recipients in one call | choose the recipient KEK list and associate each wrapped DEK with the correct recipient record |

## Public types

### Credential types

| Type | Fields | What the consumer uses it for |
| --- | --- | --- |
| `CryptKey` | `Uint8Array` | local long-lived encryption material derived from a password or token |
| `DerivedCredentials` | `authKey`, `cryptKey`, `email` | registration and login flows that start from email and password |
| `DerivedApiTokenCredentials` | `authKey`, `cryptKey`, `kekKeyPair`, `tokenHex` | web-only token flows that start from an API token |

`DerivedCredentials` is the package result that most password-based consumers must
hold onto. The `authKey` leaves the device for backend verification. The
`cryptKey` must stay local because all decrypt, rewrap, and KEK-derivation flows
depend on it.

### Symmetric payload types

| Type | Fields | Produced by | Consumed by |
| --- | --- | --- | --- |
| `EncryptedPayload` | `algorithm`, `ciphertextHex`, `nonceHex`, `version` | `encryptString()` | `decryptString()` |
| `KekWrappedPayload` | `algorithm`, `kekPublicKey`, `nonceHex`, `version`, `wrappedDekHex` | `encryptStringWithDek()`, `rewrapEncryptedDek()` | embedded inside `KekDekEncryptedPayload` |
| `KekDekEncryptedPayload` | `encryptedDek`, `encryptedPayload` | `encryptStringWithDek()` | `decryptStringWithDek()` |

Use these payloads when the consumer wants a random DEK per resource but still
wants the DEK tied to a password-derived KEK rather than to a recipient public
key.

### Asymmetric KEK types

| Type | Fields | Produced by | Consumed by |
| --- | --- | --- | --- |
| `KekKeyPair` | `algorithm`, `kekPublicKey`, `privateKeyHex`, `publicKeyHex`, `version` | `deriveKekKeyPair()`, `deriveApiTokenCredentials()` | registration, key linking, and key comparison logic |
| `KekAsymmetricWrappedPayload` | `algorithm`, `kemCiphertextHex`, `kekPublicKey`, `nonceHex`, `version`, `wrappedDekHex` | `encryptStringWithAsymmetricKek()`, `rewrapAsymmetricEncryptedDek()` | embedded inside asymmetric encrypted payloads |
| `KekAsymmetricDekEncryptedPayload` | `encryptedDek`, `encryptedPayload` | `encryptStringWithAsymmetricKek()` | `decryptStringWithAsymmetricKek()` |
| `MultiRecipientKekAsymmetricDekEncryptedPayload` | `encryptedDeks`, `encryptedPayload` | `encryptStringWithAsymmetricKeks()` | consumer-managed multi-recipient storage and transport |

These are the types to use when a resource must be readable by multiple linked
principals or when the wrapped DEK must target a specific recipient public key.

## Platform differences that matter

The common password and payload APIs are intentionally aligned across web and
native. The differences are small but important:

- only the web entry point exports `createApiToken()`
- only the web entry point exports `deriveApiTokenCredentials()`
- only the web entry point exports `encryptStringWithAsymmetricKeks()`
- only the web entry point exports the web-only result types `DerivedApiTokenCredentials` and `MultiRecipientKekAsymmetricDekEncryptedPayload`

If your app needs browser-managed API users or one-call multi-recipient wrapping,
use `@repo/e2ee-auth/web`. If your app only needs password-based mobile flows,
`@repo/e2ee-auth/native` is the matching surface.

## Consumer-owned state the package expects

The package is stateless, so the consumer must preserve enough information to
reconstruct future decrypt operations. In practice that usually means:

- the normalized `email`
- the account `saltHex`
- the active `cryptKey`
- any older linked `cryptKey` values that still correspond to active historical `kekPublicKey` values
- the backend's current KEK metadata list so the app can decide which KEK epoch is newest
- encrypted payloads and wrapped DEKs exactly as returned by the package

The package does not enforce a storage schema for that state. The consuming app
must define and maintain that schema.

## Example integration skeleton

```ts
import {
  createPasswordSalt,
  deriveCredentials,
  deriveKekKeyPair,
  encryptStringWithAsymmetricKek,
  decryptStringWithAsymmetricKek,
} from '@repo/e2ee-auth/web';

const saltHex = await createPasswordSalt();
const credentials = await deriveCredentials('person@example.com', 'correct horse', saltHex);
const kekKeyPair = await deriveKekKeyPair(credentials.cryptKey);

await registerRequest({
  authKey: credentials.authKey,
  email: credentials.email,
  kekPublicKey: kekKeyPair.kekPublicKey,
  saltHex,
});

const encrypted = await encryptStringWithAsymmetricKek('secret note', kekKeyPair.kekPublicKey);
const plaintext = await decryptStringWithAsymmetricKek(encrypted, credentials.cryptKey);
```

The package covers the derivation and encryption boundary in that example. The
consumer still owns `registerRequest`, storage of the returned session and salt,
and the decision about where the ciphertext should be persisted.