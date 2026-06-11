# preset-reactnative-frontend-rust-backend-e2ee-github

Expo frontend scaffolded inside a pnpm + Turbo monorepo, now paired with a Rust
backend using Axum, SeaORM, and Postgres.

## Workspace

- `apps/mobile`: Expo React Native app with NativeWind styling
- `apps/mobile`: registration/login flow and local E2EE note demo
- `apps/mobile`: light and dark mode persisted in `expo-secure-store`
- `apps/backend`: Axum API with `/health`, `/api/auth/register`, and `/api/auth/login`
- `apps/backend`: SeaORM migrations run automatically on startup
- `packages/e2ee-auth`: shared password-to-crypt-key/auth-key derivation and local encryption helpers
- `apps/docs`: MkDocs documentation app with light and dark theme toggle

## Run

```bash
pnpm install
pnpm setupenv
pnpm db:up
pnpm dev:backend
pnpm dev
pnpm dev:mobile
pnpm dev:docs
```

For physical device testing, set the backend URL inside the mobile auth screen or
settings screen to a LAN address such as `http://192.168.1.20:4000`.

## Backend env

`pnpm setupenv` creates any missing `.env` files from nearby `.env.example`
templates, automatically generates a local `JWT_SECRET` for the backend,
and on rerun syncs added or removed fields without overwriting existing
values.

`apps/backend/.env.example` defaults to the Postgres instance from
`docker-compose.yml`.

## Validate

```bash
pnpm check:backend
pnpm build:docs
pnpm typecheck
```

## Auth and E2EE flow

- Username is the plain email address.
- The mobile app generates a random password salt locally during registration, stores it on the backend, and fetches that salt during login before deriving the crypt key with libsodium Argon2id.
- The mobile app derives auth and encryption subkeys from that crypt key with HKDF-SHA512 and only sends the auth key to the backend.
- Local note content is encrypted and decrypted on-device with the crypt key.
