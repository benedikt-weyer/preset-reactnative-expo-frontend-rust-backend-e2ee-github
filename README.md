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
cp apps/backend/.env.example apps/backend/.env
pnpm db:up
pnpm dev:backend
pnpm dev
pnpm dev:mobile
pnpm dev:docs
```

For physical device testing, set the backend URL inside the mobile auth screen or
settings screen to a LAN address such as `http://192.168.1.20:4000`.

## Backend env

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
- The mobile app derives a crypt key from `email + password` locally using SHA-512 based PBKDF2.
- The mobile app derives an auth key from that crypt key and only sends the auth key to the backend.
- Local note content is encrypted and decrypted on-device with the crypt key.
