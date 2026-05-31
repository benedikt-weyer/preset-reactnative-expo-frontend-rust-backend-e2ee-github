# preset-reactnative-frontend-rust-backend-e2ee-github

Expo frontend scaffolded inside a pnpm + Turbo monorepo. The backend can be
added later without changing the repository shape.

## Workspace

- `apps/mobile`: Expo React Native app with NativeWind styling
- `apps/mobile`: bottom tab navigation with `Home` and `Settings`
- `apps/mobile`: light and dark mode persisted in `expo-secure-store`
- `apps/docs`: MkDocs documentation app with light and dark theme toggle

## Run

```bash
pnpm install
pnpm dev
pnpm dev:mobile
pnpm dev:docs
```

## Validate

```bash
pnpm build:docs
pnpm typecheck
```
