# Backend Integration Tests

## Overview

The repository includes a dedicated integration test package at
`packages/backend-integration-tests`.

These tests exercise the real Rust backend API, a real Postgres instance, and
the shared `@repo/e2ee-auth` package together.

The suite is designed to verify end-to-end behavior instead of mocking the
 encryption or storage layers.

## What the suite runs

The current suite covers three user-facing flows:

- register, login, and note creation
- password rotation with note DEK rewrapping
- API user creation, provisioning, and note access

Each test asserts both API responses and persisted database rows.

## Execution model

The suite is intentionally ordered.

Vitest runs the files in this sequence:

1. `01-register-login-note.test.ts`
2. `02-password-rotation.test.ts`
3. `03-api-user.test.ts`

The second and third files both begin by executing the full register/login/note
creation flow before continuing with their flow-specific assertions.

That means the logical test progression is:

1. run case 1
2. reset persisted state
3. run case 1, then run case 2
4. reset persisted state
5. run case 1, then run case 3
6. reset persisted state

This is implemented so that the password-rotation and API-user tests always
start from the exact same known-good note setup.

## Isolation and infrastructure

The integration package uses:

- `vitest` for the test runner
- `testcontainers` to start Postgres
- `pg` for direct database assertions
- `cargo run` to boot the backend during the suite

The shared harness resets the database before and after each top-level test.

This keeps every scenario isolated even when one scenario intentionally builds
on the setup flow from case 1.

## Commands

From the repository root:

### `pnpm test:integration`

Runs the integration suite through Turbo.

### `pnpm --filter @repo/backend-integration-tests typecheck`

Typechecks only the integration-test package.

### `pnpm --filter @repo/backend-integration-tests exec vitest run --config vitest.config.ts`

Runs the integration suite directly with Vitest.

## Code layout

The relevant files are:

- `packages/backend-integration-tests/src/integration-support.ts`: shared
  harness, DB reset logic, HTTP helpers, and the reusable setup flow
- `packages/backend-integration-tests/src/01-register-login-note.test.ts`:
  baseline register/login/note case
- `packages/backend-integration-tests/src/02-password-rotation.test.ts`:
  case 1 plus password rotation
- `packages/backend-integration-tests/src/03-api-user.test.ts`:
  case 1 plus API-user provisioning
- `packages/backend-integration-tests/test-sequencer.ts`: explicit file order

## Why this structure exists

The shared setup flow is not duplicated by copy-pasting assertions into each
file.

Instead, case 1 is expressed once and reused where later flows need a valid
encrypted note owned by a logged-in user. That keeps the suite strict about the
starting state while still making the dependencies between flows explicit.