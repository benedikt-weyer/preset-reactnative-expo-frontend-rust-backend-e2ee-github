# Overview

This repository is structured as a Turbo monorepo with a React Native frontend
in Expo and room for a backend later.

## Current apps

| App | Purpose | Stack |
| --- | --- | --- |
| `apps/mobile` | End-user mobile app | Expo, React Native, NativeWind |
| `apps/docs` | Project documentation | MkDocs Material |

## What exists today

- The mobile app already has a bottom tab navigator.
- The mobile app exposes a `Home` screen and a `Settings` screen.
- Light and dark mode are persisted in SecureStore.
- Turbo orchestrates workspace commands from the repository root.

## Why a docs app exists

The docs app gives the monorepo a stable place to explain structure, commands,
and conventions without overloading the root README.

It also makes GitHub Pages deployment straightforward because MkDocs produces a
fully static site.