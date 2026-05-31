# Workspace Overview

## Monorepo layout

The repository currently uses the following top-level layout:

- `apps/mobile`: Expo frontend
- `apps/docs`: MkDocs site
- `packages/*`: reserved for future shared libraries

## Mobile app summary

The mobile app is intentionally small right now, but it already has the pieces
that matter for future growth:

- feature-scoped theme persistence
- bottom tab navigation
- NativeWind styling
- a settings flow that applies theme changes immediately

## SOLID direction

The frontend setup already leans toward separation of concerns:

- persistence is isolated in the theme storage module
- theme state is exposed through a provider instead of leaking storage calls
- screens focus on rendering and user interactions
- styling tokens are centralized instead of duplicated per screen

That keeps future backend integration or shared package extraction easier.