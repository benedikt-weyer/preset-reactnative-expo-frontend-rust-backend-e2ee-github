FROM node:26-trixie-slim AS base

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
ENV NEXT_TELEMETRY_DISABLED=1

RUN npm install --global pnpm@10.33.4

FROM base AS deps

WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json ./
COPY apps/web/package.json apps/web/package.json
COPY packages/e2ee-auth/package.json packages/e2ee-auth/package.json
COPY packages/note-realtime/package.json packages/note-realtime/package.json
COPY packages/oqs-kek/package.json packages/oqs-kek/package.json

RUN pnpm install --frozen-lockfile --filter web...

FROM base AS builder

WORKDIR /app

COPY --from=deps /app/ ./
COPY apps/web ./apps/web
COPY packages/e2ee-auth ./packages/e2ee-auth
COPY packages/note-realtime ./packages/note-realtime
COPY packages/oqs-kek ./packages/oqs-kek

RUN mkdir -p apps/web/public \
    && pnpm --filter web build

FROM node:26-trixie-slim AS runner

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV HOSTNAME=0.0.0.0
ENV PORT=3000

WORKDIR /app

RUN useradd --create-home --uid 10001 appuser

COPY --from=builder /app/apps/web/.next/standalone ./
COPY --from=builder /app/apps/web/.next/static ./apps/web/.next/static
COPY --from=builder /app/apps/web/public ./apps/web/public

EXPOSE 3000

USER appuser

CMD ["node", "apps/web/server.js"]