import { spawn, type ChildProcessByStdio } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import net from 'node:net';
import path from 'node:path';
import type { Readable } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import {
  createPasswordSalt,
  decryptStringWithAsymmetricKek,
  deriveCredentials,
  deriveKekKeyPair,
  encryptStringWithAsymmetricKeks,
  type DerivedCredentials,
  type EncryptedPayload,
  type KekAsymmetricDekEncryptedPayload,
  type KekAsymmetricWrappedPayload,
} from '@repo/e2ee-auth/web';
import { Client } from 'pg';
import { afterAll, beforeAll, beforeEach, afterEach, expect } from 'vitest';
import { GenericContainer, type StartedTestContainer } from 'testcontainers';

type BackendProcess = ChildProcessByStdio<null, Readable, Readable>;

type Harness = {
  backendBaseUrl: string;
  backendLogs: string;
  backendProcess: BackendProcess;
  dbClient: Client;
  postgresContainer: StartedTestContainer;
};

type WrappedDekRequest = KekAsymmetricWrappedPayload & {
  userId: string;
};

type Recipient = {
  kekPublicKey: string;
  principalId: string;
};

export type KekMetadata = {
  kekEpochVersion: number;
  kekPublicKey: string;
};

export type AuthResponse = {
  currentPrincipal: {
    id: string;
    kind: 'user' | 'api_user';
    email?: string | null;
    username?: string | null;
  };
  kekMetadatas: KekMetadata[];
  linkedPrincipals: Array<{
    id: string;
    kind: 'user' | 'api_user';
    latestKekEpochVersion: number;
    latestKekPublicKey: string;
    email?: string | null;
    username?: string | null;
  }>;
  refreshToken: string;
  token: string;
  user: {
    email: string;
    id: string;
  };
};

export type SaltResponse = {
  kekMetadatas: KekMetadata[];
  saltHex: string;
};

export type NoteResponse = {
  createdAt: string;
  encryptedDek: WrappedDekRequest;
  encryptedPayload: EncryptedPayload;
  id: string;
  updatedAt: string;
};

export type ApiUserResponse = {
  createdAt: string;
  encryptedLabel: EncryptedPayload;
  encryptedLabelDek: WrappedDekRequest;
  id: string;
  latestKekEpochVersion: number;
  latestKekPublicKey: string;
  provisioning: {
    completedResourceCount: number;
    pendingNoteIds: string[];
    pendingResourceCount: number;
    totalResourceCount: number;
  };
  updatedAt: string;
  username: string;
};

export type KekStatusResponse = {
  allDeksUseLatestKek: boolean;
  latestKekDekCount: number;
  latestKekEpochVersion: number;
  latestKekPublicKey: string;
  pendingDekCount: number;
  totalDekCount: number;
};

export type RegisteredUser = {
  credentials: DerivedCredentials;
  email: string;
  login: AuthResponse;
  password: string;
  register: AuthResponse;
  saltHex: string;
};

export type RegisterLoginNoteFlowResult = {
  createdNote: NoteResponse;
  latestOwnerKek: KekMetadata;
  notePlaintext: string;
  registered: RegisteredUser;
};

const CURRENT_FILE = fileURLToPath(import.meta.url);
const CURRENT_DIR = path.dirname(CURRENT_FILE);
const WORKSPACE_ROOT = path.resolve(CURRENT_DIR, '../../..');
const BACKEND_DIR = path.join(WORKSPACE_ROOT, 'apps/backend');
const POSTGRES_DATABASE = 'preset';
const POSTGRES_PASSWORD = randomUUID();
const POSTGRES_USER = 'preset';

let harness: Harness | null = null;

export function useIntegrationSuite() {
  beforeAll(async () => {
    harness = await startHarness();
  });

  beforeEach(async () => {
    await resetDatabase();
  });

  afterEach(async () => {
    await resetDatabase();
  });

  afterAll(async () => {
    await stopHarness();
  });
}

export async function registerAndLoginUser(overrides?: { email?: string; password?: string }) {
  const email = overrides?.email ?? `user-${randomUUID()}@example.com`;
  const password = overrides?.password ?? `Password-${randomUUID()}`;
  const saltHex = await createPasswordSalt();
  const credentials = await deriveCredentials(email, password, saltHex);
  const kekPublicKey = await deriveUserKekPublicKey(credentials);

  const register = await requestJson<AuthResponse>('/api/auth/register', {
    body: {
      authKey: credentials.authKey,
      email,
      kekPublicKey,
      saltHex,
    },
    method: 'POST',
  });
  const fetchedSalt = await requestJson<SaltResponse>('/api/auth/salt', {
    body: { email },
    method: 'POST',
  });
  const login = await requestJson<AuthResponse>('/api/auth/login', {
    body: {
      authKey: credentials.authKey,
      email,
    },
    method: 'POST',
  });

  expect(register.currentPrincipal).toMatchObject({
    email,
    id: register.user.id,
    kind: 'user',
  });
  expect(register.kekMetadatas).toHaveLength(1);
  expect(register.linkedPrincipals).toHaveLength(1);
  expect(register.linkedPrincipals[0]).toMatchObject({
    email,
    id: register.user.id,
    kind: 'user',
    latestKekEpochVersion: 1,
    latestKekPublicKey: kekPublicKey,
    username: null,
  });
  expect(fetchedSalt).toEqual({
    kekMetadatas: register.kekMetadatas,
    saltHex,
  });

  return {
    credentials,
    email,
    login,
    password,
    register,
    saltHex,
  } satisfies RegisteredUser;
}

export async function createOwnedNote(input: {
  ownerKekPublicKey: string;
  ownerToken: string;
  ownerUserId: string;
  plaintext: string;
}) {
  const encryptedNote = await encryptStringWithAsymmetricKeks(input.plaintext, [
    input.ownerKekPublicKey,
  ]);

  return await requestJson<NoteResponse>('/api/notes', {
    body: {
      encryptedDeks: bindWrappedDeks(encryptedNote.encryptedDeks, [input.ownerUserId]),
      encryptedPayload: encryptedNote.encryptedPayload,
    },
    method: 'POST',
    token: input.ownerToken,
  });
}

export async function runRegisterLoginNoteFlow(options?: { notePlaintext?: string }) {
  const registered = await registerAndLoginUser();
  const latestOwnerKek = latestKek(registered.login);
  const ownerRow = await queryOne<{
    auth_key_hash: string;
    auth_salt: string;
    email: string;
    id: string;
  }>(
    'select id, email, auth_key_hash, auth_salt from users where id = $1',
    [registered.register.user.id],
  );

  expect(ownerRow.email).toBe(registered.email);
  expect(ownerRow.auth_salt).toBe(registered.saltHex);
  expect(ownerRow.auth_key_hash).toMatch(/^[0-9a-f]{128}$/);
  expect(ownerRow.auth_key_hash).not.toBe(registered.credentials.authKey);

  const ownerKeks = await queryRows<{
    kek_epoch_version: number;
    kek_public_key: string;
    user_id: string;
  }>(
    'select user_id, kek_public_key, kek_epoch_version from kek_metadata where user_id = $1 order by kek_epoch_version asc',
    [registered.register.user.id],
  );

  expect(ownerKeks).toEqual([
    {
      kek_epoch_version: 1,
      kek_public_key: latestOwnerKek.kekPublicKey,
      user_id: registered.register.user.id,
    },
  ]);

  const notePlaintext = options?.notePlaintext ?? `note-${randomUUID()}`;
  const createdNote = await createOwnedNote({
    ownerKekPublicKey: latestOwnerKek.kekPublicKey,
    ownerToken: registered.login.token,
    ownerUserId: registered.login.user.id,
    plaintext: notePlaintext,
  });
  const fetchedNote = await requestJson<NoteResponse>(`/api/notes/${createdNote.id}`, {
    token: registered.login.token,
  });
  const listedNotes = await requestJson<NoteResponse[]>('/api/notes', {
    token: registered.login.token,
  });

  expect(listedNotes).toHaveLength(1);
  await expect(
    decryptStringWithAsymmetricKek(toAsymmetricPayload(fetchedNote), registered.credentials.cryptKey),
  ).resolves.toBe(notePlaintext);

  const storedNote = await queryOne<{
    algorithm: string;
    ciphertext_hex: string;
    nonce_hex: string;
    user_id: string;
    version: number;
  }>(
    'select user_id, algorithm, ciphertext_hex, nonce_hex, version from notes where id = $1',
    [createdNote.id],
  );
  expect(storedNote).toEqual({
    algorithm: createdNote.encryptedPayload.algorithm,
    ciphertext_hex: createdNote.encryptedPayload.ciphertextHex,
    nonce_hex: createdNote.encryptedPayload.nonceHex,
    user_id: registered.login.user.id,
    version: createdNote.encryptedPayload.version,
  });

  const storedDek = await queryOne<{
    algorithm: string;
    kem_ciphertext_hex: string;
    kek_public_key: string;
    nonce_hex: string;
    resource_id: string;
    user_id: string;
    version: number;
    wrapped_dek_hex: string;
  }>(
    'select resource_id, user_id, kek_public_key, algorithm, kem_ciphertext_hex, wrapped_dek_hex, nonce_hex, version from deks where resource_id = $1 and user_id = $2',
    [createdNote.id, registered.login.user.id],
  );
  expect(storedDek).toEqual({
    algorithm: createdNote.encryptedDek.algorithm,
    kem_ciphertext_hex: createdNote.encryptedDek.kemCiphertextHex,
    kek_public_key: createdNote.encryptedDek.kekPublicKey,
    nonce_hex: createdNote.encryptedDek.nonceHex,
    resource_id: createdNote.id,
    user_id: registered.login.user.id,
    version: createdNote.encryptedDek.version,
    wrapped_dek_hex: createdNote.encryptedDek.wrappedDekHex,
  });

  return {
    createdNote,
    latestOwnerKek,
    notePlaintext,
    registered,
  } satisfies RegisterLoginNoteFlowResult;
}

export async function deriveUserKekPublicKey(credentials: DerivedCredentials) {
  const keyPair = await deriveKekKeyPair(credentials.cryptKey);
  return keyPair.kekPublicKey;
}

export function bindWrappedDeks(encryptedDeks: KekAsymmetricWrappedPayload[], userIds: string[]) {
  if (encryptedDeks.length !== userIds.length) {
    throw new Error('Recipient ids must match the wrapped DEK payload count.');
  }

  return encryptedDeks.map((encryptedDek, index) => ({
    ...encryptedDek,
    userId: userIds[index],
  }));
}

export function latestKek(session: AuthResponse) {
  const latest = session.kekMetadatas.reduce<KekMetadata | null>((currentLatest, current) => {
    if (!currentLatest || current.kekEpochVersion > currentLatest.kekEpochVersion) {
      return current;
    }

    return currentLatest;
  }, null);

  if (!latest) {
    throw new Error('Expected at least one KEK metadata record in the auth session.');
  }

  return latest;
}

export function toAsymmetricPayload(
  note: Pick<NoteResponse, 'encryptedDek' | 'encryptedPayload'>,
): KekAsymmetricDekEncryptedPayload {
  return {
    encryptedDek: note.encryptedDek,
    encryptedPayload: note.encryptedPayload,
  };
}

export async function requestJson<T>(
  apiPath: string,
  options?: {
    body?: unknown;
    method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
    token?: string;
  },
) {
  const activeHarness = requireHarness();
  const response = await fetch(`${activeHarness.backendBaseUrl}${apiPath}`, {
    body: options?.body ? JSON.stringify(options.body) : undefined,
    headers: {
      ...(options?.body ? { 'Content-Type': 'application/json' } : {}),
      ...(options?.token ? { Authorization: `Bearer ${options.token}` } : {}),
    },
    method: options?.method ?? 'GET',
  });
  const responseBody = await readResponseBody(response);

  if (!response.ok) {
    throw new Error(readErrorMessage(response.status, responseBody));
  }

  return responseBody as T;
}

export async function requestFailure(
  apiPath: string,
  options?: {
    body?: unknown;
    method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
    token?: string;
  },
) {
  const activeHarness = requireHarness();
  const response = await fetch(`${activeHarness.backendBaseUrl}${apiPath}`, {
    body: options?.body ? JSON.stringify(options.body) : undefined,
    headers: {
      ...(options?.body ? { 'Content-Type': 'application/json' } : {}),
      ...(options?.token ? { Authorization: `Bearer ${options.token}` } : {}),
    },
    method: options?.method ?? 'GET',
  });

  return {
    body: await readResponseBody(response),
    status: response.status,
  };
}

export async function queryOne<T extends Record<string, unknown>>(sql: string, params: unknown[]) {
  const client = requireDbClient();
  const result = await client.query<T>(sql, params);

  if (result.rows.length !== 1) {
    throw new Error(`Expected one row for query: ${sql}`);
  }

  return result.rows[0];
}

export async function queryRows<T extends Record<string, unknown>>(sql: string, params: unknown[]) {
  const client = requireDbClient();
  const result = await client.query<T>(sql, params);
  return result.rows;
}

export async function resetDatabase() {
  const client = requireDbClient();
  await client.query('TRUNCATE TABLE deks, notes, api_users, kek_metadata, users RESTART IDENTITY CASCADE');
}

async function startHarness(): Promise<Harness> {
  const postgresContainer = await new GenericContainer('postgres:16-alpine')
    .withEnvironment({
      POSTGRES_DB: POSTGRES_DATABASE,
      POSTGRES_PASSWORD: POSTGRES_PASSWORD,
      POSTGRES_USER: POSTGRES_USER,
    })
    .withExposedPorts(5432)
    .start();

  const databaseUrl = buildDatabaseUrl(postgresContainer);
  const dbClient = new Client({ connectionString: databaseUrl });
  await connectDatabaseWithRetries(dbClient);

  const backendPort = await getFreePort();
  const backendBaseUrl = `http://127.0.0.1:${backendPort}`;
  let backendLogs = '';
  const backendProcess = spawn('cargo', ['run'], {
    cwd: BACKEND_DIR,
    env: {
      ...process.env,
      BACKEND_HOST: '127.0.0.1',
      BACKEND_PORT: String(backendPort),
      DATABASE_URL: databaseUrl,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  backendProcess.stdout.on('data', (chunk: Buffer) => {
    backendLogs += chunk.toString();
  });
  backendProcess.stderr.on('data', (chunk: Buffer) => {
    backendLogs += chunk.toString();
  });

  const nextHarness = {
    backendBaseUrl,
    backendLogs,
    backendProcess,
    dbClient,
    postgresContainer,
  } satisfies Harness;
  harness = nextHarness;
  await waitForBackendReady(`${backendBaseUrl}/health`);
  return nextHarness;
}

async function stopHarness() {
  if (!harness) {
    return;
  }

  const activeHarness = harness;
  harness = null;

  try {
    await stopProcess(activeHarness.backendProcess);
  } finally {
    await activeHarness.dbClient.end();
    await activeHarness.postgresContainer.stop();
  }
}

function buildDatabaseUrl(container: StartedTestContainer) {
  return `postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${container.getHost()}:${container.getMappedPort(5432)}/${POSTGRES_DATABASE}`;
}

async function connectDatabaseWithRetries(client: Client) {
  for (let attempt = 1; attempt <= 30; attempt += 1) {
    try {
      await client.connect();
      return;
    } catch (error) {
      if (attempt === 30) {
        throw error;
      }

      await delay(1_000);
    }
  }
}

async function waitForBackendReady(healthUrl: string) {
  for (let attempt = 1; attempt <= 180; attempt += 1) {
    const activeHarness = requireHarness();

    if (activeHarness.backendProcess.exitCode !== null) {
      throw new Error(`Backend exited before becoming ready.\n${activeHarness.backendLogs}`);
    }

    try {
      const response = await fetch(healthUrl);
      if (response.ok) {
        return;
      }
    } catch {
      // Keep polling until the listener comes up.
    }

    await delay(1_000);
  }

  throw new Error(`Backend did not become ready in time.\n${requireHarness().backendLogs}`);
}

async function stopProcess(processRef: BackendProcess) {
  if (processRef.exitCode !== null) {
    return;
  }

  processRef.kill('SIGTERM');

  try {
    await Promise.race([
      once(processRef, 'exit'),
      delay(10_000).then(() => {
        throw new Error('timeout');
      }),
    ]);
  } catch {
    processRef.kill('SIGKILL');
    await once(processRef, 'exit');
  }
}

async function getFreePort() {
  return await new Promise<number>((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close(() => reject(new Error('failed to allocate a free port')));
        return;
      }

      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve(address.port);
      });
    });
  });
}

async function readResponseBody(response: Response) {
  const text = await response.text();

  if (!text) {
    return null;
  }

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function readErrorMessage(status: number, body: unknown) {
  if (body && typeof body === 'object' && 'error' in body && typeof body.error === 'string') {
    return body.error;
  }

  if (typeof body === 'string' && body.trim()) {
    return body;
  }

  return `Backend request failed with status ${status}.`;
}

function requireDbClient() {
  return requireHarness().dbClient;
}

function requireHarness() {
  if (!harness) {
    throw new Error('Integration harness is not initialized.');
  }

  return harness;
}