import { randomUUID } from 'node:crypto';

import { decryptStringWithAsymmetricKek, deriveCredentials, rewrapAsymmetricEncryptedDek } from '@repo/e2ee-auth/web';
import { describe, expect, it } from 'vitest';

import {
  deriveUserKekPublicKey,
  queryOne,
  queryRows,
  requestFailure,
  requestJson,
  runRegisterLoginNoteFlow,
  toAsymmetricPayload,
  type AuthResponse,
  type KekStatusResponse,
  type NoteResponse,
  type SaltResponse,
  useIntegrationSuite,
} from './integration-support';

useIntegrationSuite();

describe('password rotation flow', () => {
  it('rotates the password, rewraps an existing note, and keeps the note decryptable with the new credentials', async () => {
    const notePlaintext = `rotated-note-${randomUUID()}`;
    const { createdNote, latestOwnerKek: originalKek, registered } = await runRegisterLoginNoteFlow({
      notePlaintext,
    });
    const userBeforeRotate = await queryOne<{ auth_key_hash: string }>(
      'select auth_key_hash from users where id = $1',
      [registered.login.user.id],
    );

    const nextPassword = `Next-${randomUUID()}`;
    const nextCredentials = await deriveCredentials(registered.email, nextPassword, registered.saltHex);
    const nextKekPublicKey = await deriveUserKekPublicKey(nextCredentials);
    const rotatedSession = await requestJson<AuthResponse>('/api/auth/rotate-password', {
      body: {
        kekPublicKey: nextKekPublicKey,
        newAuthKey: nextCredentials.authKey,
      },
      method: 'POST',
      token: registered.login.token,
    });

    const failedOldLogin = await requestFailure('/api/auth/login', {
      body: {
        authKey: registered.credentials.authKey,
        email: registered.email,
      },
      method: 'POST',
    });
    expect(failedOldLogin.status).toBe(401);

    const saltAfterRotate = await requestJson<SaltResponse>('/api/auth/salt', {
      body: { email: registered.email },
      method: 'POST',
    });
    expect(saltAfterRotate.saltHex).toBe(registered.saltHex);

    const reauthenticated = await requestJson<AuthResponse>('/api/auth/login', {
      body: {
        authKey: nextCredentials.authKey,
        email: registered.email,
      },
      method: 'POST',
    });

    const statusBeforeRewrap = await requestJson<KekStatusResponse>('/api/auth/kek-status', {
      token: rotatedSession.token,
    });
    expect(statusBeforeRewrap).toMatchObject({
      allDeksUseLatestKek: false,
      latestKekDekCount: 0,
      latestKekEpochVersion: 2,
      latestKekPublicKey: nextKekPublicKey,
      pendingDekCount: 1,
      totalDekCount: 1,
    });

    const fetchedBeforeRewrap = await requestJson<NoteResponse>(`/api/notes/${createdNote.id}`, {
      token: reauthenticated.token,
    });
    await expect(
      decryptStringWithAsymmetricKek(toAsymmetricPayload(fetchedBeforeRewrap), nextCredentials.cryptKey),
    ).rejects.toThrow('Unable to decrypt data with the current password.');

    const rewrappedDek = await rewrapAsymmetricEncryptedDek(
      toAsymmetricPayload(fetchedBeforeRewrap),
      registered.credentials.cryptKey,
      nextKekPublicKey,
    );
    const updatedNote = await requestJson<NoteResponse>(`/api/notes/${createdNote.id}`, {
      body: {
        encryptedDeks: [{ ...rewrappedDek, userId: reauthenticated.user.id }],
        encryptedPayload: fetchedBeforeRewrap.encryptedPayload,
      },
      method: 'PUT',
      token: reauthenticated.token,
    });

    await expect(
      decryptStringWithAsymmetricKek(toAsymmetricPayload(updatedNote), nextCredentials.cryptKey),
    ).resolves.toBe(notePlaintext);

    const statusAfterRewrap = await requestJson<KekStatusResponse>('/api/auth/kek-status', {
      token: reauthenticated.token,
    });
    expect(statusAfterRewrap).toMatchObject({
      allDeksUseLatestKek: true,
      latestKekDekCount: 1,
      latestKekEpochVersion: 2,
      latestKekPublicKey: nextKekPublicKey,
      pendingDekCount: 0,
      totalDekCount: 1,
    });

    const userAfterRotate = await queryOne<{ auth_key_hash: string }>(
      'select auth_key_hash from users where id = $1',
      [registered.login.user.id],
    );
    expect(userAfterRotate.auth_key_hash).toMatch(/^[0-9a-f]{128}$/);
    expect(userAfterRotate.auth_key_hash).not.toBe(userBeforeRotate.auth_key_hash);

    const storedKeks = await queryRows<{
      kek_epoch_version: number;
      kek_public_key: string;
    }>(
      'select kek_epoch_version, kek_public_key from kek_metadata where user_id = $1 order by kek_epoch_version asc',
      [registered.login.user.id],
    );
    expect(storedKeks).toEqual([
      {
        kek_epoch_version: 1,
        kek_public_key: originalKek.kekPublicKey,
      },
      {
        kek_epoch_version: 2,
        kek_public_key: nextKekPublicKey,
      },
    ]);

    const storedDek = await queryOne<{ kek_public_key: string }>(
      'select kek_public_key from deks where resource_id = $1 and user_id = $2',
      [createdNote.id, registered.login.user.id],
    );
    expect(storedDek.kek_public_key).toBe(nextKekPublicKey);
  });
});