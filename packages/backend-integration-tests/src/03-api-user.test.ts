import { randomUUID } from 'node:crypto';

import {
  createApiToken,
  decryptStringWithAsymmetricKek,
  deriveApiTokenCredentials,
  encryptStringWithAsymmetricKeks,
  rewrapAsymmetricEncryptedDek,
} from '@repo/e2ee-auth/web';
import { describe, expect, it } from 'vitest';

import {
  bindWrappedDeks,
  queryOne,
  queryRows,
  requestJson,
  runRegisterLoginNoteFlow,
  toAsymmetricPayload,
  type ApiUserResponse,
  type AuthResponse,
  type NoteResponse,
  useIntegrationSuite,
} from './integration-support';

useIntegrationSuite();

describe('api user flow', () => {
  it('creates an api user, stores its encrypted label wraps, and allows api-user login', async () => {
    const ownerNotePlaintext = `api-user-note-${randomUUID()}`;
    const { createdNote: ownerNote, latestOwnerKek: ownerKek, registered: owner } =
      await runRegisterLoginNoteFlow({
        notePlaintext: ownerNotePlaintext,
      });

    const apiUserId = randomUUID();
    const apiToken = await createApiToken();
    const apiCredentials = await deriveApiTokenCredentials(apiToken);
    const labelPlaintext = `api-user-label-${randomUUID()}`;
    const encryptedLabel = await encryptStringWithAsymmetricKeks(labelPlaintext, [
      ownerKek.kekPublicKey,
      apiCredentials.kekKeyPair.kekPublicKey,
    ]);
    const createdApiUser = await requestJson<ApiUserResponse>('/api/auth/api-users', {
      body: {
        authKey: apiCredentials.authKey,
        encryptedLabel: encryptedLabel.encryptedPayload,
        encryptedLabelDeks: bindWrappedDeks(encryptedLabel.encryptedDeks, [
          owner.login.user.id,
          apiUserId,
        ]),
        id: apiUserId,
        kekPublicKey: apiCredentials.kekKeyPair.kekPublicKey,
      },
      method: 'POST',
      token: owner.login.token,
    });

    expect(createdApiUser.id).toBe(apiUserId);
    expect(createdApiUser.username).toMatch(/^api-[0-9a-f]{16}$/);
    expect(createdApiUser.latestKekEpochVersion).toBe(1);
    expect(createdApiUser.latestKekPublicKey).toBe(apiCredentials.kekKeyPair.kekPublicKey);
    expect(createdApiUser.provisioning).toEqual({
      completedResourceCount: 1,
      pendingNoteIds: [ownerNote.id],
      pendingResourceCount: 1,
      totalResourceCount: 2,
    });
    await expect(
      decryptStringWithAsymmetricKek(
        {
          encryptedDek: createdApiUser.encryptedLabelDek,
          encryptedPayload: createdApiUser.encryptedLabel,
        },
        owner.credentials.cryptKey,
      ),
    ).resolves.toBe(labelPlaintext);

    const apiUserLogin = await requestJson<AuthResponse>('/api/auth/api-users/login', {
      body: {
        authKey: apiCredentials.authKey,
        username: createdApiUser.username,
      },
      method: 'POST',
    });
    expect(apiUserLogin.currentPrincipal).toMatchObject({
      id: apiUserId,
      kind: 'api_user',
      username: createdApiUser.username,
    });
    expect(apiUserLogin.user.id).toBe(owner.login.user.id);

    await expect(
      requestJson<NoteResponse[]>('/api/notes', {
        token: apiUserLogin.token,
      }),
    ).rejects.toThrow('failed to query the resource dek');

    const provisionedDek = await rewrapAsymmetricEncryptedDek(
      toAsymmetricPayload(ownerNote),
      owner.credentials.cryptKey,
      apiCredentials.kekKeyPair.kekPublicKey,
    );
    const provisionedApiUser = await requestJson<ApiUserResponse>(
      `/api/auth/api-users/${apiUserId}/provision`,
      {
        body: {
          wrappedDeks: [
            {
              resourceId: ownerNote.id,
              wrappedDek: {
                ...provisionedDek,
                userId: apiUserId,
              },
            },
          ],
        },
        method: 'POST',
        token: owner.login.token,
      },
    );
    expect(provisionedApiUser.provisioning).toEqual({
      completedResourceCount: 2,
      pendingNoteIds: [],
      pendingResourceCount: 0,
      totalResourceCount: 2,
    });

    const apiUserNotes = await requestJson<NoteResponse[]>('/api/notes', {
      token: apiUserLogin.token,
    });
    expect(apiUserNotes).toHaveLength(1);
    await expect(
      decryptStringWithAsymmetricKek(toAsymmetricPayload(apiUserNotes[0]), apiCredentials.cryptKey),
    ).resolves.toBe(ownerNotePlaintext);

    const storedApiUser = await queryOne<{
      auth_key_hash: string;
      id: string;
      label_algorithm: string;
      label_ciphertext_hex: string;
      label_nonce_hex: string;
      label_version: number;
      user_id: string;
      username: string;
    }>(
      'select id, user_id, username, auth_key_hash, label_algorithm, label_ciphertext_hex, label_nonce_hex, label_version from api_users where id = $1',
      [apiUserId],
    );
    expect(storedApiUser).toEqual({
      auth_key_hash: expect.stringMatching(/^[0-9a-f]{128}$/),
      id: apiUserId,
      label_algorithm: encryptedLabel.encryptedPayload.algorithm,
      label_ciphertext_hex: encryptedLabel.encryptedPayload.ciphertextHex,
      label_nonce_hex: encryptedLabel.encryptedPayload.nonceHex,
      label_version: encryptedLabel.encryptedPayload.version,
      user_id: owner.login.user.id,
      username: createdApiUser.username,
    });

    const storedApiUserKeks = await queryRows<{
      kek_epoch_version: number;
      kek_public_key: string;
      user_id: string;
    }>(
      'select user_id, kek_public_key, kek_epoch_version from kek_metadata where user_id = $1 order by kek_epoch_version asc',
      [apiUserId],
    );
    expect(storedApiUserKeks).toEqual([
      {
        kek_epoch_version: 1,
        kek_public_key: apiCredentials.kekKeyPair.kekPublicKey,
        user_id: apiUserId,
      },
    ]);

    const storedLabelDeks = await queryRows<{
      kek_public_key: string;
      resource_id: string;
      user_id: string;
    }>(
      'select resource_id, user_id, kek_public_key from deks where resource_id = $1 order by user_id asc',
      [apiUserId],
    );
    expect(storedLabelDeks).toHaveLength(2);
    expect(storedLabelDeks).toEqual(
      expect.arrayContaining([
        {
          kek_public_key: ownerKek.kekPublicKey,
          resource_id: apiUserId,
          user_id: owner.login.user.id,
        },
        {
          kek_public_key: apiCredentials.kekKeyPair.kekPublicKey,
          resource_id: apiUserId,
          user_id: apiUserId,
        },
      ]),
    );

    const provisionedNoteDek = await queryOne<{
      kek_public_key: string;
      resource_id: string;
      user_id: string;
    }>(
      'select resource_id, user_id, kek_public_key from deks where resource_id = $1 and user_id = $2',
      [ownerNote.id, apiUserId],
    );
    expect(provisionedNoteDek).toEqual({
      kek_public_key: apiCredentials.kekKeyPair.kekPublicKey,
      resource_id: ownerNote.id,
      user_id: apiUserId,
    });
  });
});