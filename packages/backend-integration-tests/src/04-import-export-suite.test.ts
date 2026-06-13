import { randomUUID } from 'node:crypto';

import {
  decryptStringWithAsymmetricKek,
  encryptStringWithAsymmetricKeks,
} from '@repo/e2ee-auth/web';
import {
  exportImportExportSuite,
  importImportExportSuite,
  inspectImportExportSuite,
  type ImportExportSuiteNote,
} from '@repo/import-export-suite/web';
import { describe, expect, it } from 'vitest';

import {
  bindWrappedDeks,
  queryRows,
  requestJson,
  runRegisterLoginNoteFlow,
  toAsymmetricPayload,
  type NoteResponse,
  useIntegrationSuite,
} from './integration-support';

useIntegrationSuite();

describe('import export suite flow', () => {
  it('exports cleartext JSON and imports it back into backend notes', async () => {
    await runImportExportSuiteFlow();
  });

  it('exports password-protected JSON and imports it back into backend notes', async () => {
    await runImportExportSuiteFlow({
      password: `Backup-${randomUUID()}`,
    });
  });
});

async function runImportExportSuiteFlow(options?: { password?: string }) {
  const expectedDocuments = [
    {
      content: `first-content-${randomUUID()}`,
      title: `First title ${randomUUID().slice(0, 8)}`,
    },
    {
      content: `second-content-${randomUUID()}`,
      title: `Second title ${randomUUID().slice(0, 8)}`,
    },
  ];

  const { latestOwnerKek: ownerKek, registered } = await runRegisterLoginNoteFlow({
    notePlaintext: serializeNoteDocument(expectedDocuments[0]!),
  });

  for (const document of expectedDocuments.slice(1)) {
    const encryptedNote = await encryptStringWithAsymmetricKeks(
      serializeNoteDocument(document),
      [ownerKek.kekPublicKey],
    );

    await requestJson<NoteResponse>('/api/notes', {
      body: {
        encryptedDeks: bindWrappedDeks(encryptedNote.encryptedDeks, [registered.login.user.id]),
        encryptedPayload: encryptedNote.encryptedPayload,
      },
      method: 'POST',
      token: registered.login.token,
    });
  }

  const listedBeforeExport = await requestJson<NoteResponse[]>('/api/notes', {
    token: registered.login.token,
  });
  expect(listedBeforeExport).toHaveLength(expectedDocuments.length);

  const decryptedBeforeExport = await Promise.all(
    listedBeforeExport.map(async (note) => {
      const plaintext = await decryptStringWithAsymmetricKek(
        toAsymmetricPayload(note),
        registered.credentials.cryptKey,
      );
      const document = deserializeNoteDocument(plaintext);

      return {
        content: document.content,
        createdAt: note.createdAt,
        id: note.id,
        title: document.title,
        updatedAt: note.updatedAt,
      } satisfies ImportExportSuiteNote;
    }),
  );

  expect(normalizeDocuments(decryptedBeforeExport)).toEqual(normalizeDocuments(expectedDocuments));

  const exportedAt = '2026-06-13T16:30:00.000Z';
  const serializedExport = await exportImportExportSuite(
    decryptedBeforeExport,
    options?.password
      ? {
          exportedAt,
          password: options.password,
        }
      : {
          exportedAt,
        },
  );
  const inspection = inspectImportExportSuite(serializedExport);

  expect(inspection).toEqual({
    encrypted: !!options?.password,
    exportedAt,
    noteCount: expectedDocuments.length,
  });

  if (options?.password) {
    expect(serializedExport).not.toContain(expectedDocuments[0]!.content);
    await expect(
      importImportExportSuite(serializedExport, { password: `Wrong-${randomUUID()}` }),
    ).rejects.toThrow('Unable to decrypt the backup. Check the password and try again.');
  } else {
    expect(serializedExport).toContain(expectedDocuments[0]!.content);
  }

  const importedNotes = await importImportExportSuite(
    serializedExport,
    options?.password
      ? {
          password: options.password,
        }
      : undefined,
  );

  expect(normalizeDocuments(importedNotes)).toEqual(normalizeDocuments(expectedDocuments));

  for (const note of listedBeforeExport) {
    await requestJson(`/api/notes/${note.id}`, {
      method: 'DELETE',
      token: registered.login.token,
    });
  }

  const storedAfterDelete = await queryRows<{ id: string }>(
    'select id from notes where user_id = $1 order by id asc',
    [registered.login.user.id],
  );
  expect(storedAfterDelete).toHaveLength(0);

  for (const importedNote of importedNotes) {
    const encryptedNote = await encryptStringWithAsymmetricKeks(
      serializeNoteDocument({
        content: importedNote.content,
        title: importedNote.title,
      }),
      [ownerKek.kekPublicKey],
    );

    await requestJson<NoteResponse>('/api/notes', {
      body: {
        encryptedDeks: bindWrappedDeks(encryptedNote.encryptedDeks, [registered.login.user.id]),
        encryptedPayload: encryptedNote.encryptedPayload,
      },
      method: 'POST',
      token: registered.login.token,
    });
  }

  const listedAfterImport = await requestJson<NoteResponse[]>('/api/notes', {
    token: registered.login.token,
  });
  expect(listedAfterImport).toHaveLength(expectedDocuments.length);

  const decryptedAfterImport = await Promise.all(
    listedAfterImport.map(async (note) => {
      const plaintext = await decryptStringWithAsymmetricKek(
        toAsymmetricPayload(note),
        registered.credentials.cryptKey,
      );

      return deserializeNoteDocument(plaintext);
    }),
  );

  expect(normalizeDocuments(decryptedAfterImport)).toEqual(normalizeDocuments(expectedDocuments));
}

function serializeNoteDocument(note: { content: string; title: string }) {
  return JSON.stringify(note);
}

function deserializeNoteDocument(value: string) {
  const parsed = JSON.parse(value) as { content: string; title: string };

  return {
    content: parsed.content,
    title: parsed.title,
  };
}

function normalizeDocuments(notes: Array<{ content: string; title: string }>) {
  return notes
    .map((note) => ({
      content: note.content,
      title: note.title,
    }))
    .sort((left, right) => left.title.localeCompare(right.title));
}