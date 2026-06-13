import { describe, expect, it } from 'vitest';

import {
  exportImportExportSuite,
  importImportExportSuite,
  inspectImportExportSuite,
} from './index';

const notes = [
  {
    content: 'Encrypted note body',
    createdAt: '2026-06-13T10:00:00.000Z',
    id: 'note-1',
    title: 'First note',
    updatedAt: '2026-06-13T10:30:00.000Z',
  },
  {
    content: 'Another entry',
    createdAt: '2026-06-13T11:00:00.000Z',
    id: 'note-2',
    title: 'Second note',
    updatedAt: '2026-06-13T11:15:00.000Z',
  },
];

describe('import-export-suite', () => {
  it('exports and imports cleartext backups', async () => {
    const serialized = await exportImportExportSuite(notes, {
      exportedAt: '2026-06-13T12:00:00.000Z',
    });

    expect(inspectImportExportSuite(serialized)).toEqual({
      encrypted: false,
      exportedAt: '2026-06-13T12:00:00.000Z',
      noteCount: 2,
    });
    await expect(importImportExportSuite(serialized)).resolves.toEqual(notes);
  });

  it('exports and imports password protected backups', async () => {
    const serialized = await exportImportExportSuite(notes, {
      exportedAt: '2026-06-13T12:00:00.000Z',
      password: 'custom export password',
    });

    expect(inspectImportExportSuite(serialized)).toEqual({
      encrypted: true,
      exportedAt: '2026-06-13T12:00:00.000Z',
      noteCount: 2,
    });
    await expect(importImportExportSuite(serialized, { password: 'custom export password' })).resolves.toEqual(notes);
    await expect(importImportExportSuite(serialized, { password: 'wrong password' })).rejects.toThrow(
      'Unable to decrypt the backup. Check the password and try again.',
    );
  });
});