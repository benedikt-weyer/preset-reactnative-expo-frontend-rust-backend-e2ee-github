const BACKUP_FORMAT = 'preset-import-export-suite';
const BACKUP_VERSION = 1;
const AES_256_GCM_ALGORITHM = 'aes-256-gcm';
const ARGON2ID_ALGORITHM = 'argon2id';
const AES_KEY_BYTES = 32;
const AES_GCM_NONCE_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;

export type BackupNote = {
  content: string;
  createdAt: string;
  id: string;
  title: string;
  updatedAt: string;
};

export type CleartextNoteBackupDocument = {
  exportedAt: string;
  format: typeof BACKUP_FORMAT;
  notes: BackupNote[];
  version: typeof BACKUP_VERSION;
};

export type EncryptedNoteBackupDocument = {
  encryptedAtRest: true;
  encryption: {
    algorithm: typeof AES_256_GCM_ALGORITHM;
    ciphertextHex: string;
    kdf: {
      algorithm: typeof ARGON2ID_ALGORITHM;
      keyBytes: typeof AES_KEY_BYTES;
      memLimit: number;
      opsLimit: number;
      saltHex: string;
    };
    nonceHex: string;
    tagHex: string;
  };
  exportedAt: string;
  format: typeof BACKUP_FORMAT;
  noteCount: number;
  version: typeof BACKUP_VERSION;
};

export type NoteBackupDocument =
  | CleartextNoteBackupDocument
  | EncryptedNoteBackupDocument;

export type NoteBackupInspection = {
  encrypted: boolean;
  exportedAt: string;
  noteCount: number;
};

type CreateNoteBackupOptions = {
  exportedAt?: string;
  password?: string;
};

type ImportNoteBackupOptions = {
  password?: string;
};

type PasswordKeyDerivation = {
  deriveKey: (
    password: string,
    salt: Uint8Array,
    keyBytes: number,
    opsLimit: number,
    memLimit: number,
  ) => Promise<Uint8Array> | Uint8Array;
  memLimitInteractive: number;
  opsLimitInteractive: number;
  saltBytes: number;
};

type AesGcmCiphertext = {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  tag: Uint8Array;
};

type NoteBackupPlatformAdapter = {
  aesGcm: {
    decrypt: (
      payload: AesGcmCiphertext,
      key: Uint8Array,
      additionalData: Uint8Array,
    ) => Promise<Uint8Array> | Uint8Array;
    encrypt: (
      plaintext: Uint8Array,
      key: Uint8Array,
      additionalData: Uint8Array,
    ) => Promise<AesGcmCiphertext> | AesGcmCiphertext;
  };
  passwordKeyDerivation: PasswordKeyDerivation;
  randomBytes: (size: number) => Promise<Uint8Array> | Uint8Array;
  ready: Promise<unknown> | (() => Promise<unknown>);
};

export function createNoteBackup(adapter: NoteBackupPlatformAdapter) {
  return {
    async exportNotesBackup(
      notes: BackupNote[],
      options?: CreateNoteBackupOptions,
    ): Promise<string> {
      await ensureReady(adapter);

      const normalizedNotes = normalizeNotes(notes);
      const exportedAt = normalizeExportedAt(options?.exportedAt);
      const password = options?.password;

      if (password === undefined) {
        return JSON.stringify(
          {
            exportedAt,
            format: BACKUP_FORMAT,
            notes: normalizedNotes,
            version: BACKUP_VERSION,
          } satisfies CleartextNoteBackupDocument,
          null,
          2,
        );
      }

      if (password.length === 0) {
        throw new Error('Choose a non-empty backup password.');
      }

      const salt = await resolveBytes(adapter.passwordKeyDerivation.saltBytes, adapter.randomBytes);
      const opsLimit = adapter.passwordKeyDerivation.opsLimitInteractive;
      const memLimit = adapter.passwordKeyDerivation.memLimitInteractive;
      const additionalData = encodeUtf8(
        JSON.stringify({
          encryptedAtRest: true,
          exportedAt,
          format: BACKUP_FORMAT,
          kdf: {
            algorithm: ARGON2ID_ALGORITHM,
            keyBytes: AES_KEY_BYTES,
            memLimit,
            opsLimit,
            saltHex: bytesToHex(salt),
          },
          noteCount: normalizedNotes.length,
          version: BACKUP_VERSION,
        }),
      );
      const key = await resolveValue(
        adapter.passwordKeyDerivation.deriveKey(
          password,
          salt,
          AES_KEY_BYTES,
          opsLimit,
          memLimit,
        ),
      );
      const encryptedPayload = await resolveValue(
        adapter.aesGcm.encrypt(
          encodeUtf8(JSON.stringify({ notes: normalizedNotes })),
          key,
          additionalData,
        ),
      );

      return JSON.stringify(
        {
          encryptedAtRest: true,
          encryption: {
            algorithm: AES_256_GCM_ALGORITHM,
            ciphertextHex: bytesToHex(encryptedPayload.ciphertext),
            kdf: {
              algorithm: ARGON2ID_ALGORITHM,
              keyBytes: AES_KEY_BYTES,
              memLimit,
              opsLimit,
              saltHex: bytesToHex(salt),
            },
            nonceHex: bytesToHex(encryptedPayload.nonce),
            tagHex: bytesToHex(encryptedPayload.tag),
          },
          exportedAt,
          format: BACKUP_FORMAT,
          noteCount: normalizedNotes.length,
          version: BACKUP_VERSION,
        } satisfies EncryptedNoteBackupDocument,
        null,
        2,
      );
    },

    inspectNoteBackup(serializedBackup: string): NoteBackupInspection {
      const document = parseNoteBackupDocument(serializedBackup);

      return document.encryptedAtRest
        ? {
            encrypted: true,
            exportedAt: document.exportedAt,
            noteCount: document.noteCount,
          }
        : {
            encrypted: false,
            exportedAt: document.exportedAt,
            noteCount: document.notes.length,
          };
    },

    async importNotesBackup(
      serializedBackup: string,
      options?: ImportNoteBackupOptions,
    ): Promise<BackupNote[]> {
      await ensureReady(adapter);

      const document = parseNoteBackupDocument(serializedBackup);

      if (!document.encryptedAtRest) {
        return normalizeNotes(document.notes);
      }

      const password = options?.password;

      if (password === undefined) {
        throw new Error('Enter the backup password to decrypt this export.');
      }

      if (password.length === 0) {
        throw new Error('Enter the backup password to decrypt this export.');
      }

      const additionalData = encodeUtf8(
        JSON.stringify({
          encryptedAtRest: true,
          exportedAt: document.exportedAt,
          format: document.format,
          kdf: document.encryption.kdf,
          noteCount: document.noteCount,
          version: document.version,
        }),
      );
      const key = await resolveValue(
        adapter.passwordKeyDerivation.deriveKey(
          password,
          hexToBytes(document.encryption.kdf.saltHex),
          document.encryption.kdf.keyBytes,
          document.encryption.kdf.opsLimit,
          document.encryption.kdf.memLimit,
        ),
      );

      let decryptedPayload: Uint8Array;

      try {
        decryptedPayload = await resolveValue(
          adapter.aesGcm.decrypt(
            {
              ciphertext: hexToBytes(document.encryption.ciphertextHex),
              nonce: hexToBytes(document.encryption.nonceHex),
              tag: hexToBytes(document.encryption.tagHex),
            },
            key,
            additionalData,
          ),
        );
      } catch {
        throw new Error('Unable to decrypt the backup. Check the password and try again.');
      }

      const parsedPayload = parseEncryptedPayload(decodeUtf8(decryptedPayload));

      return normalizeNotes(parsedPayload.notes);
    },
  };
}

function parseNoteBackupDocument(serializedBackup: string): NoteBackupDocument {
  let parsed: unknown;

  try {
    parsed = JSON.parse(serializedBackup) as unknown;
  } catch {
    throw new Error('The selected file is not valid JSON.');
  }

  if (!isRecord(parsed)) {
    throw new Error('The selected file is not a valid import/export file.');
  }

  if (parsed.format !== BACKUP_FORMAT || parsed.version !== BACKUP_VERSION) {
    throw new Error('The selected file is not a supported import/export file.');
  }

  if (typeof parsed.exportedAt !== 'string' || Number.isNaN(Date.parse(parsed.exportedAt))) {
    throw new TypeError('The selected file is missing a valid export timestamp.');
  }

  if (parsed.encryptedAtRest === true) {
    if (!isRecord(parsed.encryption)) {
      throw new Error('The encrypted backup metadata is invalid.');
    }

    const { encryption } = parsed;

    if (
      encryption.algorithm !== AES_256_GCM_ALGORITHM ||
      typeof encryption.ciphertextHex !== 'string' ||
      typeof encryption.nonceHex !== 'string' ||
      typeof encryption.tagHex !== 'string' ||
      !isRecord(encryption.kdf) ||
      encryption.kdf.algorithm !== ARGON2ID_ALGORITHM ||
      encryption.kdf.keyBytes !== AES_KEY_BYTES ||
      typeof encryption.kdf.memLimit !== 'number' ||
      typeof encryption.kdf.opsLimit !== 'number' ||
      typeof encryption.kdf.saltHex !== 'string' ||
      typeof parsed.noteCount !== 'number'
    ) {
      throw new Error('The encrypted backup metadata is invalid.');
    }

    return parsed as EncryptedNoteBackupDocument;
  }

  if (!Array.isArray(parsed.notes)) {
    throw new TypeError('The selected file does not contain a valid notes array.');
  }

  return {
    exportedAt: parsed.exportedAt,
    format: BACKUP_FORMAT,
    notes: normalizeNotes(parsed.notes),
    version: BACKUP_VERSION,
  };
}

function parseEncryptedPayload(serializedPayload: string): { notes: BackupNote[] } {
  let parsed: unknown;

  try {
    parsed = JSON.parse(serializedPayload) as unknown;
  } catch {
    throw new Error('The decrypted backup payload is not valid JSON.');
  }

  if (!isRecord(parsed) || !Array.isArray(parsed.notes)) {
    throw new Error('The decrypted backup payload is invalid.');
  }

  return {
    notes: normalizeNotes(parsed.notes),
  };
}

function normalizeNotes(notes: unknown[]): BackupNote[] {
  return notes.map((note) => normalizeNote(note));
}

function normalizeNote(note: unknown): BackupNote {
  if (!isRecord(note)) {
    throw new Error('Every exported note must be an object.');
  }

  const normalizedNote = {
    content: note.content,
    createdAt: note.createdAt,
    id: note.id,
    title: note.title,
    updatedAt: note.updatedAt,
  };

  if (
    typeof normalizedNote.content !== 'string' ||
    typeof normalizedNote.createdAt !== 'string' ||
    typeof normalizedNote.id !== 'string' ||
    typeof normalizedNote.title !== 'string' ||
    typeof normalizedNote.updatedAt !== 'string' ||
    Number.isNaN(Date.parse(normalizedNote.createdAt)) ||
    Number.isNaN(Date.parse(normalizedNote.updatedAt))
  ) {
    throw new TypeError('Every exported note must include valid id, title, content, and timestamps.');
  }

  return normalizedNote;
}

function normalizeExportedAt(value: string | undefined) {
  const exportedAt = value ?? new Date().toISOString();

  if (Number.isNaN(Date.parse(exportedAt))) {
    throw new TypeError('The export timestamp is invalid.');
  }

  return exportedAt;
}

async function ensureReady(adapter: NoteBackupPlatformAdapter) {
  const ready = adapter.ready;

  if (typeof ready === 'function') {
    await ready();
    return;
  }

  await ready;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string) {
  if (hex.length % 2 !== 0 || /[^0-9a-f]/iu.test(hex)) {
    throw new Error('The selected backup contains invalid hexadecimal data.');
  }

  const bytes = new Uint8Array(hex.length / 2);

  for (let index = 0; index < hex.length; index += 2) {
    bytes[index / 2] = Number.parseInt(hex.slice(index, index + 2), 16);
  }

  return bytes;
}

function encodeUtf8(value: string) {
  return new TextEncoder().encode(value);
}

function decodeUtf8(value: Uint8Array) {
  return new TextDecoder().decode(value);
}

async function resolveValue<T>(value: Promise<T> | T): Promise<T> {
  return value;
}

async function resolveBytes(
  size: number,
  randomBytes: (size: number) => Promise<Uint8Array> | Uint8Array,
) {
  const bytes = await resolveValue(randomBytes(size));

  if (bytes.byteLength !== size) {
    throw new Error('The platform random byte source returned an unexpected length.');
  }

  return bytes;
}

export const importExportSuiteConstants = {
  aesGcmNonceBytes: AES_GCM_NONCE_BYTES,
  aesGcmTagBytes: AES_GCM_TAG_BYTES,
  aesKeyBytes: AES_KEY_BYTES,
  argon2idAlgorithm: ARGON2ID_ALGORITHM,
  backupFormat: BACKUP_FORMAT,
  backupVersion: BACKUP_VERSION,
};