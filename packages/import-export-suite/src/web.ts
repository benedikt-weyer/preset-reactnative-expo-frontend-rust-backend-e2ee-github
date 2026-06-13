import sodium from 'libsodium-wrappers-sumo';

import { createNoteBackup, importExportSuiteConstants } from './core';

const importExportSuite = createNoteBackup({
  aesGcm: {
    async decrypt(payload, key, additionalData) {
      const subtle = getSubtleCrypto();
      const importedKey = await subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
      const ciphertextWithTag = new Uint8Array(payload.ciphertext.length + payload.tag.length);

      ciphertextWithTag.set(payload.ciphertext, 0);
      ciphertextWithTag.set(payload.tag, payload.ciphertext.length);

      const decrypted = await subtle.decrypt(
        {
          additionalData,
          iv: payload.nonce,
          name: 'AES-GCM',
          tagLength: importExportSuiteConstants.aesGcmTagBytes * 8,
        },
        importedKey,
        ciphertextWithTag,
      );

      return new Uint8Array(decrypted);
    },

    async encrypt(plaintext, key, additionalData) {
      const subtle = getSubtleCrypto();
      const importedKey = await subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
      const nonce = sodium.randombytes_buf(importExportSuiteConstants.aesGcmNonceBytes);
      const encrypted = new Uint8Array(
        await subtle.encrypt(
          {
            additionalData,
            iv: nonce,
            name: 'AES-GCM',
            tagLength: importExportSuiteConstants.aesGcmTagBytes * 8,
          },
          importedKey,
          plaintext,
        ),
      );

      return {
        ciphertext: encrypted.subarray(0, encrypted.length - importExportSuiteConstants.aesGcmTagBytes),
        nonce,
        tag: encrypted.subarray(encrypted.length - importExportSuiteConstants.aesGcmTagBytes),
      };
    },
  },
  passwordKeyDerivation: {
    deriveKey(password, salt, keyBytes, opsLimit, memLimit) {
      return sodium.crypto_pwhash(
        keyBytes,
        password,
        salt,
        opsLimit,
        memLimit,
        sodium.crypto_pwhash_ALG_ARGON2ID13,
      );
    },
    memLimitInteractive: sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    opsLimitInteractive: sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    saltBytes: sodium.crypto_pwhash_SALTBYTES,
  },
  randomBytes(size) {
    return sodium.randombytes_buf(size);
  },
  ready: sodium.ready,
});

export const exportImportExportSuite = importExportSuite.exportNotesBackup;
export const importImportExportSuite = importExportSuite.importNotesBackup;
export const inspectImportExportSuite = importExportSuite.inspectNoteBackup;

export type {
  BackupNote as ImportExportSuiteNote,
  CleartextNoteBackupDocument as CleartextImportExportSuiteDocument,
  EncryptedNoteBackupDocument as EncryptedImportExportSuiteDocument,
  NoteBackupDocument as ImportExportSuiteDocument,
  NoteBackupInspection as ImportExportSuiteInspection,
} from './core';

function getSubtleCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto is unavailable in this browser context.');
  }

  return globalThis.crypto.subtle;
}