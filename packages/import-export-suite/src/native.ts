import * as ExpoCrypto from 'expo-crypto';
import {
  crypto_pwhash,
  crypto_pwhash_ALG_ARGON2ID13,
  crypto_pwhash_MEMLIMIT_INTERACTIVE,
  crypto_pwhash_OPSLIMIT_INTERACTIVE,
  crypto_pwhash_SALTBYTES,
  loadSumoVersion,
  randombytes_buf,
  ready,
} from 'react-native-libsodium';

import { createNoteBackup } from './core';

loadSumoVersion();

const importExportSuite = createNoteBackup({
  aesGcm: {
    async decrypt(payload, key, additionalData) {
      const importedKey = await ExpoCrypto.AESEncryptionKey.import(key);
      const sealedData = ExpoCrypto.AESSealedData.fromParts(
        payload.nonce,
        payload.ciphertext,
        payload.tag,
      );
      const decrypted = await ExpoCrypto.aesDecryptAsync(sealedData, importedKey, {
        additionalData,
        output: 'bytes',
      });

      if (!(decrypted instanceof Uint8Array)) {
        throw new TypeError('The native AES decryptor returned an unexpected payload type.');
      }

      return decrypted;
    },

    async encrypt(plaintext, key, additionalData) {
      const importedKey = await ExpoCrypto.AESEncryptionKey.import(key);
      const sealedData = await ExpoCrypto.aesEncryptAsync(plaintext, importedKey, {
        additionalData,
        nonce: {
          length: 12,
        },
        tagLength: 16,
      });
      const ciphertext = await sealedData.ciphertext({
        encoding: 'bytes',
        includeTag: false,
      });
      const nonce = await sealedData.iv('bytes');
      const tag = await sealedData.tag('bytes');

      if (!(ciphertext instanceof Uint8Array) || !(nonce instanceof Uint8Array) || !(tag instanceof Uint8Array)) {
        throw new TypeError('The native AES encryptor returned an unexpected payload type.');
      }

      return {
        ciphertext,
        nonce,
        tag,
      };
    },
  },
  passwordKeyDerivation: {
    deriveKey(password, salt, keyBytes, opsLimit, memLimit) {
      return crypto_pwhash(
        keyBytes,
        password,
        salt,
        opsLimit,
        memLimit,
        crypto_pwhash_ALG_ARGON2ID13,
      );
    },
    memLimitInteractive: crypto_pwhash_MEMLIMIT_INTERACTIVE,
    opsLimitInteractive: crypto_pwhash_OPSLIMIT_INTERACTIVE,
    saltBytes: crypto_pwhash_SALTBYTES,
  },
  randomBytes(size) {
    return randombytes_buf(size);
  },
  ready,
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