import {
  crypto_hash,
  crypto_hash_BYTES,
  crypto_pwhash,
  crypto_pwhash_ALG_ARGON2ID13,
  crypto_pwhash_MEMLIMIT_INTERACTIVE,
  crypto_pwhash_OPSLIMIT_INTERACTIVE,
  crypto_pwhash_SALTBYTES,
  crypto_secretbox_easy,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_open_easy,
  loadSumoVersion,
  randombytes_buf,
  ready,
} from 'react-native-libsodium';

import { createE2ee } from './core';

loadSumoVersion();

const e2ee = createE2ee({
  decrypt(ciphertext, nonce, key) {
    return crypto_secretbox_open_easy(ciphertext, nonce, key);
  },
  derivePasswordHash(password, salt, keyLength) {
    return crypto_pwhash(
      keyLength,
      password,
      salt,
      crypto_pwhash_OPSLIMIT_INTERACTIVE,
      crypto_pwhash_MEMLIMIT_INTERACTIVE,
      crypto_pwhash_ALG_ARGON2ID13,
    );
  },
  encrypt(message, nonce, key) {
    return crypto_secretbox_easy(message, nonce, key);
  },
  hash(message) {
    return crypto_hash(message);
  },
  hashBytes: crypto_hash_BYTES,
  randomBytes: randombytes_buf,
  ready,
  saltBytes: crypto_pwhash_SALTBYTES,
  secretboxKeyBytes: crypto_secretbox_KEYBYTES,
  secretboxNonceBytes: crypto_secretbox_NONCEBYTES,
});

export const {
  createPasswordSalt,
  decryptString,
  decryptStringWithDek,
  deriveCredentials,
  encryptString,
  encryptStringWithDek,
  normalizeEmail,
} = e2ee;
export type {
  CryptKey,
  DerivedCredentials,
  EncryptedPayload,
  KekDekEncryptedPayload,
  KekWrappedPayload,
} from './core';