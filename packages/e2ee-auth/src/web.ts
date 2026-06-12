import sodium from 'libsodium-wrappers-sumo';

import { createWebOqsKekAdapter } from '@repo/oqs-kek/web';

import { createE2ee } from './core';

const oqsKek = createWebOqsKekAdapter();

const e2ee = createE2ee({
  decrypt(ciphertext, nonce, key) {
    return sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
  },
  async deriveDeterministicKekKeyPair(seed) {
    return oqsKek.deriveDeterministicKeyPair(seed);
  },
  derivePasswordHash(password, salt, keyLength) {
    return sodium.crypto_pwhash(
      keyLength,
      password,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
  },
  encrypt(message, nonce, key) {
    return sodium.crypto_secretbox_easy(message, nonce, key);
  },
  hash(message) {
    return sodium.crypto_hash(message);
  },
  kekSeedBytes() {
    return 32;
  },
  hashBytes() {
    return sodium.crypto_hash_BYTES;
  },
  randomBytes(size) {
    return sodium.randombytes_buf(size);
  },
  ready: sodium.ready,
  saltBytes() {
    return sodium.crypto_pwhash_SALTBYTES;
  },
  secretboxKeyBytes() {
    return sodium.crypto_secretbox_KEYBYTES;
  },
  secretboxNonceBytes() {
    return sodium.crypto_secretbox_NONCEBYTES;
  },
});

export const {
  createPasswordSalt,
  decryptString,
  decryptStringWithAsymmetricKek,
  decryptStringWithDek,
  deriveKekKeyPair,
  deriveCredentials,
  encryptString,
  encryptStringWithAsymmetricKek,
  encryptStringWithDek,
  normalizeEmail,
  rewrapAsymmetricEncryptedDek,
  rewrapEncryptedDek,
} = e2ee;
export type {
  CryptKey,
  DerivedCredentials,
  EncryptedPayload,
  KekAsymmetricDekEncryptedPayload,
  KekAsymmetricWrappedPayload,
  KekKeyPair,
  KekDekEncryptedPayload,
  KekWrappedPayload,
} from './core';