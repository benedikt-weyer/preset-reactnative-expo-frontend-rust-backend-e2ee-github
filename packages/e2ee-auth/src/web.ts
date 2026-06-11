import sodium from 'libsodium-wrappers-sumo';

import { createE2ee } from './core';

const e2ee = createE2ee({
  decrypt(ciphertext, nonce, key) {
    return sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
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

export const { createPasswordSalt, decryptString, deriveCredentials, encryptString, normalizeEmail } = e2ee;
export type { CryptKey, DerivedCredentials, EncryptedPayload } from './core';