import sodium from 'libsodium-wrappers-sumo';

import { createE2ee } from './core';

const e2ee = createE2ee({
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
  randomBytes: sodium.randombytes_buf,
  ready: sodium.ready,
  saltBytes: sodium.crypto_pwhash_SALTBYTES,
});

export const { createPasswordSalt, deriveCredentials, normalizeEmail } = e2ee;
export { decryptString, encryptString } from './core';
export type { CryptKey, DerivedCredentials, EncryptedPayload } from './core';