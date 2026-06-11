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

import { createE2ee } from './core';

loadSumoVersion();

const e2ee = createE2ee({
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
  randomBytes: randombytes_buf,
  ready,
  saltBytes: crypto_pwhash_SALTBYTES,
});

export const { createPasswordSalt, deriveCredentials, normalizeEmail } = e2ee;
export { decryptString, encryptString } from './core';
export type { CryptKey, DerivedCredentials, EncryptedPayload } from './core';