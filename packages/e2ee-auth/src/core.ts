import { hkdf } from '@noble/hashes/hkdf';
import { sha512 } from '@noble/hashes/sha2';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';

const AUTH_CONTEXT_PREFIX = utf8('auth:');
const ENCRYPTION_CONTEXT_PREFIX = utf8('enc:');
const AUTH_KEY_LENGTH = 64;
const CRYPT_KEY_LENGTH = 64;

export type CryptKey = Uint8Array;

export type DerivedCredentials = {
  authKey: string;
  cryptKey: CryptKey;
  email: string;
};

export type EncryptedPayload = {
  algorithm: 'xsalsa20-poly1305';
  ciphertextHex: string;
  nonceHex: string;
  version: 1;
};

export type E2eeDriver = {
  derivePasswordHash: (
    password: Uint8Array,
    salt: Uint8Array,
    keyLength: number,
  ) => Uint8Array;
  decrypt: (ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array) => Uint8Array;
  encrypt: (message: Uint8Array, nonce: Uint8Array, key: Uint8Array) => Uint8Array;
  randomBytes: (size: number) => Uint8Array;
  ready: Promise<unknown>;
  saltBytes: number | (() => number);
  secretboxKeyBytes: number | (() => number);
  secretboxNonceBytes: number | (() => number);
};

export function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

export function createE2ee(driver: E2eeDriver) {
  async function createPasswordSalt() {
    await driver.ready;

    return bytesToHex(driver.randomBytes(resolveSaltBytes(driver)));
  }

  async function deriveCredentials(
    email: string,
    password: string,
    saltHex: string,
  ): Promise<DerivedCredentials> {
    const normalizedEmail = normalizeEmail(email);
    const trimmedPassword = password.trim();

    if (!normalizedEmail.includes('@')) {
      throw new Error('Enter a valid email address.');
    }

    if (!trimmedPassword) {
      throw new Error('Enter a password.');
    }

    await driver.ready;
    const saltBytes = resolveSaltBytes(driver);

    const cryptKey = driver.derivePasswordHash(
      utf8(password),
      normalizePasswordSalt(saltHex, saltBytes),
      CRYPT_KEY_LENGTH,
    );

    return {
      authKey: bytesToHex(deriveSubkey(cryptKey, AUTH_CONTEXT_PREFIX, AUTH_KEY_LENGTH)),
      cryptKey,
      email: normalizedEmail,
    };
  }

  function encryptString(value: string, cryptKey: CryptKey): EncryptedPayload {
    const nonce = randomBytes(resolveSecretboxNonceBytes(driver));
    const ciphertext = driver.encrypt(
      utf8(value),
      nonce,
      deriveEncryptionKey(cryptKey, resolveSecretboxKeyBytes(driver)),
    );

    return {
      algorithm: 'xsalsa20-poly1305',
      ciphertextHex: bytesToHex(ciphertext),
      nonceHex: bytesToHex(nonce),
      version: 1,
    };
  }

  function decryptString(payload: EncryptedPayload, cryptKey: CryptKey) {
    try {
      const plaintext = driver.decrypt(
        hexToBytes(payload.ciphertextHex),
        hexToBytes(payload.nonceHex),
        deriveEncryptionKey(cryptKey, resolveSecretboxKeyBytes(driver)),
      );

      return new TextDecoder().decode(plaintext);
    } catch {
      throw new Error('Unable to decrypt data with the current password.');
    }
  }

  return {
    createPasswordSalt,
    decryptString,
    deriveCredentials,
    encryptString,
    normalizeEmail,
  };
}

function deriveEncryptionKey(cryptKey: CryptKey, keyLength: number) {
  return deriveSubkey(
    cryptKey,
    ENCRYPTION_CONTEXT_PREFIX,
    keyLength,
  );
}

function deriveSubkey(cryptKey: CryptKey, info: Uint8Array, keyLength: number) {
  return hkdf(sha512, cryptKey, undefined, info, keyLength);
}

function resolveSaltBytes(driver: E2eeDriver) {
  return resolveDriverSize(driver.saltBytes);
}

function resolveSecretboxKeyBytes(driver: E2eeDriver) {
  return resolveDriverSize(driver.secretboxKeyBytes);
}

function resolveSecretboxNonceBytes(driver: E2eeDriver) {
  return resolveDriverSize(driver.secretboxNonceBytes);
}

function resolveDriverSize(value: number | (() => number)) {
  return typeof value === 'function' ? value() : value;
}

function normalizePasswordSalt(saltHex: string, saltBytes: number) {
  const normalizedSalt = saltHex.trim().toLowerCase();
  let decodedSalt: Uint8Array;

  try {
    decodedSalt = hexToBytes(normalizedSalt);
  } catch {
    throw new Error('Unable to use the stored password salt.');
  }

  if (decodedSalt.length !== saltBytes) {
    throw new Error('Unable to use the stored password salt.');
  }

  return decodedSalt;
}

function utf8(value: string) {
  return new TextEncoder().encode(value);
}