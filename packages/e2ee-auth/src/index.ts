import { sha512 } from '@noble/hashes/sha2';
import { bytesToHex, concatBytes, hexToBytes, randomBytes } from '@noble/hashes/utils';
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
import nacl from 'tweetnacl';

const AUTH_CONTEXT_PREFIX = utf8('auth:');
const ENCRYPTION_CONTEXT_PREFIX = utf8('enc:');
const CRYPT_KEY_LENGTH = 64;

loadSumoVersion();

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

export function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

export async function createPasswordSalt() {
  await ready;

  return bytesToHex(randombytes_buf(crypto_pwhash_SALTBYTES));
}

export async function deriveCredentials(
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

  await ready;

  const cryptKey = crypto_pwhash(
    CRYPT_KEY_LENGTH,
    utf8(password),
    normalizePasswordSalt(saltHex),
    crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_ALG_ARGON2ID13,
  );

  return {
    authKey: bytesToHex(sha512(concatBytes(AUTH_CONTEXT_PREFIX, cryptKey))),
    cryptKey,
    email: normalizedEmail,
  };
}

export function encryptString(value: string, cryptKey: CryptKey): EncryptedPayload {
  const nonce = randomBytes(nacl.secretbox.nonceLength);
  const ciphertext = nacl.secretbox(utf8(value), nonce, deriveEncryptionKey(cryptKey));

  return {
    algorithm: 'xsalsa20-poly1305',
    ciphertextHex: bytesToHex(ciphertext),
    nonceHex: bytesToHex(nonce),
    version: 1,
  };
}

export function decryptString(payload: EncryptedPayload, cryptKey: CryptKey) {
  const plaintext = nacl.secretbox.open(
    hexToBytes(payload.ciphertextHex),
    hexToBytes(payload.nonceHex),
    deriveEncryptionKey(cryptKey),
  );

  if (!plaintext) {
    throw new Error('Unable to decrypt data with the current password.');
  }

  return new TextDecoder().decode(plaintext);
}

function deriveEncryptionKey(cryptKey: CryptKey) {
  return sha512(concatBytes(ENCRYPTION_CONTEXT_PREFIX, cryptKey)).slice(
    0,
    nacl.secretbox.keyLength,
  );
}

function normalizePasswordSalt(saltHex: string) {
  const normalizedSalt = saltHex.trim().toLowerCase();
  let saltBytes: Uint8Array;

  try {
    saltBytes = hexToBytes(normalizedSalt);
  } catch {
    throw new Error('Unable to use the stored password salt.');
  }

  if (saltBytes.length !== crypto_pwhash_SALTBYTES) {
    throw new Error('Unable to use the stored password salt.');
  }

  return saltBytes;
}

function utf8(value: string) {
  return new TextEncoder().encode(value);
}
