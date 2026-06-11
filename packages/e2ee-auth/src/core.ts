const AUTH_CONTEXT_PREFIX = utf8('auth:');
const ENCRYPTION_CONTEXT_PREFIX = utf8('enc:');
const AUTH_KEY_LENGTH = 64;
const CRYPT_KEY_LENGTH = 64;
const SHA512_BLOCK_BYTES = 128;

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
  hash: (message: Uint8Array) => Uint8Array;
  hashBytes: number | (() => number);
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
      authKey: bytesToHex(deriveSubkey(driver, cryptKey, AUTH_CONTEXT_PREFIX, AUTH_KEY_LENGTH)),
      cryptKey,
      email: normalizedEmail,
    };
  }

  function encryptString(value: string, cryptKey: CryptKey): EncryptedPayload {
    const nonce = driver.randomBytes(resolveSecretboxNonceBytes(driver));
    const ciphertext = driver.encrypt(
      utf8(value),
      nonce,
      deriveEncryptionKey(driver, cryptKey, resolveSecretboxKeyBytes(driver)),
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
        deriveEncryptionKey(driver, cryptKey, resolveSecretboxKeyBytes(driver)),
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

function deriveEncryptionKey(driver: E2eeDriver, cryptKey: CryptKey, keyLength: number) {
  return deriveSubkey(
    driver,
    cryptKey,
    ENCRYPTION_CONTEXT_PREFIX,
    keyLength,
  );
}

function deriveSubkey(
  driver: E2eeDriver,
  cryptKey: CryptKey,
  info: Uint8Array,
  keyLength: number,
) {
  const hashBytes = resolveHashBytes(driver);

  if (keyLength > 255 * hashBytes) {
    throw new Error('Derived key length is too large.');
  }

  const pseudoRandomKey = hmacSha512(driver, cryptKey, new Uint8Array(hashBytes));
  const output = new Uint8Array(keyLength);
  let previousBlock = new Uint8Array(0);
  let offset = 0;

  for (let counter = 1; offset < keyLength; counter += 1) {
    const currentBlock = hmacSha512(
      driver,
      concatBytes(previousBlock, info, Uint8Array.of(counter)),
      pseudoRandomKey,
    );
    const chunk = currentBlock.subarray(0, Math.min(currentBlock.length, keyLength - offset));

    output.set(chunk, offset);
    previousBlock = new Uint8Array(currentBlock);
    offset += chunk.length;
  }

  return output;
}

function hmacSha512(driver: E2eeDriver, message: Uint8Array, key: Uint8Array) {
  const normalizedKey = normalizeHmacKey(driver, key);
  const innerKeyPad = new Uint8Array(SHA512_BLOCK_BYTES);
  const outerKeyPad = new Uint8Array(SHA512_BLOCK_BYTES);

  for (let index = 0; index < SHA512_BLOCK_BYTES; index += 1) {
    const value = normalizedKey[index];
    innerKeyPad[index] = value ^ 0x36;
    outerKeyPad[index] = value ^ 0x5c;
  }

  const innerHash = driver.hash(concatBytes(innerKeyPad, message));
  return driver.hash(concatBytes(outerKeyPad, innerHash));
}

function normalizeHmacKey(driver: E2eeDriver, key: Uint8Array) {
  if (key.length > SHA512_BLOCK_BYTES) {
    return padKey(driver.hash(key));
  }

  return padKey(key);
}

function padKey(key: Uint8Array) {
  const paddedKey = new Uint8Array(SHA512_BLOCK_BYTES);
  paddedKey.set(key.subarray(0, SHA512_BLOCK_BYTES));
  return paddedKey;
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

function resolveHashBytes(driver: E2eeDriver) {
  return resolveDriverSize(driver.hashBytes);
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

function bytesToHex(value: Uint8Array) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(value: string) {
  if (value.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(value)) {
    throw new Error('Invalid hex string.');
  }

  const output = new Uint8Array(value.length / 2);

  for (let index = 0; index < value.length; index += 2) {
    output[index / 2] = Number.parseInt(value.slice(index, index + 2), 16);
  }

  return output;
}

function concatBytes(...values: Uint8Array[]) {
  const totalLength = values.reduce((sum, value) => sum + value.length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;

  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }

  return output;
}