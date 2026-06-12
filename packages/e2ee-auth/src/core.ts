const AUTH_CONTEXT_PREFIX = utf8('auth:');
const ENCRYPTION_CONTEXT_PREFIX = utf8('enc:');
const KEK_SEED_CONTEXT_PREFIX = utf8('kek-seed:');
const KEK_WRAP_CONTEXT_PREFIX = utf8('kek-wrap:');
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

export type KekWrappedPayload = {
  algorithm: 'xsalsa20-poly1305';
  kekId: string;
  nonceHex: string;
  version: 1;
  wrappedDekHex: string;
};

export type KekDekEncryptedPayload = {
  encryptedDek: KekWrappedPayload;
  encryptedPayload: EncryptedPayload;
};

export type KekKeyPair = {
  algorithm: 'ml-kem-768';
  kekId: string;
  privateKeyHex: string;
  publicKeyHex: string;
  version: 1;
};

export type KekKeyPairBytes = {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
};

export type KekAsymmetricWrappedPayload = {
  algorithm: 'ml-kem-768-private-wrap+xsalsa20-poly1305';
  kekId: string;
  nonceHex: string;
  version: 2;
  wrappedDekHex: string;
};

export type KekAsymmetricDekEncryptedPayload = {
  encryptedDek: KekAsymmetricWrappedPayload;
  encryptedPayload: EncryptedPayload;
};

export type E2eeDriver = {
  hash: (message: Uint8Array) => Uint8Array;
  hashBytes: number | (() => number);
  deriveDeterministicKekKeyPair?: (seed: Uint8Array) => Promise<KekKeyPairBytes>;
  derivePasswordHash: (
    password: Uint8Array,
    salt: Uint8Array,
    keyLength: number,
  ) => Uint8Array;
  decrypt: (ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array) => Uint8Array;
  encrypt: (message: Uint8Array, nonce: Uint8Array, key: Uint8Array) => Uint8Array;
  randomBytes: (size: number) => Uint8Array;
  ready: Promise<unknown>;
  kekSeedBytes?: number | (() => number);
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
    return encryptBytesPayload(
      driver,
      utf8(value),
      deriveKek(driver, cryptKey, resolveSecretboxKeyBytes(driver)),
    );
  }

  function decryptString(payload: EncryptedPayload, cryptKey: CryptKey) {
    try {
      const plaintext = decryptBytesPayload(
        driver,
        payload,
        deriveKek(driver, cryptKey, resolveSecretboxKeyBytes(driver)),
      );

      return new TextDecoder().decode(plaintext);
    } catch {
      throw new Error('Unable to decrypt data with the current password.');
    }
  }

  function encryptStringWithDek(
    value: string,
    cryptKey: CryptKey,
    kekId: string,
  ): KekDekEncryptedPayload {
    const normalizedKekId = kekId.trim();

    if (!normalizedKekId) {
      throw new Error('A KEK id is required to encrypt data.');
    }

    const dek = driver.randomBytes(resolveSecretboxKeyBytes(driver));

    return {
      encryptedDek: encryptWrappedDekPayload(
        driver,
        dek,
        deriveKek(driver, cryptKey, resolveSecretboxKeyBytes(driver)),
        normalizedKekId,
      ),
      encryptedPayload: encryptBytesPayload(driver, utf8(value), dek),
    };
  }

  function decryptStringWithDek(payload: KekDekEncryptedPayload, cryptKey: CryptKey) {
    try {
      const dek = decryptBytesPayload(
        driver,
        mapWrappedDekToEncryptedPayload(payload.encryptedDek),
        deriveKek(driver, cryptKey, resolveSecretboxKeyBytes(driver)),
      );
      const expectedDekLength = resolveSecretboxKeyBytes(driver);

      if (dek.length !== expectedDekLength) {
        throw new Error('Invalid decrypted DEK length.');
      }

      const plaintext = decryptBytesPayload(driver, payload.encryptedPayload, dek);

      return new TextDecoder().decode(plaintext);
    } catch {
      throw new Error('Unable to decrypt data with the current password.');
    }
  }

  function rewrapEncryptedDek(
    payload: KekDekEncryptedPayload,
    currentCryptKey: CryptKey,
    nextCryptKey: CryptKey,
    nextKekId: string,
  ): KekWrappedPayload {
    const normalizedKekId = nextKekId.trim();

    if (!normalizedKekId) {
      throw new Error('A KEK id is required to rewrap a DEK.');
    }

    try {
      const dek = decryptBytesPayload(
        driver,
        mapWrappedDekToEncryptedPayload(payload.encryptedDek),
        deriveKek(driver, currentCryptKey, resolveSecretboxKeyBytes(driver)),
      );
      const expectedDekLength = resolveSecretboxKeyBytes(driver);

      if (dek.length !== expectedDekLength) {
        throw new Error('Invalid decrypted DEK length.');
      }

      return encryptWrappedDekPayload(
        driver,
        dek,
        deriveKek(driver, nextCryptKey, expectedDekLength),
        normalizedKekId,
      );
    } catch {
      throw new Error('Unable to rewrap data with the current password.');
    }
  }

  async function deriveKekKeyPair(cryptKey: CryptKey): Promise<KekKeyPair> {
    await driver.ready;

    const keyPair = await requireDeterministicKekKeyPair(
      driver,
      deriveKekSeed(driver, cryptKey),
    );
    const publicKeyHex = bytesToHex(keyPair.publicKey);

    return {
      algorithm: 'ml-kem-768',
      kekId: publicKeyHex,
      privateKeyHex: bytesToHex(keyPair.privateKey),
      publicKeyHex,
      version: 1,
    };
  }

  async function encryptStringWithAsymmetricKek(
    value: string,
    cryptKey: CryptKey,
  ): Promise<KekAsymmetricDekEncryptedPayload> {
    await driver.ready;

    const keyPair = await requireDeterministicKekKeyPair(
      driver,
      deriveKekSeed(driver, cryptKey),
    );
    const dek = driver.randomBytes(resolveSecretboxKeyBytes(driver));

    return {
      encryptedDek: encryptAsymmetricWrappedDekPayload(
        driver,
        dek,
        deriveKekWrapKey(driver, keyPair.privateKey, resolveSecretboxKeyBytes(driver)),
        bytesToHex(keyPair.publicKey),
      ),
      encryptedPayload: encryptBytesPayload(driver, utf8(value), dek),
    };
  }

  async function decryptStringWithAsymmetricKek(
    payload: KekAsymmetricDekEncryptedPayload,
    cryptKey: CryptKey,
  ) {
    await driver.ready;

    try {
      const keyPair = await requireDeterministicKekKeyPair(
        driver,
        deriveKekSeed(driver, cryptKey),
      );
      const derivedKekId = bytesToHex(keyPair.publicKey);

      if (derivedKekId !== payload.encryptedDek.kekId) {
        throw new Error('The current password does not match the wrapped KEK keypair.');
      }

      const dek = decryptBytesPayload(
        driver,
        mapAsymmetricWrappedDekToEncryptedPayload(payload.encryptedDek),
        deriveKekWrapKey(driver, keyPair.privateKey, resolveSecretboxKeyBytes(driver)),
      );
      const expectedDekLength = resolveSecretboxKeyBytes(driver);

      if (dek.length !== expectedDekLength) {
        throw new Error('Invalid decrypted DEK length.');
      }

      return new TextDecoder().decode(decryptBytesPayload(driver, payload.encryptedPayload, dek));
    } catch {
      throw new Error('Unable to decrypt data with the current password.');
    }
  }

  async function rewrapAsymmetricEncryptedDek(
    payload: KekAsymmetricDekEncryptedPayload,
    currentCryptKey: CryptKey,
    nextCryptKey: CryptKey,
  ): Promise<KekAsymmetricWrappedPayload> {
    await driver.ready;

    try {
      const currentKeyPair = await requireDeterministicKekKeyPair(
        driver,
        deriveKekSeed(driver, currentCryptKey),
      );
      const currentKekId = bytesToHex(currentKeyPair.publicKey);

      if (currentKekId !== payload.encryptedDek.kekId) {
        throw new Error('The current password does not match the wrapped KEK keypair.');
      }

      const dek = decryptBytesPayload(
        driver,
        mapAsymmetricWrappedDekToEncryptedPayload(payload.encryptedDek),
        deriveKekWrapKey(driver, currentKeyPair.privateKey, resolveSecretboxKeyBytes(driver)),
      );
      const nextKeyPair = await requireDeterministicKekKeyPair(
        driver,
        deriveKekSeed(driver, nextCryptKey),
      );

      return encryptAsymmetricWrappedDekPayload(
        driver,
        dek,
        deriveKekWrapKey(driver, nextKeyPair.privateKey, resolveSecretboxKeyBytes(driver)),
        bytesToHex(nextKeyPair.publicKey),
      );
    } catch {
      throw new Error('Unable to rewrap data with the current password.');
    }
  }

  return {
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
  };
}

function deriveKek(driver: E2eeDriver, cryptKey: CryptKey, keyLength: number) {
  return deriveSubkey(
    driver,
    cryptKey,
    ENCRYPTION_CONTEXT_PREFIX,
    keyLength,
  );
}

function deriveKekSeed(driver: E2eeDriver, cryptKey: CryptKey) {
  return deriveSubkey(
    driver,
    cryptKey,
    KEK_SEED_CONTEXT_PREFIX,
    resolveKekSeedBytes(driver),
  );
}

function deriveKekWrapKey(driver: E2eeDriver, sharedSecret: Uint8Array, keyLength: number) {
  return deriveSubkey(driver, sharedSecret, KEK_WRAP_CONTEXT_PREFIX, keyLength);
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

function resolveKekSeedBytes(driver: E2eeDriver) {
  return resolveDriverSize(driver.kekSeedBytes ?? 32);
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

function encryptBytesPayload(driver: E2eeDriver, value: Uint8Array, key: Uint8Array): EncryptedPayload {
  const nonce = driver.randomBytes(resolveSecretboxNonceBytes(driver));
  const ciphertext = driver.encrypt(value, nonce, key);

  return {
    algorithm: 'xsalsa20-poly1305',
    ciphertextHex: bytesToHex(ciphertext),
    nonceHex: bytesToHex(nonce),
    version: 1,
  };
}

function encryptWrappedDekPayload(
  driver: E2eeDriver,
  value: Uint8Array,
  key: Uint8Array,
  kekId: string,
): KekWrappedPayload {
  const encryptedPayload = encryptBytesPayload(driver, value, key);

  return {
    algorithm: encryptedPayload.algorithm,
    kekId,
    nonceHex: encryptedPayload.nonceHex,
    version: encryptedPayload.version,
    wrappedDekHex: encryptedPayload.ciphertextHex,
  };
}

function encryptAsymmetricWrappedDekPayload(
  driver: E2eeDriver,
  value: Uint8Array,
  key: Uint8Array,
  kekId: string,
): KekAsymmetricWrappedPayload {
  const encryptedPayload = encryptBytesPayload(driver, value, key);

  return {
    algorithm: 'ml-kem-768-private-wrap+xsalsa20-poly1305',
    kekId,
    nonceHex: encryptedPayload.nonceHex,
    version: 2,
    wrappedDekHex: encryptedPayload.ciphertextHex,
  };
}

function decryptBytesPayload(driver: E2eeDriver, payload: EncryptedPayload, key: Uint8Array) {
  return driver.decrypt(
    hexToBytes(payload.ciphertextHex),
    hexToBytes(payload.nonceHex),
    key,
  );
}

function mapWrappedDekToEncryptedPayload(payload: KekWrappedPayload): EncryptedPayload {
  return {
    algorithm: payload.algorithm,
    ciphertextHex: payload.wrappedDekHex,
    nonceHex: payload.nonceHex,
    version: payload.version,
  };
}

function mapAsymmetricWrappedDekToEncryptedPayload(payload: KekAsymmetricWrappedPayload): EncryptedPayload {
  return {
    algorithm: 'xsalsa20-poly1305',
    ciphertextHex: payload.wrappedDekHex,
    nonceHex: payload.nonceHex,
    version: 1,
  };
}

async function requireDeterministicKekKeyPair(driver: E2eeDriver, seed: Uint8Array) {
  if (!driver.deriveDeterministicKekKeyPair) {
    throw new Error('This E2EE driver does not support deterministic ML-KEM KEK keypairs.');
  }

  return driver.deriveDeterministicKekKeyPair(seed);
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