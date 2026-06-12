import sodium from 'libsodium-wrappers-sumo';
import { describe, expect, it, vi } from 'vitest';

vi.mock('react-native-libsodium', async () => {
  await sodium.ready;

  return {
    crypto_pwhash: sodium.crypto_pwhash,
    crypto_pwhash_ALG_ARGON2ID13: sodium.crypto_pwhash_ALG_ARGON2ID13,
    crypto_pwhash_MEMLIMIT_INTERACTIVE: sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_OPSLIMIT_INTERACTIVE: sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_SALTBYTES: sodium.crypto_pwhash_SALTBYTES,
    loadSumoVersion: () => undefined,
    randombytes_buf: sodium.randombytes_buf,
    ready: Promise.resolve(),
  };
});

import {
  createPasswordSalt,
  decryptString,
  decryptStringWithAsymmetricKek,
  decryptStringWithDek,
  deriveCredentials,
  deriveKekKeyPair,
  encryptString,
  encryptStringWithAsymmetricKek,
  encryptStringWithDek,
  normalizeEmail,
  rewrapEncryptedDek,
} from './index';
import { createE2ee } from './core';

describe('createE2ee driver access', () => {
  it('reads deferred driver properties after ready resolves', async () => {
    const encrypt = vi.fn((message: Uint8Array) => message);
    const decrypt = vi.fn((ciphertext: Uint8Array) => ciphertext);
    const hash = vi.fn(() => new Uint8Array(64));
    const randomBytes = vi.fn((size: number) => new Uint8Array(size).fill(0xab));
    const derivePasswordHash = vi.fn(
      (_password: Uint8Array, _salt: Uint8Array, keyLength: number) => new Uint8Array(keyLength),
    );
    const e2ee = createE2ee({
      decrypt,
      derivePasswordHash,
      encrypt,
      hash,
      hashBytes: () => 64,
      randomBytes,
      ready: Promise.resolve(),
      saltBytes: () => 4,
      secretboxKeyBytes: () => 32,
      secretboxNonceBytes: () => 24,
    });

    const salt = await e2ee.createPasswordSalt();
    await e2ee.deriveCredentials('person@example.com', 'correct horse', '00112233');

    expect(salt).toBe('abababab');
    expect(randomBytes).toHaveBeenCalledWith(4);
    expect(derivePasswordHash).toHaveBeenCalled();
  });
});

describe('normalizeEmail', () => {
  it('trims and lowercases the input email', () => {
    expect(normalizeEmail('  Person@Example.COM  ')).toBe('person@example.com');
  });
});

describe('createPasswordSalt', () => {
  it('creates a 16-byte salt encoded as lowercase hex', async () => {
    const salt = await createPasswordSalt();

    expect(salt).toMatch(/^[0-9a-f]{32}$/);
  });

  it('creates different salts across calls', async () => {
    const firstSalt = await createPasswordSalt();
    const secondSalt = await createPasswordSalt();

    expect(firstSalt).not.toBe(secondSalt);
  });
});

describe('deriveCredentials', () => {
  it('derives stable credentials for the same email, password, and salt', async () => {
    const salt = '00112233445566778899aabbccddeeff';

    const first = await deriveCredentials('person@example.com', 'correct horse', salt);
    const second = await deriveCredentials('person@example.com', 'correct horse', salt);

    expect(first.email).toBe('person@example.com');
    expect(first.authKey).toMatch(/^[0-9a-f]{128}$/);
    expect(first.authKey).toBe(
      'a96636da59512159dae68b179c00951ee0a9d8cb9f1e0498d5fd3e8c5e9e4b6a62b0afb064229bdf745781c497179b0eb16a4c182c0b764bf0078cbe819b342d',
    );
    expect(Array.from(first.cryptKey)).toEqual(
      Array.from(
        sodium.from_hex(
          '922fe89d2f7416dfcd9a4a094dcec3f6ee6b8ff3c01e2b35bb0c017ed95248d452b5f07373d3a7b88494a330e58a2af009b97fcffd965de54412ba650fb2ac34',
        ),
      ),
    );
    expect(Array.from(first.cryptKey)).toEqual(Array.from(second.cryptKey));
    expect(first.authKey).toBe(second.authKey);
  });

  it('changes the derived credentials when the salt changes', async () => {
    const first = await deriveCredentials(
      'person@example.com',
      'correct horse',
      '00112233445566778899aabbccddeeff',
    );
    const second = await deriveCredentials(
      'person@example.com',
      'correct horse',
      'ffeeddccbbaa99887766554433221100',
    );

    expect(first.authKey).not.toBe(second.authKey);
    expect(Array.from(first.cryptKey)).not.toEqual(Array.from(second.cryptKey));
  });

  it('rejects an invalid email', async () => {
    await expect(
      deriveCredentials('not-an-email', 'correct horse', '00112233445566778899aabbccddeeff'),
    ).rejects.toThrow('Enter a valid email address.');
  });

  it('rejects a missing password', async () => {
    await expect(
      deriveCredentials('person@example.com', '   ', '00112233445566778899aabbccddeeff'),
    ).rejects.toThrow('Enter a password.');
  });

  it('rejects an invalid salt', async () => {
    await expect(
      deriveCredentials('person@example.com', 'correct horse', 'abcd'),
    ).rejects.toThrow('Unable to use the stored password salt.');
  });
});

describe('encryptString/decryptString', () => {
  it('round-trips plaintext with the derived crypt key', async () => {
    const { cryptKey } = await deriveCredentials(
      'person@example.com',
      'correct horse',
      '00112233445566778899aabbccddeeff',
    );
    const payload = encryptString('secret note', cryptKey);

    expect(payload.algorithm).toBe('xsalsa20-poly1305');
    expect(payload.version).toBe(1);
    expect(decryptString(payload, cryptKey)).toBe('secret note');
  });

  it('fails to decrypt with a different crypt key', async () => {
    const { cryptKey } = await deriveCredentials(
      'person@example.com',
      'correct horse',
      '00112233445566778899aabbccddeeff',
    );
    const otherCredentials = await deriveCredentials(
      'person@example.com',
      'correct horse',
      'ffeeddccbbaa99887766554433221100',
    );
    const payload = encryptString('secret note', cryptKey);

    expect(() => decryptString(payload, otherCredentials.cryptKey)).toThrow(
      'Unable to decrypt data with the current password.',
    );
  });
});

describe('encryptStringWithDek/decryptStringWithDek', () => {
  it('wraps a random DEK with the password-derived KEK and decrypts successfully', async () => {
    const { cryptKey } = await deriveCredentials(
      'person@example.com',
      'correct horse',
      '00112233445566778899aabbccddeeff',
    );
    const payload = encryptStringWithDek('secret note', cryptKey, 'kek-current');

    expect(payload.encryptedDek.algorithm).toBe('xsalsa20-poly1305');
    expect(payload.encryptedDek.kekPublicKey).toBe('kek-current');
    expect(payload.encryptedDek.version).toBe(1);
    expect(payload.encryptedDek.wrappedDekHex).toMatch(/^[0-9a-f]+$/);
    expect(payload.encryptedPayload.algorithm).toBe('xsalsa20-poly1305');
    expect(payload.encryptedPayload.version).toBe(1);
    expect(decryptStringWithDek(payload, cryptKey)).toBe('secret note');
  });

  it('fails to decrypt the wrapped DEK with a different crypt key', async () => {
    const { cryptKey } = await deriveCredentials(
      'person@example.com',
      'correct horse',
      '00112233445566778899aabbccddeeff',
    );
    const otherCredentials = await deriveCredentials(
      'person@example.com',
      'correct horse',
      'ffeeddccbbaa99887766554433221100',
    );
    const payload = encryptStringWithDek('secret note', cryptKey, 'kek-current');

    expect(() => decryptStringWithDek(payload, otherCredentials.cryptKey)).toThrow(
      'Unable to decrypt data with the current password.',
    );
  });

  it('requires a KEK id when wrapping a DEK', async () => {
    const { cryptKey } = await deriveCredentials(
      'person@example.com',
      'correct horse',
      '00112233445566778899aabbccddeeff',
    );

    expect(() => encryptStringWithDek('secret note', cryptKey, '   ')).toThrow(
      'A KEK id is required to encrypt data.',
    );
  });

  it('rewraps the existing DEK to a new kek id without changing the note payload', async () => {
    const currentCredentials = await deriveCredentials(
      'person@example.com',
      'correct horse',
      '00112233445566778899aabbccddeeff',
    );
    const nextCredentials = await deriveCredentials(
      'person@example.com',
      'new horse battery',
      '00112233445566778899aabbccddeeff',
    );
    const payload = encryptStringWithDek('secret note', currentCredentials.cryptKey, 'kek-v1');

    const rewrappedDek = rewrapEncryptedDek(
      payload,
      currentCredentials.cryptKey,
      nextCredentials.cryptKey,
      'kek-v2',
    );

    expect(rewrappedDek.kekPublicKey).toBe('kek-v2');
    expect(rewrappedDek.wrappedDekHex).not.toBe(payload.encryptedDek.wrappedDekHex);
    expect(
      decryptStringWithDek(
        {
          encryptedDek: rewrappedDek,
          encryptedPayload: payload.encryptedPayload,
        },
        nextCredentials.cryptKey,
      ),
    ).toBe('secret note');
  });
});

describe('deriveKekKeyPair', () => {
  it('derives a stable ML-KEM keypair from the password crypt key', async () => {
    const { cryptKey } = await deriveCredentials(
      'person@example.com',
      'correct horse',
      '00112233445566778899aabbccddeeff',
    );

    const first = await deriveKekKeyPair(cryptKey);
    const second = await deriveKekKeyPair(cryptKey);

    expect(first.algorithm).toBe('ml-kem-768');
    expect(first.version).toBe(1);
    expect(first.kekPublicKey).toMatch(/^[0-9a-f]{2368}$/);
    expect(first.publicKeyHex).toBe(first.kekPublicKey);
    expect(first.privateKeyHex).toMatch(/^[0-9a-f]+$/);
    expect(first.kekPublicKey).toBe(second.kekPublicKey);
    expect(first.privateKeyHex).toBe(second.privateKeyHex);
  });
});

describe('encryptStringWithAsymmetricKek/decryptStringWithAsymmetricKek', () => {
  it('round-trips plaintext with a derived ML-KEM KEK keypair', async () => {
    const credentials = await deriveCredentials(
      'person@example.com',
      'correct horse',
      '00112233445566778899aabbccddeeff',
    );
    const kekKeyPair = await deriveKekKeyPair(credentials.cryptKey);
    const payload = await encryptStringWithAsymmetricKek('secret note', kekKeyPair.kekPublicKey);

    expect(payload.encryptedDek.algorithm).toBe('ml-kem-768-encapsulated+xsalsa20-poly1305');
    expect(payload.encryptedDek.kekPublicKey).toBe(kekKeyPair.kekPublicKey);
    expect(payload.encryptedDek.kemCiphertextHex).toMatch(/^[0-9a-f]{2176}$/);
    expect(payload.encryptedDek.version).toBe(3);
    await expect(decryptStringWithAsymmetricKek(payload, credentials.cryptKey)).resolves.toBe(
      'secret note',
    );
  });
});