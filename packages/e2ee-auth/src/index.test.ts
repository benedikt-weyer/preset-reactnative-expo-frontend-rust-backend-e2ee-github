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
  deriveCredentials,
  encryptString,
  normalizeEmail,
} from './index';
import { createE2ee } from './core';

describe('createE2ee driver access', () => {
  it('reads deferred driver properties after ready resolves', async () => {
    const randomBytes = vi.fn((size: number) => new Uint8Array(size).fill(0xab));
    const derivePasswordHash = vi.fn(
      (_password: Uint8Array, _salt: Uint8Array, keyLength: number) => new Uint8Array(keyLength),
    );
    const e2ee = createE2ee({
      derivePasswordHash,
      randomBytes,
      ready: Promise.resolve(),
      saltBytes: () => 4,
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