export type MlKemAlgorithm = 'ml-kem-768';

export type MlKemKeyPair = {
  algorithm: MlKemAlgorithm;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
};

export type MlKemEncapsulation = {
  cipherText: Uint8Array;
  sharedSecret: Uint8Array;
};

export type OqsKekAdapter = {
  decapsulate: (cipherText: Uint8Array, secretKey: Uint8Array) => Promise<Uint8Array>;
  deriveDeterministicKeyPair: (seed: Uint8Array) => Promise<MlKemKeyPair>;
  encapsulate: (publicKey: Uint8Array) => Promise<MlKemEncapsulation>;
  ready: Promise<void>;
};

export function bytesToHex(value: Uint8Array) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(value: string) {
  const normalized = value.trim().toLowerCase();

  if (normalized.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(normalized)) {
    throw new Error('Invalid hex string.');
  }

  const output = new Uint8Array(normalized.length / 2);

  for (let index = 0; index < normalized.length; index += 2) {
    output[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }

  return output;
}