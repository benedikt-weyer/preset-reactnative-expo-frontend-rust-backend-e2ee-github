import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import type { MlKemKeyPair } from './index';

const ML_KEM_768_SEED_BYTES = 64;

export function deriveDeterministicMlKem768KeyPair(seed: Uint8Array): MlKemKeyPair {
  if (!(seed instanceof Uint8Array) || seed.length !== ML_KEM_768_SEED_BYTES) {
    throw new Error(
      `ML-KEM-768 deterministic key derivation requires a ${ML_KEM_768_SEED_BYTES}-byte seed.`,
    );
  }

  const keyPair = ml_kem768.keygen(seed);

  return {
    algorithm: 'ml-kem-768',
    privateKey: new Uint8Array(keyPair.secretKey),
    publicKey: new Uint8Array(keyPair.publicKey),
  };
}

export { ML_KEM_768_SEED_BYTES };