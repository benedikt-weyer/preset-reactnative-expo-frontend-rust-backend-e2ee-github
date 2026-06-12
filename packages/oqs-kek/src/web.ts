import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import { deriveDeterministicMlKem768KeyPair } from './deterministic';

import type { MlKemKeyPair, OqsKekAdapter } from './index';

export function createWebOqsKekAdapter(): OqsKekAdapter {
  const ready = Promise.resolve();

  return {
    async decapsulate(cipherText, secretKey) {
      return new Uint8Array(ml_kem768.decapsulate(cipherText, secretKey));
    },
    async deriveDeterministicKeyPair(seed): Promise<MlKemKeyPair> {
      return deriveDeterministicMlKem768KeyPair(seed);
    },
    async encapsulate(publicKey) {
      const encapsulation = ml_kem768.encapsulate(publicKey);

      return {
        cipherText: new Uint8Array(encapsulation.cipherText),
        sharedSecret: new Uint8Array(encapsulation.sharedSecret),
      };
    },
    ready,
  };
}