import { deriveDeterministicMlKem768KeyPair } from './deterministic';

import type { MlKemKeyPair, OqsKekAdapter } from './index';

export function createWebOqsKekAdapter(): OqsKekAdapter {
  const ready = Promise.resolve();

  return {
    async deriveDeterministicKeyPair(seed): Promise<MlKemKeyPair> {
      return deriveDeterministicMlKem768KeyPair(seed);
    },
    ready,
  };
}