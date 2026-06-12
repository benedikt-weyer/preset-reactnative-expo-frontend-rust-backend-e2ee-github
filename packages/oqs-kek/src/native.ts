import { deriveDeterministicMlKem768KeyPair } from './deterministic';

import type { MlKemKeyPair, OqsKekAdapter } from './index';

type NativeOqsKekBridge = {
  deriveDeterministicMlKem768KeyPair: (seedHex: string) => Promise<{
    privateKeyHex: string;
    publicKeyHex: string;
  }>;
  ready?: Promise<void>;
};

declare global {
  var __repoOqsKekBridge: NativeOqsKekBridge | undefined;
}

export function createNativeOqsKekAdapter(): OqsKekAdapter {
  const bridge = globalThis.__repoOqsKekBridge;

  if (!bridge) {
    const error = new Error(
      'The native OQS KEK bridge is not registered. Implement the monorepo JSI or TurboModule bridge before using ML-KEM on React Native.',
    );

    return {
      deriveDeterministicKeyPair: async (seed): Promise<MlKemKeyPair> => {
        return deriveDeterministicMlKem768KeyPair(seed);
      },
      ready: Promise.resolve(),
    };
  }

  return {
    async deriveDeterministicKeyPair(seed) {
      const keyPair = await bridge.deriveDeterministicMlKem768KeyPair(bytesToHex(seed));

      return {
        algorithm: 'ml-kem-768',
        privateKey: hexStringToBytes(keyPair.privateKeyHex),
        publicKey: hexStringToBytes(keyPair.publicKeyHex),
      };
    },
    ready: bridge.ready ?? Promise.resolve(),
  };
}

function bytesToHex(value: Uint8Array) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function hexStringToBytes(value: string) {
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