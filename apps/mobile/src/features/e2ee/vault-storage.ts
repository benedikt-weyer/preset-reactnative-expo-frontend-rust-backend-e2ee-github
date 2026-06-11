import * as SecureStore from 'expo-secure-store';

import type { EncryptedPayload } from '@repo/e2ee-auth/native';

const E2EE_VAULT_STORAGE_KEY = 'e2ee-vault-note';

export interface VaultPersistence {
  clear: () => Promise<void>;
  read: () => Promise<EncryptedPayload | null>;
  write: (payload: EncryptedPayload) => Promise<void>;
}

export const secureStoreVaultPersistence: VaultPersistence = {
  async clear() {
    try {
      await SecureStore.deleteItemAsync(E2EE_VAULT_STORAGE_KEY);
    } catch {
      // Ignore local persistence failures so the UI can stay responsive.
    }
  },
  async read() {
    try {
      const storedPayload = await SecureStore.getItemAsync(E2EE_VAULT_STORAGE_KEY);

      return storedPayload ? (JSON.parse(storedPayload) as EncryptedPayload) : null;
    } catch {
      return null;
    }
  },
  async write(payload) {
    try {
      await SecureStore.setItemAsync(E2EE_VAULT_STORAGE_KEY, JSON.stringify(payload));
    } catch {
      // Ignore local persistence failures so encryption can still be exercised.
    }
  },
};
