import type { EncryptedPayload } from '@repo/e2ee-auth/web';

const E2EE_VAULT_STORAGE_KEY = 'e2ee-vault-note';

export function clearEncryptedVault() {
  if (typeof window === 'undefined') {
    return;
  }

  try {
    window.localStorage.removeItem(E2EE_VAULT_STORAGE_KEY);
  } catch {
    // Ignore local persistence failures so the UI can stay responsive.
  }
}

export function readEncryptedVault(): EncryptedPayload | null {
  if (typeof window === 'undefined') {
    return null;
  }

  try {
    const storedPayload = window.localStorage.getItem(E2EE_VAULT_STORAGE_KEY);

    return storedPayload ? (JSON.parse(storedPayload) as EncryptedPayload) : null;
  } catch {
    return null;
  }
}

export function writeEncryptedVault(payload: EncryptedPayload) {
  if (typeof window === 'undefined') {
    return;
  }

  try {
    window.localStorage.setItem(E2EE_VAULT_STORAGE_KEY, JSON.stringify(payload));
  } catch {
    // Ignore local persistence failures so encryption can still be exercised.
  }
}