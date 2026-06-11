import type { CryptKey } from '@repo/e2ee-auth/web';

import type { AuthApiResponse } from '@/lib/auth-api';

const AUTH_PREFERENCES_STORAGE_KEY = 'auth-preferences';

export type AuthPreferences = {
  backendUrl: string;
  lastEmail: string;
};

export type PersistedDerivedCredentials = {
  cryptKey: CryptKey;
  email: string;
  saltHex: string;
};

type StoredDerivedCredentials = {
  cryptKeyHex?: string;
  email?: string;
  saltHex?: string;
};

type StoredAuthPreferences = {
  backendUrl?: string;
  lastEmail?: string;
  authSession?: AuthApiResponse;
  derivedCredentials?: StoredDerivedCredentials;
};

export interface AuthPersistenceAdapter {
  clearAuthSession: () => void;
  clearDerivedCredentials: () => void;
  readAuthSession: () => AuthApiResponse | null;
  readDerivedCredentials: () => PersistedDerivedCredentials | null;
  readPreferences: () => AuthPreferences;
  writeAuthSession: (session: AuthApiResponse) => void;
  writeDerivedCredentials: (credentials: PersistedDerivedCredentials) => void;
  writePreferences: (preferences: AuthPreferences) => void;
}

declare global {
  interface Window {
    __RUNTIME_CONFIG__?: {
      backendUrl?: string;
    };
  }
}

function readDefaultPreferences(): AuthPreferences {
  return {
    backendUrl: readRuntimeBackendUrl(),
    lastEmail: '',
  };
}

function hasWindow() {
  return globalThis.window !== undefined;
}

function readStoredPreferences(): StoredAuthPreferences | null {
  if (!hasWindow()) {
    return null;
  }

  try {
    const storedPreferences = globalThis.window.localStorage.getItem(
      AUTH_PREFERENCES_STORAGE_KEY,
    );

    if (!storedPreferences) {
      return null;
    }

    const parsedPreferences = JSON.parse(storedPreferences) as unknown;

    return typeof parsedPreferences === 'object' && parsedPreferences !== null
      ? parsedPreferences
      : null;
  } catch {
    return null;
  }
}

function readRuntimeBackendUrl() {
  if (!hasWindow()) {
    return '';
  }

  return globalThis.window.__RUNTIME_CONFIG__?.backendUrl?.trim() ?? '';
}

function writeStoredPreferences(preferences: StoredAuthPreferences) {
  if (!hasWindow()) {
    return;
  }

  try {
    globalThis.window.localStorage.setItem(
      AUTH_PREFERENCES_STORAGE_KEY,
      JSON.stringify(preferences),
    );
  } catch {
    // Keep auth usable even when local storage is unavailable.
  }
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string) {
  const normalizedHex = hex.trim().toLowerCase();

  if (!normalizedHex || normalizedHex.length % 2 !== 0 || /[^0-9a-f]/.test(normalizedHex)) {
    return null;
  }

  const bytes = new Uint8Array(normalizedHex.length / 2);

  for (let index = 0; index < normalizedHex.length; index += 2) {
    const nextByte = Number.parseInt(normalizedHex.slice(index, index + 2), 16);

    if (Number.isNaN(nextByte)) {
      return null;
    }

    bytes[index / 2] = nextByte;
  }

  return bytes;
}

export const localStorageAuthPersistence: AuthPersistenceAdapter = {
  clearAuthSession() {
    const storedPreferences = readStoredPreferences();

    if (!storedPreferences?.authSession) {
      return;
    }

    const { authSession: _authSession, ...nextPreferences } = storedPreferences;

    writeStoredPreferences(nextPreferences);
  },
  clearDerivedCredentials() {
    const storedPreferences = readStoredPreferences();

    if (!storedPreferences?.derivedCredentials) {
      return;
    }

    const { derivedCredentials: _derivedCredentials, ...nextPreferences } = storedPreferences;

    writeStoredPreferences(nextPreferences);
  },
  readAuthSession() {
    const storedPreferences = readStoredPreferences();
    const authSession = storedPreferences?.authSession;

    if (
      !authSession ||
      typeof authSession.token !== 'string' ||
      typeof authSession.refreshToken !== 'string' ||
      !authSession.user ||
      typeof authSession.user.id !== 'string' ||
      typeof authSession.user.email !== 'string'
    ) {
      return null;
    }

    return {
      refreshToken: authSession.refreshToken,
      token: authSession.token,
      user: {
        email: authSession.user.email.trim().toLowerCase(),
        id: authSession.user.id,
      },
    };
  },
  readDerivedCredentials() {
    const storedPreferences = readStoredPreferences();
    const email = storedPreferences?.derivedCredentials?.email?.trim().toLowerCase();
    const saltHex = storedPreferences?.derivedCredentials?.saltHex?.trim().toLowerCase();
    const cryptKeyHex = storedPreferences?.derivedCredentials?.cryptKeyHex;

    if (!email || !saltHex || !cryptKeyHex) {
      return null;
    }

    const cryptKey = hexToBytes(cryptKeyHex);

    if (!cryptKey) {
      return null;
    }

    return {
      cryptKey,
      email,
      saltHex,
    };
  },
  readPreferences() {
    const defaultPreferences = readDefaultPreferences();
    const storedPreferences = readStoredPreferences();

    return {
      backendUrl: storedPreferences?.backendUrl?.trim() || defaultPreferences.backendUrl,
      lastEmail:
        storedPreferences?.lastEmail ??
        storedPreferences?.derivedCredentials?.email?.trim().toLowerCase() ??
        '',
    };
  },
  writeDerivedCredentials(credentials) {
    const storedPreferences = readStoredPreferences() ?? {};

    writeStoredPreferences({
      ...storedPreferences,
      derivedCredentials: {
        cryptKeyHex: bytesToHex(credentials.cryptKey),
        email: credentials.email.trim().toLowerCase(),
        saltHex: credentials.saltHex.trim().toLowerCase(),
      },
      lastEmail: credentials.email.trim().toLowerCase(),
    });
  },
  writeAuthSession(session) {
    const storedPreferences = readStoredPreferences() ?? {};

    writeStoredPreferences({
      ...storedPreferences,
      authSession: {
        refreshToken: session.refreshToken,
        token: session.token,
        user: {
          email: session.user.email.trim().toLowerCase(),
          id: session.user.id,
        },
      },
      lastEmail: session.user.email.trim().toLowerCase(),
    });
  },
  writePreferences(preferences) {
    const storedPreferences = readStoredPreferences() ?? {};

    writeStoredPreferences({
      ...storedPreferences,
      backendUrl: preferences.backendUrl.trim(),
      lastEmail: preferences.lastEmail.trim().toLowerCase(),
    });
  },
};

export function readAuthPreferences(): AuthPreferences {
  return localStorageAuthPersistence.readPreferences();
}

export function writeAuthPreferences(preferences: AuthPreferences) {
  localStorageAuthPersistence.writePreferences(preferences);
}