const AUTH_PREFERENCES_STORAGE_KEY = 'auth-preferences';

export type AuthPreferences = {
  backendUrl: string;
  lastEmail: string;
};

type StoredAuthPreferences = {
  lastEmail?: string;
};

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

export function readAuthPreferences(): AuthPreferences {
  const defaultPreferences = readDefaultPreferences();

  if (typeof window === 'undefined') {
    return defaultPreferences;
  }

  try {
    const storedPreferences = window.localStorage.getItem(AUTH_PREFERENCES_STORAGE_KEY);

    if (!storedPreferences) {
      return defaultPreferences;
    }

    const parsedPreferences = JSON.parse(storedPreferences) as StoredAuthPreferences;

    return {
      backendUrl: defaultPreferences.backendUrl,
      lastEmail: parsedPreferences.lastEmail ?? '',
    };
  } catch {
    return defaultPreferences;
  }
}

function readRuntimeBackendUrl() {
  if (typeof window === 'undefined') {
    return '';
  }

  return window.__RUNTIME_CONFIG__?.backendUrl?.trim() ?? '';
}

export function writeAuthPreferences(preferences: AuthPreferences) {
  if (typeof window === 'undefined') {
    return;
  }

  try {
    window.localStorage.setItem(
      AUTH_PREFERENCES_STORAGE_KEY,
      JSON.stringify({
        lastEmail: preferences.lastEmail,
      } satisfies StoredAuthPreferences),
    );
  } catch {
    // Keep auth usable even when local storage is unavailable.
  }
}