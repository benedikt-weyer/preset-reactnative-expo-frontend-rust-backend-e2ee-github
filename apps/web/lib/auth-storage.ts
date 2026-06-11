const AUTH_PREFERENCES_STORAGE_KEY = 'auth-preferences';

export type AuthPreferences = {
  backendUrl: string;
  lastEmail: string;
};

const defaultPreferences: AuthPreferences = {
  backendUrl: process.env.NEXT_PUBLIC_API_BASE_URL?.trim() ?? '',
  lastEmail: '',
};

export function readAuthPreferences(): AuthPreferences {
  if (typeof window === 'undefined') {
    return defaultPreferences;
  }

  try {
    const storedPreferences = window.localStorage.getItem(AUTH_PREFERENCES_STORAGE_KEY);

    if (!storedPreferences) {
      return defaultPreferences;
    }

    const parsedPreferences = JSON.parse(storedPreferences) as Partial<AuthPreferences>;

    return {
      backendUrl: parsedPreferences.backendUrl?.trim() ?? defaultPreferences.backendUrl,
      lastEmail: parsedPreferences.lastEmail ?? '',
    };
  } catch {
    return defaultPreferences;
  }
}

export function writeAuthPreferences(preferences: AuthPreferences) {
  if (typeof window === 'undefined') {
    return;
  }

  try {
    window.localStorage.setItem(
      AUTH_PREFERENCES_STORAGE_KEY,
      JSON.stringify(preferences),
    );
  } catch {
    // Keep auth usable even when local storage is unavailable.
  }
}