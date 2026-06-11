import * as SecureStore from 'expo-secure-store';

const AUTH_PREFERENCES_STORAGE_KEY = 'auth-preferences';

export type AuthPreferences = {
  backendUrl: string;
  lastEmail: string;
};

const defaultPreferences: AuthPreferences = {
  backendUrl: process.env.EXPO_PUBLIC_API_BASE_URL?.trim() ?? '',
  lastEmail: '',
};

export interface AuthPreferencesPersistence {
  read: () => Promise<AuthPreferences>;
  write: (preferences: AuthPreferences) => Promise<void>;
}

export const secureStoreAuthPreferences: AuthPreferencesPersistence = {
  async read() {
    try {
      const storedPreferences = await SecureStore.getItemAsync(
        AUTH_PREFERENCES_STORAGE_KEY,
      );

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
  },
  async write(preferences) {
    try {
      await SecureStore.setItemAsync(
        AUTH_PREFERENCES_STORAGE_KEY,
        JSON.stringify(preferences),
      );
    } catch {
      // Keep auth usable even when persistence is unavailable.
    }
  },
};
