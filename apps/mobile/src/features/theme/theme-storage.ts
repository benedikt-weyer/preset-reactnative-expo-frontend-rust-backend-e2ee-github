import * as SecureStore from 'expo-secure-store';

export type ThemeMode = 'light' | 'dark';

const THEME_STORAGE_KEY = 'app-theme-mode';

export interface ThemePersistence {
  read: () => Promise<ThemeMode>;
  write: (themeMode: ThemeMode) => Promise<void>;
}

export const secureStoreThemePersistence: ThemePersistence = {
  async read() {
    try {
      const storedTheme = await SecureStore.getItemAsync(THEME_STORAGE_KEY);

      return storedTheme === 'dark' ? 'dark' : 'light';
    } catch {
      return 'light';
    }
  },
  async write(themeMode) {
    try {
      await SecureStore.setItemAsync(THEME_STORAGE_KEY, themeMode);
    } catch {
      // Keep the in-memory theme usable even if persistence is unavailable.
    }
  },
};