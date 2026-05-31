import { createContext, ReactNode, useContext, useEffect, useState } from 'react';

import {
  secureStoreThemePersistence,
  type ThemeMode,
} from './theme-storage';

type ThemeContextValue = {
  isHydrated: boolean;
  setThemeMode: (themeMode: ThemeMode) => Promise<void>;
  themeMode: ThemeMode;
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

type ThemeProviderProps = {
  children: ReactNode;
};

export function ThemeProvider({ children }: ThemeProviderProps) {
  const [themeMode, setThemeModeState] = useState<ThemeMode>('light');
  const [isHydrated, setIsHydrated] = useState(false);

  useEffect(() => {
    let isMounted = true;

    async function hydrateTheme() {
      const storedTheme = await secureStoreThemePersistence.read();

      if (!isMounted) {
        return;
      }

      setThemeModeState(storedTheme);
      setIsHydrated(true);
    }

    void hydrateTheme();

    return () => {
      isMounted = false;
    };
  }, []);

  async function setThemeMode(nextThemeMode: ThemeMode) {
    setThemeModeState(nextThemeMode);
    await secureStoreThemePersistence.write(nextThemeMode);
  }

  return (
    <ThemeContext.Provider value={{ isHydrated, setThemeMode, themeMode }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useAppTheme() {
  const themeContext = useContext(ThemeContext);

  if (!themeContext) {
    throw new Error('useAppTheme must be used inside ThemeProvider');
  }

  return themeContext;
}