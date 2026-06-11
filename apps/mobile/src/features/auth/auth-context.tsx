import {
  createContext,
  ReactNode,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import {
  createPasswordSalt,
  deriveCredentials,
  normalizeEmail,
  type CryptKey,
} from '@repo/e2ee-auth';

import { fetchPasswordSalt, loginRequest, registerRequest } from './auth-api';
import {
  secureStoreAuthPreferences,
  type AuthPreferences,
} from './auth-storage';

type Session = {
  refreshToken: string;
  token: string;
  user: {
    email: string;
    id: string;
  };
};

type AuthContextValue = {
  backendUrl: string;
  cryptKey: CryptKey | null;
  isAuthenticated: boolean;
  isHydrated: boolean;
  lastEmail: string;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  session: Session | null;
  signOut: () => void;
  updateBackendUrl: (backendUrl: string) => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

type AuthProviderProps = Readonly<{
  children: ReactNode;
}>;

export function AuthProvider({ children }: AuthProviderProps) {
  const [preferences, setPreferences] = useState<AuthPreferences>({
    backendUrl: '',
    lastEmail: '',
  });
  const [session, setSession] = useState<Session | null>(null);
  const [cryptKey, setCryptKey] = useState<CryptKey | null>(null);
  const [isHydrated, setIsHydrated] = useState(false);

  useEffect(() => {
    let isMounted = true;

    async function hydrateAuthPreferences() {
      const storedPreferences = await secureStoreAuthPreferences.read();

      if (!isMounted) {
        return;
      }

      setPreferences(storedPreferences);
      setIsHydrated(true);
    }

    void hydrateAuthPreferences();

    return () => {
      isMounted = false;
    };
  }, []);

  async function persistPreferences(nextPreferences: AuthPreferences) {
    setPreferences(nextPreferences);
    await secureStoreAuthPreferences.write(nextPreferences);
  }

  async function authenticate(
    mode: 'login' | 'register',
    email: string,
    password: string,
  ) {
    const backendUrl = preferences.backendUrl.trim();
    const normalizedEmail = normalizeEmail(email);

    if (!backendUrl) {
      throw new Error('Enter the backend URL before continuing.');
    }

    const saltHex =
      mode === 'login'
        ? await fetchPasswordSalt({
            baseUrl: backendUrl,
            email: normalizedEmail,
          })
        : await createPasswordSalt();
    const credentials = await deriveCredentials(normalizedEmail, password, saltHex);
    const response =
      mode === 'login'
        ? await loginRequest({
            authKey: credentials.authKey,
            baseUrl: backendUrl,
            email: credentials.email,
          })
        : await registerRequest({
            authKey: credentials.authKey,
            baseUrl: backendUrl,
            email: credentials.email,
            saltHex,
          });

    setSession({
      refreshToken: response.refreshToken,
      token: response.token,
      user: response.user,
    });
    setCryptKey(credentials.cryptKey);

    await persistPreferences({
      backendUrl,
      lastEmail: credentials.email,
    });
  }

  async function updateBackendUrl(backendUrl: string) {
    await persistPreferences({
      ...preferences,
      backendUrl: backendUrl.trim(),
    });
  }

  function signOut() {
    setSession(null);
    setCryptKey(null);
  }

  const authContextValue = useMemo(
    () => ({
      backendUrl: preferences.backendUrl,
      cryptKey,
      isAuthenticated: session !== null && cryptKey !== null,
      isHydrated,
      lastEmail: preferences.lastEmail,
      login: (email: string, password: string) => authenticate('login', email, password),
      register: (email: string, password: string) =>
        authenticate('register', email, password),
      session,
      signOut,
      updateBackendUrl,
    }),
    [cryptKey, isHydrated, preferences, session],
  );

  return (
    <AuthContext.Provider value={authContextValue}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const authContext = useContext(AuthContext);

  if (!authContext) {
    throw new Error('useAuth must be used inside AuthProvider');
  }

  return authContext;
}
