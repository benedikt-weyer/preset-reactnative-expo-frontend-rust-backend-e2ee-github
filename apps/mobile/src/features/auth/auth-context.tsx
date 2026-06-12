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
} from '@repo/e2ee-auth/native';

import {
  fetchPasswordSalt,
  loginRequest,
  registerRequest,
  type AuthApiResponse,
  type KekMetadata,
} from './auth-api';
import {
  secureStoreAuthPreferences,
  type AuthPreferences,
  type PersistedLinkedKek,
} from './auth-storage';

type Session = AuthApiResponse;

type AuthContextValue = {
  activeKekId: string | null;
  backendUrl: string;
  isAuthenticated: boolean;
  isHydrated: boolean;
  lastEmail: string;
  linkedKeks: PersistedLinkedKek[];
  login: (email: string, password: string, olderPasswords?: Record<string, string>) => Promise<void>;
  pendingOlderKeks: KekMetadata[];
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
    email: undefined,
    lastEmail: '',
    linkedKeks: [],
  });
  const [session, setSession] = useState<Session | null>(null);
  const [activeKekId, setActiveKekId] = useState<string | null>(null);
  const [pendingOlderKeks, setPendingOlderKeks] = useState<KekMetadata[]>([]);
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
    olderPasswords: Record<string, string> = {},
  ) {
    const backendUrl = preferences.backendUrl.trim();
    const normalizedEmail = normalizeEmail(email);
    const persistedLinkedKeks =
      preferences.email === normalizedEmail ? preferences.linkedKeks ?? [] : [];

    if (!backendUrl) {
      throw new Error('Enter the backend URL before continuing.');
    }

    const saltMaterial =
      mode === 'login'
        ? await fetchPasswordSalt({
            baseUrl: backendUrl,
            email: normalizedEmail,
          })
        : {
            kekMetadatas: [] as KekMetadata[],
            saltHex: await createPasswordSalt(),
          };
    const sortedKekMetadatas = sortKekMetadatas(saltMaterial.kekMetadatas);
    const missingOlderKeks =
      mode === 'login'
        ? sortedKekMetadatas.slice(1).filter(
            (metadata) =>
              !findLinkedKek(persistedLinkedKeks, metadata.kekId) &&
              !olderPasswords[metadata.kekId]?.trim(),
          )
        : [];

    setPendingOlderKeks(sortedKekMetadatas.slice(1));

    if (missingOlderKeks.length > 0) {
      throw new Error('Enter the passwords for the older active KEKs before logging in.');
    }

    const saltHex = saltMaterial.saltHex;
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
    const responseKekMetadatas = sortKekMetadatas(response.kekMetadatas);
    const latestKekMetadata = responseKekMetadatas[0];

    if (!latestKekMetadata) {
      throw new Error('The backend did not return KEK metadata.');
    }

    const retainedLinkedKeks = persistedLinkedKeks.filter((linkedKek) =>
      responseKekMetadatas.some((metadata) => metadata.kekId === linkedKek.kekId),
    );
    const nextDerivedLinkedKeks: PersistedLinkedKek[] = [
      {
        cryptKey: credentials.cryptKey,
        kekEpochVersion: latestKekMetadata.kekEpochVersion,
        kekId: latestKekMetadata.kekId,
        saltHex,
      },
    ];

    for (const metadata of responseKekMetadatas.slice(1)) {
      if (findLinkedKek(retainedLinkedKeks, metadata.kekId)) {
        continue;
      }

      const olderPassword = olderPasswords[metadata.kekId]?.trim();

      if (!olderPassword) {
        continue;
      }

      const olderCredentials = await deriveCredentials(normalizedEmail, olderPassword, saltHex);

      nextDerivedLinkedKeks.push({
        cryptKey: olderCredentials.cryptKey,
        kekEpochVersion: metadata.kekEpochVersion,
        kekId: metadata.kekId,
        saltHex,
      });
    }

    const nextLinkedKeks = mergeLinkedKeks([
      ...retainedLinkedKeks,
      ...nextDerivedLinkedKeks,
    ]);

    setSession(response);
    setActiveKekId(latestKekMetadata.kekId);
    setPendingOlderKeks(responseKekMetadatas.slice(1));

    await persistPreferences({
      backendUrl,
      email: credentials.email,
      lastEmail: credentials.email,
      linkedKeks: nextLinkedKeks,
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
    setActiveKekId(null);
    setPendingOlderKeks([]);
  }

  const authContextValue = useMemo(
    () => ({
      activeKekId,
      backendUrl: preferences.backendUrl,
      isAuthenticated: session !== null && activeKekId !== null,
      isHydrated,
      lastEmail: preferences.lastEmail,
      linkedKeks: preferences.linkedKeks ?? [],
      login: (email: string, password: string, olderPasswords?: Record<string, string>) =>
        authenticate('login', email, password, olderPasswords),
      pendingOlderKeks,
      register: (email: string, password: string) =>
        authenticate('register', email, password),
      session,
      signOut,
      updateBackendUrl,
    }),
    [activeKekId, isHydrated, pendingOlderKeks, preferences, session],
  );

  return (
    <AuthContext.Provider value={authContextValue}>
      {children}
    </AuthContext.Provider>
  );
}

function sortKekMetadatas(kekMetadatas: KekMetadata[]) {
  return [...kekMetadatas].sort(
    (left, right) => right.kekEpochVersion - left.kekEpochVersion,
  );
}

function findLinkedKek(linkedKeks: PersistedLinkedKek[], kekId: string) {
  return linkedKeks.find((linkedKek) => linkedKek.kekId === kekId) ?? null;
}

function mergeLinkedKeks(linkedKeks: PersistedLinkedKek[]) {
  const entriesByKekId = new Map<string, PersistedLinkedKek>();

  for (const linkedKek of linkedKeks) {
    entriesByKekId.set(linkedKek.kekId, linkedKek);
  }

  return [...entriesByKekId.values()].sort(
    (left, right) => right.kekEpochVersion - left.kekEpochVersion,
  );
}

export function useAuth() {
  const authContext = useContext(AuthContext);

  if (!authContext) {
    throw new Error('useAuth must be used inside AuthProvider');
  }

  return authContext;
}
