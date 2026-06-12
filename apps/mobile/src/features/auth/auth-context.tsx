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
  deriveKekKeyPair,
  deriveCredentials,
  normalizeEmail,
} from '@repo/e2ee-auth/native';

import {
  fetchPasswordSalt,
  fetchKekMigrationStatus,
  loginRequest,
  rotatePasswordRequest,
  registerRequest,
  type AuthApiResponse,
  type KekMigrationStatusResponse,
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
  kekMigrationStatus: KekMigrationStatusResponse | null;
  lastEmail: string;
  linkedKeks: PersistedLinkedKek[];
  login: (email: string, password: string, olderPasswords?: Record<string, string>) => Promise<void>;
  pendingOlderKeks: KekMetadata[];
  persistLinkedKeks: (linkedKeks: PersistedLinkedKek[]) => Promise<void>;
  refreshKekMigrationStatus: () => Promise<KekMigrationStatusResponse | null>;
  register: (email: string, password: string) => Promise<void>;
  rotatePassword: (newPassword: string) => Promise<{
    activeKekId: string;
    linkedKeks: PersistedLinkedKek[];
    session: Session;
  }>;
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
  const [kekMigrationStatus, setKekMigrationStatus] = useState<KekMigrationStatusResponse | null>(null);
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
              !findLinkedKek(persistedLinkedKeks, metadata.kekPublicKey) &&
              !olderPasswords[metadata.kekPublicKey]?.trim(),
          )
        : [];

    setPendingOlderKeks(sortedKekMetadatas.slice(1));

    if (missingOlderKeks.length > 0) {
      throw new Error('Enter the passwords for the older active KEKs before logging in.');
    }

    const saltHex = saltMaterial.saltHex;
    const credentials = await deriveCredentials(normalizedEmail, password, saltHex);
    const registerKekKeyPair =
      mode === 'register' ? await deriveKekKeyPair(credentials.cryptKey) : null;
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
            kekPublicKey: registerKekKeyPair!.kekPublicKey,
            saltHex,
          });
    const responseKekMetadatas = sortKekMetadatas(response.kekMetadatas);
    const latestKekMetadata = responseKekMetadatas[0];

    if (!latestKekMetadata) {
      throw new Error('The backend did not return KEK metadata.');
    }

    const retainedLinkedKeks = persistedLinkedKeks.filter((linkedKek) =>
      responseKekMetadatas.some((metadata) => metadata.kekPublicKey === linkedKek.kekPublicKey),
    );
    const nextDerivedLinkedKeks: PersistedLinkedKek[] = [
      {
        cryptKey: credentials.cryptKey,
        kekEpochVersion: latestKekMetadata.kekEpochVersion,
        kekPublicKey: latestKekMetadata.kekPublicKey,
        saltHex,
      },
    ];

    for (const metadata of responseKekMetadatas.slice(1)) {
      if (findLinkedKek(retainedLinkedKeks, metadata.kekPublicKey)) {
        continue;
      }

      const olderPassword = olderPasswords[metadata.kekPublicKey]?.trim();

      if (!olderPassword) {
        continue;
      }

      const olderCredentials = await deriveCredentials(normalizedEmail, olderPassword, saltHex);

      nextDerivedLinkedKeks.push({
        cryptKey: olderCredentials.cryptKey,
        kekEpochVersion: metadata.kekEpochVersion,
        kekPublicKey: metadata.kekPublicKey,
        saltHex,
      });
    }

    const nextLinkedKeks = mergeLinkedKeks([
      ...retainedLinkedKeks,
      ...nextDerivedLinkedKeks,
    ]);

    setSession(response);
    setActiveKekId(latestKekMetadata.kekPublicKey);
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

  async function persistLinkedKeks(linkedKeks: PersistedLinkedKek[]) {
    await persistPreferences({
      ...preferences,
      linkedKeks,
    });
  }

  async function refreshKekMigrationStatus() {
    if (!session) {
      setKekMigrationStatus(null);
      return null;
    }

    const nextStatus = await fetchKekMigrationStatus({
      baseUrl: preferences.backendUrl,
      token: session.token,
    });

    setKekMigrationStatus(nextStatus);

    return nextStatus;
  }

  async function rotatePassword(newPassword: string) {
    if (!session) {
      throw new Error('Log in before rotating the password.');
    }

    const saltHex = preferences.linkedKeks?.[0]?.saltHex;

    if (!saltHex) {
      throw new Error('The current password salt is missing from local storage. Log in again.');
    }

    const credentials = await deriveCredentials(session.user.email, newPassword, saltHex);
    const kekKeyPair = await deriveKekKeyPair(credentials.cryptKey);
    const response = await rotatePasswordRequest({
      baseUrl: preferences.backendUrl,
      kekPublicKey: kekKeyPair.kekPublicKey,
      newAuthKey: credentials.authKey,
      token: session.token,
    });
    const latestKekMetadata = sortKekMetadatas(response.kekMetadatas)[0];

    if (!latestKekMetadata) {
      throw new Error('The backend did not return KEK metadata.');
    }

    const nextLinkedKeks = mergeLinkedKeks([
      ...(preferences.linkedKeks ?? []),
      {
        cryptKey: credentials.cryptKey,
        kekEpochVersion: latestKekMetadata.kekEpochVersion,
        kekPublicKey: latestKekMetadata.kekPublicKey,
        saltHex,
      },
    ]);

    setSession(response);
    setActiveKekId(latestKekMetadata.kekPublicKey);
    setPendingOlderKeks(response.kekMetadatas.slice(1));
    await persistPreferences({
      ...preferences,
      email: session.user.email,
      linkedKeks: nextLinkedKeks,
      lastEmail: session.user.email,
    });

    return {
      activeKekId: latestKekMetadata.kekPublicKey,
      linkedKeks: nextLinkedKeks,
      session: response,
    };
  }

  function signOut() {
    setSession(null);
    setActiveKekId(null);
    setKekMigrationStatus(null);
    setPendingOlderKeks([]);
  }

  const authContextValue = useMemo(
    () => ({
      activeKekId,
      backendUrl: preferences.backendUrl,
      isAuthenticated: session !== null && activeKekId !== null,
      isHydrated,
      kekMigrationStatus,
      lastEmail: preferences.lastEmail,
      linkedKeks: preferences.linkedKeks ?? [],
      login: (email: string, password: string, olderPasswords?: Record<string, string>) =>
        authenticate('login', email, password, olderPasswords),
      pendingOlderKeks,
      persistLinkedKeks,
      refreshKekMigrationStatus,
      register: (email: string, password: string) =>
        authenticate('register', email, password),
      rotatePassword,
      session,
      signOut,
      updateBackendUrl,
    }),
    [activeKekId, isHydrated, kekMigrationStatus, pendingOlderKeks, preferences, session],
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

function findLinkedKek(linkedKeks: PersistedLinkedKek[], kekPublicKey: string) {
  return linkedKeks.find((linkedKek) => linkedKek.kekPublicKey === kekPublicKey) ?? null;
}

function mergeLinkedKeks(linkedKeks: PersistedLinkedKek[]) {
  const entriesByKekPublicKey = new Map<string, PersistedLinkedKek>();

  for (const linkedKek of linkedKeks) {
    entriesByKekPublicKey.set(linkedKek.kekPublicKey, linkedKek);
  }

  return [...entriesByKekPublicKey.values()].sort(
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
