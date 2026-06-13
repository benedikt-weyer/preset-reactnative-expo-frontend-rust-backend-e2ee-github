import {
  createContext,
  ReactNode,
  useCallback,
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
  refreshSessionRequest,
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
  runWithFreshSession: <T>(callback: (session: Session) => Promise<T>) => Promise<T>;
  rotatePassword: (newPassword: string) => Promise<{
    activeKekId: string;
    linkedKeks: PersistedLinkedKek[];
    session: Session;
  }>;
  session: Session | null;
  signOut: () => Promise<void>;
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

  const applySessionState = useCallback((nextSession: Session | null) => {
    const sortedKekMetadatas = nextSession ? sortKekMetadatas(nextSession.kekMetadatas) : [];

    setSession(nextSession);
    setActiveKekId(sortedKekMetadatas[0]?.kekPublicKey ?? null);
    setPendingOlderKeks(sortedKekMetadatas.slice(1));
  }, []);

  useEffect(() => {
    let isMounted = true;

    async function hydrateAuthPreferences() {
      const storedPreferences = await secureStoreAuthPreferences.read();

      if (!isMounted) {
        return;
      }

      applySessionState(storedPreferences.session ?? null);
      setPreferences(storedPreferences);
      setIsHydrated(true);
    }

    void hydrateAuthPreferences();

    return () => {
      isMounted = false;
    };
  }, [applySessionState]);

  const persistPreferences = useCallback(async (nextPreferences: AuthPreferences) => {
    setPreferences(nextPreferences);
    await secureStoreAuthPreferences.write(nextPreferences);
  }, []);

  const persistAuthenticatedState = useCallback(async (
    nextSession: Session,
    nextPreferences: AuthPreferences,
  ) => {
    applySessionState(nextSession);
    await persistPreferences({
      ...nextPreferences,
      session: nextSession,
    });
  }, [applySessionState, persistPreferences]);

  const persistSignedOutState = useCallback(async (nextPreferences: AuthPreferences) => {
    applySessionState(null);
    setKekMigrationStatus(null);
    await persistPreferences({
      ...nextPreferences,
      session: undefined,
    });
  }, [applySessionState, persistPreferences]);

  const authenticate = useCallback(async (
    mode: 'login' | 'register',
    email: string,
    password: string,
    olderPasswords: Record<string, string> = {},
  ) => {
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

    await persistAuthenticatedState(response, {
      backendUrl,
      email: credentials.email,
      lastEmail: credentials.email,
      linkedKeks: nextLinkedKeks,
    });
  }, [persistAuthenticatedState, preferences]);

  const updateBackendUrl = useCallback(async (backendUrl: string) => {
    await persistPreferences({
      ...preferences,
      backendUrl: backendUrl.trim(),
    });
  }, [persistPreferences, preferences]);

  const persistLinkedKeks = useCallback(async (linkedKeks: PersistedLinkedKek[]) => {
    await persistPreferences({
      ...preferences,
      linkedKeks,
    });
  }, [persistPreferences, preferences]);

  const refreshSession = useCallback(async (currentSession: Session) => {
    const nextSession = await refreshSessionRequest({
      baseUrl: preferences.backendUrl,
      refreshToken: currentSession.refreshToken,
    });

    await persistAuthenticatedState(nextSession, {
      ...preferences,
      email: nextSession.user.email,
      lastEmail: nextSession.user.email,
      linkedKeks: preferences.linkedKeks ?? [],
    });

    return nextSession;
  }, [persistAuthenticatedState, preferences]);

  const runWithFreshSession = useCallback(async <T,>(
    callback: (currentSession: Session) => Promise<T>,
  ) => {
    if (!session) {
      throw new Error('Log in before continuing.');
    }

    try {
      return await callback(session);
    } catch (error) {
      if (!hasUnauthorizedStatus(error)) {
        throw error;
      }

      try {
        const refreshedSession = await refreshSession(session);
        return await callback(refreshedSession);
      } catch (refreshError) {
        if (hasUnauthorizedStatus(refreshError)) {
          await persistSignedOutState({
            ...preferences,
          });
        }

        throw refreshError;
      }
    }
  }, [persistSignedOutState, preferences, refreshSession, session]);

  const refreshKekMigrationStatus = useCallback(async () => {
    if (!session) {
      setKekMigrationStatus(null);
      return null;
    }

    const nextStatus = await runWithFreshSession((currentSession) =>
      fetchKekMigrationStatus({
        baseUrl: preferences.backendUrl,
        token: currentSession.token,
      }));

    setKekMigrationStatus(nextStatus);

    return nextStatus;
  }, [preferences.backendUrl, runWithFreshSession, session]);

  const rotatePassword = useCallback(async (newPassword: string) => {
    if (!session) {
      throw new Error('Log in before rotating the password.');
    }

    const saltHex = preferences.linkedKeks?.[0]?.saltHex;

    if (!saltHex) {
      throw new Error('The current password salt is missing from local storage. Log in again.');
    }

    const credentials = await deriveCredentials(session.user.email, newPassword, saltHex);
    const kekKeyPair = await deriveKekKeyPair(credentials.cryptKey);
    const response = await runWithFreshSession((currentSession) =>
      rotatePasswordRequest({
        baseUrl: preferences.backendUrl,
        kekPublicKey: kekKeyPair.kekPublicKey,
        newAuthKey: credentials.authKey,
        token: currentSession.token,
      }));
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

    await persistAuthenticatedState(response, {
      ...preferences,
      email: session.user.email,
      linkedKeks: nextLinkedKeks,
      lastEmail: session.user.email,
    });
    setKekMigrationStatus(null);

    return {
      activeKekId: latestKekMetadata.kekPublicKey,
      linkedKeks: nextLinkedKeks,
      session: response,
    };
  }, [persistAuthenticatedState, preferences, runWithFreshSession, session]);

  const signOut = useCallback(async () => {
    await persistSignedOutState({
      ...preferences,
    });
  }, [persistSignedOutState, preferences]);

  const login = useCallback(
    (email: string, password: string, olderPasswords?: Record<string, string>) =>
      authenticate('login', email, password, olderPasswords),
    [authenticate],
  );

  const register = useCallback(
    (email: string, password: string) => authenticate('register', email, password),
    [authenticate],
  );

  const authContextValue = useMemo(
    () => ({
      activeKekId,
      backendUrl: preferences.backendUrl,
      isAuthenticated: session !== null && activeKekId !== null,
      isHydrated,
      kekMigrationStatus,
      lastEmail: preferences.lastEmail,
      linkedKeks: preferences.linkedKeks ?? [],
      login,
      pendingOlderKeks,
      persistLinkedKeks,
      refreshKekMigrationStatus,
      register,
      runWithFreshSession,
      rotatePassword,
      session,
      signOut,
      updateBackendUrl,
    }),
    [
      activeKekId,
      isHydrated,
      kekMigrationStatus,
      login,
      pendingOlderKeks,
      persistLinkedKeks,
      preferences.backendUrl,
      preferences.lastEmail,
      preferences.linkedKeks,
      refreshKekMigrationStatus,
      register,
      runWithFreshSession,
      rotatePassword,
      session,
      signOut,
      updateBackendUrl,
    ],
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

function hasUnauthorizedStatus(error: unknown) {
  return !!error &&
    typeof error === 'object' &&
    'status' in error &&
    error.status === 401;
}

export function useAuth() {
  const authContext = useContext(AuthContext);

  if (!authContext) {
    throw new Error('useAuth must be used inside AuthProvider');
  }

  return authContext;
}
