'use client';

import { useCallback, useEffect, useRef, useState, type ChangeEvent } from 'react';
import { ArrowRight, LockKeyhole, ShieldCheck, Trash2, UserRound } from 'lucide-react';
import { subscribeToNoteEvents } from '@repo/realtime';
import {
  exportImportExportSuite,
  importImportExportSuite,
  inspectImportExportSuite,
  type ImportExportSuiteInspection,
  type ImportExportSuiteNote,
} from '@repo/import-export-suite/web';

import {
  createApiToken,
  createPasswordSalt,
  decryptStringWithAsymmetricKek,
  deriveApiTokenCredentials,
  deriveKekKeyPair,
  deriveCredentials,
  encryptStringWithAsymmetricKeks,
  normalizeEmail,
  rewrapAsymmetricEncryptedDek,
  type KekAsymmetricDekEncryptedPayload,
} from '@repo/e2ee-auth/web';

import { Button } from '@/components/ui/button';
import {
  createApiUserRequest,
  deleteAccountRequest,
  deleteApiUserRequest,
  fetchApiUser,
  fetchApiUsers,
  fetchKekMigrationStatus,
  fetchLinkedPrincipals,
  fetchPasswordSalt,
  loginRequest,
  refreshSessionRequest,
  rotatePasswordRequest,
  registerRequest,
  provisionApiUserDeksRequest,
  type ApiUserResponse,
  type AuthApiResponse,
  type KekMigrationStatusResponse,
  type KekMetadata,
} from '@/lib/auth-api';
import {
  createNote,
  deleteNote,
  fetchNotes,
  type NoteResponse,
  updateNote,
} from '@/lib/test-note-api';
import {
  localStorageAuthPersistence,
  type PersistedLinkedKek,
  readAuthPreferences,
  writeAuthPreferences,
} from '@/lib/auth-storage';

type AuthMode = 'login' | 'register';

type NoteDocument = {
  content: string;
  title: string;
};

type DecryptedNote = {
  createdAt: string;
  id: string;
  payload: KekAsymmetricDekEncryptedPayload;
  title: string;
  content: string;
  updatedAt: string;
};

type MigrationProgress = {
  completed: number;
  total: number;
};

type ApiUserView = ApiUserResponse & {
  label: string;
};

type ApiUserProvisionProgress = MigrationProgress & {
  apiUserId: string;
  username: string;
};

const featureNotes = [
  'The typed password stays in the browser and derives two keys locally.',
  'The backend sees only the derived auth key plus the per-account salt.',
  'Each note stores one encrypted document plus one wrapped DEK per linked principal addressed by that principal\'s KEK public key.',
];

export function AuthExperience() {
  const [mode, setMode] = useState<AuthMode>('register');
  const [backendUrl, setBackendUrl] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [nextPassword, setNextPassword] = useState('');
  const [noteTitle, setNoteTitle] = useState('');
  const [noteContent, setNoteContent] = useState('');
  const [notes, setNotes] = useState<DecryptedNote[]>([]);
  const [exportPassword, setExportPassword] = useState('');
  const [importPassword, setImportPassword] = useState('');
  const [importFileName, setImportFileName] = useState('');
  const [importInspection, setImportInspection] = useState<ImportExportSuiteInspection | null>(null);
  const [importPayload, setImportPayload] = useState<string | null>(null);
  const [apiUserLabel, setApiUserLabel] = useState('');
  const [apiUsers, setApiUsers] = useState<ApiUserView[]>([]);
  const [latestApiToken, setLatestApiToken] = useState<string | null>(null);
  const [selectedNoteId, setSelectedNoteId] = useState<string | null>(null);
  const [session, setSession] = useState<AuthApiResponse | null>(null);
  const [linkedKeks, setLinkedKeks] = useState<PersistedLinkedKek[]>([]);
  const [olderPasswords, setOlderPasswords] = useState<Record<string, string>>({});
  const [migrationPasswords, setMigrationPasswords] = useState<Record<string, string>>({});
  const [requiredOlderKeks, setRequiredOlderKeks] = useState<KekMetadata[]>([]);
  const [kekMigrationStatus, setKekMigrationStatus] =
    useState<KekMigrationStatusResponse | null>(null);
  const [migrationProgress, setMigrationProgress] = useState<MigrationProgress | null>(null);
  const [apiUserProgress, setApiUserProgress] = useState<ApiUserProvisionProgress | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState('');
  const [isHydrated, setIsHydrated] = useState(false);
  const [isCreatingApiUser, setIsCreatingApiUser] = useState(false);
  const [deletingApiUserId, setDeletingApiUserId] = useState<string | null>(null);
  const [isDeletingAccount, setIsDeletingAccount] = useState(false);
  const [isMigrating, setIsMigrating] = useState(false);
  const [isExportingNotes, setIsExportingNotes] = useState(false);
  const [isImportingNotes, setIsImportingNotes] = useState(false);
  const [isRotatingPassword, setIsRotatingPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const selectedNoteIdRef = useRef<string | null>(null);
  const importFileInputRef = useRef<HTMLInputElement | null>(null);

  const applySelectedNote = useCallback((note: DecryptedNote | null) => {
    const nextSelectedNoteId = note?.id ?? null;

    selectedNoteIdRef.current = nextSelectedNoteId;
    setSelectedNoteId(nextSelectedNoteId);
    setNoteTitle(note?.title ?? '');
    setNoteContent(note?.content ?? '');
  }, []);

  const persistAuthSession = useCallback((nextSession: AuthApiResponse) => {
    setSession(nextSession);
    localStorageAuthPersistence.writeAuthSession(nextSession);
  }, []);

  const clearSessionState = useCallback((options?: {
    clearDerivedCredentials?: boolean;
    statusMessage?: string;
  }) => {
    setSession(null);
    setApiUserLabel('');
    setApiUsers([]);
    setLatestApiToken(null);
    setPassword('');
    setNextPassword('');
    setOlderPasswords({});
    setMigrationPasswords({});
    setRequiredOlderKeks([]);
    setKekMigrationStatus(null);
    setMigrationProgress(null);
    setApiUserProgress(null);
    setNotes([]);
    applySelectedNote(null);
    localStorageAuthPersistence.clearAuthSession();

    if (options?.clearDerivedCredentials) {
      setLinkedKeks([]);
      localStorageAuthPersistence.clearDerivedCredentials();
    }

    if (options?.statusMessage) {
      setStatusMessage(options.statusMessage);
    }
  }, [applySelectedNote]);

  const refreshSession = useCallback(async (
    currentSession: AuthApiResponse,
    trimmedBackendUrl: string,
  ) => {
    const nextSession = await refreshSessionRequest({
      baseUrl: trimmedBackendUrl,
      refreshToken: currentSession.refreshToken,
    });

    persistAuthSession(nextSession);
    return nextSession;
  }, [persistAuthSession]);

  const runWithSessionRetry = useCallback(async <T,>(
    currentSession: AuthApiResponse,
    trimmedBackendUrl: string,
    callback: (activeSession: AuthApiResponse) => Promise<T>,
  ) => {
    try {
      return await callback(currentSession);
    } catch (error) {
      if (!hasUnauthorizedStatus(error)) {
        throw error;
      }

      try {
        const refreshedSession = await refreshSession(currentSession, trimmedBackendUrl);
        return await callback(refreshedSession);
      } catch (refreshError) {
        if (hasUnauthorizedStatus(refreshError)) {
          clearSessionState({
            statusMessage: 'Session expired. Log in again.',
          });
          throw new Error('Session expired. Log in again.');
        }

        throw refreshError;
      }
    }
  }, [clearSessionState, refreshSession]);

  const loadNotes = useCallback(
    async ({
      emptyMessage,
      linkedKeks,
      nextSession,
      trimmedBackendUrl,
    }: {
      emptyMessage: string;
      linkedKeks: PersistedLinkedKek[];
      nextSession: AuthApiResponse;
      trimmedBackendUrl: string;
    }) => {
      try {
        const remoteNotes = await runWithSessionRetry(nextSession, trimmedBackendUrl, (activeSession) =>
          fetchNotes({
            baseUrl: trimmedBackendUrl,
            token: activeSession.token,
          }));
        const decryptedNotes = sortNotes(
          await Promise.all(remoteNotes.map((note) => decryptNoteRecord(note, linkedKeks))),
        );

        setNotes(decryptedNotes);

        const nextSelectedNote =
          decryptedNotes.find((note) => note.id === selectedNoteIdRef.current) ??
          decryptedNotes[0] ??
          null;

        applySelectedNote(nextSelectedNote);
        const noteCountLabel =
          decryptedNotes.length === 1
            ? 'Loaded 1 encrypted note from the backend.'
            : `Loaded ${decryptedNotes.length} encrypted notes from the backend.`;

        setStatusMessage(nextSelectedNote ? noteCountLabel : emptyMessage);
      } catch (error) {
        setNotes([]);
        applySelectedNote(null);
        setStatusMessage(
          error instanceof Error ? error.message : 'Unable to load encrypted notes.',
        );
      }
    },
    [applySelectedNote, runWithSessionRetry],
  );

  const loadApiUsers = useCallback(
    async ({
      linkedKeks,
      nextSession,
      trimmedBackendUrl,
    }: {
      linkedKeks: PersistedLinkedKek[];
      nextSession: AuthApiResponse;
      trimmedBackendUrl: string;
    }) => {
      try {
        const remoteApiUsers = await runWithSessionRetry(nextSession, trimmedBackendUrl, (activeSession) =>
          fetchApiUsers({
            baseUrl: trimmedBackendUrl,
            token: activeSession.token,
          }));
        const decryptedApiUsers = await Promise.all(
          remoteApiUsers.map((apiUser) => decryptApiUserRecord(apiUser, linkedKeks)),
        );

        setApiUsers(decryptedApiUsers);
      } catch {
        setApiUsers([]);
      }
    },
    [runWithSessionRetry],
  );

  const refreshKekMigrationStatus = useCallback(
    async (nextSession: AuthApiResponse, trimmedBackendUrl: string) => {
      const nextStatus = await runWithSessionRetry(nextSession, trimmedBackendUrl, (activeSession) =>
        fetchKekMigrationStatus({
          baseUrl: trimmedBackendUrl,
          token: activeSession.token,
        }));

      setKekMigrationStatus(nextStatus);

      return nextStatus;
    },
    [runWithSessionRetry],
  );

  useEffect(() => {
    queueMicrotask(() => {
      const preferences = readAuthPreferences();
      const storedSession = localStorageAuthPersistence.readAuthSession();
      const storedCredentials = localStorageAuthPersistence.readDerivedCredentials();
      const nextLinkedKeks = storedCredentials?.linkedKeks ?? [];

      setBackendUrl(preferences.backendUrl);
      setLinkedKeks(nextLinkedKeks);
      setSession(storedSession);
      setEmail(storedCredentials?.email ?? preferences.lastEmail);

      setIsHydrated(true);
    });
  }, []);

  useEffect(() => {
    if (!isHydrated || !session || linkedKeks.length === 0) {
      return;
    }

    let isCancelled = false;
    const trimmedBackendUrl = backendUrl.trim();

    queueMicrotask(() => {
      if (isCancelled) {
        return;
      }

      void loadNotes({
        emptyMessage: 'No synced notes yet. Create one to push ciphertext to the backend.',
        linkedKeks,
        nextSession: session,
        trimmedBackendUrl,
      });

      if (session.currentPrincipal.kind === 'user') {
        void loadApiUsers({
          linkedKeks,
          nextSession: session,
          trimmedBackendUrl,
        });
      }

      void refreshKekMigrationStatus(session, trimmedBackendUrl);
    });

    return () => {
      isCancelled = true;
    };
  }, [backendUrl, isHydrated, linkedKeks, loadApiUsers, loadNotes, refreshKekMigrationStatus, session]);

  useEffect(() => {
    if (!isHydrated || !session || linkedKeks.length === 0) {
      return;
    }

    const trimmedBackendUrl = backendUrl.trim();

    try {
      const subscription = subscribeToNoteEvents({
        accessToken: session.token,
        baseUrl: trimmedBackendUrl,
        onError: (error) => {
          void refreshSession(session, trimmedBackendUrl).catch(() => {
            setStatusMessage(error.message);
          });
        },
        onEvent: () => {
          void loadNotes({
            emptyMessage: 'No synced notes yet. Create one to push ciphertext to the backend.',
            linkedKeks,
            nextSession: session,
            trimmedBackendUrl,
          });

          if (session.currentPrincipal.kind === 'user') {
            void loadApiUsers({
              linkedKeks,
              nextSession: session,
              trimmedBackendUrl,
            });
          }

          void refreshKekMigrationStatus(session, trimmedBackendUrl);
        },
      });

      return () => {
        subscription.close();
      };
    } catch (error) {
      setStatusMessage(
        error instanceof Error ? error.message : 'Unable to connect note realtime updates.',
      );
    }
  }, [backendUrl, isHydrated, linkedKeks, loadApiUsers, loadNotes, refreshKekMigrationStatus, refreshSession, session]);

  const missingMigrationKeks = session
    ? session.kekMetadatas.filter((metadata) => !findLinkedKek(linkedKeks, metadata.kekPublicKey))
    : [];
  const needsMigration =
    !!session &&
    !!kekMigrationStatus &&
    session.kekMetadatas.length > 1 &&
    !kekMigrationStatus.allDeksUseLatestKek;

  async function handleSubmit() {
    setErrorMessage(null);
    setIsSubmitting(true);

    try {
      const trimmedBackendUrl = backendUrl.trim();
      const normalizedEmail = normalizeEmail(email);
      const storedCredentials = localStorageAuthPersistence.readDerivedCredentials();
      const persistedLinkedKeks =
        storedCredentials?.email === normalizedEmail ? storedCredentials.linkedKeks : [];
      const saltMaterial =
        mode === 'login'
          ? await fetchPasswordSalt({
              baseUrl: trimmedBackendUrl,
              email: normalizedEmail,
            })
          : {
              kekMetadatas: [] as KekMetadata[],
              saltHex: await createPasswordSalt(),
            };
      const saltHex = saltMaterial.saltHex;
      const sortedKekMetadatas = sortKekMetadatas(saltMaterial.kekMetadatas);
      const missingOlderKeks =
        mode === 'login'
          ? sortedKekMetadatas.slice(1).filter(
              (metadata) =>
                !findLinkedKek(persistedLinkedKeks, metadata.kekPublicKey) &&
                !olderPasswords[metadata.kekPublicKey]?.trim(),
            )
          : [];

      setRequiredOlderKeks(sortedKekMetadatas.slice(1));

      if (missingOlderKeks.length > 0) {
        throw new Error('Enter the passwords for the older active KEKs before logging in.');
      }

      const credentials = await deriveCredentials(normalizedEmail, password, saltHex);
      const registerKekKeyPair =
        mode === 'register' ? await deriveKekKeyPair(credentials.cryptKey) : null;
      const response =
        mode === 'login'
          ? await loginRequest({
              authKey: credentials.authKey,
              baseUrl: trimmedBackendUrl,
              email: credentials.email,
            })
          : await registerRequest({
              authKey: credentials.authKey,
              baseUrl: trimmedBackendUrl,
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

      persistAuthSession(response);
      setLinkedKeks(nextLinkedKeks);
      setEmail(credentials.email);
      setPassword('');
      setOlderPasswords({});

      if (response.currentPrincipal.kind !== 'user') {
        setApiUsers([]);
      }

      writeAuthPreferences({
        backendUrl: trimmedBackendUrl,
        lastEmail: credentials.email,
      });
      localStorageAuthPersistence.writeDerivedCredentials({
        email: credentials.email,
        linkedKeks: nextLinkedKeks,
      });
      await refreshKekMigrationStatus(response, trimmedBackendUrl);
      await loadNotes({
        emptyMessage:
          mode === 'register'
            ? 'Account created. Create a note to push ciphertext to the backend.'
            : 'Logged in. Create a note to push ciphertext to the backend.',
        linkedKeks: nextLinkedKeks,
        nextSession: response,
        trimmedBackendUrl,
      });
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Authentication failed unexpectedly.',
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  function handleSignOut() {
    clearSessionState({
      statusMessage:
      'Signed out. Synced notes remain on the backend, and the linked KEKs stay stored for the next login.',
    });
  }

  function clearDeletedAccountState() {
    clearSessionState({ clearDerivedCredentials: true });
  }

  async function handleRotatePassword() {
    if (!session) {
      return;
    }

    setErrorMessage(null);
    setIsRotatingPassword(true);

    try {
      const trimmedBackendUrl = backendUrl.trim();
      const saltHex = linkedKeks[0]?.saltHex;

      if (!saltHex) {
        throw new Error('The current password salt is missing from local storage. Log in again.');
      }

      const credentials = await deriveCredentials(session.user.email, nextPassword, saltHex);
      const kekKeyPair = await deriveKekKeyPair(credentials.cryptKey);
      const response = await runWithSessionRetry(session, trimmedBackendUrl, (activeSession) =>
        rotatePasswordRequest({
          baseUrl: trimmedBackendUrl,
          kekPublicKey: kekKeyPair.kekPublicKey,
          newAuthKey: credentials.authKey,
          token: activeSession.token,
        }));
      const latestKekMetadata = sortKekMetadatas(response.kekMetadatas)[0];

      if (!latestKekMetadata) {
        throw new Error('The backend did not return KEK metadata.');
      }

      const nextLinkedKeks = mergeLinkedKeks([
        ...linkedKeks,
        {
          cryptKey: credentials.cryptKey,
          kekEpochVersion: latestKekMetadata.kekEpochVersion,
          kekPublicKey: latestKekMetadata.kekPublicKey,
          saltHex,
        },
      ]);

      persistAuthSession(response);
      setLinkedKeks(nextLinkedKeks);
      setNextPassword('');
      localStorageAuthPersistence.writeDerivedCredentials({
        email: session.user.email,
        linkedKeks: nextLinkedKeks,
      });
      await continueKekMigration({
        linkedKeks: nextLinkedKeks,
        nextSession: response,
      });
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Unable to rotate the password.',
      );
    } finally {
      setIsRotatingPassword(false);
    }
  }

  async function handleContinueMigration() {
    if (!session) {
      return;
    }

    setErrorMessage(null);

    try {
      await continueKekMigration({
        linkedKeks,
        nextSession: session,
      });
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Unable to continue the KEK migration.',
      );
    }
  }

  async function continueKekMigration({
    linkedKeks: baseLinkedKeks,
    nextSession,
  }: {
    linkedKeks: PersistedLinkedKek[];
    nextSession: AuthApiResponse;
  }) {
    const latestKekMetadata = sortKekMetadatas(nextSession.kekMetadatas)[0];

    if (!latestKekMetadata) {
      throw new Error('The backend did not return KEK metadata.');
    }

    const workingLinkedKeks = await deriveMissingLinkedKeks({
      baseLinkedKeks,
      email: nextSession.user.email,
      missingMetadatas: nextSession.kekMetadatas.filter(
        (metadata) => !findLinkedKek(baseLinkedKeks, metadata.kekPublicKey),
      ),
      passwordsByKekId: migrationPasswords,
    });
    const latestLinkedKek = requireLinkedKek(workingLinkedKeks, latestKekMetadata.kekPublicKey);
    const trimmedBackendUrl = backendUrl.trim();
    const currentLinkedPrincipals = await runWithSessionRetry(nextSession, trimmedBackendUrl, (activeSession) =>
      fetchLinkedPrincipals({
        baseUrl: trimmedBackendUrl,
        token: activeSession.token,
      }));
    const remoteNotes = await runWithSessionRetry(nextSession, trimmedBackendUrl, (activeSession) =>
      fetchNotes({
        baseUrl: trimmedBackendUrl,
        token: activeSession.token,
      }));
    const notesToRewrap = remoteNotes.filter(
      (note) => note.encryptedDek.kekPublicKey !== latestLinkedKek.kekPublicKey,
    );

    setIsMigrating(true);
    setMigrationProgress({
      completed: 0,
      total: notesToRewrap.length,
    });

    try {
      for (let index = 0; index < notesToRewrap.length; index += 1) {
        const note = notesToRewrap[index];
        const noteLinkedKek = findLinkedKek(workingLinkedKeks, note.encryptedDek.kekPublicKey);

        if (!noteLinkedKek) {
          throw new Error(
            `Missing the local KEK for epoch-linked id ${note.encryptedDek.kekPublicKey}. Provide the matching older password first.`,
          );
        }

        await runWithSessionRetry(nextSession, trimmedBackendUrl, async (activeSession) =>
          updateNote({
            baseUrl: trimmedBackendUrl,
            noteId: note.id,
            payload: {
              encryptedDeks: await Promise.all(
                currentLinkedPrincipals.map(async (principal) => ({
                  ...(await rewrapAsymmetricEncryptedDek(
                    note,
                    noteLinkedKek.cryptKey,
                    principal.latestKekPublicKey,
                  )),
                  userId: principal.id,
                })),
              ),
              encryptedPayload: note.encryptedPayload,
            },
            token: activeSession.token,
          }));

        setMigrationProgress({
          completed: index + 1,
          total: notesToRewrap.length,
        });
      }

      setLinkedKeks(workingLinkedKeks);
      setMigrationPasswords({});
      localStorageAuthPersistence.writeDerivedCredentials({
        email: nextSession.user.email,
        linkedKeks: workingLinkedKeks,
      });

      const finalStatus = await refreshKekMigrationStatus(nextSession, trimmedBackendUrl);

      if (!finalStatus.allDeksUseLatestKek) {
        throw new Error('The backend still reports DEKs on older KEK epochs after migration.');
      }

      await loadNotes({
        emptyMessage: 'No synced notes yet. Create one to push ciphertext to the backend.',
        linkedKeks: workingLinkedKeks,
        nextSession,
        trimmedBackendUrl,
      });
      await loadApiUsers({
        linkedKeks: workingLinkedKeks,
        nextSession,
        trimmedBackendUrl,
      });
      setStatusMessage(
        notesToRewrap.length === 0
          ? 'All DEKs already use the latest KEK epoch.'
          : `Rewrapped ${notesToRewrap.length} DEK${notesToRewrap.length === 1 ? '' : 's'} onto KEK epoch ${latestKekMetadata.kekEpochVersion}.`,
      );
    } finally {
      setIsMigrating(false);
      setMigrationProgress(null);
    }
  }

  function handleCreateNote() {
    setErrorMessage(null);
    applySelectedNote(null);
    setStatusMessage('Creating a new encrypted note draft.');
  }

  function handleSelectNote(noteId: string) {
    const nextNote = notes.find((note) => note.id === noteId) ?? null;

    applySelectedNote(nextNote);
    setStatusMessage(nextNote ? `Selected "${nextNote.title || 'Untitled note'}".` : '');
  }

  async function handleSaveNote() {
    if (!session) {
      return;
    }

    setErrorMessage(null);

    try {
      const trimmedBackendUrl = backendUrl.trim();
      const currentLinkedPrincipals = await runWithSessionRetry(session, trimmedBackendUrl, (activeSession) =>
        fetchLinkedPrincipals({
          baseUrl: trimmedBackendUrl,
          token: activeSession.token,
        }));
      const encryptedPayload = await encryptStringWithAsymmetricKeks(
        serializeNoteDocument({
          content: noteContent,
          title: noteTitle,
        }),
        currentLinkedPrincipals.map((principal) => principal.latestKekPublicKey),
      );
      const payload = {
        encryptedDeks: encryptedPayload.encryptedDeks.map((encryptedDek, index) => {
          const principal = currentLinkedPrincipals[index];

          if (!principal) {
            throw new Error('The backend returned an incomplete linked principal list.');
          }

          return {
            ...encryptedDek,
            userId: principal.id,
          };
        }),
        encryptedPayload: encryptedPayload.encryptedPayload,
      };
      const savedNote = await runWithSessionRetry(session, trimmedBackendUrl, (activeSession) =>
        selectedNoteId
          ? updateNote({
              baseUrl: trimmedBackendUrl,
              noteId: selectedNoteId,
              payload,
              token: activeSession.token,
            })
          : createNote({
              baseUrl: trimmedBackendUrl,
              payload,
              token: activeSession.token,
            }));

      const decryptedNote = await decryptNoteRecord(savedNote, linkedKeks);
      const nextNotes = sortNotes([
        decryptedNote,
        ...notes.filter((note) => note.id !== decryptedNote.id),
      ]);

      setNotes(nextNotes);
      applySelectedNote(decryptedNote);
      setStatusMessage(
        selectedNoteId
          ? `Updated "${decryptedNote.title || 'Untitled note'}".`
          : `Created "${decryptedNote.title || 'Untitled note'}".`,
      );
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Unable to save the encrypted note.',
      );
    }
  }

  async function handleClearNote() {
    if (!session || !selectedNoteId) {
      applySelectedNote(null);
      setStatusMessage('Cleared the local note draft.');
      return;
    }

    setErrorMessage(null);

    try {
      await runWithSessionRetry(session, backendUrl.trim(), (activeSession) =>
        deleteNote({
          baseUrl: backendUrl.trim(),
          noteId: selectedNoteId,
          token: activeSession.token,
        }));
      const deletedNote = notes.find((note) => note.id === selectedNoteId) ?? null;
      const remainingNotes = notes.filter((note) => note.id !== selectedNoteId);

      setNotes(remainingNotes);
      applySelectedNote(remainingNotes[0] ?? null);
      setStatusMessage(`Deleted "${deletedNote?.title || 'Untitled note'}".`);
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Unable to delete the encrypted note.',
      );
    }
  }

  async function handleExportNotes() {
    if (notes.length === 0) {
      setStatusMessage('Create or sync at least one note before exporting JSON.');
      return;
    }

    setErrorMessage(null);
    setIsExportingNotes(true);

    try {
      const noteLabel = `note${notes.length === 1 ? '' : 's'}`;
      const protectionLabel = exportPassword ? 'password-protected JSON' : 'cleartext JSON';
      const serialized = await exportImportExportSuite(
        notes.map((note) => toBackupNote(note)),
        exportPassword
          ? {
              password: exportPassword,
            }
          : undefined,
      );
      const filename = buildImportExportSuiteFilename(new Date().toISOString());

      downloadTextFile(filename, serialized, 'application/json');
      setExportPassword('');
      setStatusMessage(`Exported ${notes.length} ${noteLabel} as ${protectionLabel}.`);
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Unable to export the notes as JSON.',
      );
    } finally {
      setIsExportingNotes(false);
    }
  }

  async function handleImportFileSelection(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];

    if (!file) {
      return;
    }

    setErrorMessage(null);

    try {
      const serialized = await file.text();
      const inspection = inspectImportExportSuite(serialized);

      setImportPayload(serialized);
      setImportFileName(file.name);
      setImportInspection(inspection);
      setStatusMessage(
        inspection.encrypted
          ? `Selected ${file.name}. This export is password protected.`
          : `Selected ${file.name}. This export contains cleartext JSON.`,
      );
    } catch (error) {
      setImportPayload(null);
      setImportFileName('');
      setImportInspection(null);
      setErrorMessage(
        error instanceof Error ? error.message : 'Unable to read the selected import file.',
      );
    } finally {
      event.target.value = '';
    }
  }

  async function handleImportNotes() {
    if (!session) {
      return;
    }

    if (!importPayload) {
      setErrorMessage('Choose a JSON import file before importing notes.');
      return;
    }

    setErrorMessage(null);
    setIsImportingNotes(true);

    try {
      const importedNotes = await importImportExportSuite(
        importPayload,
        importPassword
          ? {
              password: importPassword,
            }
          : undefined,
      );

      if (importedNotes.length === 0) {
        setStatusMessage('The selected import file does not contain any notes.');
        return;
      }

      const trimmedBackendUrl = backendUrl.trim();
      const currentLinkedPrincipals = await runWithSessionRetry(
        session,
        trimmedBackendUrl,
        (activeSession) =>
          fetchLinkedPrincipals({
            baseUrl: trimmedBackendUrl,
            token: activeSession.token,
          }),
      );
      let createdCount = 0;
      let updatedCount = 0;

      for (const importedNote of importedNotes) {
        const encryptedPayload = await encryptStringWithAsymmetricKeks(
          serializeNoteDocument({
            content: importedNote.content,
            title: importedNote.title,
          }),
          currentLinkedPrincipals.map((principal) => principal.latestKekPublicKey),
        );
        const payload = {
          encryptedDeks: encryptedPayload.encryptedDeks.map((encryptedDek, index) => {
            const principal = currentLinkedPrincipals[index];

            if (!principal) {
              throw new Error('The backend returned an incomplete linked principal list.');
            }

            return {
              ...encryptedDek,
              userId: principal.id,
            };
          }),
          encryptedPayload: encryptedPayload.encryptedPayload,
        };
        const existingNote = notes.find((note) => note.id === importedNote.id) ?? null;

        await runWithSessionRetry(session, trimmedBackendUrl, (activeSession) =>
          existingNote
            ? updateNote({
                baseUrl: trimmedBackendUrl,
                noteId: existingNote.id,
                payload,
                token: activeSession.token,
              })
            : createNote({
                baseUrl: trimmedBackendUrl,
                payload,
                token: activeSession.token,
              }),
        );

        if (existingNote) {
          updatedCount += 1;
        } else {
          createdCount += 1;
        }
      }

      await loadNotes({
        emptyMessage: 'No synced notes yet. Create one to push ciphertext to the backend.',
        linkedKeks,
        nextSession: session,
        trimmedBackendUrl,
      });
      setImportPayload(null);
      setImportFileName('');
      setImportInspection(null);
      setImportPassword('');
      setStatusMessage(buildImportSummary(createdCount, updatedCount));
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Unable to import the JSON export.',
      );
    } finally {
      setIsImportingNotes(false);
    }
  }

  async function handleCreateApiUser() {
    if (!session || session.currentPrincipal.kind !== 'user') {
      return;
    }

    setErrorMessage(null);
    setIsCreatingApiUser(true);

    try {
      const trimmedBackendUrl = backendUrl.trim();
      const currentLinkedPrincipals = await runWithSessionRetry(session, trimmedBackendUrl, (activeSession) =>
        fetchLinkedPrincipals({
          baseUrl: trimmedBackendUrl,
          token: activeSession.token,
        }));
      const ownerPrincipal = currentLinkedPrincipals.find((principal) => principal.id === session.user.id);

      if (!ownerPrincipal) {
        throw new Error('The backend did not return the owner KEK metadata.');
      }

      const apiUserId = crypto.randomUUID();
      const apiToken = await createApiToken();
      const apiTokenCredentials = await deriveApiTokenCredentials(apiToken);
      const encryptedLabel = await encryptStringWithAsymmetricKeks(apiUserLabel, [
        ownerPrincipal.latestKekPublicKey,
        apiTokenCredentials.kekKeyPair.kekPublicKey,
      ]);
      const createdApiUser = await runWithSessionRetry(session, trimmedBackendUrl, (activeSession) =>
        createApiUserRequest({
          authKey: apiTokenCredentials.authKey,
          baseUrl: trimmedBackendUrl,
          encryptedLabel: encryptedLabel.encryptedPayload,
          encryptedLabelDeks: encryptedLabel.encryptedDeks.map((encryptedDek, index) => ({
            ...encryptedDek,
            userId: index === 0 ? ownerPrincipal.id : apiUserId,
          })),
          id: apiUserId,
          kekPublicKey: apiTokenCredentials.kekKeyPair.kekPublicKey,
          token: activeSession.token,
        }));

      setLatestApiToken(apiToken);
      setApiUserLabel('');
      await continueApiUserProvisioning(createdApiUser, {
        linkedKeks,
        nextSession: session,
      });
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Unable to create the api user.',
      );
    } finally {
      setIsCreatingApiUser(false);
    }
  }

  async function handleResumeApiUser(apiUserId: string) {
    if (!session || session.currentPrincipal.kind !== 'user') {
      return;
    }

    setErrorMessage(null);

    try {
      const apiUser = await runWithSessionRetry(session, backendUrl.trim(), (activeSession) =>
        fetchApiUser({
          apiUserId,
          baseUrl: backendUrl.trim(),
          token: activeSession.token,
        }));

      await continueApiUserProvisioning(apiUser, {
        linkedKeks,
        nextSession: session,
      });
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Unable to resume api user provisioning.',
      );
    }
  }

  async function handleDeleteApiUser(apiUser: ApiUserView) {
    if (!session || session.currentPrincipal.kind !== 'user') {
      return;
    }

    const confirmed = globalThis.confirm(
      `Remove api user ${apiUser.username}? This also deletes its linked KEK and DEK entries.`,
    );

    if (!confirmed) {
      return;
    }

    setErrorMessage(null);
    setDeletingApiUserId(apiUser.id);

    try {
      await runWithSessionRetry(session, backendUrl.trim(), (activeSession) =>
        deleteApiUserRequest({
          apiUserId: apiUser.id,
          baseUrl: backendUrl.trim(),
          token: activeSession.token,
        }));

      setApiUsers((currentApiUsers) => currentApiUsers.filter((entry) => entry.id !== apiUser.id));
      setStatusMessage(`Removed api user ${apiUser.username} and its linked key material.`);
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Unable to delete the api user.',
      );
    } finally {
      setDeletingApiUserId(null);
    }
  }

  async function handleDeleteAccount() {
    if (!session || session.currentPrincipal.kind !== 'user') {
      return;
    }

    const confirmed = globalThis.confirm(
      `Delete account ${session.user.email}? This removes the user, linked api users, notes, DEKs, KEKs, and stored encrypted data.`,
    );

    if (!confirmed) {
      return;
    }

    setErrorMessage(null);
    setIsDeletingAccount(true);

    try {
      await runWithSessionRetry(session, backendUrl.trim(), (activeSession) =>
        deleteAccountRequest({
          baseUrl: backendUrl.trim(),
          token: activeSession.token,
        }));

      clearDeletedAccountState();
      setStatusMessage('Deleted the account and cleared the local linked key material.');
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Unable to delete the account.',
      );
    } finally {
      setIsDeletingAccount(false);
    }
  }

  async function continueApiUserProvisioning(
    apiUser: ApiUserResponse,
    {
      linkedKeks,
      nextSession,
    }: {
      linkedKeks: PersistedLinkedKek[];
      nextSession: AuthApiResponse;
    },
  ) {
    const trimmedBackendUrl = backendUrl.trim();
    const remoteNotes = await runWithSessionRetry(nextSession, trimmedBackendUrl, (activeSession) =>
      fetchNotes({
        baseUrl: trimmedBackendUrl,
        token: activeSession.token,
      }));
    const notesById = new Map(remoteNotes.map((note) => [note.id, note]));

    setApiUserProgress({
      apiUserId: apiUser.id,
      completed: apiUser.provisioning.completedResourceCount,
      total: apiUser.provisioning.totalResourceCount,
      username: apiUser.username,
    });

    let latestApiUser = apiUser;

    try {
      for (let index = 0; index < apiUser.provisioning.pendingNoteIds.length; index += 1) {
        const noteId = apiUser.provisioning.pendingNoteIds[index]!;
        const note = notesById.get(noteId);

        if (!note) {
          throw new Error('A note required for api user provisioning is missing from the backend.');
        }

        const noteLinkedKek = findLinkedKek(linkedKeks, note.encryptedDek.kekPublicKey);

        if (!noteLinkedKek) {
          throw new Error(
            `Missing the local KEK for epoch-linked id ${note.encryptedDek.kekPublicKey}. Log in again and provide the older password for that KEK.`,
          );
        }

        latestApiUser = await runWithSessionRetry(nextSession, trimmedBackendUrl, async (activeSession) =>
          provisionApiUserDeksRequest({
            apiUserId: apiUser.id,
            baseUrl: trimmedBackendUrl,
            token: activeSession.token,
            wrappedDeks: [
              {
                resourceId: note.id,
                wrappedDek: {
                  ...(await rewrapAsymmetricEncryptedDek(
                    note,
                    noteLinkedKek.cryptKey,
                    latestApiUser.latestKekPublicKey,
                  )),
                  userId: latestApiUser.id,
                },
              },
            ],
          }));

        setApiUserProgress({
          apiUserId: latestApiUser.id,
          completed: latestApiUser.provisioning.completedResourceCount,
          total: latestApiUser.provisioning.totalResourceCount,
          username: latestApiUser.username,
        });
      }

      await loadApiUsers({
        linkedKeks,
        nextSession,
        trimmedBackendUrl,
      });
      setStatusMessage(
        latestApiUser.provisioning.pendingResourceCount === 0
          ? `Provisioned api user ${latestApiUser.username}.`
          : `Provisioning for api user ${latestApiUser.username} is still pending.`,
      );
    } finally {
      setApiUserProgress(null);
    }
  }

  return (
    <main className="relative overflow-hidden">
      <div className="absolute inset-0 -z-10 bg-grid-paper bg-[size:40px_40px] opacity-35" />
      <div className="absolute left-[8%] top-16 -z-10 size-72 rounded-full bg-secondary/55 blur-3xl" />
      <div className="absolute bottom-0 right-[10%] -z-10 size-80 rounded-full bg-primary/15 blur-3xl" />

      <section className="mx-auto grid min-h-screen max-w-6xl gap-10 px-6 py-10 sm:px-10 lg:grid-cols-[0.95fr_1.05fr] lg:px-12">
        <div className="flex flex-col justify-between gap-8">
          <div>
            <p className="font-serif text-sm uppercase tracking-[0.32em] text-primary/70">
              Web Auth + E2EE
            </p>
            <h1 className="mt-5 max-w-3xl font-serif text-5xl leading-none tracking-[-0.04em] text-foreground sm:text-6xl">
              Same password-derived login and local encryption flow, now in the browser.
            </h1>
            <p className="mt-6 max-w-2xl text-balance text-lg leading-8 text-foreground/75">
              Register or log in with your plain email. The browser derives a crypt key for
              local encryption and a separate auth key for the Rust backend, matching the mobile
              app&apos;s model.
            </p>
          </div>

          <div className="grid gap-4">
            {featureNotes.map((note) => (
              <article
                key={note}
                className="rounded-[1.6rem] border border-border/70 bg-white/75 p-5 shadow-sm backdrop-blur"
              >
                <div className="flex items-start gap-4">
                  <div className="rounded-2xl bg-primary/10 p-3 text-primary">
                    <ShieldCheck className="size-5" />
                  </div>
                  <p className="text-sm leading-6 text-foreground/80">{note}</p>
                </div>
              </article>
            ))}
          </div>
        </div>

        <div className="grid gap-5 self-start rounded-[2rem] border border-border/70 bg-white/80 p-6 shadow-panel backdrop-blur sm:p-7">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
                {session ? 'Encrypted session' : 'Authenticate'}
              </p>
              <h2 className="mt-2 text-2xl font-semibold text-foreground">
                {session ? `Signed in as ${session.user.email}` : 'Login or register'}
              </h2>
            </div>
            {session ? (
              <Button onClick={handleSignOut} variant="outline">
                Sign out
              </Button>
            ) : null}
          </div>

          {session ? (
            <div className="grid gap-5">
              <div className="grid gap-3 rounded-[1.6rem] border border-border/70 bg-background/80 p-5">
                <div className="flex items-center gap-3 text-foreground">
                  <LockKeyhole className="size-5 text-primary" />
                  <p className="text-sm uppercase tracking-[0.22em] text-muted-foreground">
                    Password rotation
                  </p>
                </div>
                <p className="text-sm leading-6 text-foreground/75">
                  Rotate the password-derived auth key first, then rewrap every stored DEK onto the
                  newest KEK epoch without changing the encrypted note ciphertext.
                </p>
                <LabeledInput
                  autoComplete="new-password"
                  label="New password"
                  onChange={setNextPassword}
                  placeholder="Type the new password for the next KEK epoch"
                  type="password"
                  value={nextPassword}
                />
                <Button
                  disabled={isRotatingPassword || isMigrating}
                  onClick={() => {
                    void handleRotatePassword();
                  }}
                  size="lg"
                >
                  {isRotatingPassword ? 'Rotating password...' : 'Rotate password and start migration'}
                </Button>
              </div>

              {needsMigration ? (
                <div className="grid gap-3 rounded-[1.6rem] border border-amber-200 bg-amber-50/80 p-5">
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-sm uppercase tracking-[0.22em] text-amber-900">
                      KEK migration
                    </p>
                    <span className="text-xs font-semibold uppercase tracking-[0.2em] text-amber-900/75">
                      {kekMigrationStatus?.pendingDekCount ?? 0} pending
                    </span>
                  </div>
                  <p className="text-sm leading-6 text-amber-950/80">
                    More than one KEK epoch is still active for this account. Continue the
                    migration to rewrap all stored DEKs onto epoch {kekMigrationStatus?.latestKekEpochVersion ?? '?'}.
                  </p>
                  {missingMigrationKeks.map((metadata) => (
                    <LabeledInput
                      autoComplete="current-password"
                      key={metadata.kekPublicKey}
                      label={`Missing password for epoch ${metadata.kekEpochVersion}`}
                      onChange={(value) =>
                        setMigrationPasswords((currentPasswords) => ({
                          ...currentPasswords,
                          [metadata.kekPublicKey]: value,
                        }))
                      }
                      placeholder="Type the password for this older KEK epoch"
                      type="password"
                      value={migrationPasswords[metadata.kekPublicKey] ?? ''}
                    />
                  ))}
                  {migrationProgress ? (
                    <div className="grid gap-2">
                      <div className="h-3 overflow-hidden rounded-full bg-amber-100">
                        <div
                          className="h-full rounded-full bg-amber-500 transition-[width]"
                          style={{
                            width: `${migrationProgress.total === 0 ? 100 : (migrationProgress.completed / migrationProgress.total) * 100}%`,
                          }}
                        />
                      </div>
                      <p className="text-sm text-amber-950/80">
                        Migrated {migrationProgress.completed} of {migrationProgress.total} DEKs.
                      </p>
                    </div>
                  ) : null}
                  {!isMigrating ? (
                    <Button
                      onClick={() => {
                        void handleContinueMigration();
                      }}
                      size="lg"
                      variant="outline"
                    >
                      Continue migration
                    </Button>
                  ) : null}
                </div>
              ) : null}

              {session.currentPrincipal.kind === 'user' ? (
                <div className="grid gap-3 rounded-[1.6rem] border border-rose-200 bg-rose-50/80 p-5">
                  <div className="flex items-center gap-3 text-rose-950">
                    <Trash2 className="size-5" />
                    <p className="text-sm uppercase tracking-[0.22em] text-rose-900/80">
                      Delete account
                    </p>
                  </div>
                  <p className="text-sm leading-6 text-rose-950/80">
                    Permanently remove the owner account together with linked api users, KEK metadata,
                    wrapped DEKs, notes, and other encrypted rows tied to this account.
                  </p>
                  <Button
                    className="border-rose-300 text-rose-950 hover:bg-rose-100"
                    disabled={isDeletingAccount || isMigrating || isRotatingPassword || !!apiUserProgress}
                    onClick={() => {
                      void handleDeleteAccount();
                    }}
                    size="lg"
                    variant="outline"
                  >
                    {isDeletingAccount ? 'Deleting account...' : 'Delete account'}
                  </Button>
                </div>
              ) : null}

              {session.currentPrincipal.kind === 'user' ? (
                <div className="grid gap-4 rounded-[1.6rem] border border-border/70 bg-background/80 p-5">
                  <div className="flex items-center gap-3 text-foreground">
                    <ShieldCheck className="size-5 text-primary" />
                    <p className="text-sm uppercase tracking-[0.22em] text-muted-foreground">
                      API user dashboard
                    </p>
                  </div>
                  <p className="text-sm leading-6 text-foreground/75">
                    Generate dedicated api tokens locally, inspect the current api users, and remove a principal together with its linked KEK and DEK records when it is no longer needed.
                  </p>
                  <LabeledInput
                    autoComplete="off"
                    label="API user label"
                    onChange={setApiUserLabel}
                    placeholder="CLI integration, automation, server agent"
                    type="text"
                    value={apiUserLabel}
                  />
                  <Button
                    disabled={isCreatingApiUser || isMigrating || !apiUserLabel.trim()}
                    onClick={() => {
                      void handleCreateApiUser();
                    }}
                    size="lg"
                    variant="outline"
                  >
                    {isCreatingApiUser ? 'Creating api user...' : 'Create api user'}
                  </Button>
                  {latestApiToken ? (
                    <div className="rounded-[1.5rem] border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm leading-6 text-emerald-950">
                      <p className="font-semibold">Latest api token</p>
                      <p className="mt-2 break-all font-mono text-xs">{latestApiToken}</p>
                    </div>
                  ) : null}
                  {apiUserProgress ? (
                    <div className="grid gap-2 rounded-[1.5rem] border border-sky-200 bg-sky-50 px-4 py-3">
                      <p className="text-sm font-semibold text-sky-950">
                        Provisioning {apiUserProgress.username}
                      </p>
                      <div className="h-3 overflow-hidden rounded-full bg-sky-100">
                        <div
                          className="h-full rounded-full bg-sky-500 transition-[width]"
                          style={{
                            width: `${apiUserProgress.total === 0 ? 100 : (apiUserProgress.completed / apiUserProgress.total) * 100}%`,
                          }}
                        />
                      </div>
                      <p className="text-sm text-sky-950/80">
                        Provisioned {apiUserProgress.completed} of {apiUserProgress.total} resources.
                      </p>
                    </div>
                  ) : null}
                  <div className="grid gap-3">
                    {apiUsers.length === 0 ? (
                      <p className="text-sm text-foreground/60">No api users created yet.</p>
                    ) : (
                      apiUsers.map((apiUser) => (
                        <article
                          className="grid gap-3 rounded-[1.4rem] border border-border/60 bg-white px-4 py-4"
                          key={apiUser.id}
                        >
                          <div className="flex flex-wrap items-start justify-between gap-3">
                            <div>
                              <p className="font-semibold text-foreground">{apiUser.label || 'Unlabeled api user'}</p>
                              <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground">
                                {apiUser.username}
                              </p>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">
                                {apiUser.provisioning.completedResourceCount}/{apiUser.provisioning.totalResourceCount}
                              </span>
                              <Button
                                disabled={
                                  deletingApiUserId === apiUser.id ||
                                  !!apiUserProgress ||
                                  isCreatingApiUser
                                }
                                onClick={() => {
                                  void handleDeleteApiUser(apiUser);
                                }}
                                size="sm"
                                variant="ghost"
                              >
                                <Trash2 className="size-4" />
                                {deletingApiUserId === apiUser.id ? 'Removing...' : 'Remove'}
                              </Button>
                            </div>
                          </div>
                          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-foreground/60">
                            <span>Created {formatTimestamp(apiUser.createdAt)}</span>
                            <span>Updated {formatTimestamp(apiUser.updatedAt)}</span>
                          </div>
                          <div className="h-2 overflow-hidden rounded-full bg-muted">
                            <div
                              className="h-full rounded-full bg-primary transition-[width]"
                              style={{
                                width: `${apiUser.provisioning.totalResourceCount === 0 ? 100 : (apiUser.provisioning.completedResourceCount / apiUser.provisioning.totalResourceCount) * 100}%`,
                              }}
                            />
                          </div>
                          <p className="text-sm text-foreground/70">
                            {apiUser.provisioning.pendingResourceCount === 0
                              ? 'Provisioning complete.'
                              : `${apiUser.provisioning.pendingResourceCount} resource wrap${apiUser.provisioning.pendingResourceCount === 1 ? '' : 's'} still pending.`}
                          </p>
                          {apiUser.provisioning.pendingResourceCount > 0 ? (
                            <Button
                              disabled={!!apiUserProgress || isCreatingApiUser || deletingApiUserId === apiUser.id}
                              onClick={() => {
                                void handleResumeApiUser(apiUser.id);
                              }}
                              size="sm"
                              variant="outline"
                            >
                              Resume provisioning
                            </Button>
                          ) : null}
                        </article>
                      ))
                    )}
                  </div>
                </div>
              ) : null}

              <div className="grid gap-3 rounded-[1.6rem] border border-border/70 bg-background/80 p-5">
                <div className="flex items-center gap-3 text-foreground">
                  <UserRound className="size-5 text-primary" />
                  <p className="text-sm uppercase tracking-[0.22em] text-muted-foreground">
                    Notes vault
                  </p>
                </div>
                <p className="text-sm leading-6 text-foreground/75">
                  Create, update, and delete encrypted notes. The backend stores ciphertext plus a
                  wrapped per-resource DEK, and only the current password-derived crypt key can
                  unwrap that DEK and decrypt the note document.
                </p>
                <div className="flex items-center justify-between gap-3">
                  <p className="text-xs font-semibold uppercase tracking-[0.24em] text-muted-foreground">
                    Notes ({notes.length})
                  </p>
                  <Button onClick={handleCreateNote} size="sm" variant="outline">
                    New note
                  </Button>
                </div>
                <div className="overflow-x-auto rounded-[1.2rem] border border-border/60 bg-white">
                  {notes.length === 0 ? (
                    <p className="px-4 py-5 text-sm text-foreground/60">
                      No encrypted notes yet.
                    </p>
                  ) : (
                    <table className="min-w-full border-collapse text-left text-sm">
                      <thead className="bg-muted/50 text-xs uppercase tracking-[0.18em] text-muted-foreground">
                        <tr>
                          <th className="px-4 py-3 font-semibold">Title</th>
                          <th className="px-4 py-3 font-semibold">Preview</th>
                          <th className="px-4 py-3 font-semibold">Updated</th>
                        </tr>
                      </thead>
                      <tbody>
                        {notes.map((note) => {
                          const isActive = note.id === selectedNoteId;

                          return (
                            <tr
                              className={`cursor-pointer border-t border-border/50 transition ${
                                isActive
                                  ? 'bg-primary/10'
                                  : 'hover:bg-primary/5'
                              }`}
                              key={note.id}
                              onClick={() => handleSelectNote(note.id)}
                            >
                              <td className="max-w-[12rem] truncate px-4 py-3 font-semibold text-foreground">
                                {note.title || 'Untitled note'}
                              </td>
                              <td className="max-w-[18rem] truncate px-4 py-3 text-foreground/70">
                                {note.content || 'No content yet'}
                              </td>
                              <td className="whitespace-nowrap px-4 py-3 text-foreground/60">
                                {formatTimestamp(note.updatedAt)}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </div>
                <div className="grid gap-3">
                  <LabeledInput
                    autoComplete="off"
                    label="Title"
                    onChange={setNoteTitle}
                    placeholder="Untitled note"
                    type="text"
                    value={noteTitle}
                  />
                  <label className="grid gap-2">
                    <span className="text-xs font-semibold uppercase tracking-[0.24em] text-muted-foreground">
                      Content
                    </span>
                    <textarea
                      className="min-h-44 rounded-[1.5rem] border border-border bg-white px-4 py-4 text-base text-foreground outline-none transition focus:border-primary/60 focus:ring-2 focus:ring-primary/20"
                      onChange={(event) => setNoteContent(event.target.value)}
                      placeholder="Write something that should stay encrypted between web and mobile"
                      value={noteContent}
                    />
                  </label>
                  <div className="flex flex-col gap-3 sm:flex-row">
                    <Button onClick={handleSaveNote} size="lg">
                      <LockKeyhole />
                      {selectedNoteId ? 'Update encrypted note' : 'Create encrypted note'}
                    </Button>
                    <Button onClick={handleClearNote} size="lg" variant="outline">
                      {selectedNoteId ? 'Delete note' : 'Clear draft'}
                    </Button>
                  </div>
                </div>
                <div className="grid gap-3 rounded-[1.4rem] border border-dashed border-border/70 bg-white/70 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <p className="text-xs font-semibold uppercase tracking-[0.24em] text-muted-foreground">
                      Import / export suite
                    </p>
                    <span className="text-xs text-foreground/60">
                      JSON with optional custom-password AES-256-GCM protection
                    </span>
                  </div>
                  <p className="text-sm leading-6 text-foreground/75">
                    Export the currently decrypted notes as JSON, or import a prior JSON export.
                    The optional import/export password is separate from the account password and
                    derives its own key with Argon2id.
                  </p>
                  <LabeledInput
                    autoComplete="new-password"
                    label="Optional export password"
                    onChange={setExportPassword}
                    placeholder="Leave empty for cleartext JSON"
                    type="password"
                    value={exportPassword}
                  />
                  <div className="flex flex-col gap-3 sm:flex-row">
                    <Button
                      disabled={isExportingNotes || notes.length === 0}
                      onClick={() => {
                        void handleExportNotes();
                      }}
                      size="lg"
                      variant="outline"
                    >
                      {isExportingNotes ? 'Exporting JSON...' : 'Export JSON'}
                    </Button>
                    <Button
                      onClick={() => {
                        importFileInputRef.current?.click();
                      }}
                      size="lg"
                      variant="outline"
                    >
                      Choose import file
                    </Button>
                  </div>
                  <input
                    accept="application/json,.json"
                    className="hidden"
                    onChange={handleImportFileSelection}
                    ref={importFileInputRef}
                    type="file"
                  />
                  <LabeledInput
                    autoComplete="current-password"
                    label="Import password"
                    onChange={setImportPassword}
                    placeholder={importInspection?.encrypted ? 'Enter the custom export password' : 'Only needed for encrypted exports'}
                    type="password"
                    value={importPassword}
                  />
                  <div className="rounded-[1.2rem] border border-border/60 bg-background/80 px-4 py-3 text-sm leading-6 text-foreground/75">
                    {importInspection ? (
                      <p>
                        Selected {importFileName} with {importInspection.noteCount} note{importInspection.noteCount === 1 ? '' : 's'}.{' '}
                        {importInspection.encrypted ? 'Password protection is enabled.' : 'This export is cleartext.'}
                      </p>
                    ) : (
                      <p>No import file selected yet.</p>
                    )}
                  </div>
                  <Button
                    disabled={isImportingNotes || !importPayload}
                    onClick={() => {
                      void handleImportNotes();
                    }}
                    size="lg"
                  >
                    {isImportingNotes ? 'Importing JSON...' : 'Import selected JSON'}
                  </Button>
                </div>
              </div>

              <div className="grid gap-3 rounded-[1.6rem] border border-border/70 bg-muted/45 p-5 text-sm leading-6 text-foreground/75">
                <p>
                  {statusMessage ||
                    'Nothing encrypted yet. Create a note to exercise the synced E2EE flow.'}
                </p>
                {selectedNoteId ? (
                  <p>
                    Selected note id:{' '}
                    <span className="font-mono text-xs">
                      {selectedNoteId}
                    </span>
                  </p>
                ) : null}
              </div>
            </div>
          ) : (
            <>
              <div className="grid grid-cols-2 gap-2 rounded-full border border-border/70 bg-muted/60 p-1">
                {(['register', 'login'] as const).map((nextMode) => {
                  const isActive = nextMode === mode;

                  return (
                    <button
                      className={`rounded-full px-4 py-3 text-sm font-semibold uppercase tracking-[0.18em] transition ${
                        isActive
                          ? 'bg-primary text-primary-foreground shadow-sm'
                          : 'text-foreground/70 hover:bg-background/80'
                      }`}
                      key={nextMode}
                      onClick={() => setMode(nextMode)}
                      type="button"
                    >
                      {nextMode}
                    </button>
                  );
                })}
              </div>

              <div className="grid gap-4">
                <LabeledInput
                  autoComplete="email"
                  label="Email"
                  onChange={setEmail}
                  placeholder="hello@example.com"
                  type="email"
                  value={email}
                />
                <LabeledInput
                  autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
                  label="Password"
                  onChange={setPassword}
                  placeholder="Type the password used to derive keys"
                  type="password"
                  value={password}
                />
                {mode === 'login' && requiredOlderKeks.length > 0
                  ? requiredOlderKeks.map((metadata) => (
                      <LabeledInput
                        autoComplete="current-password"
                        key={metadata.kekPublicKey}
                        label={`Older password v${metadata.kekEpochVersion}`}
                        onChange={(value) =>
                          setOlderPasswords((currentPasswords) => ({
                            ...currentPasswords,
                            [metadata.kekPublicKey]: value,
                          }))
                        }
                        placeholder="Type the older password for this active KEK"
                        type="password"
                        value={olderPasswords[metadata.kekPublicKey] ?? ''}
                      />
                    ))
                  : null}
              </div>

              <p className="rounded-[1.5rem] border border-border/60 bg-background/70 px-4 py-3 text-sm leading-6 text-foreground/75">
                The typed password never goes to the backend directly. The browser derives the
                local crypt key and the backend auth key from the same salt-backed input.
              </p>
              {mode === 'login' && requiredOlderKeks.length > 0 ? (
                <p className="rounded-[1.5rem] border border-amber-200 bg-amber-50 px-4 py-3 text-sm leading-6 text-amber-900">
                  Older KEKs are still active for this account. Enter the matching legacy
                  passwords so this device can relink those KEKs locally and continue decrypting
                  older notes.
                </p>
              ) : null}

              {errorMessage ? (
                <p className="rounded-[1.4rem] bg-rose-100 px-4 py-3 text-sm font-medium text-rose-700">
                  {errorMessage}
                </p>
              ) : null}

              <Button
                disabled={!isHydrated || isSubmitting}
                onClick={() => {
                  void handleSubmit();
                }}
                size="lg"
              >
                {mode === 'register' ? 'Create account' : 'Log in'}
                <ArrowRight />
              </Button>
            </>
          )}
        </div>
      </section>
    </main>
  );
}

type LabeledInputProps = {
  autoComplete: string;
  label: string;
  onChange: (value: string) => void;
  placeholder: string;
  type: 'email' | 'password' | 'text';
  value: string;
};

function LabeledInput({
  autoComplete,
  label,
  onChange,
  placeholder,
  type,
  value,
}: Readonly<LabeledInputProps>) {
  return (
    <label className="grid gap-2">
      <span className="text-xs font-semibold uppercase tracking-[0.24em] text-muted-foreground">
        {label}
      </span>
      <input
        autoComplete={autoComplete}
        className="rounded-[1.4rem] border border-border bg-background/80 px-4 py-4 text-base text-foreground outline-none transition focus:border-primary/60 focus:ring-2 focus:ring-primary/20"
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        type={type}
        value={value}
      />
    </label>
  );
}

function serializeNoteDocument(note: NoteDocument) {
  return JSON.stringify({
    content: note.content,
    title: note.title,
  });
}

async function decryptNoteRecord(note: NoteResponse, linkedKeks: PersistedLinkedKek[]): Promise<DecryptedNote> {
  const linkedKek = findLinkedKek(linkedKeks, note.encryptedDek.kekPublicKey);

  if (!linkedKek) {
    throw new Error(
      `Missing the local KEK for epoch-linked id ${note.encryptedDek.kekPublicKey}. Log in again and provide the older password for that KEK.`,
    );
  }

  const decryptedDocument = deserializeNoteDocument(
    await decryptStringWithAsymmetricKek(note, linkedKek.cryptKey),
  );

  return {
    content: decryptedDocument.content,
    createdAt: note.createdAt,
    id: note.id,
    payload: note,
    title: decryptedDocument.title,
    updatedAt: note.updatedAt,
  };
}

async function decryptApiUserRecord(
  apiUser: ApiUserResponse,
  linkedKeks: PersistedLinkedKek[],
): Promise<ApiUserView> {
  const linkedKek = findLinkedKek(linkedKeks, apiUser.encryptedLabelDek.kekPublicKey);

  if (!linkedKek) {
    throw new Error(
      `Missing the local KEK for api user label ${apiUser.encryptedLabelDek.kekPublicKey}.`,
    );
  }

  return {
    ...apiUser,
    label: await decryptStringWithAsymmetricKek(
      {
        encryptedDek: apiUser.encryptedLabelDek,
        encryptedPayload: apiUser.encryptedLabel,
      },
      linkedKek.cryptKey,
    ),
  };
}

function deserializeNoteDocument(value: string): NoteDocument {
  try {
    const parsed = JSON.parse(value) as Partial<NoteDocument>;

    if (typeof parsed?.title === 'string' && typeof parsed?.content === 'string') {
      return {
        content: parsed.content,
        title: parsed.title,
      };
    }
  } catch {
    // Fall back to treating legacy values as content-only text.
  }

  return {
    content: value,
    title: '',
  };
}

function sortNotes(notes: DecryptedNote[]) {
  return [...notes].sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
}

function sortKekMetadatas(kekMetadatas: KekMetadata[]) {
  return [...kekMetadatas].sort(
    (left, right) => right.kekEpochVersion - left.kekEpochVersion,
  );
}

function toBackupNote(note: DecryptedNote): ImportExportSuiteNote {
  return {
    content: note.content,
    createdAt: note.createdAt,
    id: note.id,
    title: note.title,
    updatedAt: note.updatedAt,
  };
}

function buildImportExportSuiteFilename(exportedAt: string) {
  const safeTimestamp = exportedAt.replace(/[.:]/g, '-');

  return `import-export-suite-${safeTimestamp}.json`;
}

function downloadTextFile(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');

  anchor.href = objectUrl;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(objectUrl);
}

function buildImportSummary(createdCount: number, updatedCount: number) {
  const segments = [];

  if (updatedCount > 0) {
    segments.push(`updated ${updatedCount}`);
  }

  if (createdCount > 0) {
    segments.push(`created ${createdCount}`);
  }

  return segments.length > 0
    ? `Imported notes: ${segments.join(' and ')}.`
    : 'The import file did not produce any note changes.';
}

function mergeLinkedKeks(linkedKeks: PersistedLinkedKek[]) {
  const entriesByKekId = new Map<string, PersistedLinkedKek>();

  for (const linkedKek of linkedKeks) {
    entriesByKekId.set(linkedKek.kekPublicKey, linkedKek);
  }

  return [...entriesByKekId.values()].sort(
    (left, right) => right.kekEpochVersion - left.kekEpochVersion,
  );
}

function findLinkedKek(linkedKeks: PersistedLinkedKek[], kekPublicKey: string) {
  return linkedKeks.find((linkedKek) => linkedKek.kekPublicKey === kekPublicKey) ?? null;
}

function requireLinkedKek(linkedKeks: PersistedLinkedKek[], activeKekId: string | null) {
  if (!activeKekId) {
    throw new Error('No active KEK is linked on this device. Log in again.');
  }

  const linkedKek = findLinkedKek(linkedKeks, activeKekId);

  if (!linkedKek) {
    throw new Error('The active KEK is missing from local storage. Log in again.');
  }

  return linkedKek;
}

function hasUnauthorizedStatus(error: unknown) {
  return !!error &&
    typeof error === 'object' &&
    'status' in error &&
    error.status === 401;
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value));
}

async function deriveMissingLinkedKeks({
  baseLinkedKeks,
  email,
  missingMetadatas,
  passwordsByKekId,
}: {
  baseLinkedKeks: PersistedLinkedKek[];
  email: string;
  missingMetadatas: KekMetadata[];
  passwordsByKekId: Record<string, string>;
}) {
  if (missingMetadatas.length === 0) {
    return baseLinkedKeks;
  }

  const saltHex = baseLinkedKeks[0]?.saltHex;

  if (!saltHex) {
    throw new Error('The current password salt is missing from local storage. Log in again.');
  }

  const derivedLinkedKeks = [...baseLinkedKeks];

  for (const metadata of missingMetadatas) {
    const password = passwordsByKekId[metadata.kekPublicKey]?.trim();

    if (!password) {
      throw new Error(
        `Enter the password for KEK epoch ${metadata.kekEpochVersion} before continuing the migration.`,
      );
    }

    const credentials = await deriveCredentials(email, password, saltHex);

    derivedLinkedKeks.push({
      cryptKey: credentials.cryptKey,
      kekEpochVersion: metadata.kekEpochVersion,
      kekPublicKey: metadata.kekPublicKey,
      saltHex,
    });
  }

  return mergeLinkedKeks(derivedLinkedKeks);
}