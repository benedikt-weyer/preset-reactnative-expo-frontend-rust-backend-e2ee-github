import { useEffect, useState } from 'react';
import { Pressable, Text, TextInput, View } from 'react-native';

import {
  decryptStringWithAsymmetricKek,
  encryptStringWithAsymmetricKek,
  deriveCredentials,
  rewrapAsymmetricEncryptedDek,
} from '@repo/e2ee-auth/native';

import { ScreenShell } from '../components/screen-shell';
import {
  createNote,
  deleteNote,
  fetchNotes,
  type NoteResponse,
  updateNote,
} from '../features/e2ee/test-note-api';
import { useAuth } from '../features/auth/auth-context';
import { useAppTheme } from '../features/theme/theme-context';
import { themeTokens } from '../theme/theme-tokens';

type NoteDocument = {
  content: string;
  title: string;
};

type DecryptedNote = {
  content: string;
  createdAt: string;
  id: string;
  title: string;
  updatedAt: string;
};

type MigrationProgress = {
  completed: number;
  total: number;
};

export function HomeScreen() {
  const {
    activeKekId,
    backendUrl,
    kekMigrationStatus,
    linkedKeks,
    persistLinkedKeks,
    refreshKekMigrationStatus,
    rotatePassword,
    session,
  } = useAuth();
  const { themeMode } = useAppTheme();
  const tokens = themeTokens[themeMode];
  const [nextPassword, setNextPassword] = useState('');
  const [migrationPasswords, setMigrationPasswords] = useState<Record<string, string>>({});
  const [noteTitle, setNoteTitle] = useState('');
  const [noteContent, setNoteContent] = useState('');
  const [notes, setNotes] = useState<DecryptedNote[]>([]);
  const [selectedNoteId, setSelectedNoteId] = useState<string | null>(null);
  const [migrationProgress, setMigrationProgress] = useState<MigrationProgress | null>(null);
  const [isMigrating, setIsMigrating] = useState(false);
  const [isRotatingPassword, setIsRotatingPassword] = useState(false);
  const [statusMessage, setStatusMessage] = useState('');

  const missingMigrationKeks = session
    ? session.kekMetadatas.filter((metadata) => !linkedKeks.some((entry) => entry.kekId === metadata.kekId))
    : [];
  const needsMigration =
    !!session &&
    !!kekMigrationStatus &&
    session.kekMetadatas.length > 1 &&
    !kekMigrationStatus.allDeksUseLatestKek;

  useEffect(() => {
    let isMounted = true;

    async function hydrateNotes() {
      if (!session || linkedKeks.length === 0) {
        if (isMounted) {
          setNotes([]);
          applySelectedNote(null);
        }
        return;
      }

      try {
        await refreshKekMigrationStatus();
        const remoteNotes = await fetchNotes({
          baseUrl: backendUrl,
          token: session.token,
        });

        if (!isMounted) {
          return;
        }

        const decryptedNotes = sortNotes(
          await Promise.all(remoteNotes.map((note) => decryptNoteRecord(note, linkedKeks))),
        );

        setNotes(decryptedNotes);
        const nextSelectedNote =
          decryptedNotes.find((note) => note.id === selectedNoteId) ?? decryptedNotes[0] ?? null;

        applySelectedNote(nextSelectedNote);
        setStatusMessage(
          nextSelectedNote
            ? `Loaded ${decryptedNotes.length} encrypted note${decryptedNotes.length === 1 ? '' : 's'} from the backend.`
            : 'No synced notes yet. Create one to push ciphertext to the backend.',
        );
      } catch (error) {
        if (!isMounted) {
          return;
        }

        setNotes([]);
        applySelectedNote(null);
        setStatusMessage(
          error instanceof Error ? error.message : 'Unable to load encrypted notes.',
        );
      }
    }

    void hydrateNotes();

    return () => {
      isMounted = false;
    };
  }, [backendUrl, linkedKeks, session]);

  function applySelectedNote(note: DecryptedNote | null) {
    setSelectedNoteId(note?.id ?? null);
    setNoteTitle(note?.title ?? '');
    setNoteContent(note?.content ?? '');
  }

  function handleCreateDraft() {
    applySelectedNote(null);
    setStatusMessage('Creating a new encrypted note draft.');
  }

  function handleSelectNote(noteId: string) {
    const nextNote = notes.find((note) => note.id === noteId) ?? null;

    applySelectedNote(nextNote);
    setStatusMessage(nextNote ? `Selected "${nextNote.title || 'Untitled note'}".` : '');
  }

  async function handleSave() {
    if (!session) {
      return;
    }

    const activeLinkedKek = requireLinkedKek(linkedKeks, activeKekId);

    try {
      const encryptedPayload = await encryptStringWithAsymmetricKek(
        serializeNoteDocument({
          content: noteContent,
          title: noteTitle,
        }),
        activeLinkedKek.cryptKey,
      );
      const savedNote = selectedNoteId
        ? await updateNote({
            baseUrl: backendUrl,
            noteId: selectedNoteId,
            payload: encryptedPayload,
            token: session.token,
          })
        : await createNote({
            baseUrl: backendUrl,
            payload: encryptedPayload,
            token: session.token,
          });

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
      setStatusMessage(
        error instanceof Error ? error.message : 'Unable to save the encrypted note.',
      );
    }
  }

  async function handleClear() {
    if (!session || !selectedNoteId) {
      applySelectedNote(null);
      setStatusMessage('Cleared the local note draft.');
      return;
    }

    try {
      await deleteNote({
        baseUrl: backendUrl,
        noteId: selectedNoteId,
        token: session.token,
      });
      const deletedNote = notes.find((note) => note.id === selectedNoteId) ?? null;
      const remainingNotes = notes.filter((note) => note.id !== selectedNoteId);

      setNotes(remainingNotes);
      applySelectedNote(remainingNotes[0] ?? null);
      setStatusMessage(`Deleted "${deletedNote?.title || 'Untitled note'}".`);
    } catch (error) {
      setStatusMessage(
        error instanceof Error ? error.message : 'Unable to delete the encrypted note.',
      );
    }
  }

  async function handleRotatePassword() {
    setIsRotatingPassword(true);

    try {
      const rotationResult = await rotatePassword(nextPassword);

      setNextPassword('');
      await continueKekMigration(rotationResult.linkedKeks, rotationResult.session, rotationResult.activeKekId);
    } catch (error) {
      setStatusMessage(
        error instanceof Error ? error.message : 'Unable to rotate the password.',
      );
    } finally {
      setIsRotatingPassword(false);
    }
  }

  async function handleContinueMigration() {
    if (!session || !activeKekId) {
      return;
    }

    try {
      await continueKekMigration(linkedKeks, session, activeKekId);
    } catch (error) {
      setStatusMessage(
        error instanceof Error ? error.message : 'Unable to continue the KEK migration.',
      );
    }
  }

  async function continueKekMigration(
    baseLinkedKeks: typeof linkedKeks,
    activeSession: NonNullable<typeof session>,
    latestKekId: string,
  ) {
    const workingLinkedKeks = await deriveMissingLinkedKeks({
      baseLinkedKeks,
      email: activeSession.user.email,
      missingMetadatas: activeSession.kekMetadatas.filter(
        (metadata) => !baseLinkedKeks.some((entry) => entry.kekId === metadata.kekId),
      ),
      passwordsByKekId: migrationPasswords,
    });
    const latestLinkedKek = requireLinkedKek(workingLinkedKeks, latestKekId);
    const remoteNotes = await fetchNotes({
      baseUrl: backendUrl,
      token: activeSession.token,
    });
    const notesToRewrap = remoteNotes.filter(
      (note) => note.encryptedDek.kekId !== latestLinkedKek.kekId,
    );

    setIsMigrating(true);
    setMigrationProgress({ completed: 0, total: notesToRewrap.length });

    try {
      for (let index = 0; index < notesToRewrap.length; index += 1) {
        const note = notesToRewrap[index];
        const currentLinkedKek = workingLinkedKeks.find(
          (entry) => entry.kekId === note.encryptedDek.kekId,
        );

        if (!currentLinkedKek) {
          throw new Error(
            `Missing the local KEK for epoch-linked id ${note.encryptedDek.kekId}. Provide the matching older password first.`,
          );
        }

        await updateNote({
          baseUrl: backendUrl,
          noteId: note.id,
          payload: {
            encryptedDek: await rewrapAsymmetricEncryptedDek(
              note,
              currentLinkedKek.cryptKey,
              latestLinkedKek.cryptKey,
            ),
            encryptedPayload: note.encryptedPayload,
          },
          token: activeSession.token,
        });

        setMigrationProgress({ completed: index + 1, total: notesToRewrap.length });
      }

      await persistLinkedKeks(workingLinkedKeks);
      setMigrationPasswords({});

      const finalStatus = await refreshKekMigrationStatus();

      if (!finalStatus?.allDeksUseLatestKek) {
        throw new Error('The backend still reports DEKs on older KEK epochs after migration.');
      }

      setStatusMessage(
        notesToRewrap.length === 0
          ? 'All DEKs already use the latest KEK epoch.'
          : `Rewrapped ${notesToRewrap.length} DEK${notesToRewrap.length === 1 ? '' : 's'} onto the latest KEK epoch.`,
      );
    } finally {
      setIsMigrating(false);
      setMigrationProgress(null);
    }
  }

  return (
    <ScreenShell
      description="Once authenticated, this screen uses the password-derived crypt key on-device to encrypt and decrypt a synced note. The backend only sees the derived auth key and ciphertext, never the raw password or plaintext note."
      themeMode={themeMode}
      title="Encrypted home"
    >
      <View className={`gap-4 rounded-[28px] border px-5 py-6 shadow-card ${tokens.card}`}>
        <Text className={`text-xl font-semibold ${tokens.title}`}>
          Signed in as {session?.user.email ?? 'unknown'}
        </Text>
        <Text className={`text-base leading-7 ${tokens.body}`}>
          The device derives a crypt key from your typed password and plain email.
          That crypt key unwraps one random DEK per encrypted resource, while a separate derived
          auth key is sent to the Rust backend for registration, login, and ciphertext sync.
        </Text>
      </View>

      <View className={`gap-3 rounded-[28px] border px-5 py-6 ${tokens.card}`}>
        <Text className={`text-sm uppercase tracking-[2px] ${tokens.kicker}`}>
          Password rotation
        </Text>
        <Text className={`text-base leading-7 ${tokens.body}`}>
          Rotate the password-derived auth key first, then rewrap every stored DEK onto the newest KEK epoch without changing the encrypted note ciphertext.
        </Text>
        <TextInput
          autoCapitalize="none"
          className={`rounded-[22px] border px-4 py-3 text-base ${tokens.card} ${tokens.title}`}
          onChangeText={setNextPassword}
          placeholder="Type the new password for the next KEK epoch"
          placeholderTextColor={themeMode === 'dark' ? '#94a3b8' : '#78716c'}
          secureTextEntry
          value={nextPassword}
        />
        <Pressable
          className={`items-center rounded-full px-4 py-4 ${tokens.segmentActive}`}
          disabled={isRotatingPassword || isMigrating}
          onPress={() => {
            void handleRotatePassword();
          }}
        >
          <Text className={`text-sm font-semibold uppercase tracking-[1.5px] ${tokens.segmentActiveText}`}>
            {isRotatingPassword ? 'Rotating password...' : 'Rotate password and start migration'}
          </Text>
        </Pressable>
      </View>

      {needsMigration ? (
        <View className="gap-3 rounded-[28px] border border-amber-300 bg-amber-50 px-5 py-6 dark:bg-amber-950/40">
          <Text className="text-sm font-semibold uppercase tracking-[2px] text-amber-900 dark:text-amber-100">
            KEK migration
          </Text>
          <Text className="text-base leading-7 text-amber-950 dark:text-amber-50">
            More than one KEK epoch is still active for this account. Continue the migration to rewrap all stored DEKs onto epoch {kekMigrationStatus?.latestKekEpochVersion ?? '?'}.
          </Text>
          {missingMigrationKeks.map((metadata) => (
            <TextInput
              autoCapitalize="none"
              className={`rounded-[22px] border px-4 py-3 text-base ${tokens.card} ${tokens.title}`}
              key={metadata.kekId}
              onChangeText={(value) =>
                setMigrationPasswords((currentPasswords) => ({
                  ...currentPasswords,
                  [metadata.kekId]: value,
                }))
              }
              placeholder={`Type the password for KEK epoch ${metadata.kekEpochVersion}`}
              placeholderTextColor={themeMode === 'dark' ? '#94a3b8' : '#78716c'}
              secureTextEntry
              value={migrationPasswords[metadata.kekId] ?? ''}
            />
          ))}
          {migrationProgress ? (
            <View className="gap-2">
              <View className="h-3 overflow-hidden rounded-full bg-amber-100 dark:bg-amber-900/70">
                <View
                  className="h-full rounded-full bg-amber-500"
                  style={{
                    width: `${migrationProgress.total === 0 ? 100 : (migrationProgress.completed / migrationProgress.total) * 100}%`,
                  }}
                />
              </View>
              <Text className="text-sm text-amber-900 dark:text-amber-100">
                Migrated {migrationProgress.completed} of {migrationProgress.total} DEKs.
              </Text>
            </View>
          ) : null}
          {!isMigrating ? (
            <Pressable
              className="items-center rounded-full border border-amber-400 px-4 py-4"
              onPress={() => {
                void handleContinueMigration();
              }}
            >
              <Text className="text-sm font-semibold uppercase tracking-[1.5px] text-amber-900 dark:text-amber-100">
                Continue migration
              </Text>
            </Pressable>
          ) : null}
        </View>
      ) : null}

      <View className={`gap-3 rounded-[28px] border px-5 py-6 ${tokens.card}`}>
        <Text className={`text-sm uppercase tracking-[2px] ${tokens.kicker}`}>
          Notes vault
        </Text>
        <Text className={`text-base leading-7 ${tokens.body}`}>
          Create, update, and delete encrypted notes. The backend stores ciphertext plus a
          wrapped per-resource DEK, and only the password-derived crypt key can unwrap that DEK
          and decrypt the note document.
        </Text>
        <View className="gap-2">
          <Pressable
            className="items-center rounded-full border border-stone-300 px-4 py-3 dark:border-slate-700"
            onPress={() => {
              handleCreateDraft();
            }}
          >
            <Text className={`text-sm font-semibold uppercase tracking-[1.5px] ${tokens.title}`}>
              New note
            </Text>
          </Pressable>
        </View>
        <View className="gap-2">
          {notes.length === 0 ? (
            <Text className={`rounded-[22px] border border-dashed px-4 py-4 text-sm ${tokens.body}`}>
              No encrypted notes yet.
            </Text>
          ) : (
            notes.map((note) => {
              const isActive = note.id === selectedNoteId;

              return (
                <Pressable
                  className={`rounded-[22px] border px-4 py-4 ${isActive ? tokens.segmentActive : tokens.card}`}
                  key={note.id}
                  onPress={() => {
                    handleSelectNote(note.id);
                  }}
                >
                  <Text className={`text-sm font-semibold ${isActive ? tokens.segmentActiveText : tokens.title}`}>
                    {note.title || 'Untitled note'}
                  </Text>
                  <Text className={`mt-1 text-sm ${isActive ? tokens.segmentActiveText : tokens.body}`} numberOfLines={1}>
                    {note.content || 'No content yet'}
                  </Text>
                </Pressable>
              );
            })
          )}
        </View>
        <TextInput
          autoCapitalize="sentences"
          className={`rounded-[22px] border px-4 py-3 text-base ${tokens.card} ${tokens.title}`}
          onChangeText={setNoteTitle}
          placeholder="Untitled note"
          placeholderTextColor={themeMode === 'dark' ? '#94a3b8' : '#78716c'}
          value={noteTitle}
        />
        <TextInput
          className={`min-h-[150px] rounded-[22px] border px-4 py-4 text-base ${tokens.card} ${tokens.title}`}
          multiline
          onChangeText={setNoteContent}
          placeholder="Write something that should stay encrypted between web and mobile"
          placeholderTextColor={themeMode === 'dark' ? '#94a3b8' : '#78716c'}
          textAlignVertical="top"
          value={noteContent}
        />
        <View className="flex-row gap-3">
          <Pressable
            className={`flex-1 items-center rounded-full px-4 py-4 ${tokens.segmentActive}`}
            onPress={() => {
              void handleSave();
            }}
          >
            <Text className={`text-sm font-semibold uppercase tracking-[1.5px] ${tokens.segmentActiveText}`}>
              {selectedNoteId ? 'Update note' : 'Create note'}
            </Text>
          </Pressable>
          <Pressable
            className="flex-1 items-center rounded-full border border-stone-300 px-4 py-4 dark:border-slate-700"
            onPress={() => {
              void handleClear();
            }}
          >
            <Text className={`text-sm font-semibold uppercase tracking-[1.5px] ${tokens.title}`}>
              {selectedNoteId ? 'Delete note' : 'Clear draft'}
            </Text>
          </Pressable>
        </View>
        <Text className={`text-base leading-7 ${tokens.body}`}>
          {statusMessage || 'Nothing encrypted yet. Create a note to exercise the synced E2EE flow.'}
        </Text>
        {selectedNoteId ? (
          <Text className={`text-sm leading-6 ${tokens.body}`}>
            Selected note id: {selectedNoteId}
          </Text>
        ) : null}
      </View>
    </ScreenShell>
  );
}

function serializeNoteDocument(note: NoteDocument) {
  return JSON.stringify({
    content: note.content,
    title: note.title,
  });
}

async function decryptNoteRecord(note: NoteResponse, linkedKeks: { cryptKey: Uint8Array; kekId: string }[]): Promise<DecryptedNote> {
  const linkedKek = linkedKeks.find((entry) => entry.kekId === note.encryptedDek.kekId);

  if (!linkedKek) {
    throw new Error(
      `Missing the local KEK for epoch-linked id ${note.encryptedDek.kekId}. Log in again and provide the older password for that KEK.`,
    );
  }

  const decryptedDocument = deserializeNoteDocument(
    await decryptStringWithAsymmetricKek(note, linkedKek.cryptKey),
  );

  return {
    content: decryptedDocument.content,
    createdAt: note.createdAt,
    id: note.id,
    title: decryptedDocument.title,
    updatedAt: note.updatedAt,
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

function requireLinkedKek(
  linkedKeks: { cryptKey: Uint8Array; kekId: string }[],
  activeKekId: string | null,
) {
  if (!activeKekId) {
    throw new Error('No active KEK is linked on this device. Log in again.');
  }

  const linkedKek = linkedKeks.find((entry) => entry.kekId === activeKekId) ?? null;

  if (!linkedKek) {
    throw new Error('The active KEK is missing from local storage. Log in again.');
  }

  return linkedKek;
}

async function deriveMissingLinkedKeks({
  baseLinkedKeks,
  email,
  missingMetadatas,
  passwordsByKekId,
}: {
  baseLinkedKeks: { cryptKey: Uint8Array; kekEpochVersion: number; kekId: string; saltHex: string }[];
  email: string;
  missingMetadatas: { kekEpochVersion: number; kekId: string }[];
  passwordsByKekId: Record<string, string>;
}) {
  if (missingMetadatas.length === 0) {
    return baseLinkedKeks;
  }

  const saltHex = baseLinkedKeks[0]?.saltHex;

  if (!saltHex) {
    throw new Error('The current password salt is missing from local storage. Log in again.');
  }

  const linkedKeks = [...baseLinkedKeks];

  for (const metadata of missingMetadatas) {
    const password = passwordsByKekId[metadata.kekId]?.trim();

    if (!password) {
      throw new Error(
        `Enter the password for KEK epoch ${metadata.kekEpochVersion} before continuing the migration.`,
      );
    }

    const credentials = await deriveCredentials(email, password, saltHex);

    linkedKeks.push({
      cryptKey: credentials.cryptKey,
      kekEpochVersion: metadata.kekEpochVersion,
      kekId: metadata.kekId,
      saltHex,
    });
  }

  return linkedKeks.sort((left, right) => right.kekEpochVersion - left.kekEpochVersion);
}