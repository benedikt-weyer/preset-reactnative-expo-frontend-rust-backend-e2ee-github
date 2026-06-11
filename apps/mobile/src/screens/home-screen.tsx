import { useEffect, useState } from 'react';
import { Pressable, Text, TextInput, View } from 'react-native';

import {
  type CryptKey,
  decryptString,
  encryptString,
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

export function HomeScreen() {
  const { backendUrl, cryptKey, session } = useAuth();
  const { themeMode } = useAppTheme();
  const tokens = themeTokens[themeMode];
  const [noteTitle, setNoteTitle] = useState('');
  const [noteContent, setNoteContent] = useState('');
  const [notes, setNotes] = useState<DecryptedNote[]>([]);
  const [selectedNoteId, setSelectedNoteId] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState('');

  useEffect(() => {
    let isMounted = true;

    async function hydrateNotes() {
      if (!cryptKey || !session) {
        if (isMounted) {
          setNotes([]);
          applySelectedNote(null);
        }
        return;
      }

      try {
        const remoteNotes = await fetchNotes({
          baseUrl: backendUrl,
          token: session.token,
        });

        if (!isMounted) {
          return;
        }

        const decryptedNotes = sortNotes(
          remoteNotes.map((note) => decryptNoteRecord(note, cryptKey)),
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
  }, [backendUrl, cryptKey, session]);

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
    if (!cryptKey || !session) {
      return;
    }

    try {
      const encryptedPayload = encryptString(
        serializeNoteDocument({
          content: noteContent,
          title: noteTitle,
        }),
        cryptKey,
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

      const decryptedNote = decryptNoteRecord(savedNote, cryptKey);
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
          That crypt key encrypts local data, while a separate derived auth key is
          sent to the Rust backend for registration, login, and ciphertext sync.
        </Text>
      </View>

      <View className={`gap-3 rounded-[28px] border px-5 py-6 ${tokens.card}`}>
        <Text className={`text-sm uppercase tracking-[2px] ${tokens.kicker}`}>
          Notes vault
        </Text>
        <Text className={`text-base leading-7 ${tokens.body}`}>
          Create, update, and delete encrypted notes. The backend stores only ciphertext,
          and only the password-derived crypt key can decrypt the note document.
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

function decryptNoteRecord(note: NoteResponse, cryptKey: CryptKey): DecryptedNote {
  const decryptedDocument = deserializeNoteDocument(decryptString(note, cryptKey));

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