'use client';

import { useEffect, useState } from 'react';
import { ArrowRight, LockKeyhole, ShieldCheck, UserRound } from 'lucide-react';

import {
  createPasswordSalt,
  decryptStringWithDek,
  deriveCredentials,
  encryptStringWithDek,
  normalizeEmail,
  type CryptKey,
  type KekDekEncryptedPayload,
} from '@repo/e2ee-auth/web';

import { Button } from '@/components/ui/button';
import {
  fetchPasswordSalt,
  loginRequest,
  registerRequest,
  type AuthApiResponse,
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
  payload: KekDekEncryptedPayload;
  title: string;
  content: string;
  updatedAt: string;
};

const featureNotes = [
  'The typed password stays in the browser and derives two keys locally.',
  'The backend sees only the derived auth key plus the per-account salt.',
  'Each note stores one encrypted document plus one wrapped per-resource DEK addressed by a UUID.',
];

export function AuthExperience() {
  const [mode, setMode] = useState<AuthMode>('register');
  const [backendUrl, setBackendUrl] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [noteTitle, setNoteTitle] = useState('');
  const [noteContent, setNoteContent] = useState('');
  const [notes, setNotes] = useState<DecryptedNote[]>([]);
  const [selectedNoteId, setSelectedNoteId] = useState<string | null>(null);
  const [session, setSession] = useState<AuthApiResponse | null>(null);
  const [linkedKeks, setLinkedKeks] = useState<PersistedLinkedKek[]>([]);
  const [activeKekId, setActiveKekId] = useState<string | null>(null);
  const [olderPasswords, setOlderPasswords] = useState<Record<string, string>>({});
  const [requiredOlderKeks, setRequiredOlderKeks] = useState<KekMetadata[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState('');
  const [isHydrated, setIsHydrated] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

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
      setActiveKekId(resolveActiveKekId(storedSession, nextLinkedKeks));

      setIsHydrated(true);
    });
  }, []);

  useEffect(() => {
    if (!isHydrated) {
      return;
    }

    if (!session || linkedKeks.length === 0) {
      setNotes([]);
      applySelectedNote(null);
      return;
    }

    void loadNotes({
      emptyMessage: 'No synced notes yet. Create one to push ciphertext to the backend.',
      linkedKeks,
      token: session.token,
      trimmedBackendUrl: backendUrl.trim(),
    });
  }, [activeKekId, backendUrl, isHydrated, linkedKeks, session]);

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
                !findLinkedKek(persistedLinkedKeks, metadata.kekId) &&
                !olderPasswords[metadata.kekId]?.trim(),
            )
          : [];

      setRequiredOlderKeks(sortedKekMetadatas.slice(1));

      if (missingOlderKeks.length > 0) {
        throw new Error('Enter the passwords for the older active KEKs before logging in.');
      }

      const credentials = await deriveCredentials(normalizedEmail, password, saltHex);
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
      setLinkedKeks(nextLinkedKeks);
      setActiveKekId(latestKekMetadata.kekId);
      setEmail(credentials.email);
      setPassword('');
      setOlderPasswords({});
      writeAuthPreferences({
        backendUrl: trimmedBackendUrl,
        lastEmail: credentials.email,
      });
      localStorageAuthPersistence.writeAuthSession(response);
      localStorageAuthPersistence.writeDerivedCredentials({
        email: credentials.email,
        linkedKeks: nextLinkedKeks,
      });
      await loadNotes({
        emptyMessage:
          mode === 'register'
            ? 'Account created. Create a note to push ciphertext to the backend.'
            : 'Logged in. Create a note to push ciphertext to the backend.',
        linkedKeks: nextLinkedKeks,
        token: response.token,
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
    setSession(null);
    setActiveKekId(null);
    setPassword('');
    setOlderPasswords({});
    setNotes([]);
    applySelectedNote(null);
    localStorageAuthPersistence.clearAuthSession();
    setStatusMessage(
      'Signed out. Synced notes remain on the backend, and the linked KEKs stay stored for the next login.',
    );
  }

  async function loadNotes({
    emptyMessage,
    linkedKeks,
    token,
    trimmedBackendUrl,
  }: {
    emptyMessage: string;
    linkedKeks: PersistedLinkedKek[];
    token: string;
    trimmedBackendUrl: string;
  }) {
    try {
      const remoteNotes = await fetchNotes({
        baseUrl: trimmedBackendUrl,
        token,
      });
      const decryptedNotes = sortNotes(
        remoteNotes.map((note) => decryptNoteRecord(note, linkedKeks)),
      );

      setNotes(decryptedNotes);

      const nextSelectedNote =
        decryptedNotes.find((note) => note.id === selectedNoteId) ?? decryptedNotes[0] ?? null;

      applySelectedNote(nextSelectedNote);
      setStatusMessage(
        nextSelectedNote
          ? `Loaded ${decryptedNotes.length} encrypted note${decryptedNotes.length === 1 ? '' : 's'} from the backend.`
          : emptyMessage,
      );
    } catch (error) {
      setNotes([]);
      applySelectedNote(null);
      setStatusMessage(
        error instanceof Error ? error.message : 'Unable to load encrypted notes.',
      );
    }
  }

  function applySelectedNote(note: DecryptedNote | null) {
    setSelectedNoteId(note?.id ?? null);
    setNoteTitle(note?.title ?? '');
    setNoteContent(note?.content ?? '');
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

    const activeLinkedKek = requireLinkedKek(linkedKeks, activeKekId);

    setErrorMessage(null);

    try {
      const encryptedPayload = encryptStringWithDek(
        serializeNoteDocument({
          content: noteContent,
          title: noteTitle,
        }),
        activeLinkedKek.cryptKey,
        activeLinkedKek.kekId,
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

          const decryptedNote = decryptNoteRecord(savedNote, linkedKeks);
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
      setErrorMessage(
        error instanceof Error ? error.message : 'Unable to delete the encrypted note.',
      );
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
                        key={metadata.kekId}
                        label={`Older password v${metadata.kekEpochVersion}`}
                        onChange={(value) =>
                          setOlderPasswords((currentPasswords) => ({
                            ...currentPasswords,
                            [metadata.kekId]: value,
                          }))
                        }
                        placeholder="Type the older password for this active KEK"
                        type="password"
                        value={olderPasswords[metadata.kekId] ?? ''}
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

function decryptNoteRecord(note: NoteResponse, linkedKeks: PersistedLinkedKek[]): DecryptedNote {
  const linkedKek = findLinkedKek(linkedKeks, note.encryptedDek.kekId);

  if (!linkedKek) {
    throw new Error(
      `Missing the local KEK for epoch-linked id ${note.encryptedDek.kekId}. Log in again and provide the older password for that KEK.`,
    );
  }

  const decryptedDocument = deserializeNoteDocument(
    decryptStringWithDek(note, linkedKek.cryptKey),
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

function mergeLinkedKeks(linkedKeks: PersistedLinkedKek[]) {
  const entriesByKekId = new Map<string, PersistedLinkedKek>();

  for (const linkedKek of linkedKeks) {
    entriesByKekId.set(linkedKek.kekId, linkedKek);
  }

  return [...entriesByKekId.values()].sort(
    (left, right) => right.kekEpochVersion - left.kekEpochVersion,
  );
}

function findLinkedKek(linkedKeks: PersistedLinkedKek[], kekId: string) {
  return linkedKeks.find((linkedKek) => linkedKek.kekId === kekId) ?? null;
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

function resolveActiveKekId(
  session: AuthApiResponse | null,
  linkedKeks: PersistedLinkedKek[],
) {
  const sortedMetadatas = sortKekMetadatas(session?.kekMetadatas ?? []);

  for (const metadata of sortedMetadatas) {
    if (findLinkedKek(linkedKeks, metadata.kekId)) {
      return metadata.kekId;
    }
  }

  return linkedKeks[0]?.kekId ?? null;
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value));
}