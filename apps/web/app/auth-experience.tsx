'use client';

import { useEffect, useState } from 'react';
import { ArrowRight, LockKeyhole, ShieldCheck, UserRound } from 'lucide-react';

import {
  createPasswordSalt,
  decryptString,
  deriveCredentials,
  encryptString,
  normalizeEmail,
  type CryptKey,
  type EncryptedPayload,
} from '@repo/e2ee-auth/web';

import { Button } from '@/components/ui/button';
import {
  fetchPasswordSalt,
  loginRequest,
  registerRequest,
  type AuthApiResponse,
} from '@/lib/auth-api';
import {
  deleteTestNote,
  fetchTestNote,
  saveTestNote,
} from '@/lib/test-note-api';
import { readAuthPreferences, writeAuthPreferences } from '@/lib/auth-storage';
import {
  clearEncryptedVault,
  readEncryptedVault,
  writeEncryptedVault,
} from '@/lib/vault-storage';

type AuthMode = 'login' | 'register';

const featureNotes = [
  'The typed password stays in the browser and derives two keys locally.',
  'The backend sees only the derived auth key plus the per-account salt.',
  'The shared demo note is synced as ciphertext and decrypted only after sign-in.',
];

export function AuthExperience() {
  const [mode, setMode] = useState<AuthMode>('register');
  const [backendUrl, setBackendUrl] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [draft, setDraft] = useState('');
  const [session, setSession] = useState<AuthApiResponse | null>(null);
  const [cryptKey, setCryptKey] = useState<CryptKey | null>(null);
  const [storedPayload, setStoredPayload] = useState<EncryptedPayload | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState('');
  const [isHydrated, setIsHydrated] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    queueMicrotask(() => {
      const preferences = readAuthPreferences();

      setBackendUrl(preferences.backendUrl);
      setEmail(preferences.lastEmail);
      setStoredPayload(readEncryptedVault());
      setIsHydrated(true);
    });
  }, []);

  async function handleSubmit() {
    setErrorMessage(null);
    setIsSubmitting(true);

    try {
      const trimmedBackendUrl = backendUrl.trim();
      const normalizedEmail = normalizeEmail(email);
      const saltHex =
        mode === 'login'
          ? await fetchPasswordSalt({
              baseUrl: trimmedBackendUrl,
              email: normalizedEmail,
            })
          : await createPasswordSalt();
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

      setSession(response);
      setCryptKey(credentials.cryptKey);
      setPassword('');
      writeAuthPreferences({
        backendUrl: trimmedBackendUrl,
        lastEmail: credentials.email,
      });
      await loadEncryptedNote({
        cryptKey: credentials.cryptKey,
        fallbackMessage:
          mode === 'register'
            ? 'Account created. Save a note to push ciphertext to the backend.'
            : 'Logged in. Save a note to push ciphertext to the backend.',
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
    setCryptKey(null);
    setPassword('');
    setStatusMessage('Signed out. The synced ciphertext remains on the backend and in local cache.');
  }

  async function loadEncryptedNote({
    cryptKey,
    fallbackMessage,
    token,
    trimmedBackendUrl,
  }: {
    cryptKey: CryptKey;
    fallbackMessage: string;
    token: string;
    trimmedBackendUrl: string;
  }) {
    const localPayload = readEncryptedVault();

    try {
      const remotePayload = await fetchTestNote({
        baseUrl: trimmedBackendUrl,
        token,
      });

      if (remotePayload) {
        writeEncryptedVault(remotePayload);
        setStoredPayload(remotePayload);
        setDraft(decryptString(remotePayload, cryptKey));
        setStatusMessage('Encrypted note loaded from the backend and decrypted locally.');
        return;
      }

      if (localPayload) {
        setStoredPayload(localPayload);
        setDraft(decryptString(localPayload, cryptKey));
        setStatusMessage('Loaded local encrypted note. Save it to sync ciphertext to the backend.');
        return;
      }

      setDraft('');
      setStoredPayload(null);
      setStatusMessage(fallbackMessage);
    } catch (error) {
      if (localPayload) {
        setStoredPayload(localPayload);

        try {
          setDraft(decryptString(localPayload, cryptKey));
          setStatusMessage(
            'Backend note unavailable. Loaded the local encrypted cache instead.',
          );
          return;
        } catch {
          // Fall through to the remote error message.
        }
      }

      setDraft('');
      setStoredPayload(null);
      setStatusMessage(
        error instanceof Error ? error.message : 'Unable to load the synced encrypted note.',
      );
    }
  }

  async function handleSaveNote() {
    if (!cryptKey || !session) {
      return;
    }

    setErrorMessage(null);

    try {
      const encryptedPayload = encryptString(draft, cryptKey);
      const savedPayload = await saveTestNote({
        baseUrl: backendUrl,
        payload: encryptedPayload,
        token: session.token,
      });

      writeEncryptedVault(savedPayload);
      setStoredPayload(savedPayload);
      setStatusMessage('Encrypted note saved to the backend as ciphertext.');
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Unable to save the synced encrypted note.',
      );
    }
  }

  async function handleClearNote() {
    if (!session) {
      return;
    }

    setErrorMessage(null);

    try {
      await deleteTestNote({
        baseUrl: backendUrl,
        token: session.token,
      });
      clearEncryptedVault();
      setDraft('');
      setStoredPayload(null);
      setStatusMessage('Encrypted note cleared from the backend and local cache.');
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Unable to clear the synced encrypted note.',
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

          {!session ? (
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
              </div>

              <p className="rounded-[1.5rem] border border-border/60 bg-background/70 px-4 py-3 text-sm leading-6 text-foreground/75">
                The typed password never goes to the backend directly. The browser derives the
                local crypt key and the backend auth key from the same salt-backed input.
              </p>

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
          ) : (
            <div className="grid gap-5">
              <div className="grid gap-3 rounded-[1.6rem] border border-border/70 bg-background/80 p-5">
                <div className="flex items-center gap-3 text-foreground">
                  <UserRound className="size-5 text-primary" />
                  <p className="text-sm uppercase tracking-[0.22em] text-muted-foreground">
                    Local vault
                  </p>
                </div>
                <p className="text-sm leading-6 text-foreground/75">
                  Save a note to verify the E2EE path. The backend stores only ciphertext,
                  and only the current password-derived crypt key can decrypt it.
                </p>
                <textarea
                  className="min-h-44 rounded-[1.5rem] border border-border bg-white px-4 py-4 text-base text-foreground outline-none transition focus:border-primary/60 focus:ring-2 focus:ring-primary/20"
                  onChange={(event) => setDraft(event.target.value)}
                  placeholder="Write something that should stay encrypted between web and mobile"
                  value={draft}
                />
                <div className="flex flex-col gap-3 sm:flex-row">
                  <Button onClick={handleSaveNote} size="lg">
                    <LockKeyhole />
                    Save encrypted note
                  </Button>
                  <Button onClick={handleClearNote} size="lg" variant="outline">
                    Clear
                  </Button>
                </div>
              </div>

              <div className="grid gap-3 rounded-[1.6rem] border border-border/70 bg-muted/45 p-5 text-sm leading-6 text-foreground/75">
                <p>
                  {statusMessage ||
                    'Nothing encrypted yet. Save a note to exercise the synced E2EE flow.'}
                </p>
                {storedPayload ? (
                  <p>
                    Ciphertext preview:{' '}
                    <span className="font-mono text-xs">
                      {storedPayload.ciphertextHex.slice(0, 64)}...
                    </span>
                  </p>
                ) : null}
              </div>
            </div>
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
  type: 'email' | 'password';
  value: string;
};

function LabeledInput({ autoComplete, label, onChange, placeholder, type, value }: LabeledInputProps) {
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