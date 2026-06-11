import { useEffect, useState } from 'react';
import { Pressable, Text, TextInput, View } from 'react-native';

import { decryptString, encryptString, type EncryptedPayload } from '@repo/e2ee-auth';

import { ScreenShell } from '../components/screen-shell';
import { useAuth } from '../features/auth/auth-context';
import { secureStoreVaultPersistence } from '../features/e2ee/vault-storage';
import { useAppTheme } from '../features/theme/theme-context';
import { themeTokens } from '../theme/theme-tokens';

export function HomeScreen() {
  const { cryptKey, session } = useAuth();
  const { themeMode } = useAppTheme();
  const tokens = themeTokens[themeMode];
  const [draft, setDraft] = useState('');
  const [statusMessage, setStatusMessage] = useState('');
  const [storedPayload, setStoredPayload] = useState<EncryptedPayload | null>(null);

  useEffect(() => {
    let isMounted = true;

    async function hydrateEncryptedNote() {
      const encryptedPayload = await secureStoreVaultPersistence.read();

      if (!isMounted) {
        return;
      }

      setStoredPayload(encryptedPayload);

      if (!encryptedPayload || !cryptKey) {
        return;
      }

      try {
        setDraft(decryptString(encryptedPayload, cryptKey));
        setStatusMessage('Encrypted note loaded and decrypted locally.');
      } catch (error) {
        setStatusMessage(
          error instanceof Error
            ? error.message
            : 'Stored note could not be decrypted.',
        );
      }
    }

    void hydrateEncryptedNote();

    return () => {
      isMounted = false;
    };
  }, [cryptKey]);

  async function handleSave() {
    if (!cryptKey) {
      return;
    }

    const encryptedPayload = encryptString(draft, cryptKey);
    await secureStoreVaultPersistence.write(encryptedPayload);
    setStoredPayload(encryptedPayload);
    setStatusMessage('Encrypted note saved to SecureStore.');
  }

  async function handleClear() {
    await secureStoreVaultPersistence.clear();
    setDraft('');
    setStoredPayload(null);
    setStatusMessage('Encrypted note cleared from local storage.');
  }

  return (
    <ScreenShell
      description="Once authenticated, this screen uses the password-derived crypt key on-device to encrypt and decrypt a local note. The backend only sees the derived auth key, never the raw password or plaintext note."
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
          sent to the Rust backend for registration and login.
        </Text>
      </View>

      <View className={`gap-3 rounded-[28px] border px-5 py-6 ${tokens.card}`}>
        <Text className={`text-sm uppercase tracking-[2px] ${tokens.kicker}`}>
          Local vault
        </Text>
        <TextInput
          className={`min-h-[150px] rounded-[22px] border px-4 py-4 text-base ${tokens.card} ${tokens.title}`}
          multiline
          onChangeText={setDraft}
          placeholder="Write something that should stay encrypted at rest on the device"
          placeholderTextColor={themeMode === 'dark' ? '#94a3b8' : '#78716c'}
          textAlignVertical="top"
          value={draft}
        />
        <View className="flex-row gap-3">
          <Pressable
            className={`flex-1 items-center rounded-full px-4 py-4 ${tokens.segmentActive}`}
            onPress={() => {
              void handleSave();
            }}
          >
            <Text className={`text-sm font-semibold uppercase tracking-[1.5px] ${tokens.segmentActiveText}`}>
              Save encrypted note
            </Text>
          </Pressable>
          <Pressable
            className="flex-1 items-center rounded-full border border-stone-300 px-4 py-4 dark:border-slate-700"
            onPress={() => {
              void handleClear();
            }}
          >
            <Text className={`text-sm font-semibold uppercase tracking-[1.5px] ${tokens.title}`}>
              Clear
            </Text>
          </Pressable>
        </View>
        <Text className={`text-base leading-7 ${tokens.body}`}>
          {statusMessage || 'Nothing encrypted yet. Save a note to exercise the E2EE flow.'}
        </Text>
        {storedPayload ? (
          <Text className={`text-sm leading-6 ${tokens.body}`}>
            Ciphertext preview: {storedPayload.ciphertextHex.slice(0, 64)}...
          </Text>
        ) : null}
      </View>
    </ScreenShell>
  );
}