import { useState } from 'react';
import { Pressable, Text, TextInput, View } from 'react-native';

import { ScreenShell } from '../components/screen-shell';
import { useAuth } from '../features/auth/auth-context';
import { ThemeModeToggle } from '../components/theme-mode-toggle';
import { useAppTheme } from '../features/theme/theme-context';
import { themeTokens } from '../theme/theme-tokens';

export function SettingsScreen() {
  const { backendUrl, signOut, updateBackendUrl } = useAuth();
  const { setThemeMode, themeMode } = useAppTheme();
  const tokens = themeTokens[themeMode];
  const [backendUrlInput, setBackendUrlInput] = useState(backendUrl);
  const [saveMessage, setSaveMessage] = useState('');

  async function handleSaveBackendUrl() {
    await updateBackendUrl(backendUrlInput);
    setSaveMessage('Backend URL updated.');
  }

  return (
    <ScreenShell
      description="Settings now covers both appearance and auth connectivity. Theme selection is still persisted securely, and the backend endpoint is configurable for device testing on your LAN."
      themeMode={themeMode}
      title="Settings"
    >
      <ThemeModeToggle onChange={setThemeMode} themeMode={themeMode} />

      <View className={`gap-3 rounded-[28px] border px-5 py-6 ${tokens.card}`}>
        <Text className={`text-sm uppercase tracking-[2px] ${tokens.kicker}`}>
          Backend
        </Text>
        <TextInput
          autoCapitalize="none"
          autoCorrect={false}
          className={`rounded-[22px] border px-4 py-4 text-base ${tokens.card} ${tokens.title}`}
          onChangeText={setBackendUrlInput}
          placeholder="http://192.168.x.x:4000"
          placeholderTextColor={themeMode === 'dark' ? '#94a3b8' : '#78716c'}
          value={backendUrlInput}
        />
        <Pressable
          className={`items-center rounded-full px-4 py-4 ${tokens.segmentActive}`}
          onPress={() => {
            void handleSaveBackendUrl();
          }}
        >
          <Text className={`text-sm font-semibold uppercase tracking-[1.5px] ${tokens.segmentActiveText}`}>
            Save backend URL
          </Text>
        </Pressable>
        <Text className={`text-base leading-7 ${tokens.body}`}>
          {saveMessage || 'Use a reachable LAN URL when testing from a physical device.'}
        </Text>
      </View>

      <View className={`gap-3 rounded-[28px] border px-5 py-6 ${tokens.card}`}>
        <Text className={`text-sm uppercase tracking-[2px] ${tokens.kicker}`}>
          Session
        </Text>
        <Text className={`text-base leading-7 ${tokens.body}`}>
          Signing out clears the stored access and refresh tokens while keeping the local KEK material for the next login.
        </Text>
        <Pressable
          className="items-center rounded-full border border-stone-300 px-4 py-4 dark:border-slate-700"
          onPress={() => {
            void signOut();
          }}
        >
          <Text className={`text-sm font-semibold uppercase tracking-[1.5px] ${tokens.title}`}>
            Sign out
          </Text>
        </Pressable>
      </View>
    </ScreenShell>
  );
}