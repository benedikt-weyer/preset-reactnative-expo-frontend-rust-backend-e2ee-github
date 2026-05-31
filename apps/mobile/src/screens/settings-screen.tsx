import { Text, View } from 'react-native';

import { ScreenShell } from '../components/screen-shell';
import { ThemeModeToggle } from '../components/theme-mode-toggle';
import { useAppTheme } from '../features/theme/theme-context';
import { themeTokens } from '../theme/theme-tokens';

export function SettingsScreen() {
  const { setThemeMode, themeMode } = useAppTheme();
  const tokens = themeTokens[themeMode];

  return (
    <ScreenShell
      description="Settings currently focuses on appearance. The selected theme is stored securely and applied immediately across the tab navigator and screens."
      themeMode={themeMode}
      title="Settings"
    >
      <ThemeModeToggle onChange={setThemeMode} themeMode={themeMode} />

      <View className={`gap-3 rounded-[28px] border px-5 py-6 ${tokens.card}`}>
        <Text className={`text-sm uppercase tracking-[2px] ${tokens.kicker}`}>
          Persistence
        </Text>
        <Text className={`text-base leading-7 ${tokens.body}`}>
          Theme mode is written to SecureStore so the selection survives app
          restarts instead of resetting to a hard-coded default.
        </Text>
      </View>
    </ScreenShell>
  );
}