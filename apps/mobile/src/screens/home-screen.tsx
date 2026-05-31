import { Text, View } from 'react-native';

import { ScreenShell } from '../components/screen-shell';
import { useAppTheme } from '../features/theme/theme-context';
import { themeTokens } from '../theme/theme-tokens';

export function HomeScreen() {
  const { themeMode } = useAppTheme();
  const tokens = themeTokens[themeMode];

  return (
    <ScreenShell
      description="The frontend is now an Expo app inside a Turbo monorepo. This screen is intentionally small, but it already sits behind real navigation and persisted theme state."
      themeMode={themeMode}
      title="Hello world"
    >
      <View className={`gap-4 rounded-[28px] border px-5 py-6 shadow-card ${tokens.card}`}>
        <Text className={`text-xl font-semibold ${tokens.title}`}>
          Frontend foundation in place
        </Text>
        <Text className={`text-base leading-7 ${tokens.body}`}>
          Use the bottom bar to move between this home screen and settings. The
          theme choice you make in settings is persisted with SecureStore.
        </Text>
      </View>

      <View className={`gap-3 rounded-[28px] border px-5 py-6 ${tokens.card}`}>
        <Text className={`text-sm uppercase tracking-[2px] ${tokens.kicker}`}>
          Monorepo
        </Text>
        <Text className={`text-base leading-7 ${tokens.body}`}>
          The mobile app lives in apps/mobile, ready for backend packages or
          shared libraries to be added later without reshaping the project.
        </Text>
      </View>
    </ScreenShell>
  );
}