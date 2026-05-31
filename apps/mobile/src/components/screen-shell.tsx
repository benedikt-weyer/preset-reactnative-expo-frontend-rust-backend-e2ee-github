import { ReactNode } from 'react';
import { Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import type { ThemeMode } from '../features/theme/theme-storage';
import { themeTokens } from '../theme/theme-tokens';

type ScreenShellProps = {
  children: ReactNode;
  description: string;
  themeMode: ThemeMode;
  title: string;
};

export function ScreenShell({
  children,
  description,
  themeMode,
  title,
}: ScreenShellProps) {
  const tokens = themeTokens[themeMode];

  return (
    <SafeAreaView className={`flex-1 ${tokens.screen}`} edges={['top']}>
      <View className="flex-1 px-6 pb-8 pt-6">
        <View className={`mb-8 gap-3 rounded-[28px] px-6 py-7 ${tokens.hero}`}>
          <Text className={`text-3xl font-semibold ${tokens.title}`}>{title}</Text>
          <Text className={`text-base leading-6 ${tokens.body}`}>{description}</Text>
        </View>
        <View className="flex-1 gap-4">{children}</View>
      </View>
    </SafeAreaView>
  );
}