import { Pressable, Text, View } from 'react-native';

import type { ThemeMode } from '../features/theme/theme-storage';
import { themeTokens } from '../theme/theme-tokens';

type ThemeModeToggleProps = {
  onChange: (themeMode: ThemeMode) => void;
  themeMode: ThemeMode;
};

const THEME_OPTIONS: ThemeMode[] = ['light', 'dark'];

export function ThemeModeToggle({ onChange, themeMode }: ThemeModeToggleProps) {
  const tokens = themeTokens[themeMode];

  return (
    <View className={`gap-5 rounded-[28px] border px-5 py-6 shadow-card ${tokens.card}`}>
      <View className="gap-2">
        <Text className={`text-xl font-semibold ${tokens.title}`}>Appearance</Text>
        <Text className={`text-sm leading-6 ${tokens.body}`}>
          Choose the mode that should be applied across the app. The selection is
          stored in SecureStore and restored when the app launches again.
        </Text>
      </View>

      <View className={`flex-row rounded-full p-1 ${tokens.segmentTrack}`}>
        {THEME_OPTIONS.map((option) => {
          const isActive = option === themeMode;

          return (
            <Pressable
              accessibilityRole="button"
              accessibilityState={{ selected: isActive }}
              className={`flex-1 rounded-full px-4 py-3 ${
                isActive ? tokens.segmentActive : 'bg-transparent'
              }`}
              key={option}
              onPress={() => onChange(option)}
            >
              <Text
                className={`text-center text-sm font-semibold ${
                  isActive ? tokens.segmentActiveText : tokens.segmentInactiveText
                }`}
              >
                {option === 'light' ? 'Light mode' : 'Dark mode'}
              </Text>
            </Pressable>
          );
        })}
      </View>
    </View>
  );
}