import { ThemeProvider as NavigationThemeProvider } from '@react-navigation/native';
import { Slot } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import { Text, View } from 'react-native';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import { ThemeProvider, useAppTheme } from '../src/features/theme/theme-context';
import { navigationThemes, themeTokens } from '../src/theme/theme-tokens';

function RootNavigator() {
  const { isHydrated, themeMode } = useAppTheme();
  const tokens = themeTokens[themeMode];

  if (!isHydrated) {
    return (
      <>
        <StatusBar style={themeMode === 'dark' ? 'light' : 'dark'} />
        <View className={`flex-1 items-center justify-center ${tokens.screen}`}>
          <Text className={`text-base font-semibold ${tokens.title}`}>
            Loading preferences...
          </Text>
        </View>
      </>
    );
  }

  return (
    <NavigationThemeProvider value={navigationThemes[themeMode]}>
      <StatusBar style={themeMode === 'dark' ? 'light' : 'dark'} />
      <Slot />
    </NavigationThemeProvider>
  );
}

export default function RootLayout() {
  return (
    <GestureHandlerRootView className="flex-1">
      <SafeAreaProvider>
        <ThemeProvider>
          <RootNavigator />
        </ThemeProvider>
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}