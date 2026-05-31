import { NavigationContainer } from '@react-navigation/native';
import { StatusBar } from 'expo-status-bar';
import { Text, View } from 'react-native';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import { ThemeProvider, useAppTheme } from './src/features/theme/theme-context';
import { AppTabs } from './src/navigation/app-tabs';
import { navigationThemes, themeTokens } from './src/theme/theme-tokens';

function AppShell() {
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
    <>
      <StatusBar style={themeMode === 'dark' ? 'light' : 'dark'} />
      <NavigationContainer theme={navigationThemes[themeMode]}>
        <AppTabs />
      </NavigationContainer>
    </>
  );
}

export default function App() {
  return (
    <GestureHandlerRootView className="flex-1">
      <SafeAreaProvider>
        <ThemeProvider>
          <AppShell />
        </ThemeProvider>
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}
