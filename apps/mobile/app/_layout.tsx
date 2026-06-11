import { ThemeProvider as NavigationThemeProvider } from '@react-navigation/native';
import { Slot, usePathname, useRouter } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import { useEffect } from 'react';
import { Text, View } from 'react-native';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { SafeAreaProvider } from 'react-native-safe-area-context';

import { AuthProvider, useAuth } from '../src/features/auth/auth-context';
import { ThemeProvider, useAppTheme } from '../src/features/theme/theme-context';
import { navigationThemes, themeTokens } from '../src/theme/theme-tokens';

function RootNavigator() {
  const { isHydrated: isAuthHydrated, isAuthenticated } = useAuth();
  const { isHydrated: isThemeHydrated, themeMode } = useAppTheme();
  const pathname = usePathname();
  const router = useRouter();
  const tokens = themeTokens[themeMode];

  useEffect(() => {
    if (!isAuthHydrated || !isThemeHydrated) {
      return;
    }

    const inAuthRoute = pathname === '/auth';
    const inTabsRoute = pathname.startsWith('/(tabs)') || pathname === '/settings' || pathname === '/';

    if (!isAuthenticated && inTabsRoute && pathname !== '/auth') {
      router.replace('/auth');
      return;
    }

    if (isAuthenticated && inAuthRoute) {
      router.replace('/(tabs)');
    }
  }, [isAuthHydrated, isAuthenticated, isThemeHydrated, pathname, router]);

  if (!isAuthHydrated || !isThemeHydrated) {
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
          <AuthProvider>
            <RootNavigator />
          </AuthProvider>
        </ThemeProvider>
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}