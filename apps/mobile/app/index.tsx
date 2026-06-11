import { Redirect } from 'expo-router';

import { useAuth } from '../src/features/auth/auth-context';

export default function IndexRoute() {
  const { isAuthenticated, isHydrated } = useAuth();

  if (!isHydrated) {
    return null;
  }

  return <Redirect href={isAuthenticated ? '/(tabs)' : '/auth'} />;
}
