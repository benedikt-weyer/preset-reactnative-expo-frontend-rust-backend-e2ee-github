import { useState } from 'react';
import {
  ActivityIndicator,
  Pressable,
  Text,
  TextInput,
  View,
} from 'react-native';

import { ScreenShell } from '../components/screen-shell';
import { useAuth } from '../features/auth/auth-context';
import { useAppTheme } from '../features/theme/theme-context';
import { themeTokens } from '../theme/theme-tokens';

type AuthMode = 'login' | 'register';

export function AuthScreen() {
  const { backendUrl, isHydrated, lastEmail, login, register, updateBackendUrl } = useAuth();
  const { themeMode } = useAppTheme();
  const tokens = themeTokens[themeMode];

  const [mode, setMode] = useState<AuthMode>('register');
  const [email, setEmail] = useState(lastEmail);
  const [password, setPassword] = useState('');
  const [backendUrlInput, setBackendUrlInput] = useState(backendUrl);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit() {
    setIsSubmitting(true);
    setErrorMessage(null);

    try {
      await updateBackendUrl(backendUrlInput);

      if (mode === 'register') {
        await register(email, password);
      } else {
        await login(email, password);
      }
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Authentication failed unexpectedly.',
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <ScreenShell
      description="Register or log in with your plain email. The typed password never leaves the device directly: the app derives a crypt key for local encryption and a separate auth key for the backend."
      themeMode={themeMode}
      title="Auth"
    >
      <View className={`gap-4 rounded-[28px] border px-5 py-6 ${tokens.card}`}>
        <View className={`flex-row rounded-full p-1 ${tokens.segmentTrack}`}>
          {(['register', 'login'] as const).map((nextMode) => {
            const isActive = nextMode === mode;
            return (
              <Pressable
                className={`flex-1 rounded-full px-4 py-3 ${isActive ? tokens.segmentActive : ''}`}
                key={nextMode}
                onPress={() => setMode(nextMode)}
              >
                <Text
                  className={`text-center text-sm font-semibold uppercase tracking-[1.5px] ${
                    isActive ? tokens.segmentActiveText : tokens.segmentInactiveText
                  }`}
                >
                  {nextMode}
                </Text>
              </Pressable>
            );
          })}
        </View>

        <LabeledInput
          autoCapitalize="none"
          autoComplete="email"
          keyboardType="email-address"
          label="Email"
          onChangeText={setEmail}
          placeholder="hello@example.com"
          themeMode={themeMode}
          value={email}
        />
        <LabeledInput
          autoCapitalize="none"
          autoComplete="password"
          label="Password"
          onChangeText={setPassword}
          placeholder="Type the password used to derive keys"
          secureTextEntry
          themeMode={themeMode}
          value={password}
        />
        <LabeledInput
          autoCapitalize="none"
          autoCorrect={false}
          label="Backend URL"
          onChangeText={setBackendUrlInput}
          placeholder="http://192.168.x.x:4000"
          themeMode={themeMode}
          value={backendUrlInput}
        />

        <Text className={`text-sm leading-6 ${tokens.body}`}>
          On a physical device, point this at a reachable LAN address for the Rust backend.
        </Text>

        {errorMessage ? (
          <Text className="rounded-2xl bg-rose-100 px-4 py-3 text-sm font-medium text-rose-700 dark:bg-rose-950 dark:text-rose-200">
            {errorMessage}
          </Text>
        ) : null}

        <Pressable
          className={`items-center rounded-full px-5 py-4 ${tokens.segmentActive}`}
          disabled={isSubmitting || !isHydrated}
          onPress={() => {
            void handleSubmit();
          }}
        >
          {isSubmitting ? (
            <ActivityIndicator color={themeMode === 'dark' ? '#020617' : '#ffffff'} />
          ) : (
            <Text className={`text-sm font-semibold uppercase tracking-[1.5px] ${tokens.segmentActiveText}`}>
              {mode === 'register' ? 'Create account' : 'Log in'}
            </Text>
          )}
        </Pressable>
      </View>
    </ScreenShell>
  );
}

type LabeledInputProps = Readonly<{
  autoCapitalize?: 'none' | 'sentences' | 'words' | 'characters';
  autoComplete?: 'email' | 'password' | 'off';
  autoCorrect?: boolean;
  keyboardType?: 'default' | 'email-address';
  label: string;
  onChangeText: (value: string) => void;
  placeholder: string;
  secureTextEntry?: boolean;
  themeMode: 'light' | 'dark';
  value: string;
}>;

function LabeledInput({ label, themeMode, ...rest }: LabeledInputProps) {
  const tokens = themeTokens[themeMode];

  return (
    <View className="gap-2">
      <Text className={`text-sm font-semibold uppercase tracking-[1.5px] ${tokens.kicker}`}>
        {label}
      </Text>
      <TextInput
        className={`rounded-[22px] border px-4 py-4 text-base ${tokens.card} ${tokens.title}`}
        placeholderTextColor={themeMode === 'dark' ? '#94a3b8' : '#78716c'}
        {...rest}
      />
    </View>
  );
}
