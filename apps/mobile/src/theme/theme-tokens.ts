import {
  DarkTheme,
  DefaultTheme,
  Theme as NavigationTheme,
} from '@react-navigation/native';

import type { ThemeMode } from '../features/theme/theme-storage';

type ThemeTokenSet = {
  body: string;
  card: string;
  hero: string;
  kicker: string;
  sceneBackground: string;
  screen: string;
  segmentActive: string;
  segmentActiveText: string;
  segmentInactiveText: string;
  segmentTrack: string;
  tabBarActiveTint: string;
  tabBarBackground: string;
  tabBarBorder: string;
  tabBarInactiveTint: string;
  title: string;
};

export const themeTokens: Record<ThemeMode, ThemeTokenSet> = {
  light: {
    body: 'text-stone-600',
    card: 'border-stone-200 bg-white',
    hero: 'border border-accent-50 bg-[#f4fff9]',
    kicker: 'text-accent-700',
    sceneBackground: '#f7f6f2',
    screen: 'bg-[#f7f6f2]',
    segmentActive: 'bg-accent-600',
    segmentActiveText: 'text-white',
    segmentInactiveText: 'text-stone-600',
    segmentTrack: 'bg-stone-100',
    tabBarActiveTint: '#0f9d68',
    tabBarBackground: '#fffdf8',
    tabBarBorder: '#e7e2d7',
    tabBarInactiveTint: '#7c7465',
    title: 'text-stone-950',
  },
  dark: {
    body: 'text-slate-300',
    card: 'border-slate-800 bg-slate-900',
    hero: 'border border-slate-800 bg-[#12231f]',
    kicker: 'text-emerald-300',
    sceneBackground: '#08120f',
    screen: 'bg-[#08120f]',
    segmentActive: 'bg-emerald-400',
    segmentActiveText: 'text-slate-950',
    segmentInactiveText: 'text-slate-300',
    segmentTrack: 'bg-slate-800',
    tabBarActiveTint: '#6ee7b7',
    tabBarBackground: '#0f1720',
    tabBarBorder: '#1f2a37',
    tabBarInactiveTint: '#94a3b8',
    title: 'text-slate-50',
  },
};

export const navigationThemes: Record<ThemeMode, NavigationTheme> = {
  light: {
    ...DefaultTheme,
    colors: {
      ...DefaultTheme.colors,
      background: '#f7f6f2',
      border: '#e7e2d7',
      card: '#fffdf8',
      notification: '#0f9d68',
      primary: '#0f9d68',
      text: '#1c1917',
    },
  },
  dark: {
    ...DarkTheme,
    colors: {
      ...DarkTheme.colors,
      background: '#08120f',
      border: '#1f2a37',
      card: '#0f1720',
      notification: '#6ee7b7',
      primary: '#6ee7b7',
      text: '#f8fafc',
    },
  },
};