import { createContext, useContext, useState, useCallback } from 'react';
import { useMountEffect } from '@/hooks/useMountEffect';

type Theme = 'light' | 'dark' | 'system';

interface ThemeContextType {
  theme: Theme;
  resolvedTheme: 'light' | 'dark';
  setTheme: (t: Theme) => void;
}

const ThemeContext = createContext<ThemeContextType>({
  theme: 'system',
  resolvedTheme: 'light',
  setTheme: () => {},
});

export const useTheme = () => useContext(ThemeContext);

function getSystemTheme(): 'light' | 'dark' {
  if (typeof window === 'undefined') return 'light';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => {
    return (localStorage.getItem('csm_theme') as Theme) || 'system';
  });

  const [systemTheme, setSystemTheme] = useState<'light' | 'dark'>(getSystemTheme);

  // Derive resolvedTheme inline — no useEffect needed
  const resolvedTheme = theme === 'system' ? systemTheme : theme;

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t);
    localStorage.setItem('csm_theme', t);
    // Apply to DOM immediately in the handler
    const resolved = t === 'system' ? getSystemTheme() : t;
    document.documentElement.classList.remove('light', 'dark');
    document.documentElement.classList.add(resolved);
  }, []);

  // Listen for system theme changes — mount-time subscription
  useMountEffect(() => {
    // Apply initial theme to DOM
    document.documentElement.classList.remove('light', 'dark');
    document.documentElement.classList.add(resolvedTheme);

    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = () => {
      const next = getSystemTheme();
      setSystemTheme(next);
      // Only update DOM if current theme is 'system'
      // Read from localStorage to get current theme since state may be stale in this closure
      const currentTheme = localStorage.getItem('csm_theme') || 'system';
      if (currentTheme === 'system') {
        document.documentElement.classList.remove('light', 'dark');
        document.documentElement.classList.add(next);
      }
    };
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  });

  return (
    <ThemeContext.Provider value={{ theme, resolvedTheme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}
