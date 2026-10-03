import {
  createContext,
  type PropsWithChildren,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { apiRequest, setCsrfToken } from '../api/client';
import type { SessionResponse, SetupStatus, UserSummary } from '../api/types';

interface AuthState {
  user: UserSummary | null;
  setupRequired: boolean | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  setup: (username: string, displayName: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: PropsWithChildren) {
  const [user, setUser] = useState<UserSummary | null>(null);
  const [setupRequired, setSetupRequired] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);

  const applySession = useCallback((session: SessionResponse | null) => {
    setUser(session?.user ?? null);
    setCsrfToken(session?.csrf_token ?? null);
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const setupStatus = await apiRequest<SetupStatus>('/api/v1/system/setup-status');
      setSetupRequired(setupStatus.setup_required);
      if (setupStatus.setup_required) {
        applySession(null);
        return;
      }
      try {
        applySession(await apiRequest<SessionResponse>('/api/v1/auth/session'));
      } catch {
        applySession(null);
      }
    } finally {
      setLoading(false);
    }
  }, [applySession]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const handleUnauthorized = () => applySession(null);
    window.addEventListener('vulnerability-workbench:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('vulnerability-workbench:unauthorized', handleUnauthorized);
  }, [applySession]);

  const login = useCallback(
    async (username: string, password: string) => {
      const session = await apiRequest<SessionResponse>('/api/v1/auth/login', {
        method: 'POST',
        body: { username, password },
      });
      applySession(session);
      setSetupRequired(false);
    },
    [applySession],
  );

  const setup = useCallback(
    async (username: string, displayName: string, password: string) => {
      const session = await apiRequest<SessionResponse>('/api/v1/auth/setup', {
        method: 'POST',
        body: { username, display_name: displayName, password },
      });
      applySession(session);
      setSetupRequired(false);
    },
    [applySession],
  );

  const logout = useCallback(async () => {
    await apiRequest('/api/v1/auth/logout', { method: 'POST' });
    applySession(null);
  }, [applySession]);

  const value = useMemo(
    () => ({ user, setupRequired, loading, login, setup, logout, refresh }),
    [user, setupRequired, loading, login, setup, logout, refresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
}
