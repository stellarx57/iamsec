/**
 * IAMsec - Auth Provider
 * React context provider for authentication state
 */

'use client';

import React, { createContext, useState, useEffect, useCallback, ReactNode } from 'react';
import Cookies from 'js-cookie';
import {
  IUser,
  ISession,
  ICredentials,
  IAuthResult,
  IAuthContext,
} from '../types';

/**
 * Auth Context
 */
export const AuthContext = createContext<IAuthContext | null>(null);

import { IAMSecConfig, mergeConfig } from '../types/config';

/**
 * Auth Provider Props
 */
interface AuthProviderProps {
  children: ReactNode;
  initialUser?: IUser | null;
  initialSession?: ISession | null;
  config?: Partial<IAMSecConfig>;
}

/**
 * Auth Provider Component
 */
export function AuthProvider({ children, initialUser, initialSession, config: userConfig }: AuthProviderProps) {
  const config = mergeConfig(userConfig);
  const [user, setUser] = useState<IUser | null>(initialUser || null);
  const [session, setSession] = useState<ISession | null>(initialSession || null);
  const [isLoading, setIsLoading] = useState(true);

  /**
   * Initialize authentication state from storage
   */
  useEffect(() => {
    const initializeAuth = async () => {
      try {
        // Check for stored session
        const cookieName = config.auth?.sessionCookieName || 'iamsec_session';
        const storedSession = Cookies.get(cookieName);
        
        if (storedSession) {
          const sessionData = JSON.parse(storedSession);
          
          // Validate session hasn't expired
          const expiresAt = new Date(sessionData.expiresAt);
          if (expiresAt > new Date()) {
            setUser(sessionData.user);
            setSession(sessionData);
          } else {
            // Session expired, clean up
            Cookies.remove(cookieName);
          }
        }
      } catch (error) {
        console.error('Failed to initialize auth:', error);
      } finally {
        setIsLoading(false);
      }
    };

    initializeAuth();
  }, []);

  /**
   * Login function
   */
  const login = useCallback(async (credentials: ICredentials): Promise<IAuthResult> => {
    setIsLoading(true);

    try {
      // Call authentication API
      const loginEndpoint = config.auth?.apiEndpoints?.login || '/api/auth/login';
      const response = await fetch(loginEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(credentials),
      });

      const result: IAuthResult = await response.json();

      if (result.success && result.session) {
        // Store session
        setUser(result.session.user);
        setSession(result.session);

        // Store in cookies
        const cookieName = config.auth?.sessionCookieName || 'iamsec_session';
        const cookieOptions = config.auth?.cookieOptions || {};
        Cookies.set(cookieName, JSON.stringify(result.session), {
          expires: new Date(result.session.expiresAt),
          secure: cookieOptions.secure ?? (process.env.NODE_ENV === 'production'),
          sameSite: cookieOptions.sameSite || 'strict',
          domain: cookieOptions.domain,
          path: cookieOptions.path || '/',
        });

        // Store access token
        Cookies.set('iamsec_access_token', result.session.tokens.accessToken, {
          expires: new Date(Date.now() + result.session.tokens.expiresIn),
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
        });
      }

      return result;
    } catch (error) {
      console.error('Login failed:', error);
      return {
        success: false,
        error: 'An error occurred during login',
      };
    } finally {
      setIsLoading(false);
    }
  }, []);

  /**
   * Logout function
   */
  const logout = useCallback(async (): Promise<void> => {
    setIsLoading(true);

    try {
      // Call logout API
      if (session) {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${session.tokens.accessToken}`,
          },
          body: JSON.stringify({ sessionId: session.sessionId }),
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear local state
      setUser(null);
      setSession(null);

      // Clear cookies
      Cookies.remove('iamsec_session');
      Cookies.remove('iamsec_access_token');
      Cookies.remove('iamsec_refresh_token');

      setIsLoading(false);
    }
  }, [session]);

  /**
   * Refresh session
   */
  const refreshSession = useCallback(async (): Promise<void> => {
    if (!session) return;

    try {
      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refreshToken: session.tokens.refreshToken }),
      });

      const result = await response.json();

      if (result.success && result.tokens) {
        // Update session with new tokens
        const updatedSession = {
          ...session,
          tokens: result.tokens,
          expiresAt: new Date(Date.now() + result.tokens.expiresIn),
        };

        setSession(updatedSession);

        // Update cookies
        Cookies.set('iamsec_session', JSON.stringify(updatedSession), {
          expires: new Date(updatedSession.expiresAt),
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
        });

        Cookies.set('iamsec_access_token', result.tokens.accessToken, {
          expires: new Date(Date.now() + result.tokens.expiresIn),
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
        });
      }
    } catch (error) {
      console.error('Failed to refresh session:', error);
      // If refresh fails, logout
      await logout();
    }
  }, [session, logout]);

  /**
   * Check if user has role
   */
  const hasRole = useCallback(
    (role: string | string[]): boolean => {
      if (!user) return false;
      const roles = Array.isArray(role) ? role : [role];
      return roles.some(r => user.roles.includes(r));
    },
    [user]
  );

  /**
   * Check if user has permission
   */
  const hasPermission = useCallback(
    (permission: string | string[]): boolean => {
      if (!user) return false;
      const permissions = Array.isArray(permission) ? permission : [permission];
      return permissions.every(p => user.permissions.includes(p));
    },
    [user]
  );

  /**
   * Update user
   */
  const updateUser = useCallback(
    (updates: Partial<IUser>): void => {
      if (!user) return;

      const updatedUser = { ...user, ...updates };
      setUser(updatedUser);

      // Update session
      if (session) {
        const updatedSession = { ...session, user: updatedUser };
        setSession(updatedSession);

        // Update cookies
        Cookies.set('iamsec_session', JSON.stringify(updatedSession), {
          expires: new Date(session.expiresAt),
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
        });
      }
    },
    [user, session]
  );

  /**
   * Auto-refresh tokens before they expire
   */
  useEffect(() => {
    if (!session) return;

    const expiresIn = session.tokens.expiresIn;
    const refreshThreshold = Math.min(expiresIn * 0.75, expiresIn - 60000); // Refresh at 75% of expiry or 1 min before

    const refreshTimer = setTimeout(() => {
      refreshSession();
    }, refreshThreshold);

    return () => clearTimeout(refreshTimer);
  }, [session, refreshSession]);

  const value: IAuthContext = {
    user,
    session,
    isAuthenticated: !!user,
    isLoading,
    login,
    logout,
    refreshSession,
    hasRole,
    hasPermission,
    updateUser,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export default AuthProvider;

