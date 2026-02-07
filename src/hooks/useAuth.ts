/**
 * IAMsec - useAuth Hook
 * React hook for authentication state and operations
 */

'use client';

import { useContext } from 'react';
import { AuthContext } from '../providers/AuthProvider';
import { IAuthContext } from '../types';

/**
 * useAuth Hook
 * Access authentication state and operations
 */
export function useAuth(): IAuthContext {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }

  return context;
}

export default useAuth;

