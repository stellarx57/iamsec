/**
 * IAMSec - Configuration Types
 * Extensible configuration interfaces for IAMSec
 */

import { IRole, IPermission, IRouteConfig } from './index';

/**
 * IAMSec Configuration
 * Users can extend this configuration in their application
 */
export interface IAMSecConfig {
  /**
   * Authentication configuration
   */
  auth?: {
    apiEndpoints?: {
      login?: string;
      logout?: string;
      refresh?: string;
      register?: string;
    };
    sessionCookieName?: string;
    tokenCookieName?: string;
    cookieOptions?: {
      secure?: boolean;
      sameSite?: 'strict' | 'lax' | 'none';
      domain?: string;
      path?: string;
    };
  };

  /**
   * Authorization configuration
   */
  authorization?: {
    roles?: IRole[];
    permissions?: IPermission[];
    routes?: IRouteConfig[];
  };

  /**
   * Security configuration
   */
  security?: {
    csrf?: {
      enabled?: boolean;
      tokenLength?: number;
      cookieName?: string;
    };
    rateLimit?: {
      enabled?: boolean;
      maxRequests?: number;
      windowMs?: number;
    };
    session?: {
      maxConcurrentSessions?: number;
      slidingExpiration?: boolean;
      sessionTimeout?: number; // in milliseconds
    };
    password?: {
      minLength?: number;
      requireUppercase?: boolean;
      requireLowercase?: boolean;
      requireNumbers?: boolean;
      requireSpecialChars?: boolean;
      maxFailedAttempts?: number;
      lockoutDuration?: number; // in milliseconds
    };
  };

  /**
   * Audit configuration
   */
  audit?: {
    enabled?: boolean;
    logLevel?: 'debug' | 'info' | 'warn' | 'error';
    retentionDays?: number;
    events?: {
      login?: boolean;
      logout?: boolean;
      accessDenied?: boolean;
      passwordChange?: boolean;
      accountLockout?: boolean;
    };
  };

  /**
   * UI configuration
   */
  ui?: {
    redirects?: {
      afterLogin?: string;
      afterLogout?: string;
      accessDenied?: string;
      unauthorized?: string;
    };
    messages?: {
      loginSuccess?: string;
      loginFailed?: string;
      logoutSuccess?: string;
      accessDenied?: string;
      sessionExpired?: string;
    };
  };
}

/**
 * Default IAMSec Configuration
 */
export const defaultConfig: IAMSecConfig = {
  auth: {
    apiEndpoints: {
      login: '/api/auth/login',
      logout: '/api/auth/logout',
      refresh: '/api/auth/refresh',
      register: '/api/auth/register',
    },
    sessionCookieName: 'iamsec_session',
    tokenCookieName: 'iamsec_token',
    cookieOptions: {
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
    },
  },

  authorization: {
    roles: [],
    permissions: [],
    routes: [],
  },

  security: {
    csrf: {
      enabled: true,
      tokenLength: 32,
      cookieName: 'iamsec_csrf',
    },
    rateLimit: {
      enabled: true,
      maxRequests: 100,
      windowMs: 15 * 60 * 1000, // 15 minutes
    },
    session: {
      maxConcurrentSessions: 5,
      slidingExpiration: true,
      sessionTimeout: 30 * 60 * 1000, // 30 minutes
    },
    password: {
      minLength: 8,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
      maxFailedAttempts: 5,
      lockoutDuration: 30 * 60 * 1000, // 30 minutes
    },
  },

  audit: {
    enabled: true,
    logLevel: 'info',
    retentionDays: 90,
    events: {
      login: true,
      logout: true,
      accessDenied: true,
      passwordChange: true,
      accountLockout: true,
    },
  },

  ui: {
    redirects: {
      afterLogin: '/dashboard',
      afterLogout: '/',
      accessDenied: '/access-denied',
      unauthorized: '/login',
    },
    messages: {
      loginSuccess: 'Successfully logged in',
      loginFailed: 'Invalid credentials',
      logoutSuccess: 'Successfully logged out',
      accessDenied: 'You do not have permission to access this resource',
      sessionExpired: 'Your session has expired. Please log in again',
    },
  },
};

/**
 * Merge user configuration with defaults
 */
export function mergeConfig(userConfig?: Partial<IAMSecConfig>): IAMSecConfig {
  if (!userConfig) return defaultConfig;

  return {
    auth: { ...defaultConfig.auth, ...userConfig.auth },
    authorization: {
      ...defaultConfig.authorization,
      ...userConfig.authorization,
      roles: userConfig.authorization?.roles || defaultConfig.authorization?.roles || [],
      permissions: userConfig.authorization?.permissions || defaultConfig.authorization?.permissions || [],
      routes: userConfig.authorization?.routes || defaultConfig.authorization?.routes || [],
    },
    security: {
      csrf: { ...defaultConfig.security?.csrf, ...userConfig.security?.csrf },
      rateLimit: { ...defaultConfig.security?.rateLimit, ...userConfig.security?.rateLimit },
      session: { ...defaultConfig.security?.session, ...userConfig.security?.session },
      password: { ...defaultConfig.security?.password, ...userConfig.security?.password },
    },
    audit: { ...defaultConfig.audit, ...userConfig.audit },
    ui: {
      redirects: { ...defaultConfig.ui?.redirects, ...userConfig.ui?.redirects },
      messages: { ...defaultConfig.ui?.messages, ...userConfig.ui?.messages },
    },
  };
}

