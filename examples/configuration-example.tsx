/**
 * IAMSec Configuration Example
 * How to configure IAMSec in your Next.js application
 */

import { AuthProvider, IAMSecConfig } from '@stellarx/iamsec';

/**
 * Example 1: Basic Configuration
 */
export function BasicExample() {
  const config: Partial<IAMSecConfig> = {
    auth: {
      apiEndpoints: {
        login: '/api/v1/auth/login',
        logout: '/api/v1/auth/logout',
        refresh: '/api/v1/auth/refresh',
      },
    },
    ui: {
      redirects: {
        afterLogin: '/app/dashboard',
        afterLogout: '/home',
        unauthorized: '/auth/login',
      },
    },
  };

  return (
    <AuthProvider config={config}>
      <YourApp />
    </AuthProvider>
  );
}

/**
 * Example 2: Full Configuration with Roles & Permissions
 */
export function FullConfigurationExample() {
  const config: Partial<IAMSecConfig> = {
    auth: {
      apiEndpoints: {
        login: '/api/auth/login',
        logout: '/api/auth/logout',
        refresh: '/api/auth/refresh',
        register: '/api/auth/register',
      },
      sessionCookieName: 'my_app_session',
      tokenCookieName: 'my_app_token',
      cookieOptions: {
        secure: true,
        sameSite: 'strict',
        domain: '.example.com',
        path: '/',
      },
    },

    authorization: {
      roles: [
        {
          id: 'admin',
          name: 'Administrator',
          priority: 100,
          permissions: ['*'], // All permissions
        },
        {
          id: 'manager',
          name: 'Manager',
          priority: 50,
          permissions: ['users:read', 'users:write', 'reports:read'],
        },
        {
          id: 'user',
          name: 'User',
          priority: 10,
          permissions: ['profile:read', 'profile:write'],
        },
      ],

      permissions: [
        {
          id: 'users:read',
          name: 'Read Users',
          resource: 'users',
          action: 'read',
        },
        {
          id: 'users:write',
          name: 'Write Users',
          resource: 'users',
          action: 'write',
        },
        {
          id: 'profile:read',
          name: 'Read Profile',
          resource: 'profile',
          action: 'read',
        },
        {
          id: 'profile:write',
          name: 'Write Profile',
          resource: 'profile',
          action: 'write',
        },
      ],

      routes: [
        {
          path: '/admin/*',
          requiredRoles: ['admin'],
        },
        {
          path: '/manager/*',
          requiredRoles: ['admin', 'manager'],
        },
        {
          path: '/dashboard',
          requiresAuth: true,
        },
      ],
    },

    security: {
      csrf: {
        enabled: true,
        tokenLength: 32,
        cookieName: 'my_app_csrf',
      },
      rateLimit: {
        enabled: true,
        maxRequests: 100,
        windowMs: 15 * 60 * 1000, // 15 minutes
      },
      session: {
        maxConcurrentSessions: 3,
        slidingExpiration: true,
        sessionTimeout: 60 * 60 * 1000, // 1 hour
      },
      password: {
        minLength: 12,
        requireUppercase: true,
        requireLowercase: true,
        requireNumbers: true,
        requireSpecialChars: true,
        maxFailedAttempts: 3,
        lockoutDuration: 60 * 60 * 1000, // 1 hour
      },
    },

    audit: {
      enabled: true,
      logLevel: 'info',
      retentionDays: 365,
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
        accessDenied: '/error/403',
        unauthorized: '/auth/login',
      },
      messages: {
        loginSuccess: 'Welcome back!',
        loginFailed: 'Invalid email or password',
        logoutSuccess: 'You have been logged out',
        accessDenied: 'You do not have permission to access this page',
        sessionExpired: 'Your session has expired. Please log in again',
      },
    },
  };

  return (
    <AuthProvider config={config}>
      <YourApp />
    </AuthProvider>
  );
}

/**
 * Example 3: Environment-Based Configuration
 */
export function EnvironmentBasedExample() {
  const config: Partial<IAMSecConfig> = {
    auth: {
      apiEndpoints: {
        login: process.env.NEXT_PUBLIC_AUTH_LOGIN_URL || '/api/auth/login',
        logout: process.env.NEXT_PUBLIC_AUTH_LOGOUT_URL || '/api/auth/logout',
        refresh: process.env.NEXT_PUBLIC_AUTH_REFRESH_URL || '/api/auth/refresh',
      },
      cookieOptions: {
        secure: process.env.NODE_ENV === 'production',
        domain: process.env.NEXT_PUBLIC_COOKIE_DOMAIN,
      },
    },

    security: {
      session: {
        sessionTimeout: Number(process.env.NEXT_PUBLIC_SESSION_TIMEOUT) || 30 * 60 * 1000,
      },
    },
  };

  return (
    <AuthProvider config={config}>
      <YourApp />
    </AuthProvider>
  );
}

/**
 * Example 4: Minimal Configuration (Uses Defaults)
 */
export function MinimalExample() {
  // You can omit the config prop entirely to use all defaults
  return (
    <AuthProvider>
      <YourApp />
    </AuthProvider>
  );
}

/**
 * Example 5: Partial Configuration (Override Only What You Need)
 */
export function PartialConfigExample() {
  const config: Partial<IAMSecConfig> = {
    // Only override UI redirects
    ui: {
      redirects: {
        afterLogin: '/my-dashboard',
        unauthorized: '/my-login',
      },
    },
  };

  return (
    <AuthProvider config={config}>
      <YourApp />
    </AuthProvider>
  );
}

/**
 * Example 6: External Configuration File
 */

// config/iamsec.config.ts
export const iamsecConfig: Partial<IAMSecConfig> = {
  auth: {
    apiEndpoints: {
      login: '/api/auth/login',
      logout: '/api/auth/logout',
    },
  },
  authorization: {
    roles: [
      { id: 'admin', name: 'Admin', priority: 100, permissions: ['*'] },
      { id: 'user', name: 'User', priority: 10, permissions: ['profile:read'] },
    ],
  },
  ui: {
    redirects: {
      afterLogin: '/dashboard',
      unauthorized: '/login',
    },
  },
};

// app/layout.tsx
import { iamsecConfig } from '@/config/iamsec.config';

export function ExternalConfigExample() {
  return (
    <AuthProvider config={iamsecConfig}>
      <YourApp />
    </AuthProvider>
  );
}

// Placeholder component
function YourApp() {
  return <div>Your App</div>;
}

