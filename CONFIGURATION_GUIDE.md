# IAMSec Configuration Guide

## 📘 Overview

IAMSec is designed to be **highly configurable without modifying package files**. You can extend and customize IAMSec by passing configuration to the `AuthProvider` component.

---

## 🎯 Key Principle

**❌ DON'T** modify files inside `node_modules/@stellarx/iamsec/`  
**✅ DO** configure IAMSec through the `config` prop

---

## 🚀 Quick Start

### Basic Configuration

```typescript
// app/layout.tsx
import { AuthProvider, IAMSecConfig } from '@stellarx/iamsec';

const config: Partial<IAMSecConfig> = {
  auth: {
    apiEndpoints: {
      login: '/api/auth/login',
      logout: '/api/auth/logout',
    },
  },
  ui: {
    redirects: {
      afterLogin: '/dashboard',
      unauthorized: '/login',
    },
  },
};

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        <AuthProvider config={config}>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
```

---

## ⚙️ Configuration Options

### 1. Authentication Configuration

```typescript
const config: Partial<IAMSecConfig> = {
  auth: {
    // API Endpoints
    apiEndpoints: {
      login: '/api/auth/login',       // Login endpoint
      logout: '/api/auth/logout',     // Logout endpoint
      refresh: '/api/auth/refresh',   // Token refresh endpoint
      register: '/api/auth/register', // Registration endpoint
    },

    // Cookie Names
    sessionCookieName: 'my_app_session',
    tokenCookieName: 'my_app_token',

    // Cookie Options
    cookieOptions: {
      secure: true,              // HTTPS only
      sameSite: 'strict',        // CSRF protection
      domain: '.example.com',    // Cookie domain
      path: '/',                 // Cookie path
    },
  },
};
```

### 2. Authorization Configuration

```typescript
const config: Partial<IAMSecConfig> = {
  authorization: {
    // Define Roles
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

    // Define Permissions
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
    ],

    // Define Protected Routes
    routes: [
      {
        path: '/admin/*',
        requiredRoles: ['admin'],
      },
      {
        path: '/dashboard',
        requiresAuth: true,
      },
    ],
  },
};
```

### 3. Security Configuration

```typescript
const config: Partial<IAMSecConfig> = {
  security: {
    // CSRF Protection
    csrf: {
      enabled: true,
      tokenLength: 32,
      cookieName: 'my_csrf_token',
    },

    // Rate Limiting
    rateLimit: {
      enabled: true,
      maxRequests: 100,          // Max requests
      windowMs: 15 * 60 * 1000,  // 15 minutes
    },

    // Session Management
    session: {
      maxConcurrentSessions: 5,
      slidingExpiration: true,
      sessionTimeout: 30 * 60 * 1000, // 30 minutes
    },

    // Password Policy
    password: {
      minLength: 12,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
      maxFailedAttempts: 5,
      lockoutDuration: 30 * 60 * 1000, // 30 minutes
    },
  },
};
```

### 4. Audit Configuration

```typescript
const config: Partial<IAMSecConfig> = {
  audit: {
    enabled: true,
    logLevel: 'info',        // 'debug' | 'info' | 'warn' | 'error'
    retentionDays: 90,       // Log retention period

    // Event Logging
    events: {
      login: true,
      logout: true,
      accessDenied: true,
      passwordChange: true,
      accountLockout: true,
    },
  },
};
```

### 5. UI Configuration

```typescript
const config: Partial<IAMSecConfig> = {
  ui: {
    // Redirect URLs
    redirects: {
      afterLogin: '/dashboard',
      afterLogout: '/',
      accessDenied: '/error/403',
      unauthorized: '/login',
    },

    // User Messages
    messages: {
      loginSuccess: 'Welcome back!',
      loginFailed: 'Invalid credentials',
      logoutSuccess: 'Logged out successfully',
      accessDenied: 'Access denied',
      sessionExpired: 'Session expired. Please log in',
    },
  },
};
```

---

## 📁 Recommended File Structure

### Option 1: Single Configuration File

```
src/
├── config/
│   └── iamsec.config.ts      # IAMSec configuration
├── app/
│   └── layout.tsx             # Use config here
```

```typescript
// src/config/iamsec.config.ts
import { IAMSecConfig } from '@stellarx/iamsec';

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

// src/app/layout.tsx
import { AuthProvider } from '@stellarx/iamsec';
import { iamsecConfig } from '@/config/iamsec.config';

export default function RootLayout({ children }) {
  return (
    <AuthProvider config={iamsecConfig}>
      {children}
    </AuthProvider>
  );
}
```

### Option 2: Modular Configuration

```
src/
├── config/
│   ├── iamsec/
│   │   ├── index.ts          # Combine all configs
│   │   ├── auth.config.ts    # Auth settings
│   │   ├── roles.config.ts   # Roles & permissions
│   │   ├── security.config.ts # Security settings
│   │   └── ui.config.ts      # UI settings
```

```typescript
// src/config/iamsec/roles.config.ts
export const rolesConfig = {
  roles: [
    { id: 'admin', name: 'Admin', priority: 100, permissions: ['*'] },
    { id: 'user', name: 'User', priority: 10, permissions: ['profile:read'] },
  ],
  permissions: [
    { id: 'profile:read', name: 'Read Profile', resource: 'profile', action: 'read' },
  ],
};

// src/config/iamsec/index.ts
import { IAMSecConfig } from '@stellarx/iamsec';
import { rolesConfig } from './roles.config';
import { authConfig } from './auth.config';
import { securityConfig } from './security.config';
import { uiConfig } from './ui.config';

export const iamsecConfig: Partial<IAMSecConfig> = {
  auth: authConfig,
  authorization: rolesConfig,
  security: securityConfig,
  ui: uiConfig,
};
```

---

## 🌍 Environment-Based Configuration

```typescript
// src/config/iamsec.config.ts
import { IAMSecConfig } from '@stellarx/iamsec';

export const iamsecConfig: Partial<IAMSecConfig> = {
  auth: {
    apiEndpoints: {
      login: process.env.NEXT_PUBLIC_AUTH_LOGIN_URL || '/api/auth/login',
      logout: process.env.NEXT_PUBLIC_AUTH_LOGOUT_URL || '/api/auth/logout',
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
```

```env
# .env.local
NEXT_PUBLIC_AUTH_LOGIN_URL=/api/v1/auth/login
NEXT_PUBLIC_AUTH_LOGOUT_URL=/api/v1/auth/logout
NEXT_PUBLIC_COOKIE_DOMAIN=.example.com
NEXT_PUBLIC_SESSION_TIMEOUT=3600000
```

---

## 🎨 TypeScript Support

IAMSec is fully typed, so you'll get autocomplete and type checking:

```typescript
import { IAMSecConfig } from '@stellarx/iamsec';

// Full type safety
const config: Partial<IAMSecConfig> = {
  auth: {
    apiEndpoints: {
      login: '/api/auth/login', // ✅ Type-checked
      // invalid: 'test',        // ❌ Error: Property doesn't exist
    },
  },
};
```

---

## 📦 Default Configuration

IAMSec comes with sensible defaults. You only need to override what you need:

```typescript
// Default configuration (used if you don't provide config)
{
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
  security: {
    csrf: { enabled: true, tokenLength: 32 },
    rateLimit: { enabled: true, maxRequests: 100, windowMs: 900000 },
    session: { maxConcurrentSessions: 5, slidingExpiration: true, sessionTimeout: 1800000 },
    password: { minLength: 8, requireUppercase: true, requireLowercase: true, requireNumbers: true, requireSpecialChars: true },
  },
  ui: {
    redirects: {
      afterLogin: '/dashboard',
      afterLogout: '/',
      accessDenied: '/access-denied',
      unauthorized: '/login',
    },
  },
}
```

---

## ✅ Best Practices

1. **Create a separate config file**: Don't clutter your layout.tsx
2. **Use environment variables**: For different environments (dev, staging, prod)
3. **Type your config**: Use `Partial<IAMSecConfig>` for type safety
4. **Only override what you need**: The rest will use sensible defaults
5. **Version control your config**: Track changes to your IAMSec configuration
6. **Document custom roles**: Comment your role/permission definitions

---

## 🚫 What NOT to Do

❌ **DON'T** modify files in `node_modules/@stellarx/iamsec/`  
❌ **DON'T** copy and paste IAMSec source files into your project  
❌ **DON'T** fork the package just to change configuration  

✅ **DO** use the `config` prop to customize IAMSec  
✅ **DO** extend types if needed  
✅ **DO** open GitHub issues for feature requests  

---

## 📚 See Also

- `examples/configuration-example.tsx` - Working examples
- `README.md` - Package documentation
- `QUICK_REFERENCE.md` - API quick reference

---

**Configure once, use everywhere!** 🎉

