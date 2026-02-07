# IAMSec

**Identity and Access Management for Next.js**

[![npm version](https://img.shields.io/npm/v/@stellarx/iamsec.svg)](https://www.npmjs.com/package/@stellarx/iamsec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)](https://www.typescriptlang.org/)
[![Next.js](https://img.shields.io/badge/Next.js-14%20%7C%2015-black.svg)](https://nextjs.org/)

> Production-ready authentication, authorization, and security framework for Next.js applications. OWASP & NIST compliant. Zero-config to fully customizable.

---

## ✨ Features

🔐 **Authentication**
- JWT token management (access + refresh)
- Session management with concurrent session limits
- Password policies (NIST 800-63B compliant)
- MFA-ready (TOTP, Email, SMS)
- Account lockout & brute force protection

🛡️ **Authorization**
- Role-Based Access Control (RBAC)
- Permission-based authorization
- Hierarchical role priorities
- Resource ownership checks
- Declarative route protection

🔒 **Security**
- CSRF protection
- Rate limiting
- XSS & SQL injection prevention
- Security headers configuration
- Audit logging & compliance

⚛️ **React Integration**
- React hooks (`useAuth`, `usePermissions`)
- Route guards & HOCs
- Context providers
- Full TypeScript support

⚙️ **Fully Configurable**
- Zero-config to fully customizable
- No package modifications required
- TypeScript autocomplete
- Environment-aware

---

## 📦 Installation

```bash
npm install @stellarx/iamsec
```

```bash
yarn add @stellarx/iamsec
```

```bash
pnpm add @stellarx/iamsec
```

---

## 🚀 Quick Start

### 1. Wrap your app with AuthProvider

```typescript
// app/layout.tsx
import { AuthProvider } from '@stellarx/iamsec';

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
```

### 2. Use authentication hooks

```typescript
// components/LoginForm.tsx
'use client';

import { useAuth } from '@stellarx/iamsec';

export function LoginForm() {
  const { login, isLoading, error } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const formData = new FormData(e.target as HTMLFormElement);
    
    await login({
      email: formData.get('email') as string,
      password: formData.get('password') as string,
    });
  };

  return (
    <form onSubmit={handleSubmit}>
      <input name="email" type="email" required />
      <input name="password" type="password" required />
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Logging in...' : 'Login'}
      </button>
      {error && <p>{error}</p>}
    </form>
  );
}
```

### 3. Protect routes

```typescript
// app/dashboard/page.tsx
import { RouteGuard } from '@stellarx/iamsec';

export default function Dashboard() {
  return (
    <RouteGuard requiredRoles={['user']}>
      <DashboardContent />
    </RouteGuard>
  );
}
```

### 4. Check permissions

```typescript
// components/AdminPanel.tsx
'use client';

import { usePermissions } from '@stellarx/iamsec';

export function AdminPanel() {
  const { hasRole, hasPermission } = usePermissions();

  if (!hasRole('admin')) {
    return <div>Access denied</div>;
  }

  return (
    <div>
      {hasPermission('users:write') && (
        <button>Edit Users</button>
      )}
      {hasPermission('reports:read') && (
        <button>View Reports</button>
      )}
    </div>
  );
}
```

---

## ⚙️ Configuration

IAMSec works out of the box with sensible defaults, but you can customize everything:

### Basic Configuration

```typescript
// src/config/iamsec.config.ts
import { IAMSecConfig } from '@stellarx/iamsec';

export const iamsecConfig: Partial<IAMSecConfig> = {
  auth: {
    apiEndpoints: {
      login: '/api/auth/login',
      logout: '/api/auth/logout',
      refresh: '/api/auth/refresh',
    },
  },
  ui: {
    redirects: {
      afterLogin: '/dashboard',
      afterLogout: '/',
      unauthorized: '/login',
    },
  },
};

// app/layout.tsx
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

### Full Configuration with Roles & Permissions

```typescript
import { IAMSecConfig } from '@stellarx/iamsec';

export const iamsecConfig: Partial<IAMSecConfig> = {
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
    ],
  },
  security: {
    session: {
      sessionTimeout: 60 * 60 * 1000, // 1 hour
      maxConcurrentSessions: 3,
    },
    password: {
      minLength: 12,
      requireUppercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
    },
  },
};
```

**📖 See [CONFIGURATION_GUIDE.md](./CONFIGURATION_GUIDE.md) for complete configuration options.**

---

## 🎯 API Reference

### Hooks

#### `useAuth()`

```typescript
const {
  user,              // Current user object
  session,           // Current session
  isAuthenticated,   // Boolean: is user logged in?
  isLoading,         // Boolean: is auth loading?
  login,             // Function: login(credentials)
  logout,            // Function: logout()
  register,          // Function: register(userData)
} = useAuth();
```

#### `usePermissions()`

```typescript
const {
  hasRole,           // Function: hasRole(role)
  hasAnyRole,        // Function: hasAnyRole(roles[])
  hasPermission,     // Function: hasPermission(permission)
  hasAllPermissions, // Function: hasAllPermissions(permissions[])
  canPerformAction,  // Function: canPerformAction(resource, action)
} = usePermissions();
```

### Components

#### `<AuthProvider>`

```typescript
<AuthProvider config={iamsecConfig}>
  {children}
</AuthProvider>
```

#### `<RouteGuard>`

```typescript
<RouteGuard
  requiredRoles={['admin', 'manager']}
  requiredPermissions={['users:read']}
  fallbackUrl="/access-denied"
>
  {children}
</RouteGuard>
```

**📖 See [QUICK_REFERENCE.md](./QUICK_REFERENCE.md) for complete API documentation.**

---

## 🏗️ Architecture

```
@stellarx/iamsec
├── core/              # Authentication & Authorization
│   ├── authentication
│   ├── authorization
│   ├── session
│   └── tokens
├── hooks/             # React Hooks
│   ├── useAuth
│   └── usePermissions
├── guards/            # Route Protection
│   └── RouteGuard
├── middleware/        # Security Middleware
│   ├── auth-middleware
│   ├── csrf
│   └── rate-limiter
└── providers/         # React Providers
    └── AuthProvider
```

---

## 🔐 Security Features

### OWASP Top 10 Coverage

- ✅ **A01 Broken Access Control** - RBAC & permissions
- ✅ **A02 Cryptographic Failures** - Secure token management
- ✅ **A03 Injection** - Input validation & sanitization
- ✅ **A05 Security Misconfiguration** - Secure defaults
- ✅ **A07 Authentication Failures** - Robust authentication
- ✅ **A08 Software and Data Integrity** - Audit logging

### NIST Compliance

- ✅ **NIST 800-63B** - Password policies
- ✅ **NIST 800-53** - Access control
- ✅ **NIST Cybersecurity Framework** - Security controls

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [CONFIGURATION_GUIDE.md](./CONFIGURATION_GUIDE.md) | Complete configuration options |
| [QUICK_REFERENCE.md](./QUICK_REFERENCE.md) | API quick reference |
| [INTEGRATION_GUIDE.md](./INTEGRATION_GUIDE.md) | Backend integration guide |

---

## 🎨 TypeScript Support

IAMSec is built with TypeScript and provides full type definitions:

```typescript
import { 
  IAMSecConfig, 
  IUser, 
  ISession, 
  IRole, 
  IPermission,
  IAuthResult 
} from '@stellarx/iamsec';

// Full autocomplete and type checking
const config: Partial<IAMSecConfig> = {
  // TypeScript will suggest all available options
};
```

---

## 🌍 Environment Support

```typescript
const config: Partial<IAMSecConfig> = {
  auth: {
    apiEndpoints: {
      login: process.env.NEXT_PUBLIC_AUTH_LOGIN || '/api/auth/login',
    },
    cookieOptions: {
      secure: process.env.NODE_ENV === 'production',
      domain: process.env.NEXT_PUBLIC_COOKIE_DOMAIN,
    },
  },
};
```

---

## 🚀 Why IAMSec?

### Zero-Config to Fully Customizable

Start with zero configuration and customize as you grow:

```typescript
// Start simple
<AuthProvider>
  <App />
</AuthProvider>

// Customize when needed
<AuthProvider config={myConfig}>
  <App />
</AuthProvider>
```

### No Package Modifications

Unlike other libraries, you **never** modify IAMSec's source files. All configuration is done through props:

❌ **Other libraries:** Edit `node_modules/lib/config.ts`  
✅ **IAMSec:** Pass configuration through `config` prop

### Enterprise-Ready

- Production-tested security patterns
- OWASP & NIST compliant
- Comprehensive audit logging
- Multi-session management
- Brute force protection

### Next.js Optimized

Built specifically for Next.js 14+ with:
- App Router support
- Server & client component compatibility
- Streaming SSR support
- TypeScript-first design

---

## 📋 Requirements

- **Next.js:** 14.0.0 or later
- **React:** 18.0.0 or later
- **TypeScript:** 5.0.0 or later (recommended)
- **Node.js:** 18.0.0 or later

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to your fork
5. Open a Pull Request

---

## 📝 License

MIT © [stellarx](https://github.com/stellarx)

---

## 🔗 Links

- **GitHub:** [https://github.com/stellarx/iamsec](https://github.com/stellarx/iamsec)
- **NPM:** [https://www.npmjs.com/package/@stellarx/iamsec](https://www.npmjs.com/package/@stellarx/iamsec)
- **Issues:** [https://github.com/stellarx/iamsec/issues](https://github.com/stellarx/iamsec/issues)

---

## 💬 Support

- 📖 Read the [documentation](https://github.com/stellarx/iamsec#readme)
- 💬 Open an [issue](https://github.com/stellarx/iamsec/issues)
- 🐛 Report [bugs](https://github.com/stellarx/iamsec/issues/new)
- 💡 Request [features](https://github.com/stellarx/iamsec/issues/new)

---

## 🌟 Show Your Support

If you find IAMSec helpful, please give it a ⭐️ on [GitHub](https://github.com/stellarx/iamsec)!

---

**Built with ❤️ by stellarx**

*Secure your Next.js applications with enterprise-grade authentication & authorization.*
