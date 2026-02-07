# IAMsec Integration Guide

Complete step-by-step guide to integrate IAMsec into your Next.js application.

---

## 📋 Prerequisites

- Next.js 14+ or 15+
- React 18+
- TypeScript 5+
- Material-UI (MUI) 5+ or 6+

---

## 🚀 Integration Steps

### Step 1: Environment Configuration

Create or update `.env.local` in your project root:

```env
# Required: JWT Secrets (MUST be changed in production!)
IAMSEC_ACCESS_TOKEN_SECRET=your_super_secure_access_token_secret_min_32_characters_long
IAMSEC_REFRESH_TOKEN_SECRET=your_super_secure_refresh_token_secret_min_32_characters_long

# JWT Configuration
IAMSEC_JWT_ISSUER=metrosquire
IAMSEC_JWT_AUDIENCE=metrosquire-app
IAMSEC_ACCESS_TOKEN_EXPIRY=15m
IAMSEC_REFRESH_TOKEN_EXPIRY=7d

# Storage Encryption (optional but recommended)
IAMSEC_STORAGE_ENCRYPTION_KEY=your_storage_encryption_key_min_32_characters_long
```

**⚠️ IMPORTANT:** Generate strong, random secrets:

```bash
# Generate secure secrets using Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

---

### Step 2: Update Root Layout

Wrap your application with `AuthProvider` in `src/app/layout.tsx`:

```typescript
import { AuthProvider } from '@/iamsec';
import './globals.css';

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
```

---

### Step 3: Configure Routes

Update `iamsec/src/config/routes.config.ts` to match your application routes:

```typescript
export const ROUTE_CONFIG: IRouteConfig[] = [
  // Public routes
  {
    path: '/',
    isPublic: true,
  },
  {
    path: '/shop',
    isPublic: true,
  },
  {
    path: '/auth/login',
    isPublic: true,
  },
  
  // Protected routes
  {
    path: '/account',
    isPublic: false,
    requiredRoles: ['customer', 'vendor', 'admin'],
    fallbackUrl: '/auth/login',
  },
  {
    path: '/admin',
    isPublic: false,
    requiredRoles: ['admin', 'super-admin'],
    fallbackUrl: '/account',
  },
  
  // Add your custom routes here...
];
```

---

### Step 4: Configure Roles & Permissions

Update `iamsec/src/config/roles.config.ts` for your application:

```typescript
// Add custom permissions
export const PERMISSIONS: Record<string, IPermission> = {
  // ... existing permissions ...
  
  // Add your custom permissions
  CUSTOM_RESOURCE_READ: {
    id: 'custom:read',
    name: 'Read Custom Resource',
    resource: 'custom',
    action: 'read',
    description: 'Can view custom resources',
  },
};

// Add or modify roles
export const ROLES: Record<string, IRole> = {
  // ... existing roles ...
  
  // Add your custom roles
  CUSTOM_ROLE: {
    id: 'custom-role',
    name: 'Custom Role',
    description: 'Custom role for specific users',
    permissions: [
      PERMISSIONS.PRODUCT_READ.id,
      PERMISSIONS.CUSTOM_RESOURCE_READ.id,
    ],
    priority: 15,
    isSystemRole: false,
  },
};
```

---

### Step 5: Create Authentication API Routes

#### Login Route: `src/app/api/auth/login/route.ts`

See `iamsec/examples/api-route-login.ts` for complete implementation.

```typescript
import { NextRequest, NextResponse } from 'next/server';
import {
  createAuthenticationService,
  createTokenManager,
  createSessionManager,
  createStorageAdapter,
  getSecurityConfig,
} from '@/iamsec';

export async function POST(request: NextRequest) {
  // ... see example file for full implementation
}
```

#### Logout Route: `src/app/api/auth/logout/route.ts`

```typescript
import { NextRequest, NextResponse } from 'next/server';
import {
  createSessionManager,
  createStorageAdapter,
  getSecurityConfig,
} from '@/iamsec';

const securityConfig = getSecurityConfig();
const storageAdapter = createStorageAdapter();
const sessionManager = createSessionManager(securityConfig.session, storageAdapter);

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { sessionId } = body;

    if (sessionId) {
      await sessionManager.terminateSession(sessionId);
    }

    const response = NextResponse.json({ success: true });
    
    // Clear cookies
    response.cookies.delete('iamsec_access_token');
    response.cookies.delete('iamsec_refresh_token');
    response.cookies.delete('iamsec_session_id');

    return response;
  } catch (error) {
    return NextResponse.json(
      { success: false, error: 'Logout failed' },
      { status: 500 }
    );
  }
}
```

#### Refresh Token Route: `src/app/api/auth/refresh/route.ts`

```typescript
import { NextRequest, NextResponse } from 'next/server';
import {
  createAuthenticationService,
  createTokenManager,
  createSessionManager,
  createStorageAdapter,
  getSecurityConfig,
} from '@/iamsec';

const securityConfig = getSecurityConfig();
const tokenManager = createTokenManager(securityConfig.jwt);
const storageAdapter = createStorageAdapter();
const sessionManager = createSessionManager(securityConfig.session, storageAdapter);
const authService = createAuthenticationService(securityConfig, tokenManager, sessionManager);

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { refreshToken } = body;

    if (!refreshToken) {
      return NextResponse.json(
        { success: false, error: 'Refresh token required' },
        { status: 400 }
      );
    }

    const tokens = await authService.refreshTokens(refreshToken);

    if (!tokens) {
      return NextResponse.json(
        { success: false, error: 'Invalid refresh token' },
        { status: 401 }
      );
    }

    const response = NextResponse.json({
      success: true,
      tokens,
    });

    // Update cookies
    response.cookies.set('iamsec_access_token', tokens.accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: tokens.expiresIn / 1000,
      path: '/',
    });

    return response;
  } catch (error) {
    return NextResponse.json(
      { success: false, error: 'Token refresh failed' },
      { status: 500 }
    );
  }
}
```

---

### Step 6: Create Login Page

Create `src/app/auth/login/page.tsx`:

See `iamsec/examples/login-page-example.tsx` for complete implementation.

---

### Step 7: Protect Pages with RouteGuard

#### Option A: Component-level Protection

```typescript
// src/app/account/page.tsx
'use client';

import { RouteGuard } from '@/iamsec';

export default function AccountPage() {
  return (
    <RouteGuard requiredRoles={['customer', 'admin']}>
      <div>
        <h1>My Account</h1>
        {/* Your account content */}
      </div>
    </RouteGuard>
  );
}
```

#### Option B: Layout-level Protection

```typescript
// src/app/admin/layout.tsx
'use client';

import { RouteGuard } from '@/iamsec';

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  return (
    <RouteGuard
      requiredRoles={['admin', 'super-admin']}
      fallbackUrl="/account"
    >
      <div className="admin-layout">
        {children}
      </div>
    </RouteGuard>
  );
}
```

---

### Step 8: Use Authentication Hooks

```typescript
// Any client component
'use client';

import { useAuth, usePermissions } from '@/iamsec';

export function MyComponent() {
  const { user, isAuthenticated, logout } = useAuth();
  const { hasRole, hasPermission, isAdmin } = usePermissions();

  if (!isAuthenticated) {
    return <div>Please log in</div>;
  }

  return (
    <div>
      <h1>Welcome, {user.email}!</h1>
      
      {hasRole('admin') && (
        <button>Admin Panel</button>
      )}
      
      {hasPermission('product:create') && (
        <button>Create Product</button>
      )}
      
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

---

### Step 9: Conditional Rendering Components

```typescript
import { RequireRole, RequirePermission } from '@/iamsec';

export function Dashboard() {
  return (
    <div>
      <h1>Dashboard</h1>
      
      <RequireRole role="admin">
        <AdminWidgets />
      </RequireRole>
      
      <RequirePermission permission="analytics:view">
        <AnalyticsChart />
      </RequirePermission>
      
      <RequireRole 
        role="manager" 
        fallback={<div>Manager access required</div>}
      >
        <ManagerTools />
      </RequireRole>
    </div>
  );
}
```

---

### Step 10: Middleware (Optional - Advanced)

Create `src/middleware.ts` for server-side route protection:

```typescript
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { isPublicRoute } from '@/iamsec';

export function middleware(request: NextRequest) {
  const pathname = request.nextUrl.pathname;
  
  // Check if route is public
  if (isPublicRoute(pathname)) {
    return NextResponse.next();
  }
  
  // Check for authentication token
  const token = request.cookies.get('iamsec_access_token');
  
  if (!token) {
    // Redirect to login
    const url = new URL('/auth/login', request.url);
    url.searchParams.set('redirect', pathname);
    return NextResponse.redirect(url);
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
```

---

## 🔒 Security Checklist

Before going to production, ensure:

- ✅ All JWT secrets are changed from defaults
- ✅ Secrets are stored in environment variables (never in code)
- ✅ HTTPS is enabled in production
- ✅ Cookie settings use `secure: true` in production
- ✅ CSRF protection is enabled
- ✅ Rate limiting is configured
- ✅ Audit logging is enabled
- ✅ Password policy is enforced
- ✅ Session timeouts are appropriate
- ✅ Regular security audits are scheduled

---

## 🧪 Testing Integration

### Test Authentication Flow

```typescript
// __tests__/auth.test.ts
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { AuthProvider } from '@/iamsec';
import LoginPage from '@/app/auth/login/page';

describe('Authentication', () => {
  it('logs in successfully', async () => {
    render(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    );
    
    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: 'test@example.com' },
    });
    
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'password123' },
    });
    
    fireEvent.click(screen.getByText(/sign in/i));
    
    await waitFor(() => {
      expect(window.location.pathname).toBe('/account');
    });
  });
});
```

---

## 📊 Monitoring & Logging

### View Audit Logs

```typescript
import { getAuditLogger } from '@/iamsec';

const logger = getAuditLogger();

// Get recent logs
const recentLogs = logger.getRecentLogs(100);

// Query specific logs
const failedLogins = logger.queryLogs({
  eventType: AuditEventType.LOGIN_FAILED,
  startDate: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
});

// Export logs for compliance
const csvLogs = logger.exportLogs('csv');
```

---

## 🆘 Troubleshooting

### Common Issues

#### 1. "useAuth must be used within an AuthProvider"
**Solution:** Ensure `AuthProvider` wraps your app in `layout.tsx`

#### 2. Infinite redirect loops
**Solution:** Check `routes.config.ts` - ensure login page is marked as public

#### 3. "Invalid token" errors
**Solution:** Verify JWT secrets in `.env.local` match between client and server

#### 4. Session not persisting
**Solution:** Check cookie settings - ensure `httpOnly` and `sameSite` are correct

#### 5. CORS errors with API routes
**Solution:** Ensure API routes are in `/api` directory and check Next.js middleware config

---

## 🎓 Next Steps

1. Customize roles and permissions for your app
2. Implement user registration API route
3. Add password reset functionality
4. Set up MFA if required
5. Configure monitoring and alerting
6. Review and test security policies
7. Perform security audit before production

---

## 📚 Additional Resources

- [IAMsec README](./README.md)
- [Security Best Practices](./README.md#best-practices)
- [API Reference](./README.md#api-reference)
- [Example Files](./examples/)

---

**Need Help?** Check the README or review the example files in `/iamsec/examples/`

