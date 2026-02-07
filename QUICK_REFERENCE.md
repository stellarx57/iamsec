# IAMsec - Quick Reference Card

One-page reference for common IAMsec operations.

---

## 🔐 Authentication

### Login
```typescript
const { login } = useAuth();
const result = await login({ email, password });
```

### Logout
```typescript
const { logout } = useAuth();
await logout();
```

### Check Auth Status
```typescript
const { user, isAuthenticated, isLoading } = useAuth();
```

---

## 🛡️ Authorization

### Check Single Role
```typescript
const { hasRole } = usePermissions();
if (hasRole('admin')) { /* ... */ }
```

### Check Multiple Roles (ANY)
```typescript
const { hasAnyRole } = usePermissions();
if (hasAnyRole(['admin', 'manager'])) { /* ... */ }
```

### Check Permission
```typescript
const { hasPermission } = usePermissions();
if (hasPermission('product:create')) { /* ... */ }
```

### Check Resource Action
```typescript
const { canPerformAction } = usePermissions();
if (canPerformAction('order', 'delete')) { /* ... */ }
```

---

## 🚪 Route Protection

### Component Level
```typescript
<RouteGuard requiredRoles={['customer']}>
  <ProtectedContent />
</RouteGuard>
```

### With Permissions
```typescript
<RouteGuard 
  requiredRoles={['admin']}
  requiredPermissions={['user:read']}
  fallbackUrl="/account"
>
  <AdminPanel />
</RouteGuard>
```

### Custom Guard
```typescript
<RouteGuard customGuard={(user) => user.isVerified}>
  <VerifiedContent />
</RouteGuard>
```

---

## 🎨 Conditional Rendering

### By Role
```typescript
<RequireRole role="admin">
  <AdminContent />
</RequireRole>
```

### By Permission
```typescript
<RequirePermission permission="product:create">
  <CreateButton />
</RequirePermission>
```

### With Fallback
```typescript
<RequireRole role="manager" fallback={<Denied />}>
  <ManagerTools />
</RequireRole>
```

---

## ⚙️ Configuration

### Environment Variables
```env
IAMSEC_ACCESS_TOKEN_SECRET=your_secret_here
IAMSEC_REFRESH_TOKEN_SECRET=your_secret_here
IAMSEC_JWT_ISSUER=your_app_name
IAMSEC_JWT_AUDIENCE=your_app_audience
```

### Add Custom Role
```typescript
// iamsec/src/config/roles.config.ts
export const ROLES = {
  MY_ROLE: {
    id: 'my-role',
    name: 'My Role',
    permissions: ['resource:action'],
    priority: 50,
  },
};
```

### Add Protected Route
```typescript
// iamsec/src/config/routes.config.ts
export const ROUTE_CONFIG = [
  {
    path: '/my-page',
    isPublic: false,
    requiredRoles: ['my-role'],
    fallbackUrl: '/login',
  },
];
```

---

## 🔧 API Routes

### Login Endpoint
```typescript
// src/app/api/auth/login/route.ts
const result = await authService.authenticate(
  { email, password },
  ipAddress,
  userAgent
);
```

### Logout Endpoint
```typescript
// src/app/api/auth/logout/route.ts
await sessionManager.terminateSession(sessionId);
response.cookies.delete('iamsec_access_token');
```

### Refresh Token
```typescript
// src/app/api/auth/refresh/route.ts
const tokens = await authService.refreshTokens(refreshToken);
```

---

## 📊 Audit Logging

### Log Custom Event
```typescript
import { getAuditLogger, AuditEventType } from '@/iamsec';

const logger = getAuditLogger();
await logger.log({
  eventType: AuditEventType.ACCESS_GRANTED,
  action: 'User accessed resource',
  userId: user.id,
  status: 'success',
});
```

### Query Logs
```typescript
const failedLogins = logger.queryLogs({
  eventType: AuditEventType.LOGIN_FAILED,
  startDate: new Date(Date.now() - 86400000),
});
```

### Export Logs
```typescript
const csvLogs = logger.exportLogs('csv');
const jsonLogs = logger.exportLogs('json');
```

---

## 🔒 Security Utilities

### Validate Password
```typescript
import { validatePassword } from '@/iamsec';

const result = validatePassword(password, securityConfig.passwordPolicy);
if (!result.isValid) {
  console.error(result.errors);
}
```

### Sanitize Input
```typescript
import { sanitizeInput } from '@/iamsec';

const clean = sanitizeInput(userInput);
```

### Check Email
```typescript
import { isValidEmail } from '@/iamsec';

if (isValidEmail(email)) { /* ... */ }
```

---

## 🎭 Common Patterns

### Protected Page
```typescript
// src/app/admin/page.tsx
'use client';
import { RouteGuard } from '@/iamsec';

export default function AdminPage() {
  return (
    <RouteGuard requiredRoles={['admin']}>
      <h1>Admin Dashboard</h1>
    </RouteGuard>
  );
}
```

### User Profile
```typescript
'use client';
import { useAuth } from '@/iamsec';

export function UserProfile() {
  const { user, logout } = useAuth();
  
  return (
    <div>
      <p>Email: {user?.email}</p>
      <p>Roles: {user?.roles.join(', ')}</p>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

### Admin-Only Button
```typescript
import { RequireRole } from '@/iamsec';

export function Toolbar() {
  return (
    <div>
      <button>View</button>
      <RequireRole role="admin">
        <button>Delete</button>
      </RequireRole>
    </div>
  );
}
```

---

## 🐛 Debugging

### Enable Debug Logging
```typescript
// In development mode, IAMsec logs to console
if (process.env.NODE_ENV === 'development') {
  console.log('Auth state:', useAuth());
  console.log('Permissions:', usePermissions());
}
```

### Check Token Expiry
```typescript
import { TokenManager } from '@/iamsec';

const tokenManager = new TokenManager(config.jwt);
const expired = tokenManager.isTokenExpired(token);
const lifetime = tokenManager.getTokenLifetime(token);
```

### Verify Route Config
```typescript
import { getRouteConfig, canAccessRoute } from '@/iamsec';

const config = getRouteConfig('/my-page');
const access = canAccessRoute('/my-page', user.roles, user.permissions);
```

---

## ⚡ Performance Tips

1. **Memoize Permission Checks**: Use `useMemo` for expensive checks
2. **Lazy Load Guards**: Use dynamic imports for route guards
3. **Cache Audit Logs**: Don't query on every render
4. **Optimize Middleware**: Keep middleware logic minimal
5. **Use Token Refresh**: Don't re-authenticate unnecessarily

---

## 🆘 Troubleshooting

| Issue | Solution |
|-------|----------|
| "useAuth must be used within AuthProvider" | Wrap app with `<AuthProvider>` |
| Infinite redirects | Mark login page as public in routes config |
| Token expired | Implement automatic token refresh |
| CORS errors | Check API route configuration |
| Permission denied | Verify user roles and route config |

---

## 📚 More Resources

- **Full Documentation**: `iamsec/README.md`
- **Integration Guide**: `iamsec/INTEGRATION_GUIDE.md`
- **Examples**: `iamsec/examples/`
- **Types**: `iamsec/src/types/index.ts`

---

**IAMsec v1.0.0** - Enterprise Security Made Simple 🔐

