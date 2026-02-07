/**
 * IAMsec - Route Guard
 * Client-side route protection component
 */

'use client';

import React, { ReactNode, useEffect, useState } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { useAuth } from '../hooks/useAuth';
import { usePermissions } from '../hooks/usePermissions';
import { canAccessRoute, getRouteConfig } from '../config/routes.config';
import { getPermissionsForRoles } from '../config/roles.config';
import { Box, CircularProgress, Typography } from '@mui/material';

/**
 * Route Guard Props
 */
interface RouteGuardProps {
  children: ReactNode;
  requiredRoles?: string[];
  requiredPermissions?: string[];
  fallbackUrl?: string;
  loadingComponent?: ReactNode;
  unauthorizedComponent?: ReactNode;
  customGuard?: (user: any) => boolean;
}

/**
 * Route Guard Component
 * Protects routes based on authentication and authorization
 */
export function RouteGuard({
  children,
  requiredRoles,
  requiredPermissions,
  fallbackUrl,
  loadingComponent,
  unauthorizedComponent,
  customGuard,
}: RouteGuardProps) {
  const router = useRouter();
  const pathname = usePathname();
  const { user, isAuthenticated, isLoading } = useAuth();
  const { hasAnyRole, hasAllPermissions } = usePermissions();
  const [authorized, setAuthorized] = useState(false);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    const checkAuthorization = async () => {
      setChecking(true);

      // Wait for auth to initialize
      if (isLoading) {
        return;
      }

      // Check route configuration
      const routeConfig = getRouteConfig(pathname);
      
      // If route is public, allow access
      if (routeConfig?.isPublic) {
        setAuthorized(true);
        setChecking(false);
        return;
      }

      // Check if user is authenticated
      if (!isAuthenticated || !user) {
        const redirectUrl = fallbackUrl || `/auth/login?redirect=${encodeURIComponent(pathname)}`;
        router.push(redirectUrl);
        setChecking(false);
        return;
      }

      // Check custom guard
      if (customGuard && !customGuard(user)) {
        const redirectUrl = fallbackUrl || '/account';
        router.push(redirectUrl);
        setChecking(false);
        return;
      }

      // Determine required roles and permissions
      const rolesToCheck = requiredRoles || routeConfig?.requiredRoles || [];
      const permissionsToCheck = requiredPermissions || routeConfig?.requiredPermissions || [];

      // Check roles
      if (rolesToCheck.length > 0 && !hasAnyRole(rolesToCheck)) {
        const redirectUrl = fallbackUrl || routeConfig?.fallbackUrl || '/account';
        router.push(redirectUrl);
        setChecking(false);
        return;
      }

      // Check permissions
      if (permissionsToCheck.length > 0 && !hasAllPermissions(permissionsToCheck)) {
        const redirectUrl = fallbackUrl || routeConfig?.fallbackUrl || '/account';
        router.push(redirectUrl);
        setChecking(false);
        return;
      }

      // All checks passed
      setAuthorized(true);
      setChecking(false);
    };

    checkAuthorization();
  }, [
    pathname,
    isLoading,
    isAuthenticated,
    user,
    requiredRoles,
    requiredPermissions,
    customGuard,
    fallbackUrl,
    router,
    hasAnyRole,
    hasAllPermissions,
  ]);

  // Show loading state
  if (checking || isLoading) {
    if (loadingComponent) {
      return <>{loadingComponent}</>;
    }

    return (
      <Box
        display="flex"
        flexDirection="column"
        alignItems="center"
        justifyContent="center"
        minHeight="100vh"
        gap={2}
      >
        <CircularProgress />
        <Typography variant="body2" color="text.secondary">
          Loading...
        </Typography>
      </Box>
    );
  }

  // Show unauthorized state
  if (!authorized) {
    if (unauthorizedComponent) {
      return <>{unauthorizedComponent}</>;
    }

    return (
      <Box
        display="flex"
        flexDirection="column"
        alignItems="center"
        justifyContent="center"
        minHeight="100vh"
        gap={2}
      >
        <Typography variant="h5">Unauthorized</Typography>
        <Typography variant="body2" color="text.secondary">
          You don't have permission to access this page.
        </Typography>
      </Box>
    );
  }

  // Render protected content
  return <>{children}</>;
}

/**
 * Helper component for role-based rendering
 */
interface RequireRoleProps {
  children: ReactNode;
  role: string | string[];
  fallback?: ReactNode;
}

export function RequireRole({ children, role, fallback }: RequireRoleProps) {
  const { hasAnyRole } = usePermissions();
  const roles = Array.isArray(role) ? role : [role];

  if (!hasAnyRole(roles)) {
    return fallback ? <>{fallback}</> : null;
  }

  return <>{children}</>;
}

/**
 * Helper component for permission-based rendering
 */
interface RequirePermissionProps {
  children: ReactNode;
  permission: string | string[];
  fallback?: ReactNode;
}

export function RequirePermission({ children, permission, fallback }: RequirePermissionProps) {
  const { hasAllPermissions } = usePermissions();
  const permissions = Array.isArray(permission) ? permission : [permission];

  if (!hasAllPermissions(permissions)) {
    return fallback ? <>{fallback}</> : null;
  }

  return <>{children}</>;
}

export default RouteGuard;

