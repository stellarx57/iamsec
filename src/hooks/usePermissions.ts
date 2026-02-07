/**
 * IAMsec - usePermissions Hook
 * React hook for permission and role checks
 */

'use client';

import { useMemo } from 'react';
import { useAuth } from './useAuth';
import { AuthorizationService } from '../core/authorization';

/**
 * usePermissions Hook
 * Provides permission and role checking utilities
 */
export function usePermissions() {
  const { user } = useAuth();
  const authzService = useMemo(() => new AuthorizationService(), []);

  return {
    /**
     * Check if user has a specific role
     */
    hasRole: (role: string | string[]) => authzService.hasRole(user, role),

    /**
     * Check if user has a specific permission
     */
    hasPermission: (permission: string | string[]) =>
      authzService.hasPermission(user, permission),

    /**
     * Check if user has ANY of the specified roles
     */
    hasAnyRole: (roles: string[]) => authzService.hasAnyRole(user, roles),

    /**
     * Check if user has ALL of the specified roles
     */
    hasAllRoles: (roles: string[]) => authzService.hasAllRoles(user, roles),

    /**
     * Check if user has ANY of the specified permissions
     */
    hasAnyPermission: (permissions: string[]) =>
      authzService.hasAnyPermission(user, permissions),

    /**
     * Check if user has ALL of the specified permissions
     */
    hasAllPermissions: (permissions: string[]) =>
      authzService.hasAllPermissions(user, permissions),

    /**
     * Check if user can perform action on resource
     */
    canPerformAction: (resource: string, action: string) =>
      authzService.canPerformAction(user, resource, action),

    /**
     * Get all effective permissions for user
     */
    getUserPermissions: () => authzService.getUserPermissions(user),

    /**
     * Check if user is admin
     */
    isAdmin: () => authzService.isAdmin(user),

    /**
     * Check if user is super admin
     */
    isSuperAdmin: () => authzService.isSuperAdmin(user),

    /**
     * Check if user owns a resource
     */
    isResourceOwner: (resourceOwnerId: string) =>
      authzService.isResourceOwner(user, resourceOwnerId),

    /**
     * Get user's highest priority role
     */
    getHighestPriorityRole: () => authzService.getHighestPriorityRole(user),
  };
}

export default usePermissions;

