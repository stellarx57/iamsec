/**
 * IAMsec - Authorization Module
 * Role-Based Access Control (RBAC) and Permission Management
 */

import { IUser, IRole, IPermission } from '../types';
import { ROLES, PERMISSIONS, getPermissionsForRoles } from '../config/roles.config';
import { auditLog } from '../utils/logger';

/**
 * Authorization Service
 */
export class AuthorizationService {
  /**
   * Check if user has a specific role
   */
  hasRole(user: IUser | null, role: string | string[]): boolean {
    if (!user) return false;

    const roles = Array.isArray(role) ? role : [role];
    return roles.some(r => user.roles.includes(r));
  }

  /**
   * Check if user has a specific permission
   */
  hasPermission(user: IUser | null, permission: string | string[]): boolean {
    if (!user) return false;

    const permissions = Array.isArray(permission) ? permission : [permission];
    
    // Get all permissions from user's roles
    const userPermissions = getPermissionsForRoles(user.roles);
    
    // Also include directly assigned permissions
    const allPermissions = [...new Set([...userPermissions, ...user.permissions])];
    
    return permissions.every(p => allPermissions.includes(p));
  }

  /**
   * Check if user has ANY of the specified roles
   */
  hasAnyRole(user: IUser | null, roles: string[]): boolean {
    if (!user) return false;
    return roles.some(role => user.roles.includes(role));
  }

  /**
   * Check if user has ALL of the specified roles
   */
  hasAllRoles(user: IUser | null, roles: string[]): boolean {
    if (!user) return false;
    return roles.every(role => user.roles.includes(role));
  }

  /**
   * Check if user has ANY of the specified permissions
   */
  hasAnyPermission(user: IUser | null, permissions: string[]): boolean {
    if (!user) return false;
    
    const userPermissions = getPermissionsForRoles(user.roles);
    const allPermissions = [...new Set([...userPermissions, ...user.permissions])];
    
    return permissions.some(p => allPermissions.includes(p));
  }

  /**
   * Check if user has ALL of the specified permissions
   */
  hasAllPermissions(user: IUser | null, permissions: string[]): boolean {
    return this.hasPermission(user, permissions);
  }

  /**
   * Get user's highest priority role
   */
  getHighestPriorityRole(user: IUser | null): IRole | null {
    if (!user) return null;

    let highestRole: IRole | null = null;
    let highestPriority = -1;

    for (const roleId of user.roles) {
      const role = ROLES[roleId.toUpperCase().replace('-', '_')];
      if (role && role.priority > highestPriority) {
        highestRole = role;
        highestPriority = role.priority;
      }
    }

    return highestRole;
  }

  /**
   * Assign role to user
   */
  async assignRole(
    user: IUser,
    roleId: string,
    assignedBy?: string
  ): Promise<{ success: boolean; error?: string }> {
    const role = ROLES[roleId.toUpperCase().replace('-', '_')];
    
    if (!role) {
      return {
        success: false,
        error: 'Role not found',
      };
    }

    if (user.roles.includes(roleId)) {
      return {
        success: false,
        error: 'User already has this role',
      };
    }

    // Check if trying to assign system role
    if (role.isSystemRole && roleId !== 'customer') {
      return {
        success: false,
        error: 'Cannot assign system role',
      };
    }

    user.roles.push(roleId);

    // Audit log
    await auditLog.logout(user.id, ''); // Using logout as placeholder, should create proper audit method

    return {
      success: true,
    };
  }

  /**
   * Revoke role from user
   */
  async revokeRole(
    user: IUser,
    roleId: string,
    revokedBy?: string
  ): Promise<{ success: boolean; error?: string }> {
    if (!user.roles.includes(roleId)) {
      return {
        success: false,
        error: 'User does not have this role',
      };
    }

    // Prevent revoking last role
    if (user.roles.length === 1) {
      return {
        success: false,
        error: 'Cannot revoke user\'s last role',
      };
    }

    user.roles = user.roles.filter(r => r !== roleId);

    return {
      success: true,
    };
  }

  /**
   * Grant permission directly to user
   */
  async grantPermission(
    user: IUser,
    permissionId: string
  ): Promise<{ success: boolean; error?: string }> {
    const permission = PERMISSIONS[permissionId.toUpperCase().replace(/:/g, '_')];
    
    if (!permission) {
      return {
        success: false,
        error: 'Permission not found',
      };
    }

    if (user.permissions.includes(permissionId)) {
      return {
        success: false,
        error: 'User already has this permission',
      };
    }

    user.permissions.push(permissionId);

    return {
      success: true,
    };
  }

  /**
   * Revoke permission from user
   */
  async revokePermission(
    user: IUser,
    permissionId: string
  ): Promise<{ success: boolean; error?: string }> {
    if (!user.permissions.includes(permissionId)) {
      return {
        success: false,
        error: 'User does not have this permission',
      };
    }

    user.permissions = user.permissions.filter(p => p !== permissionId);

    return {
      success: true,
    };
  }

  /**
   * Check if user can perform action on resource
   */
  canPerformAction(
    user: IUser | null,
    resource: string,
    action: string
  ): boolean {
    const permissionId = `${resource}:${action}`;
    return this.hasPermission(user, permissionId);
  }

  /**
   * Get all effective permissions for user (from roles + direct permissions)
   */
  getUserPermissions(user: IUser | null): string[] {
    if (!user) return [];
    
    const rolePermissions = getPermissionsForRoles(user.roles);
    return [...new Set([...rolePermissions, ...user.permissions])];
  }

  /**
   * Check if user is admin
   */
  isAdmin(user: IUser | null): boolean {
    return this.hasAnyRole(user, ['admin', 'super-admin']);
  }

  /**
   * Check if user is super admin
   */
  isSuperAdmin(user: IUser | null): boolean {
    return this.hasRole(user, 'super-admin');
  }

  /**
   * Check resource ownership
   */
  isResourceOwner(user: IUser | null, resourceOwnerId: string): boolean {
    if (!user) return false;
    return user.id === resourceOwnerId;
  }

  /**
   * Authorize user for action
   * Combines role, permission, and ownership checks
   */
  async authorize(params: {
    user: IUser | null;
    requiredRoles?: string[];
    requiredPermissions?: string[];
    resource?: string;
    action?: string;
    resourceOwnerId?: string;
    allowOwner?: boolean;
  }): Promise<{ authorized: boolean; reason?: string }> {
    const {
      user,
      requiredRoles,
      requiredPermissions,
      resource,
      action,
      resourceOwnerId,
      allowOwner = true,
    } = params;

    // Check if user is authenticated
    if (!user) {
      await auditLog.accessDenied(undefined, resource || 'unknown', 'Not authenticated');
      return {
        authorized: false,
        reason: 'Authentication required',
      };
    }

    // Check ownership if applicable
    if (allowOwner && resourceOwnerId && this.isResourceOwner(user, resourceOwnerId)) {
      return { authorized: true };
    }

    // Check roles
    if (requiredRoles && requiredRoles.length > 0) {
      if (!this.hasAnyRole(user, requiredRoles)) {
        await auditLog.accessDenied(
          user.id,
          resource || 'unknown',
          'Insufficient role privileges'
        );
        return {
          authorized: false,
          reason: 'Insufficient role privileges',
        };
      }
    }

    // Check permissions
    if (requiredPermissions && requiredPermissions.length > 0) {
      if (!this.hasAllPermissions(user, requiredPermissions)) {
        await auditLog.accessDenied(
          user.id,
          resource || 'unknown',
          'Insufficient permissions'
        );
        return {
          authorized: false,
          reason: 'Insufficient permissions',
        };
      }
    }

    // Check resource:action permission
    if (resource && action) {
      if (!this.canPerformAction(user, resource, action)) {
        await auditLog.accessDenied(
          user.id,
          resource,
          `Cannot perform ${action} on ${resource}`
        );
        return {
          authorized: false,
          reason: `Cannot perform ${action} on ${resource}`,
        };
      }
    }

    return { authorized: true };
  }
}

/**
 * Create authorization service instance
 */
export function createAuthorizationService(): AuthorizationService {
  return new AuthorizationService();
}

export default AuthorizationService;

