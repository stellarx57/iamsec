/**
 * IAMsec - Roles Configuration
 * Define roles and permissions for your application
 */

import { IRole, IPermission } from '../types';

/**
 * System Permissions
 * Define all available permissions in your application
 */
export const PERMISSIONS: Record<string, IPermission> = {
  // User Management
  USER_CREATE: {
    id: 'user:create',
    name: 'Create User',
    resource: 'user',
    action: 'create',
    description: 'Can create new users',
  },
  USER_READ: {
    id: 'user:read',
    name: 'Read User',
    resource: 'user',
    action: 'read',
    description: 'Can view user information',
  },
  USER_UPDATE: {
    id: 'user:update',
    name: 'Update User',
    resource: 'user',
    action: 'update',
    description: 'Can update user information',
  },
  USER_DELETE: {
    id: 'user:delete',
    name: 'Delete User',
    resource: 'user',
    action: 'delete',
    description: 'Can delete users',
  },

  // Product Management
  PRODUCT_CREATE: {
    id: 'product:create',
    name: 'Create Product',
    resource: 'product',
    action: 'create',
    description: 'Can create new products',
  },
  PRODUCT_READ: {
    id: 'product:read',
    name: 'Read Product',
    resource: 'product',
    action: 'read',
    description: 'Can view products',
  },
  PRODUCT_UPDATE: {
    id: 'product:update',
    name: 'Update Product',
    resource: 'product',
    action: 'update',
    description: 'Can update products',
  },
  PRODUCT_DELETE: {
    id: 'product:delete',
    name: 'Delete Product',
    resource: 'product',
    action: 'delete',
    description: 'Can delete products',
  },

  // Order Management
  ORDER_CREATE: {
    id: 'order:create',
    name: 'Create Order',
    resource: 'order',
    action: 'create',
    description: 'Can create orders',
  },
  ORDER_READ: {
    id: 'order:read',
    name: 'Read Order',
    resource: 'order',
    action: 'read',
    description: 'Can view orders',
  },
  ORDER_UPDATE: {
    id: 'order:update',
    name: 'Update Order',
    resource: 'order',
    action: 'update',
    description: 'Can update order status',
  },
  ORDER_DELETE: {
    id: 'order:delete',
    name: 'Delete Order',
    resource: 'order',
    action: 'delete',
    description: 'Can delete orders',
  },

  // Settings Management
  SETTINGS_READ: {
    id: 'settings:read',
    name: 'Read Settings',
    resource: 'settings',
    action: 'read',
    description: 'Can view system settings',
  },
  SETTINGS_UPDATE: {
    id: 'settings:update',
    name: 'Update Settings',
    resource: 'settings',
    action: 'update',
    description: 'Can modify system settings',
  },

  // Analytics & Reports
  ANALYTICS_VIEW: {
    id: 'analytics:read',
    name: 'View Analytics',
    resource: 'analytics',
    action: 'read',
    description: 'Can view analytics and reports',
  },

  // Audit Logs
  AUDIT_READ: {
    id: 'audit:read',
    name: 'Read Audit Logs',
    resource: 'audit',
    action: 'read',
    description: 'Can view audit logs',
  },
};

/**
 * System Roles
 * Define roles with their associated permissions
 */
export const ROLES: Record<string, IRole> = {
  // Public/Guest - No authentication required
  GUEST: {
    id: 'guest',
    name: 'Guest',
    description: 'Unauthenticated user with minimal access',
    permissions: [
      PERMISSIONS.PRODUCT_READ.id,
    ],
    priority: 0,
    isSystemRole: true,
  },

  // Customer - Regular authenticated user
  CUSTOMER: {
    id: 'customer',
    name: 'Customer',
    description: 'Regular authenticated customer',
    permissions: [
      PERMISSIONS.PRODUCT_READ.id,
      PERMISSIONS.ORDER_CREATE.id,
      PERMISSIONS.ORDER_READ.id, // Can read own orders
      PERMISSIONS.USER_READ.id, // Can read own profile
      PERMISSIONS.USER_UPDATE.id, // Can update own profile
    ],
    priority: 10,
    isSystemRole: true,
  },

  // Vendor - Can manage their own products
  VENDOR: {
    id: 'vendor',
    name: 'Vendor',
    description: 'Product vendor with limited management access',
    permissions: [
      PERMISSIONS.PRODUCT_READ.id,
      PERMISSIONS.PRODUCT_CREATE.id,
      PERMISSIONS.PRODUCT_UPDATE.id,
      PERMISSIONS.ORDER_READ.id,
      PERMISSIONS.ORDER_UPDATE.id,
      PERMISSIONS.USER_READ.id,
      PERMISSIONS.USER_UPDATE.id,
    ],
    priority: 20,
    isSystemRole: false,
  },

  // Manager - Can manage products and orders
  MANAGER: {
    id: 'manager',
    name: 'Manager',
    description: 'Store manager with extended privileges',
    permissions: [
      PERMISSIONS.PRODUCT_READ.id,
      PERMISSIONS.PRODUCT_CREATE.id,
      PERMISSIONS.PRODUCT_UPDATE.id,
      PERMISSIONS.PRODUCT_DELETE.id,
      PERMISSIONS.ORDER_READ.id,
      PERMISSIONS.ORDER_UPDATE.id,
      PERMISSIONS.ORDER_DELETE.id,
      PERMISSIONS.USER_READ.id,
      PERMISSIONS.ANALYTICS_VIEW.id,
    ],
    priority: 30,
    isSystemRole: false,
  },

  // Admin - Full access except system configuration
  ADMIN: {
    id: 'admin',
    name: 'Administrator',
    description: 'System administrator with full access',
    permissions: [
      PERMISSIONS.USER_CREATE.id,
      PERMISSIONS.USER_READ.id,
      PERMISSIONS.USER_UPDATE.id,
      PERMISSIONS.USER_DELETE.id,
      PERMISSIONS.PRODUCT_CREATE.id,
      PERMISSIONS.PRODUCT_READ.id,
      PERMISSIONS.PRODUCT_UPDATE.id,
      PERMISSIONS.PRODUCT_DELETE.id,
      PERMISSIONS.ORDER_CREATE.id,
      PERMISSIONS.ORDER_READ.id,
      PERMISSIONS.ORDER_UPDATE.id,
      PERMISSIONS.ORDER_DELETE.id,
      PERMISSIONS.SETTINGS_READ.id,
      PERMISSIONS.SETTINGS_UPDATE.id,
      PERMISSIONS.ANALYTICS_VIEW.id,
      PERMISSIONS.AUDIT_READ.id,
    ],
    priority: 90,
    isSystemRole: false,
  },

  // Super Admin - Complete system access
  SUPER_ADMIN: {
    id: 'super-admin',
    name: 'Super Administrator',
    description: 'Highest level system administrator',
    permissions: Object.values(PERMISSIONS).map(p => p.id), // All permissions
    priority: 100,
    isSystemRole: true,
  },
};

/**
 * Get role by ID
 */
export function getRole(roleId: string): IRole | undefined {
  return Object.values(ROLES).find(role => role.id === roleId);
}

/**
 * Get permission by ID
 */
export function getPermission(permissionId: string): IPermission | undefined {
  return Object.values(PERMISSIONS).find(perm => perm.id === permissionId);
}

/**
 * Check if a role has a specific permission
 */
export function roleHasPermission(roleId: string, permissionId: string): boolean {
  const role = getRole(roleId);
  return role ? role.permissions.includes(permissionId) : false;
}

/**
 * Get all permissions for a list of roles
 */
export function getPermissionsForRoles(roleIds: string[]): string[] {
  const permissions = new Set<string>();
  
  roleIds.forEach(roleId => {
    const role = getRole(roleId);
    if (role) {
      role.permissions.forEach(perm => permissions.add(perm));
    }
  });
  
  return Array.from(permissions);
}

/**
 * Check if user has required role
 */
export function hasRequiredRole(userRoles: string[], requiredRoles: string[]): boolean {
  return requiredRoles.some(required => userRoles.includes(required));
}

/**
 * Check if user has required permission
 */
export function hasRequiredPermission(
  userRoles: string[],
  requiredPermissions: string[]
): boolean {
  const userPermissions = getPermissionsForRoles(userRoles);
  return requiredPermissions.every(required => userPermissions.includes(required));
}

export default ROLES;

