/**
 * IAMsec - Routes Configuration
 * Declarative route protection and access control
 */

import { IRouteConfig } from '../types';

/**
 * Route Access Configuration
 * Define which routes are public and which require authentication/authorization
 */
export const ROUTE_CONFIG: IRouteConfig[] = [
  // ============================================
  // PUBLIC ROUTES (No authentication required)
  // ============================================
  {
    path: '/',
    isPublic: true,
  },
  {
    path: '/shop',
    isPublic: true,
  },
  {
    path: '/product/:slug',
    isPublic: true,
  },
  {
    path: '/category/:slug',
    isPublic: true,
  },
  {
    path: '/about',
    isPublic: true,
  },
  {
    path: '/contact',
    isPublic: true,
  },
  {
    path: '/help',
    isPublic: true,
  },
  {
    path: '/auth/login',
    isPublic: true,
  },
  {
    path: '/auth/register',
    isPublic: true,
  },
  {
    path: '/auth/forgot-password',
    isPublic: true,
  },
  {
    path: '/auth/reset-password',
    isPublic: true,
  },

  // ============================================
  // AUTHENTICATED ROUTES (Login required)
  // ============================================
  {
    path: '/account',
    isPublic: false,
    requiredRoles: ['customer', 'vendor', 'manager', 'admin', 'super-admin'],
    fallbackUrl: '/auth/login',
  },
  {
    path: '/account/:tab',
    isPublic: false,
    requiredRoles: ['customer', 'vendor', 'manager', 'admin', 'super-admin'],
    fallbackUrl: '/auth/login',
  },
  {
    path: '/wishlist',
    isPublic: false,
    requiredRoles: ['customer', 'vendor', 'manager', 'admin', 'super-admin'],
    fallbackUrl: '/auth/login',
  },
  {
    path: '/cart',
    isPublic: true, // Cart can be viewed by guests, but checkout requires auth
  },
  {
    path: '/checkout',
    isPublic: false,
    requiredRoles: ['customer', 'vendor', 'manager', 'admin', 'super-admin'],
    fallbackUrl: '/auth/login',
  },
  {
    path: '/orders',
    isPublic: false,
    requiredRoles: ['customer', 'vendor', 'manager', 'admin', 'super-admin'],
    fallbackUrl: '/auth/login',
  },
  {
    path: '/orders/:id',
    isPublic: false,
    requiredRoles: ['customer', 'vendor', 'manager', 'admin', 'super-admin'],
    fallbackUrl: '/auth/login',
  },

  // ============================================
  // VENDOR ROUTES
  // ============================================
  {
    path: '/vendor/dashboard',
    isPublic: false,
    requiredRoles: ['vendor', 'manager', 'admin', 'super-admin'],
    fallbackUrl: '/auth/login',
  },
  {
    path: '/vendor/products',
    isPublic: false,
    requiredRoles: ['vendor', 'manager', 'admin', 'super-admin'],
    fallbackUrl: '/auth/login',
  },
  {
    path: '/vendor/orders',
    isPublic: false,
    requiredRoles: ['vendor', 'manager', 'admin', 'super-admin'],
    fallbackUrl: '/auth/login',
  },

  // ============================================
  // MANAGER ROUTES
  // ============================================
  {
    path: '/manager/dashboard',
    isPublic: false,
    requiredRoles: ['manager', 'admin', 'super-admin'],
    fallbackUrl: '/account',
  },
  {
    path: '/manager/products',
    isPublic: false,
    requiredRoles: ['manager', 'admin', 'super-admin'],
    fallbackUrl: '/account',
  },
  {
    path: '/manager/analytics',
    isPublic: false,
    requiredRoles: ['manager', 'admin', 'super-admin'],
    fallbackUrl: '/account',
  },

  // ============================================
  // ADMIN ROUTES
  // ============================================
  {
    path: '/admin',
    isPublic: false,
    requiredRoles: ['admin', 'super-admin'],
    fallbackUrl: '/account',
  },
  {
    path: '/admin/dashboard',
    isPublic: false,
    requiredRoles: ['admin', 'super-admin'],
    fallbackUrl: '/account',
  },
  {
    path: '/admin/users',
    isPublic: false,
    requiredRoles: ['admin', 'super-admin'],
    requiredPermissions: ['user:read'],
    fallbackUrl: '/account',
  },
  {
    path: '/admin/products',
    isPublic: false,
    requiredRoles: ['admin', 'super-admin'],
    requiredPermissions: ['product:read'],
    fallbackUrl: '/account',
  },
  {
    path: '/admin/orders',
    isPublic: false,
    requiredRoles: ['admin', 'super-admin'],
    requiredPermissions: ['order:read'],
    fallbackUrl: '/account',
  },
  {
    path: '/admin/settings',
    isPublic: false,
    requiredRoles: ['admin', 'super-admin'],
    requiredPermissions: ['settings:read'],
    fallbackUrl: '/account',
  },
  {
    path: '/admin/audit-logs',
    isPublic: false,
    requiredRoles: ['admin', 'super-admin'],
    requiredPermissions: ['audit:read'],
    fallbackUrl: '/account',
  },

  // ============================================
  // SUPER ADMIN ROUTES
  // ============================================
  {
    path: '/admin/system',
    isPublic: false,
    requiredRoles: ['super-admin'],
    fallbackUrl: '/account',
  },
  {
    path: '/admin/roles',
    isPublic: false,
    requiredRoles: ['super-admin'],
    fallbackUrl: '/account',
  },
];

/**
 * Get route configuration for a given path
 */
export function getRouteConfig(path: string): IRouteConfig | undefined {
  // Try exact match first
  let config = ROUTE_CONFIG.find(route => route.path === path);
  
  // If no exact match, try pattern matching
  if (!config) {
    config = ROUTE_CONFIG.find(route => {
      // Convert route pattern to regex (e.g., /product/:slug -> /product/[^/]+)
      const pattern = route.path.replace(/:[^/]+/g, '[^/]+');
      const regex = new RegExp(`^${pattern}$`);
      return regex.test(path);
    });
  }
  
  return config;
}

/**
 * Check if a route is public
 */
export function isPublicRoute(path: string): boolean {
  const config = getRouteConfig(path);
  return config ? config.isPublic : false;
}

/**
 * Check if user can access a route
 */
export function canAccessRoute(
  path: string,
  userRoles: string[] = [],
  userPermissions: string[] = []
): { allowed: boolean; reason?: string; fallbackUrl?: string } {
  const config = getRouteConfig(path);
  
  // If no config found, default to protected (deny access)
  if (!config) {
    return {
      allowed: false,
      reason: 'Route configuration not found',
      fallbackUrl: '/auth/login',
    };
  }
  
  // Public routes are always accessible
  if (config.isPublic) {
    return { allowed: true };
  }
  
  // Check if user is authenticated
  if (userRoles.length === 0) {
    return {
      allowed: false,
      reason: 'Authentication required',
      fallbackUrl: config.fallbackUrl || '/auth/login',
    };
  }
  
  // Check custom guard if provided
  if (config.customGuard) {
    // Note: customGuard would need user object, but we can't pass it here
    // This would be handled in the component/middleware
  }
  
  // Check role requirements
  if (config.requiredRoles && config.requiredRoles.length > 0) {
    const hasRole = config.requiredRoles.some(role => userRoles.includes(role));
    if (!hasRole) {
      return {
        allowed: false,
        reason: 'Insufficient role privileges',
        fallbackUrl: config.fallbackUrl || '/account',
      };
    }
  }
  
  // Check permission requirements
  if (config.requiredPermissions && config.requiredPermissions.length > 0) {
    const hasPermission = config.requiredPermissions.every(perm =>
      userPermissions.includes(perm)
    );
    if (!hasPermission) {
      return {
        allowed: false,
        reason: 'Insufficient permissions',
        fallbackUrl: config.fallbackUrl || '/account',
      };
    }
  }
  
  return { allowed: true };
}

/**
 * Get all public routes
 */
export function getPublicRoutes(): string[] {
  return ROUTE_CONFIG.filter(route => route.isPublic).map(route => route.path);
}

/**
 * Get all protected routes
 */
export function getProtectedRoutes(): string[] {
  return ROUTE_CONFIG.filter(route => !route.isPublic).map(route => route.path);
}

/**
 * Add custom route configuration (for extending at runtime)
 */
export function addRouteConfig(config: IRouteConfig): void {
  const existingIndex = ROUTE_CONFIG.findIndex(r => r.path === config.path);
  if (existingIndex >= 0) {
    ROUTE_CONFIG[existingIndex] = config;
  } else {
    ROUTE_CONFIG.push(config);
  }
}

export default ROUTE_CONFIG;

