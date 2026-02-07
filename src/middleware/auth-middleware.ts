/**
 * IAMsec - Authentication Middleware
 * Next.js middleware for route protection and authentication
 */

import { IUser, ISession, IMiddlewareContext, IMiddlewareResult } from '../types';
import { canAccessRoute } from '../config/routes.config';
import { getPermissionsForRoles } from '../config/roles.config';

/**
 * Authentication Middleware Class
 */
export class AuthMiddleware {
  /**
   * Check if user can access route
   */
  async checkRouteAccess(params: {
    path: string;
    user: IUser | null;
    session: ISession | null;
  }): Promise<IMiddlewareResult> {
    const { path, user } = params;

    const userRoles = user?.roles || [];
    const userPermissions = user ? getPermissionsForRoles(userRoles) : [];

    const accessCheck = canAccessRoute(path, userRoles, userPermissions);

    if (!accessCheck.allowed) {
      return {
        allowed: false,
        reason: accessCheck.reason,
        statusCode: user ? 403 : 401, // 403 Forbidden if authenticated, 401 Unauthorized if not
      };
    }

    return {
      allowed: true,
    };
  }

  /**
   * Extract user from request context
   */
  extractUser(context: IMiddlewareContext): IUser | null {
    return context.user;
  }

  /**
   * Extract session from request context
   */
  extractSession(context: IMiddlewareContext): ISession | null {
    return context.session;
  }

  /**
   * Create middleware context from request
   */
  createContext(params: {
    path: string;
    method: string;
    headers: Record<string, string>;
    user?: IUser | null;
    session?: ISession | null;
    ip?: string;
    userAgent?: string;
  }): IMiddlewareContext {
    return {
      user: params.user || null,
      session: params.session || null,
      request: {
        path: params.path,
        method: params.method,
        headers: params.headers,
        ip: params.ip,
        userAgent: params.userAgent,
      },
    };
  }

  /**
   * Validate authentication token from request
   */
  extractTokenFromRequest(headers: Record<string, string>): string | null {
    // Check Authorization header
    const authHeader = headers['authorization'] || headers['Authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }

    // Check X-Auth-Token header
    const xAuthToken = headers['x-auth-token'] || headers['X-Auth-Token'];
    if (xAuthToken) {
      return xAuthToken;
    }

    return null;
  }

  /**
   * Get redirect URL for unauthorized access
   */
  getRedirectUrl(path: string, user: IUser | null): string {
    if (!user) {
      // Not authenticated - redirect to login
      return `/auth/login?redirect=${encodeURIComponent(path)}`;
    }

    // Authenticated but insufficient permissions - redirect to account
    return '/account';
  }
}

/**
 * Create auth middleware instance
 */
export function createAuthMiddleware(): AuthMiddleware {
  return new AuthMiddleware();
}

export default AuthMiddleware;

