/**
 * IAMsec - Identity and Access Management Security Framework
 * Main entry point
 */

// Types
export * from './types';
export * from './types/config';

// Configuration
export * from './config/security.config';
export * from './config/roles.config';
export * from './config/routes.config';

// Core Modules
export * from './core/authentication';
export * from './core/authorization';
export * from './core/session';
export * from './core/tokens';

// Middleware
export * from './middleware/auth-middleware';
export * from './middleware/rate-limiter';
export * from './middleware/csrf';

// Utils
export * from './utils/encryption';
export * from './utils/validation';
export * from './utils/logger';

// Storage
export * from './storage/storage-adapter';

// React Components & Hooks
export * from './providers/AuthProvider';
export * from './guards/RouteGuard';
export * from './hooks/useAuth';
export * from './hooks/usePermissions';

/**
 * IAMsec Version
 */
export const VERSION = '1.0.0';

/**
 * Default export
 */
export default {
  VERSION,
};

