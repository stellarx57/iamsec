/**
 * IAMsec - Identity and Access Management Security Framework
 * Type Definitions
 */

/**
 * User authentication state
 */
export interface IUser {
  id: string;
  email: string;
  username?: string;
  roles: string[];
  permissions: string[];
  metadata?: Record<string, any>;
  createdAt: Date;
  lastLoginAt?: Date;
  isActive: boolean;
  isMfaEnabled?: boolean;
}

/**
 * Authentication credentials
 */
export interface ICredentials {
  email: string;
  password: string;
  rememberMe?: boolean;
  mfaToken?: string;
}

/**
 * Authentication tokens
 */
export interface IAuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
}

/**
 * Authentication session
 */
export interface ISession {
  user: IUser;
  tokens: IAuthTokens;
  sessionId: string;
  expiresAt: Date;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * Role definition
 */
export interface IRole {
  id: string;
  name: string;
  description?: string;
  permissions: string[];
  priority: number; // Higher priority roles take precedence
  isSystemRole?: boolean;
}

/**
 * Permission definition
 */
export interface IPermission {
  id: string;
  name: string;
  resource: string;
  action: string; // create, read, update, delete, execute
  description?: string;
}

/**
 * Route protection configuration
 */
export interface IRouteConfig {
  path: string;
  isPublic: boolean;
  requiredRoles?: string[];
  requiredPermissions?: string[];
  fallbackUrl?: string;
  customGuard?: (user: IUser | null) => boolean;
}

/**
 * Security configuration
 */
export interface ISecurityConfig {
  // JWT Configuration
  jwt: {
    accessTokenSecret: string;
    refreshTokenSecret: string;
    accessTokenExpiry: string; // e.g., '15m', '1h'
    refreshTokenExpiry: string; // e.g., '7d', '30d'
    issuer: string;
    audience: string;
  };

  // Password Policy
  passwordPolicy: {
    minLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSpecialChars: boolean;
    maxAge?: number; // Days before password must be changed
    preventReuse?: number; // Number of previous passwords to check
  };

  // Session Management
  session: {
    maxConcurrentSessions: number;
    slidingExpiration: boolean;
    absoluteTimeout: number; // Minutes
    inactivityTimeout: number; // Minutes
  };

  // Rate Limiting
  rateLimit: {
    enabled: boolean;
    maxAttempts: number;
    windowMs: number; // Time window in milliseconds
    blockDuration: number; // Block duration in milliseconds
  };

  // Account Lockout
  accountLockout: {
    enabled: boolean;
    maxFailedAttempts: number;
    lockoutDuration: number; // Minutes
    resetOnSuccess: boolean;
  };

  // CSRF Protection
  csrf: {
    enabled: boolean;
    tokenLength: number;
    cookieName: string;
    headerName: string;
  };

  // Audit Logging
  audit: {
    enabled: boolean;
    logSuccessfulLogins: boolean;
    logFailedLogins: boolean;
    logPasswordChanges: boolean;
    logRoleChanges: boolean;
    logPermissionChanges: boolean;
    logSessionActivity: boolean;
    retentionDays: number;
  };

  // Encryption
  encryption: {
    algorithm: string; // e.g., 'aes-256-gcm'
    saltRounds: number; // For bcrypt
    keyDerivationIterations: number;
  };

  // MFA (Multi-Factor Authentication)
  mfa: {
    enabled: boolean;
    enforceForRoles?: string[];
    allowedMethods: ('totp' | 'sms' | 'email')[];
  };
}

/**
 * Audit log entry
 */
export interface IAuditLog {
  id: string;
  timestamp: Date;
  userId?: string;
  sessionId?: string;
  eventType: AuditEventType;
  eventCategory: AuditCategory;
  action: string;
  resource?: string;
  ipAddress?: string;
  userAgent?: string;
  status: 'success' | 'failure' | 'warning';
  details?: Record<string, any>;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Audit event types
 */
export enum AuditEventType {
  // Authentication Events
  LOGIN = 'LOGIN',
  LOGOUT = 'LOGOUT',
  LOGIN_FAILED = 'LOGIN_FAILED',
  TOKEN_REFRESH = 'TOKEN_REFRESH',
  PASSWORD_CHANGE = 'PASSWORD_CHANGE',
  PASSWORD_RESET = 'PASSWORD_RESET',
  MFA_ENABLED = 'MFA_ENABLED',
  MFA_DISABLED = 'MFA_DISABLED',

  // Authorization Events
  ACCESS_GRANTED = 'ACCESS_GRANTED',
  ACCESS_DENIED = 'ACCESS_DENIED',
  PERMISSION_CHANGE = 'PERMISSION_CHANGE',
  ROLE_ASSIGNED = 'ROLE_ASSIGNED',
  ROLE_REVOKED = 'ROLE_REVOKED',

  // Security Events
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  BRUTE_FORCE_DETECTED = 'BRUTE_FORCE_DETECTED',
  CSRF_ATTACK_PREVENTED = 'CSRF_ATTACK_PREVENTED',

  // Session Events
  SESSION_CREATED = 'SESSION_CREATED',
  SESSION_EXPIRED = 'SESSION_EXPIRED',
  SESSION_TERMINATED = 'SESSION_TERMINATED',
  CONCURRENT_SESSION_LIMIT = 'CONCURRENT_SESSION_LIMIT',
}

/**
 * Audit categories
 */
export enum AuditCategory {
  AUTHENTICATION = 'AUTHENTICATION',
  AUTHORIZATION = 'AUTHORIZATION',
  SECURITY = 'SECURITY',
  SESSION = 'SESSION',
  DATA_ACCESS = 'DATA_ACCESS',
  CONFIGURATION = 'CONFIGURATION',
}

/**
 * Authentication result
 */
export interface IAuthResult {
  success: boolean;
  session?: ISession;
  error?: string;
  requiresMfa?: boolean;
}

/**
 * Authorization context
 */
export interface IAuthContext {
  user: IUser | null;
  session: ISession | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: ICredentials) => Promise<IAuthResult>;
  logout: () => Promise<void>;
  refreshSession: () => Promise<void>;
  hasRole: (role: string | string[]) => boolean;
  hasPermission: (permission: string | string[]) => boolean;
  updateUser: (user: Partial<IUser>) => void;
}

/**
 * Rate limit store entry
 */
export interface IRateLimitEntry {
  attempts: number;
  firstAttempt: Date;
  lastAttempt: Date;
  blockedUntil?: Date;
}

/**
 * Account lockout entry
 */
export interface ILockoutEntry {
  userId: string;
  failedAttempts: number;
  lockedUntil?: Date;
  lastFailedAttempt: Date;
}

/**
 * Security event
 */
export interface ISecurityEvent {
  type: 'rate_limit' | 'lockout' | 'suspicious' | 'csrf' | 'xss' | 'injection';
  userId?: string;
  ipAddress?: string;
  timestamp: Date;
  details: Record<string, any>;
}

/**
 * Password validation result
 */
export interface IPasswordValidation {
  isValid: boolean;
  errors: string[];
  strength: 'weak' | 'medium' | 'strong' | 'very-strong';
}

/**
 * Token payload
 */
export interface ITokenPayload {
  sub: string; // User ID
  email: string;
  roles: string[];
  permissions: string[];
  sessionId: string;
  iat: number; // Issued at
  exp: number; // Expires at
  iss: string; // Issuer
  aud: string; // Audience
}

/**
 * Storage adapter interface
 */
export interface IStorageAdapter {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttl?: number): Promise<void>;
  delete(key: string): Promise<void>;
  clear(): Promise<void>;
  has(key: string): Promise<boolean>;
}

/**
 * Authentication provider interface
 */
export interface IAuthProvider {
  authenticate(credentials: ICredentials): Promise<IAuthResult>;
  validateToken(token: string): Promise<ITokenPayload | null>;
  refreshToken(refreshToken: string): Promise<IAuthTokens | null>;
  revokeToken(token: string): Promise<void>;
}

/**
 * Middleware context
 */
export interface IMiddlewareContext {
  user: IUser | null;
  session: ISession | null;
  request: {
    path: string;
    method: string;
    headers: Record<string, string>;
    ip?: string;
    userAgent?: string;
  };
}

/**
 * Middleware result
 */
export interface IMiddlewareResult {
  allowed: boolean;
  reason?: string;
  statusCode?: number;
}

