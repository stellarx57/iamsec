/**
 * IAMsec - Security Configuration
 * Industry-standard security settings for authentication and authorization
 */

import { ISecurityConfig } from '../types';

/**
 * Default security configuration
 * Following OWASP and NIST guidelines
 */
export const defaultSecurityConfig: ISecurityConfig = {
  // JWT Configuration
  jwt: {
    accessTokenSecret: process.env.IAMSEC_ACCESS_TOKEN_SECRET || 'change-this-in-production',
    refreshTokenSecret: process.env.IAMSEC_REFRESH_TOKEN_SECRET || 'change-this-in-production',
    accessTokenExpiry: process.env.IAMSEC_ACCESS_TOKEN_EXPIRY || '15m',
    refreshTokenExpiry: process.env.IAMSEC_REFRESH_TOKEN_EXPIRY || '7d',
    issuer: process.env.IAMSEC_JWT_ISSUER || 'iamsec',
    audience: process.env.IAMSEC_JWT_AUDIENCE || 'iamsec-app',
  },

  // Password Policy (NIST 800-63B compliant)
  passwordPolicy: {
    minLength: 12, // NIST recommends minimum 8, we use 12 for enhanced security
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    maxAge: 90, // Days (optional - some standards now recommend against forced rotation)
    preventReuse: 5, // Prevent reuse of last 5 passwords
  },

  // Session Management
  session: {
    maxConcurrentSessions: 3, // Allow user to be logged in on 3 devices
    slidingExpiration: true, // Extend session on activity
    absoluteTimeout: 480, // 8 hours maximum session duration
    inactivityTimeout: 30, // 30 minutes of inactivity logs user out
  },

  // Rate Limiting (DDoS and Brute Force Protection)
  rateLimit: {
    enabled: true,
    maxAttempts: 5, // Max attempts per window
    windowMs: 15 * 60 * 1000, // 15 minutes
    blockDuration: 60 * 60 * 1000, // Block for 1 hour after exceeding limit
  },

  // Account Lockout (Brute Force Protection)
  accountLockout: {
    enabled: true,
    maxFailedAttempts: 5, // Lock account after 5 failed login attempts
    lockoutDuration: 30, // Lock for 30 minutes
    resetOnSuccess: true, // Reset counter on successful login
  },

  // CSRF Protection
  csrf: {
    enabled: true,
    tokenLength: 32,
    cookieName: 'iamsec-csrf-token',
    headerName: 'X-CSRF-Token',
  },

  // Audit Logging (Compliance and Forensics)
  audit: {
    enabled: true,
    logSuccessfulLogins: true,
    logFailedLogins: true,
    logPasswordChanges: true,
    logRoleChanges: true,
    logPermissionChanges: true,
    logSessionActivity: true,
    retentionDays: 365, // Keep logs for 1 year (adjust per compliance requirements)
  },

  // Encryption (Data Protection)
  encryption: {
    algorithm: 'aes-256-gcm', // AES-256-GCM for authenticated encryption
    saltRounds: 12, // bcrypt salt rounds (higher = more secure but slower)
    keyDerivationIterations: 100000, // PBKDF2 iterations
  },

  // Multi-Factor Authentication
  mfa: {
    enabled: false, // Can be enabled when MFA implementation is ready
    enforceForRoles: ['admin', 'super-admin'], // Enforce MFA for privileged roles
    allowedMethods: ['totp', 'email'], // TOTP (authenticator apps) and email codes
  },
};

/**
 * Get security configuration with environment overrides
 */
export function getSecurityConfig(overrides?: Partial<ISecurityConfig>): ISecurityConfig {
  return {
    ...defaultSecurityConfig,
    ...overrides,
  };
}

/**
 * Validate security configuration
 */
export function validateSecurityConfig(config: ISecurityConfig): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  // Validate JWT secrets in production
  if (process.env.NODE_ENV === 'production') {
    if (config.jwt.accessTokenSecret === 'change-this-in-production') {
      errors.push('JWT access token secret must be changed in production');
    }
    if (config.jwt.refreshTokenSecret === 'change-this-in-production') {
      errors.push('JWT refresh token secret must be changed in production');
    }
    if (config.jwt.accessTokenSecret === config.jwt.refreshTokenSecret) {
      errors.push('Access token and refresh token secrets must be different');
    }
  }

  // Validate password policy
  if (config.passwordPolicy.minLength < 8) {
    errors.push('Password minimum length should be at least 8 characters');
  }

  // Validate session timeouts
  if (config.session.inactivityTimeout > config.session.absoluteTimeout) {
    errors.push('Inactivity timeout cannot exceed absolute timeout');
  }

  // Validate rate limiting
  if (config.rateLimit.enabled && config.rateLimit.maxAttempts < 1) {
    errors.push('Rate limit max attempts must be at least 1');
  }

  // Validate account lockout
  if (config.accountLockout.enabled && config.accountLockout.maxFailedAttempts < 1) {
    errors.push('Account lockout max failed attempts must be at least 1');
  }

  // Validate encryption
  if (config.encryption.saltRounds < 10) {
    errors.push('Salt rounds should be at least 10 for bcrypt');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Security headers configuration (for Next.js middleware)
 */
export const securityHeaders = {
  // Prevent clickjacking
  'X-Frame-Options': 'DENY',
  
  // Enable browser XSS protection
  'X-Content-Type-Options': 'nosniff',
  
  // Control referrer information
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  
  // Permissions policy
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  
  // Content Security Policy (adjust based on your app needs)
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self' 'unsafe-eval' 'unsafe-inline'", // Adjust for Next.js
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
  ].join('; '),
  
  // HSTS (HTTP Strict Transport Security) - only in production with HTTPS
  ...(process.env.NODE_ENV === 'production' && {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  }),
};

export default defaultSecurityConfig;

