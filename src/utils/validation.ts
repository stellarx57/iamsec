/**
 * IAMsec - Validation Utilities
 * Input validation and sanitization functions
 */

import { IPasswordValidation, ISecurityConfig } from '../types';

/**
 * Validate email address
 */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Validate password against security policy
 */
export function validatePassword(
  password: string,
  policy: ISecurityConfig['passwordPolicy']
): IPasswordValidation {
  const errors: string[] = [];
  
  // Check minimum length
  if (password.length < policy.minLength) {
    errors.push(`Password must be at least ${policy.minLength} characters long`);
  }
  
  // Check uppercase requirement
  if (policy.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  // Check lowercase requirement
  if (policy.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  // Check numbers requirement
  if (policy.requireNumbers && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  // Check special characters requirement
  if (policy.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  // Calculate password strength
  const strength = calculatePasswordStrength(password);
  
  return {
    isValid: errors.length === 0,
    errors,
    strength,
  };
}

/**
 * Calculate password strength
 */
export function calculatePasswordStrength(
  password: string
): 'weak' | 'medium' | 'strong' | 'very-strong' {
  let score = 0;
  
  // Length
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  
  // Character variety
  if (/[a-z]/.test(password)) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score++;
  
  // Patterns (reduce score for common patterns)
  if (/(.)\1{2,}/.test(password)) score--; // Repeated characters
  if (/^[a-zA-Z]+$/.test(password)) score--; // Only letters
  if (/^\d+$/.test(password)) score--; // Only numbers
  
  if (score >= 7) return 'very-strong';
  if (score >= 5) return 'strong';
  if (score >= 3) return 'medium';
  return 'weak';
}

/**
 * Sanitize input to prevent XSS
 */
export function sanitizeInput(input: string): string {
  return input
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Validate username
 */
export function isValidUsername(username: string): { valid: boolean; error?: string } {
  if (username.length < 3) {
    return { valid: false, error: 'Username must be at least 3 characters long' };
  }
  
  if (username.length > 30) {
    return { valid: false, error: 'Username must not exceed 30 characters' };
  }
  
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
    return {
      valid: false,
      error: 'Username can only contain letters, numbers, underscores, and hyphens',
    };
  }
  
  return { valid: true };
}

/**
 * Check for SQL injection patterns
 */
export function hasSqlInjectionPattern(input: string): boolean {
  const sqlPatterns = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)/gi,
    /(\bOR\b\s+\d+\s*=\s*\d+)/gi,
    /(\bAND\b\s+\d+\s*=\s*\d+)/gi,
    /(--|;|\/\*|\*\/)/g,
    /(\bUNION\b.*\bSELECT\b)/gi,
  ];
  
  return sqlPatterns.some(pattern => pattern.test(input));
}

/**
 * Check for XSS patterns
 */
export function hasXssPattern(input: string): boolean {
  const xssPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
    /javascript:/gi,
    /on\w+\s*=\s*["'][^"']*["']/gi, // Event handlers
  ];
  
  return xssPatterns.some(pattern => pattern.test(input));
}

/**
 * Validate and sanitize redirect URL
 */
export function validateRedirectUrl(url: string, allowedDomains: string[] = []): boolean {
  try {
    const parsed = new URL(url, window.location.origin);
    
    // Only allow relative URLs or URLs from allowed domains
    if (parsed.origin === window.location.origin) {
      return true;
    }
    
    return allowedDomains.some(domain => parsed.hostname.endsWith(domain));
  } catch {
    // If URL parsing fails, check if it's a relative path
    return url.startsWith('/') && !url.startsWith('//');
  }
}

/**
 * Validate JWT token format (basic check)
 */
export function isValidJwtFormat(token: string): boolean {
  const parts = token.split('.');
  return parts.length === 3 && parts.every(part => part.length > 0);
}

/**
 * Validate UUID format
 */
export function isValidUuid(uuid: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

/**
 * Validate IP address
 */
export function isValidIpAddress(ip: string): boolean {
  // IPv4
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(ip)) {
    return ip.split('.').every(num => parseInt(num) <= 255);
  }
  
  // IPv6 (simplified)
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$/;
  return ipv6Regex.test(ip);
}

/**
 * Rate limit key generator
 */
export function generateRateLimitKey(identifier: string, action: string): string {
  return `ratelimit:${action}:${identifier}`;
}

/**
 * Validate phone number (basic international format)
 */
export function isValidPhoneNumber(phone: string): boolean {
  const phoneRegex = /^\+?[1-9]\d{1,14}$/;
  return phoneRegex.test(phone.replace(/[\s-]/g, ''));
}

/**
 * Check if string contains only alphanumeric characters
 */
export function isAlphanumeric(str: string): boolean {
  return /^[a-zA-Z0-9]+$/.test(str);
}

/**
 * Validate date string
 */
export function isValidDate(dateString: string): boolean {
  const date = new Date(dateString);
  return date instanceof Date && !isNaN(date.getTime());
}

/**
 * Normalize email address
 */
export function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}

/**
 * Check for common weak passwords
 */
export function isCommonPassword(password: string): boolean {
  const commonPasswords = [
    'password',
    '123456',
    '12345678',
    'qwerty',
    'abc123',
    'monkey',
    'letmein',
    'dragon',
    '111111',
    'baseball',
    'iloveyou',
    'trustno1',
    'sunshine',
    'master',
    'welcome',
    'shadow',
    'ashley',
    'football',
    'jesus',
    'michael',
  ];
  
  const lowerPassword = password.toLowerCase();
  return commonPasswords.some(common => lowerPassword.includes(common));
}

export default {
  isValidEmail,
  validatePassword,
  calculatePasswordStrength,
  sanitizeInput,
  isValidUsername,
  hasSqlInjectionPattern,
  hasXssPattern,
  validateRedirectUrl,
  isValidJwtFormat,
  isValidUuid,
  isValidIpAddress,
  generateRateLimitKey,
  isValidPhoneNumber,
  isAlphanumeric,
  isValidDate,
  normalizeEmail,
  isCommonPassword,
};

