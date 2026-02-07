/**
 * IAMsec - Rate Limiter Middleware
 * Protection against brute force and DDoS attacks
 */

import { ISecurityConfig, IRateLimitEntry } from '../types';
import { IStorageAdapter } from '../types';
import { auditLog } from '../utils/logger';
import { AuditEventType, AuditCategory } from '../types';

/**
 * Rate Limiter Class
 */
export class RateLimiter {
  private config: ISecurityConfig['rateLimit'];
  private storage: IStorageAdapter;
  private limitsMap: Map<string, IRateLimitEntry> = new Map();

  constructor(config: ISecurityConfig['rateLimit'], storage: IStorageAdapter) {
    this.config = config;
    this.storage = storage;

    // Start cleanup interval
    if (typeof window === 'undefined') {
      this.startCleanupInterval();
    }
  }

  /**
   * Check if request is allowed
   */
  async isAllowed(
    identifier: string,
    action: string = 'default'
  ): Promise<{ allowed: boolean; remaining: number; resetTime: Date }> {
    if (!this.config.enabled) {
      return {
        allowed: true,
        remaining: this.config.maxAttempts,
        resetTime: new Date(Date.now() + this.config.windowMs),
      };
    }

    const key = this.generateKey(identifier, action);
    const entry = await this.getEntry(key);
    const now = new Date();

    // Check if currently blocked
    if (entry.blockedUntil && entry.blockedUntil > now) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: entry.blockedUntil,
      };
    }

    // Check if window has expired
    const windowExpired =
      !entry.firstAttempt ||
      now.getTime() - entry.firstAttempt.getTime() > this.config.windowMs;

    if (windowExpired) {
      // Reset counter
      await this.resetEntry(key);
      return {
        allowed: true,
        remaining: this.config.maxAttempts - 1,
        resetTime: new Date(now.getTime() + this.config.windowMs),
      };
    }

    // Check if limit exceeded
    if (entry.attempts >= this.config.maxAttempts) {
      // Block the identifier
      const blockedUntil = new Date(now.getTime() + this.config.blockDuration);
      entry.blockedUntil = blockedUntil;
      await this.saveEntry(key, entry);

      // Log suspicious activity
      await auditLog.suspiciousActivity(
        undefined,
        'Rate limit exceeded',
        { identifier, action, attempts: entry.attempts },
        identifier
      );

      return {
        allowed: false,
        remaining: 0,
        resetTime: blockedUntil,
      };
    }

    // Increment counter
    entry.attempts++;
    entry.lastAttempt = now;
    await this.saveEntry(key, entry);

    return {
      allowed: true,
      remaining: this.config.maxAttempts - entry.attempts,
      resetTime: new Date(entry.firstAttempt.getTime() + this.config.windowMs),
    };
  }

  /**
   * Record an attempt
   */
  async recordAttempt(identifier: string, action: string = 'default'): Promise<void> {
    await this.isAllowed(identifier, action);
  }

  /**
   * Reset rate limit for identifier
   */
  async reset(identifier: string, action: string = 'default'): Promise<void> {
    const key = this.generateKey(identifier, action);
    await this.resetEntry(key);
  }

  /**
   * Get current rate limit status
   */
  async getStatus(
    identifier: string,
    action: string = 'default'
  ): Promise<{ attempts: number; remaining: number; isBlocked: boolean; resetTime?: Date }> {
    const key = this.generateKey(identifier, action);
    const entry = await this.getEntry(key);
    const now = new Date();

    const isBlocked = !!(entry.blockedUntil && entry.blockedUntil > now);

    return {
      attempts: entry.attempts,
      remaining: Math.max(0, this.config.maxAttempts - entry.attempts),
      isBlocked,
      resetTime: entry.blockedUntil || (entry.firstAttempt
        ? new Date(entry.firstAttempt.getTime() + this.config.windowMs)
        : undefined),
    };
  }

  /**
   * Generate storage key
   */
  private generateKey(identifier: string, action: string): string {
    return `iamsec_ratelimit_${action}_${identifier}`;
  }

  /**
   * Get rate limit entry
   */
  private async getEntry(key: string): Promise<IRateLimitEntry> {
    // Check memory first
    if (this.limitsMap.has(key)) {
      return this.limitsMap.get(key)!;
    }

    // Check storage
    const stored = await this.storage.get<IRateLimitEntry>(key);
    if (stored) {
      // Convert date strings back to Date objects
      const entry = {
        ...stored,
        firstAttempt: new Date(stored.firstAttempt),
        lastAttempt: new Date(stored.lastAttempt),
        blockedUntil: stored.blockedUntil ? new Date(stored.blockedUntil) : undefined,
      };
      this.limitsMap.set(key, entry);
      return entry;
    }

    // Create new entry
    const entry: IRateLimitEntry = {
      attempts: 0,
      firstAttempt: new Date(),
      lastAttempt: new Date(),
    };
    this.limitsMap.set(key, entry);
    return entry;
  }

  /**
   * Save rate limit entry
   */
  private async saveEntry(key: string, entry: IRateLimitEntry): Promise<void> {
    this.limitsMap.set(key, entry);
    
    // Calculate TTL
    const ttl = this.config.blockDuration + this.config.windowMs;
    await this.storage.set(key, entry, ttl);
  }

  /**
   * Reset rate limit entry
   */
  private async resetEntry(key: string): Promise<void> {
    const entry: IRateLimitEntry = {
      attempts: 0,
      firstAttempt: new Date(),
      lastAttempt: new Date(),
    };
    await this.saveEntry(key, entry);
  }

  /**
   * Clean up expired entries
   */
  private async cleanup(): Promise<void> {
    const now = new Date();
    
    for (const [key, entry] of this.limitsMap.entries()) {
      const expired =
        (!entry.blockedUntil || entry.blockedUntil < now) &&
        now.getTime() - entry.firstAttempt.getTime() > this.config.windowMs;

      if (expired) {
        this.limitsMap.delete(key);
        await this.storage.delete(key);
      }
    }
  }

  /**
   * Start cleanup interval
   */
  private startCleanupInterval(): void {
    setInterval(() => {
      this.cleanup();
    }, 60 * 1000); // Every minute
  }
}

/**
 * Create rate limiter instance
 */
export function createRateLimiter(
  config: ISecurityConfig['rateLimit'],
  storage: IStorageAdapter
): RateLimiter {
  return new RateLimiter(config, storage);
}

export default RateLimiter;

