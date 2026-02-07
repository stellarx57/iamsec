/**
 * IAMsec - CSRF Protection Middleware
 * Cross-Site Request Forgery protection
 */

import { ISecurityConfig } from '../types';
import { IStorageAdapter } from '../types';
import { generateCsrfToken } from '../utils/encryption';
import { auditLog } from '../utils/logger';
import { AuditEventType, AuditCategory } from '../types';

/**
 * CSRF Protection Class
 */
export class CsrfProtection {
  private config: ISecurityConfig['csrf'];
  private storage: IStorageAdapter;
  private tokens: Map<string, { token: string; createdAt: Date; sessionId: string }> = new Map();

  constructor(config: ISecurityConfig['csrf'], storage: IStorageAdapter) {
    this.config = config;
    this.storage = storage;
  }

  /**
   * Generate CSRF token for a session
   */
  async generateToken(sessionId: string): Promise<string> {
    if (!this.config.enabled) {
      return '';
    }

    const token = generateCsrfToken();
    const createdAt = new Date();

    // Store in memory
    this.tokens.set(sessionId, { token, createdAt, sessionId });

    // Store in persistent storage
    await this.storage.set(
      `iamsec_csrf_${sessionId}`,
      { token, createdAt, sessionId },
      24 * 60 * 60 * 1000 // 24 hours
    );

    return token;
  }

  /**
   * Validate CSRF token
   */
  async validateToken(sessionId: string, providedToken: string): Promise<boolean> {
    if (!this.config.enabled) {
      return true;
    }

    // Check memory first
    let tokenData = this.tokens.get(sessionId);

    // If not in memory, check storage
    if (!tokenData) {
      const stored = await this.storage.get<{
        token: string;
        createdAt: Date;
        sessionId: string;
      }>(`iamsec_csrf_${sessionId}`);

      if (stored) {
        tokenData = {
          ...stored,
          createdAt: new Date(stored.createdAt),
        };
        this.tokens.set(sessionId, tokenData);
      }
    }

    if (!tokenData) {
      return false;
    }

    // Validate token
    const isValid = tokenData.token === providedToken;

    if (!isValid) {
      // Log CSRF attack attempt
      await this.logCsrfAttack(sessionId, providedToken);
    }

    return isValid;
  }

  /**
   * Rotate CSRF token (generate new one)
   */
  async rotateToken(sessionId: string): Promise<string> {
    // Invalidate old token
    await this.invalidateToken(sessionId);

    // Generate new token
    return await this.generateToken(sessionId);
  }

  /**
   * Invalidate CSRF token
   */
  async invalidateToken(sessionId: string): Promise<void> {
    this.tokens.delete(sessionId);
    await this.storage.delete(`iamsec_csrf_${sessionId}`);
  }

  /**
   * Get CSRF token for session
   */
  async getToken(sessionId: string): Promise<string | null> {
    // Check memory first
    let tokenData = this.tokens.get(sessionId);

    // If not in memory, check storage
    if (!tokenData) {
      const stored = await this.storage.get<{
        token: string;
        createdAt: Date;
        sessionId: string;
      }>(`iamsec_csrf_${sessionId}`);

      if (stored) {
        tokenData = {
          ...stored,
          createdAt: new Date(stored.createdAt),
        };
        this.tokens.set(sessionId, tokenData);
      }
    }

    return tokenData ? tokenData.token : null;
  }

  /**
   * Verify request has valid CSRF token
   */
  async verifyRequest(params: {
    sessionId: string;
    token?: string;
    method: string;
    origin?: string;
  }): Promise<{ valid: boolean; reason?: string }> {
    if (!this.config.enabled) {
      return { valid: true };
    }

    const { sessionId, token, method, origin } = params;

    // Only validate state-changing methods
    const methodsToValidate = ['POST', 'PUT', 'PATCH', 'DELETE'];
    if (!methodsToValidate.includes(method.toUpperCase())) {
      return { valid: true };
    }

    // Check if token is provided
    if (!token) {
      return {
        valid: false,
        reason: 'CSRF token missing',
      };
    }

    // Validate token
    const isValid = await this.validateToken(sessionId, token);

    if (!isValid) {
      return {
        valid: false,
        reason: 'Invalid CSRF token',
      };
    }

    return { valid: true };
  }

  /**
   * Get CSRF cookie name
   */
  getCookieName(): string {
    return this.config.cookieName;
  }

  /**
   * Get CSRF header name
   */
  getHeaderName(): string {
    return this.config.headerName;
  }

  /**
   * Log CSRF attack attempt
   */
  private async logCsrfAttack(sessionId: string, invalidToken: string): Promise<void> {
    const logger = (await import('../utils/logger')).getAuditLogger();
    await logger.log({
      eventType: AuditEventType.CSRF_ATTACK_PREVENTED,
      eventCategory: AuditCategory.SECURITY,
      action: 'CSRF attack attempt detected',
      sessionId,
      status: 'warning',
      details: {
        invalidToken: invalidToken.substring(0, 10) + '...',
      },
      severity: 'critical',
    });
  }

  /**
   * Clean up expired tokens
   */
  async cleanup(): Promise<void> {
    const now = new Date();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    for (const [sessionId, tokenData] of this.tokens.entries()) {
      if (now.getTime() - tokenData.createdAt.getTime() > maxAge) {
        await this.invalidateToken(sessionId);
      }
    }
  }
}

/**
 * Create CSRF protection instance
 */
export function createCsrfProtection(
  config: ISecurityConfig['csrf'],
  storage: IStorageAdapter
): CsrfProtection {
  return new CsrfProtection(config, storage);
}

export default CsrfProtection;

