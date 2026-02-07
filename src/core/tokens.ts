/**
 * IAMsec - Token Management
 * JWT token creation, validation, and management
 */

import { IAuthTokens, ITokenPayload, IUser } from '../types';
import { ISecurityConfig } from '../types';

/**
 * Token Manager Class
 * Handles JWT token operations
 */
export class TokenManager {
  private config: ISecurityConfig['jwt'];

  constructor(config: ISecurityConfig['jwt']) {
    this.config = config;
  }

  /**
   * Create access and refresh tokens for a user
   */
  async createTokens(user: IUser, sessionId: string): Promise<IAuthTokens> {
    const accessToken = await this.createAccessToken(user, sessionId);
    const refreshToken = await this.createRefreshToken(user, sessionId);

    // Parse expiry time (e.g., '15m', '1h', '7d')
    const expiresIn = this.parseExpiryTime(this.config.accessTokenExpiry);

    return {
      accessToken,
      refreshToken,
      expiresIn,
      tokenType: 'Bearer',
    };
  }

  /**
   * Create access token
   */
  private async createAccessToken(user: IUser, sessionId: string): Promise<string> {
    const now = Date.now();
    const expiresIn = this.parseExpiryTime(this.config.accessTokenExpiry);

    const payload: ITokenPayload = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
      permissions: user.permissions,
      sessionId,
      iat: Math.floor(now / 1000),
      exp: Math.floor((now + expiresIn) / 1000),
      iss: this.config.issuer,
      aud: this.config.audience,
    };

    return this.encodeToken(payload, this.config.accessTokenSecret);
  }

  /**
   * Create refresh token
   */
  private async createRefreshToken(user: IUser, sessionId: string): Promise<string> {
    const now = Date.now();
    const expiresIn = this.parseExpiryTime(this.config.refreshTokenExpiry);

    const payload: Partial<ITokenPayload> = {
      sub: user.id,
      sessionId,
      iat: Math.floor(now / 1000),
      exp: Math.floor((now + expiresIn) / 1000),
      iss: this.config.issuer,
      aud: this.config.audience,
    };

    return this.encodeToken(payload, this.config.refreshTokenSecret);
  }

  /**
   * Validate and decode access token
   */
  async validateAccessToken(token: string): Promise<ITokenPayload | null> {
    return this.decodeToken(token, this.config.accessTokenSecret);
  }

  /**
   * Validate and decode refresh token
   */
  async validateRefreshToken(token: string): Promise<Partial<ITokenPayload> | null> {
    return this.decodeToken(token, this.config.refreshTokenSecret);
  }

  /**
   * Encode token (JWT creation)
   * Simple implementation - in production, use a library like jsonwebtoken
   */
  private encodeToken(payload: any, secret: string): string {
    // Header
    const header = {
      alg: 'HS256',
      typ: 'JWT',
    };

    // Encode header and payload
    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));

    // Create signature
    const signature = this.createSignature(
      `${encodedHeader}.${encodedPayload}`,
      secret
    );

    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }

  /**
   * Decode and validate token
   */
  private decodeToken(token: string, secret: string): any | null {
    try {
      const [encodedHeader, encodedPayload, signature] = token.split('.');

      // Verify signature
      const expectedSignature = this.createSignature(
        `${encodedHeader}.${encodedPayload}`,
        secret
      );

      if (signature !== expectedSignature) {
        return null;
      }

      // Decode payload
      const payload = JSON.parse(this.base64UrlDecode(encodedPayload));

      // Check expiration
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) {
        return null;
      }

      // Verify issuer and audience
      if (payload.iss !== this.config.issuer || payload.aud !== this.config.audience) {
        return null;
      }

      return payload;
    } catch {
      return null;
    }
  }

  /**
   * Create HMAC-SHA256 signature
   */
  private createSignature(data: string, secret: string): string {
    if (typeof window !== 'undefined') {
      // Browser environment - use Web Crypto API
      // This is a simplified version - production should use proper crypto
      return this.base64UrlEncode(this.simpleHmac(data, secret));
    } else {
      // Node.js environment
      const crypto = require('crypto');
      return crypto
        .createHmac('sha256', secret)
        .update(data)
        .digest('base64url');
    }
  }

  /**
   * Simple HMAC for browser (not cryptographically secure - use for demo only)
   */
  private simpleHmac(data: string, secret: string): string {
    // This is NOT secure - in production, use a proper library
    return Buffer.from(`${data}:${secret}`).toString('base64');
  }

  /**
   * Base64 URL encode
   */
  private base64UrlEncode(str: string): string {
    if (typeof window !== 'undefined') {
      return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    } else {
      return Buffer.from(str)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    }
  }

  /**
   * Base64 URL decode
   */
  private base64UrlDecode(str: string): string {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    
    // Add padding
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }

    if (typeof window !== 'undefined') {
      return atob(base64);
    } else {
      return Buffer.from(base64, 'base64').toString('utf-8');
    }
  }

  /**
   * Parse expiry time string (e.g., '15m', '1h', '7d')
   */
  private parseExpiryTime(expiry: string): number {
    const unit = expiry.slice(-1);
    const value = parseInt(expiry.slice(0, -1));

    switch (unit) {
      case 's':
        return value * 1000;
      case 'm':
        return value * 60 * 1000;
      case 'h':
        return value * 60 * 60 * 1000;
      case 'd':
        return value * 24 * 60 * 60 * 1000;
      default:
        return 15 * 60 * 1000; // Default 15 minutes
    }
  }

  /**
   * Get token expiration time
   */
  getTokenExpiration(token: string): Date | null {
    try {
      const [, encodedPayload] = token.split('.');
      const payload = JSON.parse(this.base64UrlDecode(encodedPayload));
      return payload.exp ? new Date(payload.exp * 1000) : null;
    } catch {
      return null;
    }
  }

  /**
   * Check if token is expired
   */
  isTokenExpired(token: string): boolean {
    const expiration = this.getTokenExpiration(token);
    if (!expiration) return true;
    return expiration.getTime() < Date.now();
  }

  /**
   * Get remaining token lifetime in milliseconds
   */
  getTokenLifetime(token: string): number {
    const expiration = this.getTokenExpiration(token);
    if (!expiration) return 0;
    return Math.max(0, expiration.getTime() - Date.now());
  }
}

/**
 * Create token manager instance
 */
export function createTokenManager(config: ISecurityConfig['jwt']): TokenManager {
  return new TokenManager(config);
}

export default TokenManager;

