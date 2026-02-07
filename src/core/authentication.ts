/**
 * IAMsec - Authentication Module
 * Core authentication logic and credential validation
 */

import { ICredentials, IAuthResult, IUser, ISecurityConfig, IAuthTokens } from '../types';
import { TokenManager } from './tokens';
import { SessionManager } from './session';
import { hashPassword, verifyPassword } from '../utils/encryption';
import { isValidEmail, validatePassword, normalizeEmail } from '../utils/validation';
import { auditLog } from '../utils/logger';

/**
 * Authentication Service
 */
export class AuthenticationService {
  private config: ISecurityConfig;
  private tokenManager: TokenManager;
  private sessionManager: SessionManager;
  private lockouts: Map<string, { attempts: number; lockedUntil?: Date }> = new Map();

  constructor(
    config: ISecurityConfig,
    tokenManager: TokenManager,
    sessionManager: SessionManager
  ) {
    this.config = config;
    this.tokenManager = tokenManager;
    this.sessionManager = sessionManager;
  }

  /**
   * Authenticate user with credentials
   */
  async authenticate(
    credentials: ICredentials,
    ipAddress?: string,
    userAgent?: string
  ): Promise<IAuthResult> {
    const email = normalizeEmail(credentials.email);

    // Validate email format
    if (!isValidEmail(email)) {
      await auditLog.loginFailure(email, 'Invalid email format', ipAddress, userAgent);
      return {
        success: false,
        error: 'Invalid email or password',
      };
    }

    // Check account lockout
    if (this.isAccountLocked(email)) {
      const lockout = this.lockouts.get(email);
      const minutesRemaining = lockout?.lockedUntil
        ? Math.ceil((lockout.lockedUntil.getTime() - Date.now()) / 60000)
        : 0;

      await auditLog.loginFailure(
        email,
        'Account locked',
        ipAddress,
        userAgent
      );

      return {
        success: false,
        error: `Account is locked. Try again in ${minutesRemaining} minutes.`,
      };
    }

    // TODO: Fetch user from database
    // For now, this is a placeholder - integrate with your actual user store
    const user = await this.fetchUserByEmail(email);

    if (!user) {
      this.recordFailedAttempt(email);
      await auditLog.loginFailure(email, 'User not found', ipAddress, userAgent);
      return {
        success: false,
        error: 'Invalid email or password',
      };
    }

    // Verify password
    const isValidPassword = await this.verifyUserPassword(user, credentials.password);

    if (!isValidPassword) {
      this.recordFailedAttempt(email);
      await auditLog.loginFailure(email, 'Invalid password', ipAddress, userAgent);
      return {
        success: false,
        error: 'Invalid email or password',
      };
    }

    // Check if user is active
    if (!user.isActive) {
      await auditLog.loginFailure(email, 'Account inactive', ipAddress, userAgent);
      return {
        success: false,
        error: 'Your account has been deactivated',
      };
    }

    // Check MFA if enabled
    if (user.isMfaEnabled && !credentials.mfaToken) {
      return {
        success: false,
        requiresMfa: true,
        error: 'MFA verification required',
      };
    }

    if (user.isMfaEnabled && credentials.mfaToken) {
      const mfaValid = await this.verifyMfaToken(user, credentials.mfaToken);
      if (!mfaValid) {
        await auditLog.loginFailure(email, 'Invalid MFA token', ipAddress, userAgent);
        return {
          success: false,
          error: 'Invalid MFA code',
        };
      }
    }

    // Reset failed attempts on successful login
    this.resetFailedAttempts(email);

    // Create tokens
    const tokens = await this.tokenManager.createTokens(user, '');

    // Create session
    const session = await this.sessionManager.createSession(
      user,
      tokens,
      ipAddress,
      userAgent
    );

    return {
      success: true,
      session,
    };
  }

  /**
   * Register a new user
   */
  async register(
    email: string,
    password: string,
    username?: string,
    metadata?: Record<string, any>
  ): Promise<{ success: boolean; user?: IUser; error?: string }> {
    email = normalizeEmail(email);

    // Validate email
    if (!isValidEmail(email)) {
      return {
        success: false,
        error: 'Invalid email address',
      };
    }

    // Validate password
    const passwordValidation = validatePassword(password, this.config.passwordPolicy);
    if (!passwordValidation.isValid) {
      return {
        success: false,
        error: passwordValidation.errors[0],
      };
    }

    // Check if user already exists
    const existingUser = await this.fetchUserByEmail(email);
    if (existingUser) {
      return {
        success: false,
        error: 'An account with this email already exists',
      };
    }

    // Hash password
    const hashedPassword = await hashPassword(password, this.config.encryption.saltRounds);

    // Create user
    const user: IUser = {
      id: this.generateUserId(),
      email,
      username,
      roles: ['customer'], // Default role
      permissions: [],
      metadata,
      createdAt: new Date(),
      isActive: true,
      isMfaEnabled: false,
    };

    // TODO: Save user to database with hashed password
    // await this.saveUser(user, hashedPassword);

    return {
      success: true,
      user,
    };
  }

  /**
   * Verify user credentials (for password changes, etc.)
   */
  async verifyCredentials(userId: string, password: string): Promise<boolean> {
    // TODO: Fetch user from database
    const user = await this.fetchUserById(userId);
    if (!user) return false;

    return await this.verifyUserPassword(user, password);
  }

  /**
   * Change user password
   */
  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string
  ): Promise<{ success: boolean; error?: string }> {
    // Verify current password
    const isValid = await this.verifyCredentials(userId, currentPassword);
    if (!isValid) {
      return {
        success: false,
        error: 'Current password is incorrect',
      };
    }

    // Validate new password
    const validation = validatePassword(newPassword, this.config.passwordPolicy);
    if (!validation.isValid) {
      return {
        success: false,
        error: validation.errors[0],
      };
    }

    // Hash new password
    const hashedPassword = await hashPassword(
      newPassword,
      this.config.encryption.saltRounds
    );

    // TODO: Update password in database
    // await this.updateUserPassword(userId, hashedPassword);

    // Log password change
    await auditLog.passwordChanged(userId, '');

    // Terminate all other sessions (force re-login)
    await this.sessionManager.terminateAllUserSessions(userId);

    return {
      success: true,
    };
  }

  /**
   * Logout user
   */
  async logout(sessionId: string): Promise<void> {
    await this.sessionManager.terminateSession(sessionId);
  }

  /**
   * Refresh authentication tokens
   */
  async refreshTokens(refreshToken: string): Promise<IAuthTokens | null> {
    // Validate refresh token
    const payload = await this.tokenManager.validateRefreshToken(refreshToken);
    if (!payload || !payload.sub) {
      return null;
    }

    // Fetch user
    const user = await this.fetchUserById(payload.sub);
    if (!user) {
      return null;
    }

    // Get session
    const session = payload.sessionId
      ? await this.sessionManager.getSession(payload.sessionId)
      : null;

    if (!session) {
      return null;
    }

    // Create new tokens
    const tokens = await this.tokenManager.createTokens(user, session.sessionId);

    // Update session
    await this.sessionManager.updateSession(session.sessionId, { tokens });

    return tokens;
  }

  /**
   * Check if account is locked
   */
  private isAccountLocked(email: string): boolean {
    const lockout = this.lockouts.get(email);
    if (!lockout || !lockout.lockedUntil) return false;

    if (Date.now() >= lockout.lockedUntil.getTime()) {
      // Lockout expired
      this.lockouts.delete(email);
      return false;
    }

    return true;
  }

  /**
   * Record failed login attempt
   */
  private recordFailedAttempt(email: string): void {
    if (!this.config.accountLockout.enabled) return;

    const lockout = this.lockouts.get(email) || { attempts: 0 };
    lockout.attempts++;

    if (lockout.attempts >= this.config.accountLockout.maxFailedAttempts) {
      // Lock account
      lockout.lockedUntil = new Date(
        Date.now() + this.config.accountLockout.lockoutDuration * 60 * 1000
      );

      auditLog.accountLocked('', `Too many failed attempts for ${email}`);
    }

    this.lockouts.set(email, lockout);
  }

  /**
   * Reset failed attempts counter
   */
  private resetFailedAttempts(email: string): void {
    this.lockouts.delete(email);
  }

  /**
   * Verify MFA token (placeholder - implement with actual MFA provider)
   */
  private async verifyMfaToken(user: IUser, token: string): Promise<boolean> {
    // TODO: Implement MFA verification (TOTP, SMS, Email)
    // For now, return true for demo purposes
    return token.length === 6 && /^\d+$/.test(token);
  }

  /**
   * Generate unique user ID
   */
  private generateUserId(): string {
    return `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Fetch user by email (placeholder - integrate with your database)
   */
  private async fetchUserByEmail(email: string): Promise<IUser | null> {
    // TODO: Implement actual database query
    // This is a placeholder for demonstration
    return null;
  }

  /**
   * Fetch user by ID (placeholder - integrate with your database)
   */
  private async fetchUserById(userId: string): Promise<IUser | null> {
    // TODO: Implement actual database query
    return null;
  }

  /**
   * Verify user password (placeholder - integrate with your database)
   */
  private async verifyUserPassword(user: IUser, password: string): Promise<boolean> {
    // TODO: Fetch hashed password from database and verify
    // For now, this is a placeholder
    return false;
  }
}

/**
 * Create authentication service instance
 */
export function createAuthenticationService(
  config: ISecurityConfig,
  tokenManager: TokenManager,
  sessionManager: SessionManager
): AuthenticationService {
  return new AuthenticationService(config, tokenManager, sessionManager);
}

export default AuthenticationService;

