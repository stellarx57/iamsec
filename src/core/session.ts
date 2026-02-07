/**
 * IAMsec - Session Management
 * Handles user sessions, concurrent session limits, and session lifecycle
 */

import { ISession, IUser, IAuthTokens, ISecurityConfig } from '../types';
import { IStorageAdapter } from '../types';
import { generateSessionId } from '../utils/encryption';
import { auditLog } from '../utils/logger';

/**
 * Session Manager Class
 */
export class SessionManager {
  private config: ISecurityConfig['session'];
  private storageAdapter: IStorageAdapter;
  private activeSessions: Map<string, ISession> = new Map();

  constructor(config: ISecurityConfig['session'], storageAdapter: IStorageAdapter) {
    this.config = config;
    this.storageAdapter = storageAdapter;
    
    // Start session cleanup interval
    if (typeof window === 'undefined') {
      this.startCleanupInterval();
    }
  }

  /**
   * Create a new session
   */
  async createSession(
    user: IUser,
    tokens: IAuthTokens,
    ipAddress?: string,
    userAgent?: string
  ): Promise<ISession> {
    const sessionId = generateSessionId();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + tokens.expiresIn);

    const session: ISession = {
      user,
      tokens,
      sessionId,
      expiresAt,
      ipAddress,
      userAgent,
    };

    // Check concurrent session limit
    await this.enforceConcurrentSessionLimit(user.id);

    // Store session
    await this.storeSession(session);

    // Audit log
    await auditLog.loginSuccess(user, sessionId, ipAddress, userAgent);

    return session;
  }

  /**
   * Get session by ID
   */
  async getSession(sessionId: string): Promise<ISession | null> {
    // Check memory first
    if (this.activeSessions.has(sessionId)) {
      const session = this.activeSessions.get(sessionId)!;
      
      // Check if expired
      if (this.isSessionExpired(session)) {
        await this.terminateSession(sessionId);
        return null;
      }
      
      return session;
    }

    // Check storage
    const session = await this.storageAdapter.get<ISession>(
      `iamsec_session_${sessionId}`
    );

    if (!session) return null;

    // Check if expired
    if (this.isSessionExpired(session)) {
      await this.terminateSession(sessionId);
      return null;
    }

    // Cache in memory
    this.activeSessions.set(sessionId, session);

    return session;
  }

  /**
   * Update session (for token refresh or activity tracking)
   */
  async updateSession(sessionId: string, updates: Partial<ISession>): Promise<void> {
    const session = await this.getSession(sessionId);
    if (!session) return;

    const updatedSession: ISession = {
      ...session,
      ...updates,
    };

    // Update sliding expiration if enabled
    if (this.config.slidingExpiration && !updates.expiresAt) {
      const now = new Date();
      updatedSession.expiresAt = new Date(
        now.getTime() + this.config.inactivityTimeout * 60 * 1000
      );
    }

    await this.storeSession(updatedSession);
  }

  /**
   * Terminate a session
   */
  async terminateSession(sessionId: string): Promise<void> {
    const session = await this.getSession(sessionId);
    
    if (session) {
      await auditLog.logout(session.user.id, sessionId);
    }

    // Remove from memory
    this.activeSessions.delete(sessionId);

    // Remove from storage
    await this.storageAdapter.delete(`iamsec_session_${sessionId}`);

    // Remove from user sessions list
    if (session) {
      await this.removeUserSession(session.user.id, sessionId);
    }
  }

  /**
   * Terminate all sessions for a user
   */
  async terminateAllUserSessions(userId: string): Promise<void> {
    const userSessions = await this.getUserSessions(userId);
    
    for (const sessionId of userSessions) {
      await this.terminateSession(sessionId);
    }
  }

  /**
   * Get all active sessions for a user
   */
  async getUserSessions(userId: string): Promise<string[]> {
    const sessions = await this.storageAdapter.get<string[]>(
      `iamsec_user_sessions_${userId}`
    );
    return sessions || [];
  }

  /**
   * Store session in storage
   */
  private async storeSession(session: ISession): Promise<void> {
    // Store in memory
    this.activeSessions.set(session.sessionId, session);

    // Store in persistent storage
    const ttl = session.expiresAt.getTime() - Date.now();
    await this.storageAdapter.set(
      `iamsec_session_${session.sessionId}`,
      session,
      ttl
    );

    // Add to user sessions list
    await this.addUserSession(session.user.id, session.sessionId);
  }

  /**
   * Add session to user's session list
   */
  private async addUserSession(userId: string, sessionId: string): Promise<void> {
    const userSessions = await this.getUserSessions(userId);
    
    if (!userSessions.includes(sessionId)) {
      userSessions.push(sessionId);
      await this.storageAdapter.set(
        `iamsec_user_sessions_${userId}`,
        userSessions
      );
    }
  }

  /**
   * Remove session from user's session list
   */
  private async removeUserSession(userId: string, sessionId: string): Promise<void> {
    const userSessions = await this.getUserSessions(userId);
    const filtered = userSessions.filter(id => id !== sessionId);
    
    await this.storageAdapter.set(
      `iamsec_user_sessions_${userId}`,
      filtered
    );
  }

  /**
   * Enforce concurrent session limit
   */
  private async enforceConcurrentSessionLimit(userId: string): Promise<void> {
    const userSessions = await this.getUserSessions(userId);
    
    if (userSessions.length >= this.config.maxConcurrentSessions) {
      // Terminate oldest session(s)
      const sessionsToTerminate = userSessions.length - this.config.maxConcurrentSessions + 1;
      
      for (let i = 0; i < sessionsToTerminate; i++) {
        await this.terminateSession(userSessions[i]);
      }
    }
  }

  /**
   * Check if session is expired
   */
  private isSessionExpired(session: ISession): boolean {
    const now = new Date();
    
    // Check absolute expiration
    if (session.expiresAt && session.expiresAt < now) {
      return true;
    }

    // Check absolute timeout (if configured)
    if (this.config.absoluteTimeout) {
      const sessionAge = now.getTime() - new Date(session.user.lastLoginAt || 0).getTime();
      if (sessionAge > this.config.absoluteTimeout * 60 * 1000) {
        return true;
      }
    }

    return false;
  }

  /**
   * Start periodic cleanup of expired sessions
   */
  private startCleanupInterval(): void {
    setInterval(() => {
      this.cleanupExpiredSessions();
    }, 5 * 60 * 1000); // Every 5 minutes
  }

  /**
   * Clean up expired sessions
   */
  private async cleanupExpiredSessions(): Promise<void> {
    for (const [sessionId, session] of this.activeSessions.entries()) {
      if (this.isSessionExpired(session)) {
        await this.terminateSession(sessionId);
      }
    }
  }

  /**
   * Validate session and update activity
   */
  async validateSession(sessionId: string): Promise<ISession | null> {
    const session = await this.getSession(sessionId);
    
    if (!session) return null;

    // Update last activity if sliding expiration is enabled
    if (this.config.slidingExpiration) {
      await this.updateSession(sessionId, {});
    }

    return session;
  }

  /**
   * Get session count for a user
   */
  async getUserSessionCount(userId: string): Promise<number> {
    const sessions = await this.getUserSessions(userId);
    return sessions.length;
  }

  /**
   * Check if user has reached max concurrent sessions
   */
  async hasReachedMaxSessions(userId: string): Promise<boolean> {
    const count = await this.getUserSessionCount(userId);
    return count >= this.config.maxConcurrentSessions;
  }
}

/**
 * Create session manager instance
 */
export function createSessionManager(
  config: ISecurityConfig['session'],
  storageAdapter: IStorageAdapter
): SessionManager {
  return new SessionManager(config, storageAdapter);
}

export default SessionManager;

