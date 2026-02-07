/**
 * IAMsec - Audit Logger
 * Comprehensive audit logging for security events
 */

import { IAuditLog, AuditEventType, AuditCategory, IUser } from '../types';
import { generateToken } from './encryption';

/**
 * Audit Logger Class
 */
export class AuditLogger {
  private logs: IAuditLog[] = [];
  private maxLogsInMemory: number = 1000;
  private storageAdapter?: any; // TODO: Implement storage adapter

  constructor(storageAdapter?: any) {
    this.storageAdapter = storageAdapter;
  }

  /**
   * Log an audit event
   */
  async log(params: {
    eventType: AuditEventType;
    eventCategory: AuditCategory;
    action: string;
    userId?: string;
    sessionId?: string;
    resource?: string;
    ipAddress?: string;
    userAgent?: string;
    status: 'success' | 'failure' | 'warning';
    details?: Record<string, any>;
    severity?: 'low' | 'medium' | 'high' | 'critical';
  }): Promise<void> {
    const logEntry: IAuditLog = {
      id: generateToken(16),
      timestamp: new Date(),
      userId: params.userId,
      sessionId: params.sessionId,
      eventType: params.eventType,
      eventCategory: params.eventCategory,
      action: params.action,
      resource: params.resource,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      status: params.status,
      details: params.details,
      severity: params.severity || this.determineSeverity(params.eventType, params.status),
    };

    // Store in memory
    this.logs.push(logEntry);

    // Trim logs if exceeding limit
    if (this.logs.length > this.maxLogsInMemory) {
      this.logs.shift();
    }

    // Persist to storage if adapter is available
    if (this.storageAdapter) {
      try {
        await this.storageAdapter.save(logEntry);
      } catch (error) {
        console.error('Failed to persist audit log:', error);
      }
    }

    // Log to console in development
    if (process.env.NODE_ENV === 'development') {
      this.consoleLog(logEntry);
    }
  }

  /**
   * Determine severity based on event type and status
   */
  private determineSeverity(
    eventType: AuditEventType,
    status: 'success' | 'failure' | 'warning'
  ): 'low' | 'medium' | 'high' | 'critical' {
    // Critical events
    if ([
      AuditEventType.SUSPICIOUS_ACTIVITY,
      AuditEventType.BRUTE_FORCE_DETECTED,
      AuditEventType.CSRF_ATTACK_PREVENTED,
    ].includes(eventType)) {
      return 'critical';
    }

    // High severity events
    if ([
      AuditEventType.ACCOUNT_LOCKED,
      AuditEventType.PERMISSION_CHANGE,
      AuditEventType.ROLE_ASSIGNED,
      AuditEventType.ROLE_REVOKED,
    ].includes(eventType)) {
      return 'high';
    }

    // Medium severity events
    if ([
      AuditEventType.LOGIN_FAILED,
      AuditEventType.ACCESS_DENIED,
      AuditEventType.PASSWORD_CHANGE,
    ].includes(eventType)) {
      return status === 'failure' ? 'high' : 'medium';
    }

    // Low severity for successful routine operations
    return 'low';
  }

  /**
   * Format and log to console
   */
  private consoleLog(log: IAuditLog): void {
    const severityColors: Record<string, string> = {
      low: '\x1b[32m',      // Green
      medium: '\x1b[33m',   // Yellow
      high: '\x1b[35m',     // Magenta
      critical: '\x1b[31m', // Red
    };

    const statusIcons: Record<string, string> = {
      success: '✓',
      failure: '✗',
      warning: '⚠',
    };

    const color = severityColors[log.severity];
    const reset = '\x1b[0m';
    const icon = statusIcons[log.status];

    console.log(
      `${color}[${log.severity.toUpperCase()}]${reset} ${icon} ${log.eventType} - ${log.action}`,
      {
        userId: log.userId,
        sessionId: log.sessionId,
        resource: log.resource,
        status: log.status,
        details: log.details,
      }
    );
  }

  /**
   * Get recent logs
   */
  getRecentLogs(limit: number = 100): IAuditLog[] {
    return this.logs.slice(-limit);
  }

  /**
   * Query logs by filter
   */
  queryLogs(filter: {
    userId?: string;
    sessionId?: string;
    eventType?: AuditEventType;
    eventCategory?: AuditCategory;
    status?: 'success' | 'failure' | 'warning';
    severity?: 'low' | 'medium' | 'high' | 'critical';
    startDate?: Date;
    endDate?: Date;
  }): IAuditLog[] {
    return this.logs.filter(log => {
      if (filter.userId && log.userId !== filter.userId) return false;
      if (filter.sessionId && log.sessionId !== filter.sessionId) return false;
      if (filter.eventType && log.eventType !== filter.eventType) return false;
      if (filter.eventCategory && log.eventCategory !== filter.eventCategory) return false;
      if (filter.status && log.status !== filter.status) return false;
      if (filter.severity && log.severity !== filter.severity) return false;
      if (filter.startDate && log.timestamp < filter.startDate) return false;
      if (filter.endDate && log.timestamp > filter.endDate) return false;
      return true;
    });
  }

  /**
   * Clear logs (use with caution)
   */
  clearLogs(): void {
    this.logs = [];
  }

  /**
   * Export logs (for compliance/audit purposes)
   */
  exportLogs(format: 'json' | 'csv' = 'json'): string {
    if (format === 'json') {
      return JSON.stringify(this.logs, null, 2);
    }

    // CSV format
    const headers = [
      'ID',
      'Timestamp',
      'User ID',
      'Session ID',
      'Event Type',
      'Category',
      'Action',
      'Resource',
      'Status',
      'Severity',
      'IP Address',
    ];

    const rows = this.logs.map(log => [
      log.id,
      log.timestamp.toISOString(),
      log.userId || '',
      log.sessionId || '',
      log.eventType,
      log.eventCategory,
      log.action,
      log.resource || '',
      log.status,
      log.severity,
      log.ipAddress || '',
    ]);

    return [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(',')),
    ].join('\n');
  }
}

/**
 * Global audit logger instance
 */
let globalLogger: AuditLogger | null = null;

/**
 * Initialize global audit logger
 */
export function initializeAuditLogger(storageAdapter?: any): AuditLogger {
  if (!globalLogger) {
    globalLogger = new AuditLogger(storageAdapter);
  }
  return globalLogger;
}

/**
 * Get global audit logger instance
 */
export function getAuditLogger(): AuditLogger {
  if (!globalLogger) {
    globalLogger = new AuditLogger();
  }
  return globalLogger;
}

/**
 * Quick logging functions
 */
export const auditLog = {
  /**
   * Log successful login
   */
  loginSuccess: async (user: IUser, sessionId: string, ipAddress?: string, userAgent?: string) => {
    const logger = getAuditLogger();
    await logger.log({
      eventType: AuditEventType.LOGIN,
      eventCategory: AuditCategory.AUTHENTICATION,
      action: 'User logged in successfully',
      userId: user.id,
      sessionId,
      ipAddress,
      userAgent,
      status: 'success',
      severity: 'low',
    });
  },

  /**
   * Log failed login
   */
  loginFailure: async (email: string, reason: string, ipAddress?: string, userAgent?: string) => {
    const logger = getAuditLogger();
    await logger.log({
      eventType: AuditEventType.LOGIN_FAILED,
      eventCategory: AuditCategory.AUTHENTICATION,
      action: 'Login attempt failed',
      ipAddress,
      userAgent,
      status: 'failure',
      details: { email, reason },
      severity: 'medium',
    });
  },

  /**
   * Log logout
   */
  logout: async (userId: string, sessionId: string) => {
    const logger = getAuditLogger();
    await logger.log({
      eventType: AuditEventType.LOGOUT,
      eventCategory: AuditCategory.AUTHENTICATION,
      action: 'User logged out',
      userId,
      sessionId,
      status: 'success',
      severity: 'low',
    });
  },

  /**
   * Log access denied
   */
  accessDenied: async (
    userId: string | undefined,
    resource: string,
    reason: string,
    ipAddress?: string
  ) => {
    const logger = getAuditLogger();
    await logger.log({
      eventType: AuditEventType.ACCESS_DENIED,
      eventCategory: AuditCategory.AUTHORIZATION,
      action: 'Access denied to resource',
      userId,
      resource,
      ipAddress,
      status: 'failure',
      details: { reason },
      severity: 'medium',
    });
  },

  /**
   * Log suspicious activity
   */
  suspiciousActivity: async (
    userId: string | undefined,
    reason: string,
    details: Record<string, any>,
    ipAddress?: string
  ) => {
    const logger = getAuditLogger();
    await logger.log({
      eventType: AuditEventType.SUSPICIOUS_ACTIVITY,
      eventCategory: AuditCategory.SECURITY,
      action: 'Suspicious activity detected',
      userId,
      ipAddress,
      status: 'warning',
      details: { reason, ...details },
      severity: 'critical',
    });
  },

  /**
   * Log account lockout
   */
  accountLocked: async (userId: string, reason: string, ipAddress?: string) => {
    const logger = getAuditLogger();
    await logger.log({
      eventType: AuditEventType.ACCOUNT_LOCKED,
      eventCategory: AuditCategory.SECURITY,
      action: 'Account locked',
      userId,
      ipAddress,
      status: 'warning',
      details: { reason },
      severity: 'high',
    });
  },

  /**
   * Log password change
   */
  passwordChanged: async (userId: string, sessionId: string) => {
    const logger = getAuditLogger();
    await logger.log({
      eventType: AuditEventType.PASSWORD_CHANGE,
      eventCategory: AuditCategory.AUTHENTICATION,
      action: 'Password changed',
      userId,
      sessionId,
      status: 'success',
      severity: 'medium',
    });
  },
};

export default AuditLogger;

