/**
 * IAMsec - Encryption Utilities
 * Industry-standard encryption and hashing functions
 */

import crypto from 'crypto';

/**
 * Hash password using bcrypt-compatible algorithm
 * Note: In browser environments, this should be done server-side
 */
export async function hashPassword(password: string, saltRounds: number = 12): Promise<string> {
  // For server-side use only
  if (typeof window !== 'undefined') {
    throw new Error('Password hashing must be done server-side for security');
  }
  
  try {
    // Using PBKDF2 as a bcrypt alternative (works in Node.js without dependencies)
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return `pbkdf2$100000$${salt}$${hash}`;
  } catch (error) {
    throw new Error('Failed to hash password');
  }
}

/**
 * Verify password against hash
 */
export async function verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
  if (typeof window !== 'undefined') {
    throw new Error('Password verification must be done server-side for security');
  }
  
  try {
    const [algorithm, iterations, salt, hash] = hashedPassword.split('$');
    
    if (algorithm !== 'pbkdf2') {
      throw new Error('Unsupported hashing algorithm');
    }
    
    const verifyHash = crypto
      .pbkdf2Sync(password, salt, parseInt(iterations), 64, 'sha512')
      .toString('hex');
    
    return hash === verifyHash;
  } catch (error) {
    return false;
  }
}

/**
 * Generate random token
 */
export function generateToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Generate CSRF token
 */
export function generateCsrfToken(): string {
  return generateToken(32);
}

/**
 * Encrypt data using AES-256-GCM
 */
export function encrypt(data: string, key: string): string {
  const algorithm = 'aes-256-gcm';
  const iv = crypto.randomBytes(16);
  
  // Derive key from password
  const derivedKey = crypto.scryptSync(key, 'salt', 32);
  
  const cipher = crypto.createCipheriv(algorithm, derivedKey, iv);
  
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  // Return iv:authTag:encrypted
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

/**
 * Decrypt data using AES-256-GCM
 */
export function decrypt(encryptedData: string, key: string): string {
  const algorithm = 'aes-256-gcm';
  const [ivHex, authTagHex, encrypted] = encryptedData.split(':');
  
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  
  // Derive key from password
  const derivedKey = crypto.scryptSync(key, 'salt', 32);
  
  const decipher = crypto.createDecipheriv(algorithm, derivedKey, iv);
  decipher.setAuthTag(authTag);
  
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

/**
 * Generate cryptographically secure random string
 */
export function generateSecureRandom(length: number = 32): string {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.randomBytes(length);
  let result = '';
  
  for (let i = 0; i < length; i++) {
    result += charset[bytes[i] % charset.length];
  }
  
  return result;
}

/**
 * Hash data using SHA-256
 */
export function sha256(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Hash data using SHA-512
 */
export function sha512(data: string): string {
  return crypto.createHash('sha512').update(data).digest('hex');
}

/**
 * Generate HMAC signature
 */
export function hmacSign(data: string, secret: string): string {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

/**
 * Verify HMAC signature
 */
export function hmacVerify(data: string, signature: string, secret: string): boolean {
  const expectedSignature = hmacSign(data, secret);
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

/**
 * Mask sensitive data for logging
 */
export function maskSensitiveData(data: string, visibleChars: number = 4): string {
  if (data.length <= visibleChars) {
    return '*'.repeat(data.length);
  }
  return data.slice(0, visibleChars) + '*'.repeat(data.length - visibleChars);
}

/**
 * Generate session ID
 */
export function generateSessionId(): string {
  return `sess_${Date.now()}_${generateSecureRandom(32)}`;
}

export default {
  hashPassword,
  verifyPassword,
  generateToken,
  generateCsrfToken,
  encrypt,
  decrypt,
  generateSecureRandom,
  sha256,
  sha512,
  hmacSign,
  hmacVerify,
  maskSensitiveData,
  generateSessionId,
};

