/**
 * IAMsec - Storage Adapter
 * Unified storage interface for sessions, tokens, and audit logs
 */

import { IStorageAdapter } from '../types';
import Cookies from 'js-cookie';

/**
 * In-Memory Storage Adapter
 * For server-side or temporary storage
 */
export class MemoryStorageAdapter implements IStorageAdapter {
  private storage: Map<string, { value: any; expires?: number }> = new Map();

  async get<T>(key: string): Promise<T | null> {
    const item = this.storage.get(key);
    
    if (!item) return null;
    
    // Check expiration
    if (item.expires && Date.now() > item.expires) {
      this.storage.delete(key);
      return null;
    }
    
    return item.value as T;
  }

  async set<T>(key: string, value: T, ttl?: number): Promise<void> {
    const expires = ttl ? Date.now() + ttl : undefined;
    this.storage.set(key, { value, expires });
  }

  async delete(key: string): Promise<void> {
    this.storage.delete(key);
  }

  async clear(): Promise<void> {
    this.storage.clear();
  }

  async has(key: string): Promise<boolean> {
    return this.storage.has(key);
  }

  /**
   * Clean up expired entries
   */
  cleanup(): void {
    const now = Date.now();
    for (const [key, item] of this.storage.entries()) {
      if (item.expires && now > item.expires) {
        this.storage.delete(key);
      }
    }
  }
}

/**
 * Browser Storage Adapter
 * Uses localStorage + cookies for client-side storage
 */
export class BrowserStorageAdapter implements IStorageAdapter {
  private storageAvailable: boolean;

  constructor() {
    this.storageAvailable = this.checkStorageAvailable();
  }

  private checkStorageAvailable(): boolean {
    if (typeof window === 'undefined') return false;
    
    try {
      const test = '__storage_test__';
      localStorage.setItem(test, test);
      localStorage.removeItem(test);
      return true;
    } catch {
      return false;
    }
  }

  async get<T>(key: string): Promise<T | null> {
    if (!this.storageAvailable) {
      // Fallback to cookies
      const cookieValue = Cookies.get(key);
      if (!cookieValue) return null;
      
      try {
        const parsed = JSON.parse(cookieValue);
        if (parsed.expires && Date.now() > parsed.expires) {
          Cookies.remove(key);
          return null;
        }
        return parsed.value as T;
      } catch {
        return null;
      }
    }

    try {
      const item = localStorage.getItem(key);
      if (!item) return null;

      const parsed = JSON.parse(item);
      
      // Check expiration
      if (parsed.expires && Date.now() > parsed.expires) {
        localStorage.removeItem(key);
        return null;
      }

      return parsed.value as T;
    } catch {
      return null;
    }
  }

  async set<T>(key: string, value: T, ttl?: number): Promise<void> {
    const expires = ttl ? Date.now() + ttl : undefined;
    const data = { value, expires };

    if (!this.storageAvailable) {
      // Fallback to cookies
      const cookieOptions = ttl
        ? { expires: new Date(Date.now() + ttl) }
        : { expires: 7 }; // 7 days default
      
      Cookies.set(key, JSON.stringify(data), cookieOptions);
      return;
    }

    try {
      localStorage.setItem(key, JSON.stringify(data));
    } catch (error) {
      console.error('Failed to store in localStorage:', error);
      // Fallback to cookies
      Cookies.set(key, JSON.stringify(data), { expires: 7 });
    }
  }

  async delete(key: string): Promise<void> {
    if (this.storageAvailable) {
      localStorage.removeItem(key);
    }
    Cookies.remove(key);
  }

  async clear(): Promise<void> {
    if (this.storageAvailable) {
      localStorage.clear();
    }
    // Clear all IAMsec cookies
    Object.keys(Cookies.get()).forEach(key => {
      if (key.startsWith('iamsec_')) {
        Cookies.remove(key);
      }
    });
  }

  async has(key: string): Promise<boolean> {
    if (this.storageAvailable) {
      return localStorage.getItem(key) !== null;
    }
    return Cookies.get(key) !== undefined;
  }
}

/**
 * Secure Storage Adapter
 * Encrypts data before storing (for sensitive information)
 */
export class SecureStorageAdapter implements IStorageAdapter {
  private baseAdapter: IStorageAdapter;
  private encryptionKey: string;

  constructor(baseAdapter: IStorageAdapter, encryptionKey: string) {
    this.baseAdapter = baseAdapter;
    this.encryptionKey = encryptionKey;
  }

  async get<T>(key: string): Promise<T | null> {
    const encrypted = await this.baseAdapter.get<string>(key);
    if (!encrypted) return null;

    try {
      // TODO: Implement encryption/decryption
      // For now, just parse JSON
      return JSON.parse(encrypted) as T;
    } catch {
      return null;
    }
  }

  async set<T>(key: string, value: T, ttl?: number): Promise<void> {
    try {
      // TODO: Implement encryption
      // For now, just stringify
      const encrypted = JSON.stringify(value);
      await this.baseAdapter.set(key, encrypted, ttl);
    } catch (error) {
      console.error('Failed to store encrypted data:', error);
    }
  }

  async delete(key: string): Promise<void> {
    await this.baseAdapter.delete(key);
  }

  async clear(): Promise<void> {
    await this.baseAdapter.clear();
  }

  async has(key: string): Promise<boolean> {
    return await this.baseAdapter.has(key);
  }
}

/**
 * Create storage adapter based on environment
 */
export function createStorageAdapter(secure: boolean = false): IStorageAdapter {
  const isBrowser = typeof window !== 'undefined';
  
  let adapter: IStorageAdapter;
  
  if (isBrowser) {
    adapter = new BrowserStorageAdapter();
  } else {
    adapter = new MemoryStorageAdapter();
  }
  
  // Wrap with secure adapter if requested
  if (secure) {
    const encryptionKey = process.env.IAMSEC_STORAGE_ENCRYPTION_KEY || 'default-key';
    adapter = new SecureStorageAdapter(adapter, encryptionKey);
  }
  
  return adapter;
}

export default {
  MemoryStorageAdapter,
  BrowserStorageAdapter,
  SecureStorageAdapter,
  createStorageAdapter,
};

