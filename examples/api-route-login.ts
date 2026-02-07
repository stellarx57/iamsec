/**
 * IAMsec - Example: Login API Route
 * File: src/app/api/auth/login/route.ts
 */

import { NextRequest, NextResponse } from 'next/server';
import {
  createAuthenticationService,
  createTokenManager,
  createSessionManager,
  createStorageAdapter,
  getSecurityConfig,
} from '@/iamsec';

// Initialize IAMsec services
const securityConfig = getSecurityConfig();
const tokenManager = createTokenManager(securityConfig.jwt);
const storageAdapter = createStorageAdapter();
const sessionManager = createSessionManager(securityConfig.session, storageAdapter);
const authService = createAuthenticationService(securityConfig, tokenManager, sessionManager);

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email, password, rememberMe } = body;

    // Validate input
    if (!email || !password) {
      return NextResponse.json(
        { success: false, error: 'Email and password are required' },
        { status: 400 }
      );
    }

    // Get client info
    const ipAddress = request.headers.get('x-forwarded-for') || 
                     request.headers.get('x-real-ip') || 
                     'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';

    // Authenticate user
    const result = await authService.authenticate(
      { email, password, rememberMe },
      ipAddress,
      userAgent
    );

    if (!result.success) {
      return NextResponse.json(
        { success: false, error: result.error },
        { status: 401 }
      );
    }

    // Create response with session
    const response = NextResponse.json({
      success: true,
      session: result.session,
    });

    // Set cookies
    if (result.session) {
      // Access token cookie
      response.cookies.set('iamsec_access_token', result.session.tokens.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: result.session.tokens.expiresIn / 1000,
        path: '/',
      });

      // Refresh token cookie
      response.cookies.set('iamsec_refresh_token', result.session.tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60, // 7 days
        path: '/',
      });

      // Session ID cookie
      response.cookies.set('iamsec_session_id', result.session.sessionId, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: result.session.tokens.expiresIn / 1000,
        path: '/',
      });
    }

    return response;
  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json(
      { success: false, error: 'An error occurred during login' },
      { status: 500 }
    );
  }
}

